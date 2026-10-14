"""HTTP 服务：路由、加密信道、认证、静态资源、公开 CRL 分发。

传输安全模型（为什么没有 HTTPS）
--------------------------------
按需求不使用 HTTPS 证书，改为**在明文 HTTP 之上自建应用层加密信道**：

* ``GET  /api/handshake``  取服务端长期公钥与指纹（公开）
* ``POST /api/handshake``  X25519 协商，建立信道（公开）
* ``POST /api/rpc``        所有业务请求/响应都在 XSalsa20-Poly1305 密文里（公开可达，
                           但没有信道密钥无法解密，也无法伪造）
* ``GET  /crl/*``          公开的 CRL 分发端点（给 strongSwan 对端自动拉取，明文）

因此：登录口令、证书私钥、备份内容都不会以明文出现在网络上；服务端也不需要信任任何证书。

每个请求依次经过的安全检查
--------------------------
1. Host 校验（可选，``CA_ALLOWED_HOSTS``）—— 防 DNS rebinding
2. 请求体大小限制（默认 64MB）
3. ``/api/rpc``：信道查找 → AEAD 解密 → 计数器防重放 → 分发
4. 明文 REST：默认只允许本机回环（``CA_LEGACY_API=loopback``），便于运维与自动化；
   远程明文请求会被 403 拒绝并提示使用界面
5. 写明文的会话：cookie 为不透明随机 ID + 服务端会话表 + 绝对/空闲超时
6. CSRF：写明文的写方法必须有与会话匹配的 ``X-CSRF-Token`` 且 Origin 同源；
   加密信道内不需要（攻击者无法跨站获知信道密钥）
7. 响应头：CSP、X-Frame-Options、nosniff、Referrer-Policy；API 一律 no-store
"""
from __future__ import annotations

import json
import mimetypes
from email.utils import formatdate as email_utils_formatdate
import os
import re
import ssl
import sys
import traceback
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import api, ca, config, db, publish, secure_channel, security, x509util
from .api import ApiError, FilePart, Request, Resp
from .secure_channel import ChannelError

CT_JSON = "application/json; charset=utf-8"
PUBLIC_CRL_RE = re.compile(r"^/crl/(?:ca-(?P<ca_id>\d+)|current)\.crl(?:\.pem)?$")
STATIC_EXT = {".html", ".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg",
              ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".json", ".txt"}


def log(msg: str) -> None:
    sys.stderr.write(f"[{x509util.to_iso(x509util.now())}] {msg}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------- 工具
def parse_cookies(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    try:
        jar = SimpleCookie()
        jar.load(header)
        return {k: v.value for k, v in jar.items()}
    except Exception:  # noqa: BLE001 - 畸形 cookie 不应导致 500
        return {}


def parse_multipart(body: bytes, boundary: str) -> tuple[dict[str, str], dict[str, list[FilePart]]]:
    form: dict[str, str] = {}
    files: dict[str, list[FilePart]] = {}
    delim = b"--" + boundary.encode()
    for chunk in body.split(delim):
        if not chunk or chunk in (b"--", b"--\r\n", b"\r\n"):
            continue
        chunk = chunk.lstrip(b"\r\n")
        if chunk.startswith(b"--"):
            continue
        head, sep, content = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        content = content.rstrip(b"\r\n")
        disposition = ""
        content_type = "application/octet-stream"
        for line in head.decode("utf-8", "replace").split("\r\n"):
            key, _, value = line.partition(":")
            key = key.strip().lower()
            if key == "content-disposition":
                disposition = value.strip()
            elif key == "content-type":
                content_type = value.strip()
        name_m = re.search(r'name="([^"]*)"', disposition)
        if not name_m:
            continue
        name = name_m.group(1)
        file_m = re.search(r'filename="([^"]*)"', disposition)
        if file_m:
            files.setdefault(name, []).append(
                FilePart(filename=file_m.group(1) or "unnamed", content=content,
                         content_type=content_type))
        else:
            form[name] = content.decode("utf-8", "replace")
    return form, files


# ---------------------------------------------------------------- Handler
class Handler(BaseHTTPRequestHandler):
    server_version = f"CAAdmin/{config.VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self):        self._dispatch("GET")
    def do_HEAD(self):       self._dispatch("HEAD")
    def do_POST(self):       self._dispatch("POST")
    def do_PUT(self):        self._dispatch("PUT")
    def do_PATCH(self):      self._dispatch("PATCH")
    def do_DELETE(self):     self._dispatch("DELETE")
    def do_OPTIONS(self):    self._dispatch("OPTIONS")

    def log_message(self, fmt, *args):  # noqa: A003 - 基类签名
        pass  # 统一在 _dispatch 里输出更简洁的日志

    # ------------------------------------------------------------ 请求解析
    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > config.MAX_BODY_BYTES:
            raise ApiError(413, f"请求体过大（上限 {config.MAX_BODY_BYTES // 1048576}MB）")
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _json_body(self) -> dict:
        body = self._read_body()
        if not body:
            return {}
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "JSON 请求体格式错误")
        if not isinstance(parsed, dict):
            raise ApiError(400, "JSON 请求体必须是对象")
        return parsed

    def _build_request(self, method: str, path: str, query: dict, session) -> Request:
        req = Request(method=method, path=path, query=query, session=session,
                      ip=security.client_ip(self, config.TRUST_PROXY),
                      host=self.headers.get("Host", ""))
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            body = self._read_body()
            ctype = (self.headers.get("Content-Type") or "").lower()
            if body and "multipart/form-data" in ctype:
                m = re.search(r'boundary="?([^";]+)"?', ctype)
                if not m:
                    raise ApiError(400, "multipart 请求缺少 boundary")
                req.form, req.files = parse_multipart(body, m.group(1))
            elif body and "application/json" in ctype:
                try:
                    req.payload = json.loads(body.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    raise ApiError(400, "JSON 请求体格式错误")
            elif body and "application/x-www-form-urlencoded" in ctype:
                parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
                req.form = {k: v[0] for k, v in parsed.items()}
            elif body:
                try:
                    req.payload = json.loads(body.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    req.form = {"_raw": body.decode("utf-8", "replace")}
        return req

    # ------------------------------------------------------------ 分发
    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        ip = security.client_ip(self, config.TRUST_PROXY)
        try:
            if not self._host_allowed():
                raise ApiError(421, "Host 头不被允许（请用配置的主机名/地址访问）")
            if path == "/api/handshake":
                resp = self._handle_handshake(method, query)
            elif path == "/api/rpc":
                resp = self._handle_rpc(method)
            elif PUBLIC_CRL_RE.match(path):
                resp = self._handle_public_crl(path)
            elif path.startswith("/api/"):
                secure_channel.enforce_legacy(ip)
                resp = self._handle_legacy_api(method, path, query)
            elif method in ("GET", "HEAD"):
                resp = self._handle_static(path, self._session())
            else:
                raise ApiError(405, "不支持的方法")
        except ApiError as exc:
            resp = Resp(status=exc.status, json={"error": exc.message})
        except Exception as exc:  # noqa: BLE001 - 任何未捕获异常都返回 500 而非断开连接
            log(f"ERROR {method} {path}: {exc}\n{traceback.format_exc()}")
            resp = Resp(status=500, json={"error": f"服务器内部错误: {type(exc).__name__}"})
        self._send(resp, method)

    def _host_allowed(self) -> bool:
        if not config.ALLOWED_HOSTS:
            return True
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        return host in [h.lower() for h in config.ALLOWED_HOSTS]

    def _session(self):
        cookie = parse_cookies(self.headers.get("Cookie"))
        # 会话与首次登录的 IP/UA 绑定：cookie 被搬到别的机器即失效（纵深防御）
        return security.sessions.get(
            cookie.get(config.SESSION_COOKIE),
            ip=security.client_ip(self, config.TRUST_PROXY),
            user_agent=self.headers.get("User-Agent"))

    # ------------------------------------------------------------ 加密信道
    def _handle_handshake(self, method: str, query: dict) -> Resp:
        if method == "GET":
            info = secure_channel.handshake_info()
            info["tls"] = config.TLS_ENABLED
            info["legacy_api"] = config.LEGACY_API
            return Resp(json=info)
        if method != "POST":
            raise ApiError(405, "握手接口只支持 GET / POST")
        payload = self._json_body()
        ip = security.client_ip(self, config.TRUST_PROXY)
        try:
            result = secure_channel.handshake(payload, ip,
                                             self.headers.get("User-Agent", ""))
        except ChannelError as exc:
            # 注意：握手失败**不**计入登录失败锁定。
            # 握手阶段不校验任何口令，若计入，一个老浏览器或被 CSP 拦住的页面
            # 反复重试就可能把管理员永久锁在门外（真实踩过）。
            # 这里只留审计，便于排查；真正的口令暴力破解由登录失败计数拦截。
            audit_fail(ip)
            raise ApiError(400, str(exc))
        return Resp(json=result)

    def _handle_rpc(self, method: str) -> Resp:
        if method != "POST":
            raise ApiError(405, "RPC 接口只支持 POST")
        envelope = self._json_body()
        ip = security.client_ip(self, config.TRUST_PROXY)
        # 把同一浏览器的 cookie 会话也带进去：登录页登录后跳转 index.html 时，
        # 新信道尚未绑定身份，靠这个会话授权（否则页面会又弹回登录页）。
        status, body, extra = secure_channel.rpc(
            envelope, ip, host=self.headers.get("Host", ""),
            user_agent=self.headers.get("User-Agent", ""), cookie_session=self._session())
        resp = Resp(status=status, json=body)
        for k, v in (extra or {}).items():
            resp.headers[k] = v
        return resp

    # ------------------------------------------------------------ 明文 REST
    def _handle_legacy_api(self, method: str, path: str, query: dict) -> Resp:
        session = self._session()
        needs_auth = True
        for route_method, pattern, _h, auth_required in api.ROUTES:
            if re.match(pattern, path) and route_method == method:
                needs_auth = auth_required
                break
        if needs_auth and session is None:
            return Resp(status=401, json={"error": "unauthorized"})
        if needs_auth and method in api.WRITE_METHODS:
            # 只对需要认证的写操作校验 CSRF；登录接口本身没有会话，不适用
            self._check_csrf(session)
        req = self._build_request(method, path, query, session)
        if session is not None:
            req.form.setdefault("_sid", session.sid)
        try:
            return api.route_api(req)
        finally:
            self._log_access(method, path, session)

    def _check_csrf(self, session) -> None:
        if session is None:
            raise ApiError(401, "unauthorized")
        token = (self.headers.get("X-CSRF-Token") or "").strip()
        import hmac as _hmac
        if not token or not _hmac.compare_digest(token, session.csrf):
            raise ApiError(403, "CSRF 令牌缺失或不正确，请刷新页面后重试")
        if not security.same_origin(self):
            raise ApiError(403, "请求来源与本站不一致，已拒绝")

    def _log_access(self, method: str, path: str, session) -> None:
        if path in ("/api/health", "/api/me"):
            return
        actor = session.username if session else "-"
        ip = security.client_ip(self, config.TRUST_PROXY)
        log(f"{method} {path} {actor}@{ip} [plain]")

    # ------------------------------------------------------------ 公开 CRL
    def _handle_public_crl(self, path: str) -> Resp:
        m = PUBLIC_CRL_RE.match(path)
        ca_id = m.group("ca_id")
        want_pem = path.endswith(".pem")
        row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1") if ca_id is None else \
            db.q1("SELECT * FROM crls WHERE ca_id=? ORDER BY id DESC LIMIT 1", (int(ca_id),))
        if row is None:
            raise ApiError(404, "尚未生成 CRL")
        rel = row["path"] if want_pem else row["der_path"]
        target = config.DATA_DIR / rel
        if not target.exists():
            raise ApiError(404, "CRL 文件不存在")
        return Resp(status=200, body=target.read_bytes(),
                    content_type="application/x-pem-file" if want_pem else "application/pkix-crl",
                    headers={"Content-Disposition": "inline",
                             "Cache-Control": "public, max-age=300",
                             "X-CRL-Number": str(row["number"] or ""),
                             "X-CRL-Next-Update": str(row["next_update"] or "")})

    # ------------------------------------------------------------ 静态
    def _handle_static(self, path: str, session) -> Resp:
        if path in ("/", "/index.html") and session is None:
            return Resp(status=302, body=b"", headers={"Location": "/login.html"})
        rel = "index.html" if path == "/" else path.lstrip("/")
        if rel.endswith("/"):
            rel += "index.html"
        base = config.FRONTEND_DIR.resolve()
        try:
            resolved = (config.FRONTEND_DIR / rel).resolve()
        except OSError:
            raise ApiError(404, "资源不存在")
        try:
            resolved.relative_to(base)
        except ValueError:
            raise ApiError(404, "资源不存在")
        if not resolved.is_file():
            raise ApiError(404, "资源不存在")
        if resolved.suffix.lower() not in STATIC_EXT:
            raise ApiError(403, "不允许访问该类型的文件")
        ctype = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        # 缓存校验：一定要给出 ETag/Last-Modified。
        # 只有 no-cache 而没有校验器时，部分浏览器会继续用内存/磁盘里的旧副本，
        # 于是"升级后看到的还是旧页面"（真实踩过：旧登录页被 CSP 拦掉，表现为点登录没反应）。
        st = resolved.stat()
        etag = f'"{int(st.st_mtime)}-{st.st_size}"'
        last_modified = email_utils_formatdate(st.st_mtime, usegmt=True)
        headers = {"Cache-Control": "no-cache", "ETag": etag, "Last-Modified": last_modified}
        inm = (self.headers.get("If-None-Match") or "").strip()
        ims = (self.headers.get("If-Modified-Since") or "").strip()
        if (inm and inm == etag) or (not inm and ims and ims == last_modified):
            return Resp(status=304, body=b"", headers=headers)
        return Resp(status=200, body=resolved.read_bytes(), content_type=ctype,
                    headers=headers)

    # ------------------------------------------------------------ 响应
    def _send(self, resp: Resp, method: str) -> None:
        headers = dict(resp.headers)
        if resp.file is not None:
            body = resp.file.read_bytes()
            headers.setdefault("Content-Type", resp.content_type)
            if resp.filename:
                headers["Content-Disposition"] = (
                    f"attachment; filename=\"{_ascii(resp.filename)}\"; "
                    f"filename*=UTF-8''{_q(resp.filename)}")
            headers.setdefault("Cache-Control", "no-store")
        elif resp.body is not None:
            body = resp.body
            headers.setdefault("Content-Type", resp.content_type)
        else:
            body = json.dumps(resp.json if resp.json is not None else {"ok": True},
                              ensure_ascii=False, default=str).encode("utf-8")
            headers.setdefault("Content-Type", CT_JSON)
        headers.update(security.security_headers(
            config.TLS_ENABLED, api=resp.file is None and resp.body is None))
        if resp.status == 421:
            headers["Connection"] = "close"
        try:
            self.send_response(resp.status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if method != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_expect_100(self) -> bool:
        self.send_response_only(HTTPStatus.CONTINUE)
        self.end_headers()
        return True


def _q(text: str) -> str:
    from urllib.parse import quote
    return quote(text or "", safe="")


def _ascii(text: str) -> str:
    return (text or "download").encode("ascii", "ignore").decode() or "download"


def audit_fail(ip: str) -> None:
    from . import audit
    audit.log("channel.handshake_failed", target_type="channel", actor=ip, detail={"ip": ip})


# ---------------------------------------------------------------- 启动
def build_server(host: str | None = None, port: int | None = None,
                 tls: bool | None = None) -> ThreadingHTTPServer:
    host = host if host is not None else config.HOST
    port = port if port is not None else config.PORT
    tls = config.TLS_ENABLED if tls is None else tls
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True
    if tls:
        cert_path, key_path = security.ensure_tls_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!RC4")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.tls = bool(tls)
    return httpd


def bootstrap(verbose: bool = True) -> dict:
    config.ensure_dirs()
    db.init_db()
    from . import automation, rules
    rules.seed_builtin()            # 内置规则集（strongSwan 优先），已有则保留管理员修改
    automation.install_presets()    # 自动化扩展示例（默认停用，不与发布目标重复）
    initial = security.ensure_admin()
    publish.ensure_default_targets()
    # 默认 CRL 分发点：没配过就按本机地址生成一个，便于 strongSwan 对端自动拉取
    if not (db.get_setting("crl_url") or "").strip():
        try:
            ips = [i for i in security._local_ips() if i not in ("127.0.0.1", "::1")]
            host = config.HOST if config.HOST not in ("0.0.0.0", "::") else (ips[0] if ips else "127.0.0.1")
            db.set_setting("crl_url", f"http://{host}:{config.PORT}/crl/current.crl")
        except Exception:  # noqa: BLE001
            pass
    fingerprint = secure_channel.identity.fingerprint     # 触发/加载信道密钥
    if verbose:
        _banner(initial, fingerprint)
    return {"initial_password": initial, "channel_fingerprint": fingerprint,
            "rulesets": len(rules.list_all()), "automation_tasks": len(automation.list_tasks())}


def _banner(initial_password: str | None, fingerprint: str) -> None:
    scheme = "https" if config.TLS_ENABLED else "http"
    ca_row = ca.active_ca_row()
    st = publish.status()
    log("=" * 78)
    log(f"  {config.APP_NAME} v{config.VERSION}")
    log(f"  监听: {scheme}://{config.HOST}:{config.PORT}")
    log(f"  数据目录: {config.DATA_DIR}")
    log(f"  CA: {(ca_row['subject'] if ca_row else '未导入')}"
        f"{'（私钥已就绪）' if ca_row and ca_row['has_key'] else '（缺少私钥）' if ca_row else ''}")
    log(f"  CRL 健康度: {st['health']}  自动发布: "
        f"{'开' if st['auto_publish'] else '关'}  目标数: {st['enabled_targets']}")
    log("-" * 78)
    log(f"  运行身份: uid={os.geteuid()}（{'root：可直接写 /etc/swanctl 并执行 swanctl' if config.RUN_AS_ROOT else '非 root：/etc/swanctl 需靠同步单元'}）")
    log(f"  加密信道服务端指纹: {fingerprint}")
    log("  ↑ 首次在浏览器打开界面时会显示同一指纹，请核对一致（只需核对一次，之后自动固定）")
    log(f"  传输模式: HTTP + 应用层加密信道（XSalsa20-Poly1305）"
        f"{' + TLS' if config.TLS_ENABLED else ''}")
    log(f"  明文 REST 接口范围: {config.LEGACY_API}（可设 CA_LEGACY_API=off 完全关闭）")
    if not config.TLS_ENABLED and not security.is_loopback_ip(config.HOST):
        log("  [!] 安全警告：当前**非回环绑定 + 未启用 TLS**。")
        log("      明文 HTTP 上的会话 cookie 属于 bearer 凭据，可能被嗅探后用于接管管理权限；")
        log("      因此非回环来源登录时**不会下发 cookie**，跨页面会话不可用。")
        log("      请改用：只监听回环 + ssh -L 9443:127.0.0.1:9443，或设置 CA_TLS=on。")
    if initial_password:
        log("-" * 78)
        log(f"  已创建管理员 {security.DEFAULT_USERNAME}，初始口令: {initial_password}")
        log(f"  同步写入: {config.INITIAL_PW_FILE}（登录后请立即修改口令并删除该文件）")
    log("=" * 78)


def main() -> int:
    bootstrap()
    httpd = build_server()
    publish.scheduler.start()
    scheme = "https" if getattr(httpd, "tls", False) else "http"
    log(f"服务已启动: {scheme}://{config.HOST}:{config.PORT}/")
    if config.HOST == "0.0.0.0":
        try:
            for ip in security._local_ips():
                if ip not in ("127.0.0.1", "::1"):
                    log(f"  局域网访问: {scheme}://{ip}:{config.PORT}/")
            log(f"  本机访问:   {scheme}://127.0.0.1:{config.PORT}/")
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("收到中断信号，正在停止…")
    finally:
        publish.scheduler.stop()
        httpd.server_close()
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
