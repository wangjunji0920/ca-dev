"""安全层：口令哈希、会话、CSRF、登录限速、TLS 自签证书、安全响应头。

安全设计（单管理员场景，但按公网可达的标准做）
--------------------------------------------
* **口令**：``hashlib.scrypt``（n=2^14, r=8, p=1）+ 每用户随机盐，格式
  ``scrypt$n$r$p$b64salt$b64hash``；校验用 ``hmac.compare_digest`` 常量时间比较。
* **会话**：cookie 里只放**不透明随机 ID**，真正的会话数据存在服务端内存里
  （可随时单条/全部吊销）。cookie 属性 ``HttpOnly`` + ``SameSite=Strict`` +
  ``Path=/``，HTTPS 下再加 ``Secure``。空闲超时 + 绝对超时双重限制。
* **CSRF**：每个会话一个随机 token，前端通过 ``X-CSRF-Token`` 头回传；
  所有写方法（POST/PUT/PATCH/DELETE）都校验。另加 Origin/Referer 同源校验。
* **暴力破解**：按 IP 统计失败次数，超阈值锁定并指数退避；成功登录清零。
* **传输**：默认只监听回环，不默认启用 HTTPS；显式开启 TLS 时自动生成自签证书
  （含本机 IP 与主机名 SAN）。非回环明文监听由 doctor 报告错误。
* **响应头**：CSP、X-Frame-Options、nosniff、Referrer-Policy 等；
  API 响应一律 ``Cache-Control: no-store``（避免证书/私钥被缓存）。
* **审计**：登录成功/失败、退出、改密、加锁等全部落审计日志，带来源 IP。
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import audit, config, db, x509util

# ---------------------------------------------------------------- 口令
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN = 2 ** 14, 8, 1, 32


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=SCRYPT_LEN, maxmem=64 * 1024 * 1024)
    return "$".join(["scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
                     base64.b64encode(salt).decode(), base64.b64encode(dk).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, b64salt, b64hash = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(b64salt),
                            n=int(n), r=int(r), p=int(p), dklen=len(base64.b64decode(b64hash)),
                            maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(dk, base64.b64decode(b64hash))
    except Exception:  # noqa: BLE001 - 存储格式异常一律视为校验失败
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password or "") < 10:
        problems.append("长度至少 10 位")
    if not any(c.isdigit() for c in password or ""):
        problems.append("至少包含 1 个数字")
    if not any(c.isalpha() for c in password or ""):
        problems.append("至少包含 1 个字母")
    return problems


# ---------------------------------------------------------------- 用户
DEFAULT_USERNAME = os.environ.get("CA_ADMIN_USER", "admin")


def ensure_admin() -> str | None:
    """首次运行创建管理员；返回初始明文口令（仅首次，写入 0600 文件）。"""
    row = db.q1("SELECT * FROM users WHERE username=?", (DEFAULT_USERNAME,))
    if row is not None:
        return None
    env_pw = os.environ.get("CA_ADMIN_PASSWORD")
    password = env_pw or secrets.token_urlsafe(12)
    ts = x509util.to_iso(x509util.now())
    with db.tx() as conn:
        # INSERT OR IGNORE：并发 bootstrap（例如服务首次启动时管理员同时跑 cli doctor）
        # 下，两个进程都可能走到这里；用户名有唯一约束，忽略即可而不是抛异常。
        conn.execute("INSERT OR IGNORE INTO users(username,password_hash,created_at,updated_at) "
                     "VALUES(?,?,?,?)", (DEFAULT_USERNAME, hash_password(password), ts, ts))
        audit.log("auth.user_created", target_type="user", target_label=DEFAULT_USERNAME,
                  actor="system", detail={"generated": not bool(env_pw)}, conn=conn)
    config.ensure_dirs()
    config.atomic_write_text(
        config.INITIAL_PW_FILE,
        f"用户名: {DEFAULT_USERNAME}\n初始口令: {password}\n"
        f"生成时间: {ts}\n请在登录后立即修改口令，并删除本文件。\n", private=True)
    return password


def change_password(old: str, new: str, actor: str = DEFAULT_USERNAME) -> None:
    row = db.q1("SELECT * FROM users WHERE username=?", (actor,))
    if row is None:
        raise PermissionError("用户不存在")
    if not verify_password(old, row["password_hash"]):
        raise PermissionError("原口令不正确")
    problems = password_problems(new)
    if problems:
        raise ValueError("新口令不符合要求：" + "；".join(problems))
    with db.tx() as conn:
        conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                     (hash_password(new), x509util.to_iso(x509util.now()), row["id"]))
        audit.log("auth.password_change", target_type="user", target_label=actor, actor=actor,
                  conn=conn)
    # 纪元 +1：**跨进程**让所有旧会话与旧信道立即失效（内存表只能清本进程的）
    db.set_setting(PASSWORD_CHANGED_KEY, x509util.to_iso(x509util.now()))
    bump_credential_epoch()
    sessions.revoke_all(actor)          # cookie 会话：全部失效
    dropped = revoke_sessions_of(actor, reason="password_change")   # 加密信道：同样失效
    if dropped:
        audit.log("auth.channels_revoked", target_type="user", target_label=actor, actor=actor,
                  detail={"count": dropped, "reason": "password_change"})
    try:
        if config.INITIAL_PW_FILE.exists():
            config.INITIAL_PW_FILE.unlink()
    except OSError:
        pass


# ---------------------------------------------------------------- 会话
@dataclass
class Session:
    sid: str
    username: str
    csrf: str
    created: float
    last_seen: float
    ip: str
    user_agent: str = ""
    # 创建时的凭据纪元：改密（含其它进程）后纪元 +1 → 该会话立即失效
    epoch: int = 0
    auth_failures: int = field(default=0)


class SessionStore:
    """进程内会话表（服务重启即全部失效，属于预期行为）。"""

    def __init__(self) -> None:
        self._items: dict[str, Session] = {}
        self._lock = threading.RLock()

    def create(self, username: str, ip: str, user_agent: str = "") -> Session:
        now = time.time()
        s = Session(sid=secrets.token_urlsafe(32), username=username,
                    csrf=secrets.token_urlsafe(24), created=now, last_seen=now, ip=ip,
                    user_agent=(user_agent or "")[:200], epoch=credential_epoch())
        with self._lock:
            self._prune_locked()
            self._items[s.sid] = s
        audit.log("auth.login", target_type="user", target_label=username, actor=username,
                  detail={"ip": ip, "user_agent": s.user_agent})
        return s

    def get(self, sid: str | None, ip: str | None = None,
            user_agent: str | None = None) -> Session | None:
        """取会话；给了 ip/user_agent 时**绑定校验**（cookie 被搬到别的机器就失效）。"""
        if not sid:
            return None
        with self._lock:
            s = self._items.get(sid)
            if s is None:
                return None
            now = time.time()
            if now - s.created > config.SESSION_TTL or now - s.last_seen > config.SESSION_IDLE:
                self._items.pop(sid, None)
                return None
            # 改密后（含 CLI 在其它进程改的）旧 cookie 会话立即失效
            if s.epoch < credential_epoch():
                self._items.pop(sid, None)
                return None
            # 绑定校验：会话与首次登录的 IP/UA 绑定，降低 cookie 被窃取后的可用性
            if ip and s.ip and s.ip != ip:
                audit.log("auth.session_ip_mismatch", target_type="user", target_label=s.username,
                          actor=s.username, detail={"session_ip": s.ip, "request_ip": ip})
                return None
            if user_agent is not None and s.user_agent and user_agent:
                if s.user_agent[:80] != str(user_agent)[:80]:
                    return None
            s.last_seen = now
            return s

    def destroy(self, sid: str | None, reason: str = "logout") -> None:
        if not sid:
            return
        with self._lock:
            s = self._items.pop(sid, None)
        if s is not None:
            audit.log(f"auth.{reason}", target_type="user", target_label=s.username,
                      actor=s.username, detail={"ip": s.ip})

    def revoke_all(self, username: str) -> None:
        with self._lock:
            for sid in [k for k, v in self._items.items() if v.username == username]:
                self._items.pop(sid, None)

    def count(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._items)

    def _prune_locked(self) -> None:
        now = time.time()
        for sid in [k for k, v in self._items.items()
                    if now - v.created > config.SESSION_TTL or now - v.last_seen > config.SESSION_IDLE]:
            self._items.pop(sid, None)


sessions = SessionStore()


# ---------------------------------------------------------------- 登录限速
class LoginGuard:
    """按 IP 的失败计数 + 锁定，防口令暴力破解。"""

    MAX_FAILURES = 5            # 非回环客户端
    # 回环客户端（服务只监听 127.0.0.1 时的本机/SSH 隧道访问）给更宽的阈值：
    # 隧道下**所有**浏览器都表现为 127.0.0.1，若沿用 5 次阈值，管理员多点几次就把自己锁死。
    # 能连到回环端口的前提是已经拿到该主机的 shell/SSH 权限，暴力破解的边际风险很低。
    MAX_FAILURES_LOOPBACK = 20
    WINDOW = 900          # 15 分钟内累计
    LOCK_BASE = 30        # 首次锁定 30s，之后翻倍
    LOCK_MAX = 900
    LOOPBACK = ("127.0.0.1", "::1", "localhost", "unknown")

    def __init__(self) -> None:
        self._state: dict[str, dict] = {}
        self._lock = threading.RLock()

    def check(self, ip: str) -> int:
        """返回还需等待的秒数，0 表示可以尝试。"""
        with self._lock:
            st = self._state.get(ip)
            if not st:
                return 0
            until = st.get("locked_until", 0)
            if until and until > time.time():
                return int(until - time.time()) + 1
            if until and until <= time.time():
                st["locked_until"] = 0
            return 0

    def threshold(self, ip: str) -> int:
        return self.MAX_FAILURES_LOOPBACK if ip in self.LOOPBACK else self.MAX_FAILURES

    def reset(self, ip: str | None = None) -> None:
        """清空失败计数（cli unlock 用）。ip=None 清全部。"""
        with self._lock:
            if ip is None:
                self._state.clear()
            else:
                self._state.pop(ip, None)

    def fail(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            st = self._state.setdefault(ip, {"failures": 0, "first": now, "locked_until": 0,
                                             "lock_level": 0})
            if now - st["first"] > self.WINDOW:
                st["failures"], st["first"] = 0, now
            st["failures"] += 1
            if st["failures"] >= self.threshold(ip):
                st["lock_level"] += 1
                duration = min(self.LOCK_BASE * (2 ** (st["lock_level"] - 1)), self.LOCK_MAX)
                st["locked_until"] = now + duration
                st["failures"] = 0
                st["first"] = now
                audit.log("auth.locked", target_type="user", actor=ip,
                          detail={"seconds": duration, "ip": ip})

    def succeed(self, ip: str) -> None:
        with self._lock:
            self._state.pop(ip, None)


def revoke_sessions_of(username: str, reason: str = "password_change") -> int:
    """丢弃某用户的**全部**已认证加密信道（改密后旧信道必须立即失效）。

    为什么需要：信道登录成功是**把身份绑定在信道对象上**的，不走 cookie；
    只清 cookie 会话的话，攻击者手里那条旧信道仍然有管理权限（审查复现）。
    """
    try:
        from . import secure_channel as _sc
        return _sc.drop_user_channels(username, reason=reason)
    except Exception:  # noqa: BLE001
        return 0


login_guard = LoginGuard()

# 失败计数在服务进程内存里，另一个进程（cli unlock）无法直接清；
# 于是用"标记文件"跨进程通信：服务在处理登录前发现标记就清空计数并删掉它。
GUARD_RESET_FILE = "login_guard_reset"


def request_guard_reset() -> None:
    """请求清空登录失败计数（写标记文件；需要对该进程数据目录有写权限）。"""
    config.ensure_dirs()
    config.atomic_write_text(config.DATA_DIR / GUARD_RESET_FILE,
                             x509util.to_iso(x509util.now()) + "\n")


def consume_guard_reset() -> bool:
    """服务进程侧调用：有标记就清空计数并删除标记，返回是否清过。"""
    marker = config.DATA_DIR / GUARD_RESET_FILE
    try:
        if not marker.exists():
            return False
        marker.unlink()
    except OSError:
        return False
    login_guard.reset()
    return True


# ---------------------------------------------------------------- 客户端信息
def _peer_ip(handler) -> str:
    return handler.client_address[0] if handler.client_address else "unknown"


def trusted_proxy_peers() -> set[str]:
    """可信反向代理的来源地址（CA_TRUSTED_PROXIES，逗号分隔）。默认为空。"""
    raw = os.environ.get("CA_TRUSTED_PROXIES", "") or db.get_setting("trusted_proxies", "")
    return {x.strip() for x in str(raw).split(",") if x.strip()}


def client_ip(handler, trust_proxy: bool) -> str:
    """解析客户端来源 IP。

    **只有来自已核实代理来源的连接才允许采信 X-Forwarded-For**：
    审查复现——开启 CA_TRUST_PROXY=1 时，任何直连客户端都能用 `X-Forwarded-For: 127.0.0.1`
    把自己伪装成"本机"，从而绕过"明文仅回环"限制并拿到会话 cookie。
    因此：对端是回环（本机反代/SSH 隧道）或显式列在 CA_TRUSTED_PROXIES 里才采信；
    其余情况一律忽略该头（用真实对端地址），并记一次审计便于排查。
    """
    peer = _peer_ip(handler)
    if trust_proxy:
        trusted = is_loopback_ip(peer) or peer in trusted_proxy_peers()
        fwd = handler.headers.get("X-Forwarded-For")
        if fwd and trusted:
            return fwd.split(",")[0].strip()
        if fwd and not trusted:
            try:
                audit.log("security.xff_ignored", target_type="request", target_label=peer,
                          actor="system",
                          detail={"reason": "来源不是已核实的代理，忽略 X-Forwarded-For",
                                  "xff": str(fwd)[:120]})
            except Exception:  # noqa: BLE001
                pass
    return peer


def same_origin(handler) -> bool:
    """校验 Origin/Referer 与本机 Host 一致（防 CSRF 的纵深防御）。"""
    origin = handler.headers.get("Origin")
    if not origin:
        return True  # 非浏览器客户端（curl / 自动化）没有 Origin，交给 CSRF token 把关
    host = handler.headers.get("Host", "")
    for prefix in ("http://", "https://"):
        if origin.startswith(prefix):
            return origin[len(prefix):].rstrip("/") == host
    return False


# ---------------------------------------------------------------- 安全响应头
def security_headers(https: bool, api: bool = False) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), usb=()",
        # 前端不使用任何外部资源，因此可以下很严的 CSP
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        ),
    }
    if api:
        headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        headers["Pragma"] = "no-cache"
    if https:
        headers["Strict-Transport-Security"] = "max-age=31536000"
    return headers


PASSWORD_CHANGED_KEY = "auth_password_changed_at"      # 仅用于展示/审计
CREDENTIAL_EPOCH_KEY = "auth_credential_epoch"          # 单调递增，跨进程判定失效


def credential_epoch() -> int:
    """凭据纪元号：每次改密/强制下线 +1。会话与信道都记录创建时的纪元，
    纪元变大即失效 —— 用整数而不是时间戳，避免同秒/时钟漂移/ISO 截断的判定漏洞。"""
    try:
        return int(db.get_setting(CREDENTIAL_EPOCH_KEY, "0") or 0)
    except (TypeError, ValueError):
        return 0


def bump_credential_epoch() -> int:
    """改密/强制下线时调用：纪元 +1（跨进程立即生效）。"""
    new_epoch = credential_epoch() + 1
    db.set_setting(CREDENTIAL_EPOCH_KEY, str(new_epoch))
    return new_epoch


def channel_still_valid(login_epoch: int) -> bool:
    """信道登录时的纪元是否仍是当前纪元（否则该信道必须失效）。"""
    try:
        return int(login_epoch or 0) >= credential_epoch()
    except (TypeError, ValueError):
        return False


def is_loopback_ip(ip: str | None) -> bool:
    """来源是否为回环（本机 / SSH 隧道在服务端就是 127.0.0.1）。"""
    if not ip:
        return False
    ip = str(ip).strip()
    if ip in ("127.0.0.1", "::1", "localhost", "unknown"):
        return ip != "unknown"
    try:
        import ipaddress as _ip
        return _ip.ip_address(ip).is_loopback
    except ValueError:
        return False


def cookie(name: str, value: str, *, max_age: int | None = None, secure: bool = False,
           http_only: bool = True, path: str = "/", same_site: str = "Strict") -> str:
    parts = [f"{name}={value}", f"Path={path}", f"SameSite={same_site}"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


# ---------------------------------------------------------------- TLS 自签证书
def _local_ips() -> list[str]:
    ips = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except OSError:
        pass
    # 通过 UDP “连接”外部地址来推断默认出口 IP（不会真的发包）
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(i for i in ips if ":" not in i or i == "::1")


def ensure_tls_cert() -> tuple[Path, Path]:
    """首次运行生成自签 TLS 证书（管理界面用），返回 (cert, key)。"""
    config.ensure_dirs()
    cert_path = config.DATA_DIR / "tls" / "admin-ui.crt"
    key_path = config.DATA_DIR / "tls" / "admin-ui.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = socket.gethostname()
    names: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.DNSName(hostname)]
    for extra in (os.environ.get("CA_TLS_EXTRA_NAMES") or "").split(","):
        extra = extra.strip()
        if extra:
            names.append(x509.DNSName(extra))
    ips = _local_ips()
    for ip in ips:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            continue

    now = x509util.now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname or "ca-admin"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                            db.get_setting("org_name", "CA") or "CA")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                         key_cert_sign=False, crl_sign=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(private_key=key, algorithm=hashes.SHA256()))

    config.atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    config.atomic_write(key_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), private=True)
    audit.log("tls.self_signed_created", target_type="tls", target_label=str(cert_path),
              actor="system",
              detail={"san": [str(n.value) for n in names], "fingerprint":
                      x509util.fingerprint(cert)})
    return cert_path, key_path
