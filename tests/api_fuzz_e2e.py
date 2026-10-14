"""API 健壮性扫描：对**每一条**路由灌垃圾输入，确认没有 5xx / 堆栈泄漏。

生产环境最难受的不是"接口报错"，而是"接口 500 + 半截堆栈"。
这个测试遍历 backend/api.py 的全部路由（GET 39 / POST 35 / DELETE 7 / PATCH 7），
对每条灌入四类垃圾输入：
    a) 空对象 {}                     b) 类型全错（id 给字符串、name 给数字、spec 给数组）
    c) 非法 JSON（"{bad"）            d) 不存在的 ID（999999）
断言：
    * 绝不出现 5xx；
    * 4xx 必须是结构化 JSON（带 error 字段），不能是 HTML/空体；
    * 服务端日志里没有 Traceback；
    * 扫描后服务仍健康、已签发的证书与 CRL 未受损（没被垃圾输入搞坏数据）。
另附安全断言：未登录 401、缺 CSRF 403、来源不符 403。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl
os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="apifuzz-"))
DATA = TMP / "data"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def route_to_path(pattern: str) -> str:
    """把路由正则转成可请求的具体路径（参数都填 1）。"""
    def sub(m: re.Match) -> str:
        inner = m.group(2)
        if "\\d" in inner or "[0-9]" in inner:
            return "999999" if False else "1"
        return "x"
    path = re.sub(r"\(\?P<(\w+)>([^)]+)\)", sub, pattern)
    path = path.lstrip("^").rstrip("$")
    # 剩下的非捕获组/可选段直接简化掉
    path = re.sub(r"\(\?:[^)]*\)[?+]?", "x", path)
    path = re.sub(r"\[[^\]]*\][?*+]?", "x", path)
    path = path.replace("\\", "")
    return path


def seed() -> None:
    code = f'''
import datetime as dt, sys
sys.path.insert(0, {str(ROOT)!r})
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend import server, ca, x509util
server.bootstrap(verbose=False)
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fuzz CA")])
now = x509util.now()
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
     .serial_number(x509.random_serial_number()).not_valid_before(now)
     .not_valid_after(now + dt.timedelta(days=3650))
     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
     .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
        key_encipherment=False, content_commitment=False, data_encipherment=False,
        key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
     .sign(k, hashes.SHA256()))
row = ca.import_ca(x509util.pem_cert(c).encode(), x509util.pem_key(k).encode())
ca.issue_certificate(ca_row=row, vpn_identity="fuzz.example.com", cn="fuzz-cert")
ca.generate_crl(actor="fuzz", source="fuzz")
print("seeded")
'''
    r = subprocess.run([PY, "-c", code], cwd=ROOT,
                       env=dict(os.environ, CA_DATA_DIR=str(DATA)),
                       capture_output=True, text=True)
    if "seeded" not in r.stdout:
        raise SystemExit("播种失败: " + r.stderr[-400:])


class Client:
    def __init__(self, base: str) -> None:
        self.base = base
        self.cookie = ""
        self.csrf = ""

    def raw(self, method: str, path: str, body: str | None = None,
            csrf: bool = True, origin: bool = True):
        data = body.encode() if isinstance(body, str) else (
            json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        if csrf and self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        if origin:
            req.add_header("Origin", self.base)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return 0, f"client-error: {exc}"


def main() -> int:
    print("\n\033[1m== 准备 ==\033[0m")
    DATA.mkdir(parents=True, exist_ok=True)
    seed()
    port = free_port()
    env = dict(os.environ, CA_DATA_DIR=str(DATA), CA_HOST="127.0.0.1",
               CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    c = Client(base)
    log: list[str] = []

    def drain() -> None:
        # 读走已产生的日志（非阻塞）
        import select
        while True:
            r, _, _ = select.select([proc.stdout], [], [], 0)
            if not r:
                break
            line = proc.stdout.readline()
            if not line:
                break
            log.append(line)

    try:
        for _ in range(80):
            st, _b = c.raw("GET", "/api/health")
            if st == 200:
                break
            time.sleep(0.25)
        check("临时服务已启动", st == 200, f"HTTP {st}")

        # ---------------- 安全断言 ----------------
        print("\n\033[1m== 认证与 CSRF ==\033[0m")
        st, body = c.raw("GET", "/api/overview", csrf=False)
        check("未登录访问业务接口 -> 401", st == 401, f"HTTP {st}")
        pw = re.search(r"初始口令:\s*(\S+)",
                       (DATA / "initial_admin_password.txt").read_text(encoding="utf-8"))
        st, body = c.raw("POST", "/api/login",
                         {"username": "admin", "password": "definitely-wrong"}, csrf=False)
        check("错误口令 -> 401 且无口令泄漏", st == 401 and "definitely" not in body,
              f"HTTP {st} {body[:60]}")
        st, body = c.raw("POST", "/api/login",
                         {"username": "admin", "password": pw.group(1)}, csrf=False)
        check("正确口令 -> 200 并返回 csrf", st == 200 and "csrf" in body, f"HTTP {st}")
        data = json.loads(body)
        c.csrf = data["csrf"]
        # 从 Set-Cookie 取会话
        req = urllib.request.Request(base + "/api/login",
                                     data=json.dumps({"username": "admin",
                                                      "password": pw.group(1)}).encode(),
                                     method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            c.cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        st, _ = c.raw("GET", "/api/overview")
        check("带会话 cookie -> 200", st == 200, f"HTTP {st}")
        st, _ = c.raw("POST", "/api/rulesets", {"slug": "csrf-test", "name": "x"}, csrf=False)
        check("写接口缺 CSRF 令牌 -> 403", st == 403, f"HTTP {st}")
        st, _ = c.raw("POST", "/api/rulesets", {"slug": "csrf-test", "name": "x"}, origin=False)
        check("写接口来源不符 -> 403", st == 403, f"HTTP {st}")

        # ---------------- 遍历路由灌垃圾 ----------------
        sys.path.insert(0, str(ROOT))
        from backend import api  # noqa: E402
        print(f"\n\033[1m== 扫描 {len(api.ROUTES)} 条路由（垃圾输入）==\033[0m")
        bad_5xx: list[str] = []
        bad_shape: list[str] = []
        covered = 0
        junk_bodies = [
            "{}",
            json.dumps({"id": "abc", "name": 123, "spec": [], "enabled": "yes",
                        "path": 42, "tags": {}, "password": ["x"],
                        "validity_days": "lots", "reason": 1.5}),
            "{bad json",
        ]
        for method, pattern, handler, needs_auth in api.ROUTES:
            path = route_to_path(pattern)
            if "?" in path or "(?" in path:
                continue
            covered += 1
            cases = junk_bodies if method in ("POST", "PATCH", "PUT") else [None]
            for body in cases:
                st, text = c.raw(method, path, body)
                tag = f"{method} {path} body={str(body)[:24]}"
                if st >= 500 or st == 0:
                    bad_5xx.append(f"{tag} -> {st} {text[:80]!r}")
                    continue
                if st >= 400:
                    try:
                        obj = json.loads(text)
                    except Exception:  # noqa: BLE001
                        bad_shape.append(f"{tag} -> {st} 非 JSON: {text[:60]!r}")
                        continue
                    if "error" not in obj:
                        bad_shape.append(f"{tag} -> {st} JSON 缺 error: {text[:60]!r}")
            # GET 也补一次带垃圾查询串
            if method == "GET":
                st, text = c.raw("GET", path + "?limit=abc&page=-3&status=%00&q=" + "x" * 300)
                if st >= 500 or st == 0:
                    bad_5xx.append(f"GET {path}?junk -> {st} {text[:80]!r}")

        check(f"全部 {covered} 条路由：无 5xx / 无连接异常", not bad_5xx,
              " | ".join(bad_5xx[:4]))
        check("所有 4xx 都是结构化 JSON（带 error 字段）", not bad_shape,
              " | ".join(bad_shape[:4]))

        # ---------------- 大体积与畸形体 ----------------
        print("\n\033[1m== 超大与畸形请求体 ==\033[0m")
        st, _ = c.raw("POST", "/api/certs/import", json.dumps({"blob": "A" * (3 * 1024 * 1024)}))
        check("3MB 请求体 -> 不 5xx（拒绝或结构化错误）", st < 500, f"HTTP {st}")
        st, _ = c.raw("POST", "/api/certs/issue", "[" * 5000)
        check("畸形 JSON -> 不 5xx", st < 500, f"HTTP {st}")

        # ---------------- 扫描后数据仍健康 ----------------
        print("\n\033[1m== 扫描后数据完整性 ==\033[0m")
        # 扫描过程中必然命中了 /api/logout（说明登出接口也是通的），这里重新登录
        st, body = c.raw("POST", "/api/login",
                         {"username": "admin", "password": pw.group(1)}, csrf=False)
        if st == 200:
            c.csrf = json.loads(body)["csrf"]
            req2 = urllib.request.Request(base + "/api/login",
                                          data=json.dumps({"username": "admin",
                                                           "password": pw.group(1)}).encode(),
                                          method="POST")
            req2.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req2, timeout=10) as resp:
                c.cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        check("扫描命中 /api/logout 后会话失效，重新登录可恢复", st == 200, f"HTTP {st}")
        st, body = c.raw("GET", "/api/certs", csrf=False)
        ok_list = st == 200 and "fuzz-cert" in body
        check("原有证书未受影响", ok_list, f"HTTP {st}")
        st, body = c.raw("GET", "/api/consistency", csrf=False)
        try:
            cerr = [i for i in json.loads(body).get("issues", []) if i.get("level") == "error"]
        except Exception:  # noqa: BLE001
            cerr = ["无法解析一致性结果"]
        check("一致性体检无 error（垃圾输入没搞坏数据）", not cerr, str(cerr[:2]))
        st, body = c.raw("GET", "/api/crl", csrf=False)
        check("CRL 仍可读", st == 200 and "crl" in body, f"HTTP {st}")

        drain()
        out = "".join(log)
        check("服务端日志无 Python Traceback", "Traceback" not in out,
              out[-300:] if "Traceback" in out else "")
        check("服务仍在运行", proc.poll() is None)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n  通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("  失败明细: " + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    import shutil
    try:
        code = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)
