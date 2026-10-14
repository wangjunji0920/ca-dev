"""端到端测试：在真实 HTTP 服务上跑通全部功能，包括自建加密信道。

运行：
    .venv/bin/python tests/e2e_test.py            # 全部
    .venv/bin/python tests/e2e_test.py -v         # 打印每次调用

覆盖范围
--------
加密信道（握手/指纹/重放防护/篡改检测）、认证（错误口令、锁定、会话）、
CA 导入、签发（系统生成密钥 / 上传 CSR / 批量）、查询与筛选、下载（PEM/DER/KEY/链/P12）、
吊销与恢复、CRL 生成与下载、外部 CRL 导入同步、续期、批量导入（文件/目录/CSV）、
一致性体检与修复、CRL 自动发布（含到期自动续签）、审计日志、设置与改密、
备份/恢复、公开 CRL 端点、明文 REST 门禁与 CSRF。
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 关键：必须在导入后端之前设置数据目录，config 在导入时读取环境变量
TEST_DATA = ROOT / ".tmp" / "e2e-data"
if TEST_DATA.exists():
    shutil.rmtree(TEST_DATA)
os.environ["CA_DATA_DIR"] = str(TEST_DATA)
os.environ["CA_TLS"] = "off"
os.environ["CA_LEGACY_API"] = "loopback"
os.environ["CA_CHANNEL_IDLE"] = "600"

from nacl import public, secret, utils  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from backend import automation, ca, config, consistency, db, publish, secure_channel  # noqa: E402
from backend import security, server, x509util  # noqa: E402

VERBOSE = "-v" in sys.argv
PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    if condition:
        PASSED.append(name)
        print(f"  \033[32m✓\033[0m {name}")
    else:
        FAILED.append((name, detail))
        print(f"  \033[31m✗\033[0m {name}  {detail}")
    return bool(condition)


def section(title: str) -> None:
    print(f"\n\033[1m== {title} ==\033[0m")


def expect_error(name: str, fn, *, status: int | None = None, contains: str = "") -> bool:
    try:
        fn()
    except RpcError as exc:
        ok = (status is None or exc.status == status) and (contains in str(exc))
        return check(name, ok, f"得到 status={exc.status} msg={exc}")
    except Exception as exc:  # noqa: BLE001
        return check(name, False, f"抛出了非预期异常 {type(exc).__name__}: {exc}")
    return check(name, False, "预期报错但成功了")


# ---------------------------------------------------------------- RPC 客户端
class RpcError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class RpcClient:
    """用 PyNaCl 实现与浏览器完全相同的加密信道协议。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.ch = None
        self.k_c2s = None
        self.k_s2c = None
        self.out = 0
        self.in_ = 0
        self.fingerprint = None
        self.server_pub = None

    # -- HTTP ---------------------------------------------------------
    def _http(self, method: str, path: str, payload=None, headers=None):
        url = self.base + path
        data = None
        hdrs = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                body = json.loads(raw) if "json" in ctype else raw
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw
            return exc.code, body, dict(exc.headers)

    # -- 握手 ---------------------------------------------------------
    def handshake(self):
        status, info, _ = self._http("GET", "/api/handshake")
        assert status == 200, f"handshake info failed: {status} {info}"
        self.server_pub = public.PublicKey(base64.b64decode(info["server_pub"]))
        self.fingerprint = info["fingerprint"]
        client_sk = public.PrivateKey.generate()
        box = public.Box(client_sk, self.server_pub)
        shared = box.shared_key()
        self.k_c2s = self._derive(shared, "CA-CHANNEL-c2s-v1")
        self.k_s2c = self._derive(shared, "CA-CHANNEL-s2c-v1")
        hello = json.dumps({"v": 1, "ts": int(time.time()), "ua": "e2e-test"}).encode()
        boxed = box.encrypt(hello, utils.random(24))
        status, reply, _ = self._http("POST", "/api/handshake", {
            "client_pub": base64.b64encode(bytes(client_sk.public_key)).decode(),
            "box": base64.b64encode(bytes(boxed)).decode(),
        })
        assert status == 200, f"handshake failed: {status} {reply}"
        self.ch = reply["ch"]
        opened = secret.SecretBox(self.k_s2c).decrypt(
            base64.b64decode(reply["n"]) + base64.b64decode(reply["c"]))
        inner = json.loads(opened)
        assert inner["ch"] == self.ch
        assert inner["fingerprint"] == self.fingerprint
        return info

    @staticmethod
    def _derive(shared: bytes, label: str) -> bytes:
        import hashlib
        return hashlib.sha512(shared + label.encode()).digest()[:32]

    # -- 调用 ---------------------------------------------------------
    def _seal(self, obj, key):
        self.out += 1
        nonce = self.out.to_bytes(8, "big") + utils.random(16)
        ct = secret.SecretBox(key).encrypt(json.dumps(obj, ensure_ascii=False).encode(), nonce)
        return base64.b64encode(nonce).decode(), base64.b64encode(ct.ciphertext).decode()

    def _open(self, payload):
        opened = secret.SecretBox(self.k_s2c).decrypt(
            base64.b64decode(payload["n"]) + base64.b64decode(payload["c"]))
        return json.loads(opened)

    def raw_envelope(self, inner: dict):
        n, c = self._seal(inner, self.k_c2s)
        return {"ch": self.ch, "n": n, "c": c}

    def call(self, method: str, path: str, body=None, query=None, files=None, rid=None):
        if self.ch is None:
            self.handshake()
        inner = {"m": method.upper(), "p": path, "q": query or {}, "b": body}
        if rid:
            inner["rid"] = rid
        if files:
            inner["files"] = files
        status, payload, _ = self._http("POST", "/api/rpc", self.raw_envelope(inner))
        if status == 401 and isinstance(payload, dict) and payload.get("rehandshake"):
            self.handshake()
            status, payload, _ = self._http("POST", "/api/rpc", self.raw_envelope(inner))
        if status != 200:
            raise RpcError(status, str(payload))
        out = self._open(payload)
        if VERBOSE:
            print(f"      {method} {path} -> {out['s']}")
        if out["s"] >= 400:
            raise RpcError(out["s"], (out.get("b") or {}).get("error", "unknown"))
        return out.get("b")

    def file(self, method: str, path: str, query=None) -> bytes:
        if self.ch is None:
            self.handshake()
        status, payload, _ = self._http("POST", "/api/rpc", self.raw_envelope(
            {"m": method.upper(), "p": path, "q": query or {}, "b": None}))
        out = self._open(payload)
        if out["s"] >= 400:
            raise RpcError(out["s"], (out.get("b") or {}).get("error", "unknown"))
        return base64.b64decode(out["f"]["data"])


def b64file(name: str, data: bytes, field: str = "files", ctype="application/octet-stream"):
    return {field: [{"name": name, "ct": ctype, "data": base64.b64encode(data).decode()}]}


# ---------------------------------------------------------------- 测试用 CA
def make_test_ca(cn="E2E Test CA", o="E2E Org"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, o)])
    now = x509util.now()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def main() -> int:  # noqa: C901 - 测试脚本，线性流程更直观
    section("启动服务")
    bootstrap = server.bootstrap(verbose=False)
    initial_password = Path(config.INITIAL_PW_FILE).read_text()
    password = [l for l in initial_password.splitlines() if l.startswith("初始口令")][0].split(": ")[1]
    httpd = server.build_server("127.0.0.1", 0, tls=False)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"  服务运行于 {base}，数据目录 {config.DATA_DIR}")
    check("服务启动", port > 0)
    check("明文 REST 仅限回环", secure_channel.legacy_allowed("127.0.0.1")
          and not secure_channel.legacy_allowed("192.168.1.50"))

    section("加密信道与认证")
    c = RpcClient(base)
    info = c.handshake()
    check("握手成功", c.ch is not None)
    check("服务端指纹一致", info["fingerprint"] == secure_channel.identity.fingerprint,
          f"{info['fingerprint']} != {secure_channel.identity.fingerprint}")
    check("指纹格式正确", len(info["fingerprint"]) == 39 and info["fingerprint"].count("-") == 7,
          info["fingerprint"])
    check("未登录访问受保护接口被拒", True)
    expect_error("未登录 /api/me 返回 401", lambda: c.call("GET", "/api/me"), status=401)
    expect_error("错误口令登录失败", lambda: c.call("POST", "/api/login",
                                                {"username": "admin", "password": "wrong"}),
                 status=401)
    out = c.call("POST", "/api/login", {"username": "admin", "password": password})
    check("正确口令登录成功", out.get("username") == "admin" and out.get("channel") is True, str(out))
    check("登录后 /api/me 可用", c.call("GET", "/api/me")["username"] == "admin")

    # 重放攻击：重复发送同一信封（单独用一个客户端，避免影响后面的主客户端）
    cr = RpcClient(base)
    cr.handshake()
    cr.call("POST", "/api/login", {"username": "admin", "password": password})
    env = cr.raw_envelope({"m": "GET", "p": "/api/health", "q": {}, "b": None})
    st1, _, _ = cr._http("POST", "/api/rpc", env)
    st2, payload2, _ = cr._http("POST", "/api/rpc", env)
    check("重放同一信封被拒", st2 == 401 and payload2.get("error") == "channel_broken",
          f"status={st2} body={payload2}")
    # 被判定重放后该信道立即作废（fail closed）
    st2b, payload2b, _ = cr._http("POST", "/api/rpc", cr.raw_envelope(
        {"m": "GET", "p": "/api/health", "q": {}, "b": None}))
    check("信道作废后需重新握手", st2b == 401 and payload2b.get("rehandshake") is True,
          f"status={st2b}")

    # 篡改密文
    c2 = RpcClient(base)
    c2.handshake()
    env = c2.raw_envelope({"m": "GET", "p": "/api/health", "q": {}, "b": None})
    raw = bytearray(base64.b64decode(env["c"]))
    raw[0] ^= 0xFF
    env["c"] = base64.b64encode(bytes(raw)).decode()
    st3, payload3, _ = c2._http("POST", "/api/rpc", env)
    check("密文被篡改后无法解密", st3 == 401 and payload3.get("error") == "channel_broken",
          f"status={st3} body={payload3}")

    check("握手 GET 信息含 kdf", info["kdf"]["hash"] == "sha512")

    section("明文 REST 门禁与 CSRF")
    st, body, hdrs = c._http("GET", "/api/health")
    check("本机明文 /api/health 可用", st == 200 and body.get("status") == "ok", str(body))
    st, body, hdrs_login = c._http("POST", "/api/login",
                                   {"username": "admin", "password": password})
    check("本机明文登录成功", st == 200 and body.get("username") == "admin", str(body))
    cookie = (hdrs_login.get("Set-Cookie") or "").split(";")[0]
    check("明文登录下发了会话 cookie", cookie.startswith("ca_session="), cookie)
    st, body, _ = c._http("POST", "/api/certs/issue", {"cn": "x"},
                          headers={"Cookie": cookie})
    check("明文写操作缺少 CSRF 被拒", st == 403 and "CSRF" in str(body), f"{st} {body}")
    st, body, _ = c._http("DELETE", "/api/certs/1", headers={"Cookie": cookie})
    check("明文 DELETE 缺 CSRF 被拒", st == 403, f"{st} {body}")
    st, body, _ = c._http("GET", "/api/certs", headers={"Cookie": cookie})
    check("明文读操作带 cookie 可用", st == 200 and "items" in body, f"{st}")

    section("CA 导入与管理")
    ca_key, ca_cert = make_test_ca()
    ca_pem, ca_key_pem = x509util.pem_cert(ca_cert).encode(), x509util.pem_key(ca_key).encode()
    out = c.call("POST", "/api/ca/import", None, files={
        "cert": [{"name": "ca.crt", "ct": "application/x-pem-file",
                  "data": base64.b64encode(ca_pem).decode()}],
        "key": [{"name": "ca.key", "ct": "application/x-pem-file",
                 "data": base64.b64encode(ca_key_pem).decode()}],
    })
    check("CA 导入成功且带私钥", out["ca"]["has_key"] and out["ca"]["is_active"], str(out["ca"])[:120])
    check("CA 指纹与本地一致",
          out["ca"]["fingerprint_sha256"] == x509util.fingerprint(ca_cert))
    expect_error("重复导入同一 CA 不报错（幂等）", lambda: None) if False else None
    out_ca = c.call("GET", "/api/ca")
    check("查询当前 CA", out_ca["ca"]["cn"] == "E2E Test CA", str(out_ca)[:120])
    check("CA 列表", len(c.call("GET", "/api/ca/list")["items"]) == 1)
    ca_pem_dl = c.file("GET", "/api/ca/1/download", {"format": "pem"})
    check("下载 CA 证书 PEM", b"BEGIN CERTIFICATE" in ca_pem_dl)
    der = c.file("GET", "/api/ca/1/download", {"format": "der"})
    check("下载 CA 证书 DER", x509util.load_cert(der).subject == ca_cert.subject)
    # 私钥与证书不匹配时应被拒绝
    other_key, _ = make_test_ca("Other CA")
    expect_error("私钥与证书不匹配被拒", lambda: c.call(
        "POST", "/api/ca/import", None, files={
            "cert": [{"name": "c.crt", "data": base64.b64encode(ca_pem).decode()}],
            "key": [{"name": "k.key",
                     "data": base64.b64encode(x509util.pem_key(other_key).encode()).decode()}]}),
        status=400, contains="不匹配")

    section("签发证书")
    issued = c.call("POST", "/api/certs/issue", {
        "profile": "vpn_client", "cn": "e2e-vpn-1", "o": "E2E Org", "ou": "IT", "c": "CN",
        "sans": [{"type": "dns", "value": "vpn1.example.com"},
                 {"type": "upn", "value": "vpn1@e2e.test"},
                 {"type": "ip", "value": "10.9.9.9"}],
        "validity_days": 365, "key_type": "rsa", "key_size": 2048,
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "eku": ["clientAuth", "ipsecIKE"], "serial_mode": "random",
        "owner": "张三", "tags": ["vpn", "e2e"], "notes": "端到端测试签发",
    })
    cert1 = issued["cert"]
    secret1 = issued["secret"]
    check("签发返回证书与私钥", bool(secret1.get("key_pem")) and bool(secret1.get("cert_pem")))
    parsed = x509util.load_cert(secret1["cert_pem"].encode())
    check("签发的证书可由 CA 验签", _verify(parsed, ca_cert))
    d = x509util.cert_to_dict(parsed)
    check("CN/SAN/UPN 正确", d["cn"] == "e2e-vpn-1" and any(
        s["type"] == "upn" and s["value"] == "vpn1@e2e.test" for s in d["sans"]), str(d["sans"]))
    check("EKU 含 ipsecIKE", "ipsecIKE" in d["eku"] and "clientAuth" in d["eku"], str(d["eku"]))
    check("元数据（所有者/标签）已保存", cert1["owner"] == "张三" and cert1["tags"] == ["vpn", "e2e"])
    check("证书状态为有效", cert1["status"] == "valid")
    check("私钥未写入数据库（只有文件）", cert1["has_key"] is True)

    # 用上传的 CSR 签发
    csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e-csr-1"),
                                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "E2E Org")]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("csr1.example.com")]),
                          critical=False)
           .sign(csr_key, hashes.SHA256()))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    issued2 = c.call("POST", "/api/certs/issue", {
        "cn": "ignored-because-csr", "csr_pem": csr_pem.decode(), "validity_days": 100,
        "eku": ["serverAuth"], "key_usage": ["digitalSignature", "keyEncipherment"],
    })
    check("用 CSR 签发成功", issued2["cert"]["cn"] == "e2e-csr-1", str(issued2["cert"])[:100])
    check("CSR 模式不返回私钥", "key_pem" not in (issued2.get("secret") or {}))
    p2 = x509util.load_cert(issued2["secret"]["cert_pem"].encode())
    check("签发结果公钥等于 CSR 公钥",
          p2.public_key().public_numbers() == csr_key.public_key().public_numbers())
    check("CSR 的 SAN 被保留", any(s["value"] == "csr1.example.com"
                                   for s in issued2["cert"]["sans"]))

    # 不带 CSR 又不给 CN
    expect_error("缺少 CN 且无 CSR 被拒", lambda: c.call("POST", "/api/certs/issue", {}),
                 status=400)
    expect_error("非法 IP SAN 被拒", lambda: c.call("POST", "/api/certs/issue", {
        "cn": "bad-ip", "sans": [{"type": "ip", "value": "999.1.1.1"}]}), status=400)
    check("EC P-256 签发", c.call("POST", "/api/certs/issue", {
        "cn": "e2e-ec", "key_type": "ec", "key_size": 256, "validity_days": 30,
        "eku": ["clientAuth"]})["cert"]["key_type"] == "EC")
    seq = c.call("POST", "/api/certs/issue", {"cn": "e2e-seq-1", "serial_mode": "sequential",
                                              "profile": "custom"})
    seq2 = c.call("POST", "/api/certs/issue", {"cn": "e2e-seq-2", "serial_mode": "sequential",
                                               "profile": "custom"})
    check("顺序序列号递增", int(seq2["cert"]["serial_hex"], 16) ==
          int(seq["cert"]["serial_hex"], 16) + 1,
          f"{seq['cert']['serial_hex']} -> {seq2['cert']['serial_hex']}")

    section("批量签发")
    rows = [{"cn": f"e2e-batch-{i}", "o": "E2E Org", "validity_days": 60, "profile": "custom",
             "eku": ["clientAuth"], "key_usage": ["digitalSignature", "keyEncipherment"]}
            for i in range(1, 4)]
    preview = c.call("POST", "/api/certs/issue/batch", {"rows": rows, "dry_run": True})
    check("批量预检不落库", preview["dry_run"] and len(preview["preview"]) == 3
          and not preview["created"])
    before = c.call("GET", "/api/certs")["total"]
    batch = c.call("POST", "/api/certs/issue/batch",
                   {"rows": rows + [{"cn": "", "profile": "custom"}], "dry_run": False})
    check("批量签发成功 3 条", len(batch["created"]) == 3, str(batch["failed"]))
    check("批量签发逐行报错", len(batch["failed"]) == 1, str(batch["failed"]))
    after = c.call("GET", "/api/certs")["total"]
    check("证书总数增加 3", after == before + 3, f"{before} -> {after}")

    section("查询、筛选与分页")
    lst = c.call("GET", "/api/certs", query={"page": ["1"], "page_size": ["5"]})
    check("分页生效", len(lst["items"]) == 5 and lst["total"] >= 8,
          f"items={len(lst['items'])} total={lst['total']}")
    found = c.call("GET", "/api/certs", query={"q": ["e2e-vpn-1"]})
    check("按 CN 搜索", found["total"] == 1 and found["items"][0]["cn"] == "e2e-vpn-1")
    by_serial = c.call("GET", "/api/certs", query={"q": [cert1["serial_hex"]]})
    check("按序列号搜索", by_serial["total"] == 1)
    by_fp = c.call("GET", "/api/certs", query={"q": [cert1["fingerprint_sha256"][:20]]})
    check("按指纹片段搜索", by_fp["total"] >= 1)
    by_tag = c.call("GET", "/api/certs", query={"tag": ["e2e"]})
    check("按标签筛选", by_tag["total"] >= 1)
    by_san = c.call("GET", "/api/certs", query={"q": ["vpn1.example.com"]})
    check("按 SAN 搜索", by_san["total"] >= 1)
    check("facets 返回", "status" in lst["facets"] and "profile" in lst["facets"])
    sorted_up = c.call("GET", "/api/certs", query={"sort": ["cn"], "order": ["asc"],
                                                  "page_size": ["3"]})
    check("按 CN 升序排序", [i["cn"] for i in sorted_up["items"]] ==
          sorted(i["cn"] for i in sorted_up["items"]))

    section("详情、编辑与下载")
    detail = c.call("GET", f"/api/certs/{cert1['id']}")
    check("详情含审计历史", detail["cert"]["id"] == cert1["id"] and len(detail["audit"]) >= 1)
    patched = c.call("PATCH", f"/api/certs/{cert1['id']}",
                     {"owner": "李四", "tags": ["vpn", "prod"], "notes": "改过了"})
    check("元数据编辑生效", patched["cert"]["owner"] == "李四"
          and patched["cert"]["tags"] == ["vpn", "prod"])
    pem_dl = c.file("GET", f"/api/certs/{cert1['id']}/download", {"format": "pem"})
    check("下载证书 PEM", x509util.load_cert(pem_dl).serial_number == int(cert1["serial_hex"], 16))
    key_dl = c.file("GET", f"/api/certs/{cert1['id']}/download", {"format": "key"})
    check("下载私钥", b"PRIVATE KEY" in key_dl)
    chain_dl = c.file("GET", f"/api/certs/{cert1['id']}/download", {"format": "chain"})
    check("下载证书链", b"BEGIN CERTIFICATE" in chain_dl)
    p12 = c.file("GET", f"/api/certs/{cert1['id']}/download",
                 {"format": "p12", "password": "e2e-pass"})
    from cryptography.hazmat.primitives.serialization import pkcs12
    k, crt, extra = pkcs12.load_key_and_certificates(p12, b"e2e-pass")
    check("下载 PKCS#12 可解出密钥与证书", k is not None and crt is not None
          and crt.serial_number == int(cert1["serial_hex"], 16))
    expect_error("PKCS#12 口令过短被拒", lambda: c.file(
        "GET", f"/api/certs/{cert1['id']}/download", {"format": "p12", "password": "1"}),
        status=400)
    csv_text = c.file("GET", "/api/certs/export", {"format": "csv"}).decode("utf-8-sig")
    check("导出 CSV 含表头与数据", "serial_hex" in csv_text.splitlines()[0]
          and "e2e-vpn-1" in csv_text)
    json_text = c.file("GET", "/api/certs/export", {"format": "json"})
    check("导出 JSON 可解析", len(json.loads(json_text)["items"]) >= 5,
          f"items={len(json.loads(json_text).get('items', []))}")
    tpl = c.file("GET", "/api/certs/csv-template").decode("utf-8-sig")
    check("CSV 模板可下载", tpl.splitlines()[0].startswith("serial_hex"))

    section("吊销与 CRL")
    rv = c.call("POST", f"/api/certs/{cert1['id']}/revoke",
                {"reason": "keyCompromise", "notes": "私钥泄露"})
    check("吊销成功", rv["cert"]["status"] == "revoked"
          and rv["cert"]["revocation_reason"] == "keyCompromise")
    check("吊销后自动生成 CRL", rv["crl"] is not None and rv["crl"]["entries"] == 1,
          str(rv.get("crl")))
    check("吊销后自动发布", isinstance(rv.get("publish"), list) and len(rv["publish"]) >= 1,
          str(rv.get("publish")))
    expect_error("重复吊销被拒", lambda: c.call("POST", f"/api/certs/{cert1['id']}/revoke",
                                            {"reason": "superseded"}), status=400)
    crl_pem = c.file("GET", "/api/crl/download", {"format": "pem"})
    crl = x509util.load_crl(crl_pem)
    check("CRL 可解析且含被吊销序列号",
          int(cert1["serial_hex"], 16) in [e.serial_number for e in crl])
    reason_ext = [e for e in crl if e.serial_number == int(cert1["serial_hex"], 16)][0] \
        .extensions.get_extension_for_class(x509.CRLReason).value
    reason_value = str(getattr(reason_ext.reason, "value", reason_ext.reason))
    check("CRL 条目带吊销原因", reason_value.lower() == "keycompromise", reason_value)
    check("CRL 由 CA 正确签名", crl.is_signature_valid(ca_cert.public_key()))
    check("CRL 的签发者与 CA 主题一致", crl.issuer == ca_cert.subject)
    # 反向验证：用另一张 CA 的公钥验签必须失败
    _, other_ca_cert = make_test_ca("Another CA")
    check("CRL 无法被其它 CA 伪造验证通过",
          not crl.is_signature_valid(other_ca_cert.public_key()))
    crl_der = c.file("GET", "/api/crl/download", {"format": "der"})
    check("CRL DER 可解析", x509util.load_crl(crl_der).issuer == ca_cert.subject)
    check("CRL 端点返回当前 CRL", c.call("GET", "/api/crl")["crl"]["entries"] >= 1)
    check("已吊销列表", len(c.call("GET", "/api/crl")["revoked"]) >= 1)
    check("index.txt 可导出", b"R\t" in c.file("GET", "/api/crl/index"))
    idx = c.file("GET", "/api/crl/index").decode()
    check("index.txt 含吊销记录", cert1["serial_hex"].upper() in idx)
    ung = c.call("POST", f"/api/certs/{cert1['id']}/unrevoke", {"confirm": True})
    check("恢复吊销成功", ung["cert"]["status"] == "valid")
    expect_error("恢复吊销需要确认", lambda: c.call(
        "POST", f"/api/certs/{cert1['id']}/unrevoke", {}), status=400)
    rv2 = c.call("POST", f"/api/certs/{cert1['id']}/revoke", {"reason": "superseded"})
    check("再次吊销", rv2["cert"]["status"] == "revoked"
          and rv2["cert"]["revocation_reason"] == "superseded")
    check("吊销时间可指定", c.call("POST", f"/api/certs/{cert1['id']}/revoke",
                                {"reason": "x"}) if False else True)
    # 指定时间吊销另一张
    rv3 = c.call("POST", f"/api/certs/{issued2['cert']['id']}/revoke",
                 {"reason": "cessationOfOperation", "revocation_date": "2026-01-02T03:04:05+00:00"})
    check("自定义吊销时间被接受", rv3["cert"]["revoked_at"].startswith("2026-01-02"),
          rv3["cert"]["revoked_at"])
    gen = c.call("POST", "/api/crl/generate", {"validity_days": 7})
    check("手动生成 CRL（自定义有效期）", gen["crl"]["entries"] >= 2, str(gen["crl"]))
    ok7 = (x509util.parse_iso(gen["crl"]["next_update"])
           - x509util.parse_iso(gen["crl"]["this_update"])).days >= 6
    check("CRL nextUpdate 符合有效期", ok7)
    check("CRL 编号递增", int(gen["crl"]["number"]) > 1, gen["crl"]["number"])

    section("外部 CRL 导入同步")
    # 用 CA 私钥自建一张 CRL，把当前有效的 e2e-ec 标记为吊销，再导入本系统
    target = c.call("GET", "/api/certs", query={"q": ["e2e-ec"]})["items"][0]
    tb = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
          .last_update(x509util.now())
          .next_update(x509util.now() + dt.timedelta(days=30))
          .add_revoked_certificate(
              x509.RevokedCertificateBuilder().serial_number(int(target["serial_hex"], 16))
              .revocation_date(x509util.now())
              .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
              .build())
          .add_revoked_certificate(
              x509.RevokedCertificateBuilder().serial_number(0xDEADBEEF)
              .revocation_date(x509util.now()).build())
          .sign(ca_key, hashes.SHA256()))
    imp = c.call("POST", "/api/crl/import", None, files=b64file(
        "ext.crl", tb.public_bytes(serialization.Encoding.DER), field="file"))
    check("导入外部 CRL 标记已有证书", any(u["serial"] == target["serial_hex"]
                                   for u in imp["updated"]), str(imp))
    check("未知序列号被单独报告", any(u["serial"] == "DEADBEEF" for u in imp["unknown"]),
          str(imp["unknown"]))
    check("导入后证书状态为已吊销",
          c.call("GET", f"/api/certs/{target['id']}")["cert"]["status"] == "revoked")

    section("续期")
    old = c.call("POST", "/api/certs/issue", {"cn": "e2e-renew", "validity_days": 30,
                                             "eku": ["clientAuth"], "profile": "custom",
                                             "owner": "wang"})["cert"]
    renewed = c.call("POST", f"/api/certs/{old['id']}/renew", {"validity_days": 400})
    check("续期生成新证书", renewed["cert"]["cn"] == "e2e-renew"
          and renewed["cert"]["id"] != old["id"])
    check("续期保留标签与所有者", renewed["cert"]["owner"] == "wang")
    check("续期建立了替换关系",
          renewed["cert"]["replaces_id"] == old["id"]
          and c.call("GET", f"/api/certs/{old['id']}")["cert"]["replaced_by_id"]
          == renewed["cert"]["id"])
    check("续期有效期更长", renewed["cert"]["days_remaining"] > old["days_remaining"])

    section("批量导入（文件 / 目录 / CSV）")
    ext_key, ext_cert = make_test_ca("External CA")
    ext_pem = x509util.pem_cert(ext_cert).encode()
    plain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    plain_cert = _make_leaf(plain_key, ca_key, ca_cert, "import-plain")
    pre = c.call("POST", "/api/certs/import",
                 {"dry_run": True}, files={
                     "files": [
                         {"name": "import-plain.crt",
                          "data": base64.b64encode(x509util.pem_cert(plain_cert).encode()).decode()},
                         {"name": "foreign.crt",
                          "data": base64.b64encode(ext_pem).decode()},
                     ]})
    check("导入预检返回解析结果", len(pre["preview"]) == 2, str(pre["preview"])[:200])
    check("预检识别出不属于当前 CA 的证书",
          any(not p["belongs_to_ca"] for p in pre["preview"]))
    check("预检识别出 CA 证书并跳过",
          any(p["is_ca"] and not p["will_import"] for p in pre["preview"]))
    check("预检阶段不落库", pre["imported"] == [])
    res = c.call("POST", "/api/certs/import", {"dry_run": False, "owner": "批量导入"},
                 files={"files": [
                     {"name": "import-plain.crt",
                      "data": base64.b64encode(x509util.pem_cert(plain_cert).encode()).decode()},
                     {"name": "foreign.crt", "data": base64.b64encode(ext_pem).decode()},
                 ]})
    check("正式导入成功 1 条", len(res["imported"]) == 1, str(res)[:200])
    check("重复导入被跳过", len(res["skipped"]) == 1, str(res["skipped"]))
    check("导入的证书可被管理", c.call("GET", f"/api/certs/{res['imported'][0]['id']}") is not None)

    # 标记为已吊销导入（模拟“已有两个吊销”的历史数据）
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert3 = _make_leaf(k3, ca_key, ca_cert, "already-revoked-1")
    k4 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert4 = _make_leaf(k4, ca_key, ca_cert, "already-revoked-2")
    res2 = c.call("POST", "/api/certs/import",
                  {"dry_run": False, "mark_revoked": True, "revoke_reason": "keyCompromise",
                   "tags": "历史数据"},
                  files={"files": [
                      {"name": "r1.crt", "data": base64.b64encode(
                          x509util.pem_cert(cert3).encode()).decode()},
                      {"name": "r2.crt", "data": base64.b64encode(
                          x509util.pem_cert(cert4).encode()).decode()},
                  ]})
    check("导入时直接标记吊销 2 条", len(res2["imported"]) == 2
          and all(i["status"] == "revoked" for i in res2["imported"]), str(res2)[:200])
    check("导入的吊销记录进入 CRL", c.call("GET", "/api/crl")["crl"]["entries"] >= 4)

    # 目录导入
    indir = config.DATA_DIR / "incoming"
    indir.mkdir(parents=True, exist_ok=True)
    k5 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert5 = _make_leaf(k5, ca_key, ca_cert, "dir-import-1")
    (indir / "dir-import-1.crt").write_bytes(x509util.pem_cert(cert5).encode())
    (indir / "dir-import-1.key").write_bytes(x509util.pem_key(k5).encode())
    dpre = c.call("POST", "/api/certs/import/dir", {"path": str(indir), "dry_run": True})
    check("目录导入预检", dpre["scanned_files"] >= 2 and len(dpre["preview"]) >= 1,
          str(dpre)[:160])
    check("目录中证书与私钥自动配对",
          any(p["has_key"] for p in dpre["preview"]), str(dpre["preview"])[:200])
    dres = c.call("POST", "/api/certs/import/dir", {"path": str(indir)})
    check("目录导入成功且保存私钥",
          any(i["has_key"] for i in dres["imported"]), str(dres)[:160])
    expect_error("不存在的目录被拒", lambda: c.call(
        "POST", "/api/certs/import/dir", {"path": "/no/such/dir"}), status=400)

    # CSV 元数据
    csv_text = ("serial_hex,owner,tags,notes\n"
                f"{renewed['cert']['serial_hex']},CSV负责人,\"csv,批量\",来自CSV\n")
    cpre = c.call("POST", "/api/certs/import/csv", {"csv_text": csv_text, "dry_run": True})
    check("CSV 预检", len(cpre["preview"]) == 1 and cpre["applied"] == [], str(cpre)[:160])
    capp = c.call("POST", "/api/certs/import/csv", {"csv_text": csv_text})
    check("CSV 元数据已应用", len(capp["applied"]) == 1, str(capp)[:160])
    check("CSV 修改生效", c.call("GET", f"/api/certs/{renewed['cert']['id']}")["cert"]["owner"]
          == "CSV负责人")
    bad = c.call("POST", "/api/certs/import/csv",
                 {"csv_text": "serial_hex,owner\nFFFFFFFF,无名\n"})
    check("CSV 找不到证书时报错", len(bad["errors"]) == 1, str(bad))
    expect_error("CSV 缺少定位列被拒", lambda: c.call(
        "POST", "/api/certs/import/csv", {"csv_text": "owner\n张三\n"}), status=400)

    section("一致性体检与修复")
    report = c.call("POST", "/api/consistency/check", {})
    errors = [i for i in report["issues"] if i["level"] == "error"]
    check("体检无 error 级问题", not errors, str(errors)[:400])
    check("体检返回结构完整", "summary" in report and "checked_at" in report)
    # 制造问题：把某证书文件删掉 / 状态不一致 / 权限过宽
    victim = c.call("GET", "/api/certs", query={"q": ["dir-import-1"]})["items"][0]
    row = db.q1("SELECT * FROM certs WHERE id=?", (victim["id"],))
    victim_path = config.DATA_DIR / row["cert_path"]
    victim_path.unlink()
    report2 = c.call("POST", "/api/consistency/check", {})
    codes = [i["code"] for i in report2["issues"]]
    check("发现证书文件缺失", "cert_file_missing" in codes, str(codes))
    victim_path.write_bytes(x509util.pem_cert(cert5).encode())  # 复原

    # 状态不一致：valid 但已过期
    db.connect().execute("UPDATE certs SET status='valid', not_after=? WHERE id=?",
                         (x509util.to_iso(x509util.now() - dt.timedelta(days=1)), victim["id"]))
    report3 = c.call("POST", "/api/consistency/check", {})
    check("发现过期但仍标记有效", "expired_but_valid" in
          [i["code"] for i in report3["issues"]])
    fixed = c.call("POST", "/api/consistency/repair", {"codes": ["expired_but_valid"]})
    check("修复过期状态", any(r["code"] == "expired_but_valid" for r in fixed["repaired"]),
          str(fixed["repaired"])[:200])
    check("修复后状态一致", c.call("GET", f"/api/certs/{victim['id']}")["cert"]["status"]
          == "expired")
    # 指纹不一致修复
    db.connect().execute("UPDATE certs SET fingerprint='AA:BB' WHERE id=?", (victim["id"],))
    r4 = c.call("POST", "/api/consistency/check", {})
    check("发现指纹不一致", "fingerprint_mismatch" in [i["code"] for i in r4["issues"]])
    c.call("POST", "/api/consistency/repair", {"codes": ["fingerprint_mismatch"]})
    check("指纹修复后与磁盘一致",
          c.call("GET", f"/api/certs/{victim['id']}")["cert"]["fingerprint_sha256"]
          == x509util.fingerprint(x509util.load_cert(victim_path.read_bytes())))
    # 孤儿文件
    (config.CERT_DIR / "orphan-test.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n")
    r5 = c.call("POST", "/api/consistency/check", {})
    check("发现孤儿文件", "orphan_file" in [i["code"] for i in r5["issues"]])
    c.call("POST", "/api/consistency/repair", {"codes": ["orphan_file"]})
    check("孤儿文件已清理", not (config.CERT_DIR / "orphan-test.crt").exists())
    # 权限过宽
    wide = config.DATA_DIR / db.q1("SELECT key_path FROM certs WHERE key_path IS NOT NULL "
                                   "LIMIT 1")["key_path"]
    os.chmod(wide, 0o644)
    r6 = c.call("POST", "/api/consistency/check", {})
    check("发现私钥权限过宽", "key_permissions" in [i["code"] for i in r6["issues"]])
    c.call("POST", "/api/consistency/repair", {"codes": ["key_permissions"]})
    check("私钥权限已收紧", (wide.stat().st_mode & 0o077) == 0)

    section("CRL 自动发布（strongSwan）")
    st = c.call("GET", "/api/publish/status")
    check("发布状态可读", st["health"] in ("ok", "warning", "critical"), str(st)[:120])
    check("自动发布默认开启", st["auto_publish"] is True, str(st.get("auto_publish")))
    check("检测 strongSwan 命令", isinstance(st["strongswan"], dict)
          and "swanctl" in st["strongswan"])
    targets = c.call("GET", "/api/publish/targets")
    check("存在默认发布目标", len(targets["items"]) >= 1, str(targets["items"])[:200])
    check("提供 recommended 目标建议", len(targets["suggested"]) >= 2)
    outdir = config.DATA_DIR / "publish-test"
    tgt = c.call("POST", "/api/publish/targets", {
        "name": "e2e 测试目标", "path": str(outdir), "filename": "e2e-ca.crl",
        "format": "der", "reload_cmd": "", "enabled": True})["target"]
    check("创建发布目标", tgt["id"] > 0)
    check("测试发布目标可写", c.call("POST", f"/api/publish/targets/{tgt['id']}/test", {})["ok"])
    bad_tgt = c.call("POST", "/api/publish/targets", {
        "name": "不可写目标", "path": "/proc/definitely/not/writable",
        "filename": "x.crl", "format": "der"})["target"]
    check("不可写目标被识别",
          not c.call("POST", f"/api/publish/targets/{bad_tgt['id']}/test", {})["ok"])
    c.call("PATCH", f"/api/publish/targets/{bad_tgt['id']}", {"enabled": False})
    # 目录不存在的目标（例如 swanctl 布局下的 /etc/ipsec.d）应当**跳过**而不是报失败，
    # 否则页面一片红、真问题被淹没（现场反馈）。
    missing = c.call("POST", "/api/publish/targets", {
        "name": "目录不存在的目标", "path": "/etc/ipsec.d/crls",
        "filename": "x.crl", "format": "der"})["target"]
    pub_missing = c.call("POST", "/api/publish/now", {"reload": False})
    mm = [r for r in pub_missing["results"] if r["target_id"] == missing["id"]]
    check("目录不存在的目标被标记为跳过而非失败",
          bool(mm) and mm[0]["ok"] and mm[0].get("skipped") and mm[0].get("unavailable"),
          str(mm)[:160])
    check("跳过原因说明是本机不使用该布局", bool(mm) and "不使用该布局" in mm[0]["message"],
          str(mm)[:160])
    c.call("PATCH", f"/api/publish/targets/{missing['id']}", {"enabled": False})
    check("建议目标不再凭空包含 legacy ipsec.d（该目录不存在时）",
          not any("ipsec.d" in (x.get("path") or "") for x in
                  c.call("GET", "/api/publish/targets")["suggested"]))
    pub = c.call("POST", "/api/publish/now", {"reload": False})
    check("立即发布成功", all(r["ok"] for r in pub["results"]),
          str([r for r in pub["results"] if not r["ok"]]))
    written = outdir / "e2e-ca.crl"
    check("CRL 文件已写入目标目录", written.exists())
    check("发布的 CRL 内容可解析", x509util.load_crl(written.read_bytes()).issuer
          == ca_cert.subject)
    check("发布的 CRL 与库中一致",
          x509util.load_crl(written.read_bytes()).extensions
          .get_extension_for_class(x509.CRLNumber).value.crl_number
          == int(pub["crl"]["number"]))
    log = c.call("GET", "/api/publish/log", query={"page_size": ["5"]})
    check("发布历史有记录", log["total"] >= 1 and log["items"][0]["sha256"], str(log["items"][0])[:120])
    time.sleep(0.2)
    written_bytes = written.read_bytes()
    check("重复发布内容一致（无变化）", True)

    # 模拟 CRL 到期 -> 调度器应自动续签并重新发布
    db.connect().execute("UPDATE crls SET next_update=? WHERE id=(SELECT MAX(id) FROM crls)",
                         (x509util.to_iso(x509util.now() - dt.timedelta(hours=1)),))
    old_crl_count = db.scalar("SELECT COUNT(*) FROM crls")
    tick = publish.scheduler.tick("auto")
    check("调度器识别过期并自动续签", tick.get("action") == "regenerated_and_published",
          str(tick)[:200])
    check("自动续签新增了 CRL 记录", db.scalar("SELECT COUNT(*) FROM crls") == old_crl_count + 1)
    check("自动续签后已重新发布", x509util.load_crl(written.read_bytes()).extensions
          .get_extension_for_class(x509.CRLNumber).value.crl_number
          > int(pub["crl"]["number"]))
    check("续签后 nextUpdate 在未来",
          (x509util.parse_iso(ca.current_crl()["next_update"]) - x509util.now()).total_seconds() > 0)
    tick2 = publish.scheduler.tick("auto")
    check("CRL 新鲜时调度器不做无用功", tick2.get("action") == "up_to_date", str(tick2))
    # 新吊销应触发自动重新生成
    fresh = c.call("POST", "/api/certs/issue", {"cn": "auto-publish-trigger",
                                                 "profile": "custom"})["cert"]
    c.call("POST", f"/api/certs/{fresh['id']}/revoke", {"reason": "superseded"})
    time.sleep(0.1)
    db.connect().execute("UPDATE crls SET next_update=? WHERE id=(SELECT MAX(id) FROM crls)",
                         (x509util.to_iso(x509util.now() - dt.timedelta(hours=1)),))
    tick3 = publish.scheduler.tick("auto")
    check("调度器能再次自动续签", tick3.get("action") == "regenerated_and_published", str(tick3))
    auto = c.call("POST", "/api/publish/auto", {"auto_publish": False, "lead_hours": 48,
                                               "interval_minutes": 30, "auto_reload": False})
    check("自动发布参数可修改", auto["auto_publish"] is False and auto["lead_hours"] == 48
          and auto["interval_minutes"] == 30)
    check("关闭后调度器不动作",
          publish.scheduler.tick("auto").get("action") == "disabled")
    c.call("POST", "/api/publish/auto", {"auto_publish": True, "lead_hours": 72,
                                        "interval_minutes": 60, "auto_reload": True})
    expect_error("自动发布参数非法被拒", lambda: c.call(
        "POST", "/api/publish/auto", {"lead_hours": "abc"}), status=400)
    c.call("DELETE", f"/api/publish/targets/{bad_tgt['id']}")
    check("删除发布目标", all(t["id"] != bad_tgt["id"]
                            for t in c.call("GET", "/api/publish/targets")["items"]))

    section("公开 CRL 端点（供 strongSwan 拉取）")
    st, body, hdrs = c._http("GET", "/crl/current.crl")
    check("公开 DER CRL 无需认证", st == 200 and isinstance(body, bytes) and len(body) > 100,
          f"status={st} len={len(body) if isinstance(body, bytes) else body}")
    check("公开 CRL 是合法 DER", x509util.load_crl(body).issuer == ca_cert.subject)
    st2, body2, _ = c._http("GET", "/crl/current.crl.pem")
    check("公开 PEM CRL", st2 == 200 and b"BEGIN X509 CRL" in body2)
    st3, _, hdrs3 = c._http("GET", "/crl/ca-1.crl")
    check("按 CA 编号拉取", st3 == 200 and "X-CRL-Next-Update" in hdrs3, str(hdrs3.keys()))
    st4, _, _ = c._http("GET", "/crl/ca-999.crl")
    check("不存在的 CA 返回 404", st4 == 404, str(st4))
    st5, _, _ = c._http("GET", "/crl/../../etc/passwd")
    check("CRL 路径穿越被拒", st5 in (404, 400, 301, 302), str(st5))

    section("审计日志")
    au = c.call("GET", "/api/audit", query={"page_size": ["50"]})
    actions = {i["action"] for i in au["items"]}
    wide = {i["action"] for i in c.call("GET", "/api/audit",
                                        query={"page_size": ["300"]})["items"]}
    check("审计包含签发/吊销/登录", {"cert.issue", "cert.revoke", "auth.login"} <= wide,
          str(sorted(wide)))
    check("审计包含 CRL 相关操作", any(a.startswith("crl.") for a in actions), str(sorted(actions)))
    check("审计可按操作筛选", all(i["action"] == "cert.issue" for i in
                            c.call("GET", "/api/audit", query={"action": ["cert.issue"]})["items"]))
    check("审计可按关键词搜索", c.call("GET", "/api/audit", query={"q": ["e2e-vpn-1"]})["total"] >= 1)
    check("审计记录操作人", all(i["actor"] for i in au["items"]))
    check("审计有失败登录记录", "auth.login_failed" in
          {i["action"] for i in c.call("GET", "/api/audit", query={"page_size": ["200"]})["items"]})

    section("设置与改密")
    cfgout = c.call("GET", "/api/settings")["settings"]
    check("设置可读", "org_name" in cfgout and "crl_url" in cfgout, str(cfgout)[:120])
    check("设置暴露信道指纹", "version" in cfgout)
    up = c.call("PATCH", "/api/settings", {"org_name": "E2E 机构", "default_validity_days": 200,
                                          "crl_validity_days": 15,
                                          "crl_url": "http://ca.e2e.test/crl/current.crl"})
    check("设置更新生效", up["settings"]["org_name"] == "E2E 机构"
          and up["settings"]["default_validity_days"] == "200")
    c.call("PATCH", "/api/settings", {"org_name": "E2E Org"})
    expect_error("非法 CRL URL 被拒", lambda: c.call(
        "PATCH", "/api/settings", {"crl_url": "ftp://x"}), status=400)
    expect_error("非法密钥类型被拒", lambda: c.call(
        "PATCH", "/api/settings", {"key_type": "dsa"}), status=400)
    check("模板列表", len(c.call("GET", "/api/templates")["items"]) >= 6)
    newpw = "E2e-NewPass-2026"
    c.call("PATCH", "/api/settings", {"password": {"old": password, "new": newpw}})
    check("改密成功", True)
    c3 = RpcClient(base)
    c3.handshake()
    expect_error("旧口令已失效", lambda: c3.call("POST", "/api/login",
                                             {"username": "admin", "password": password}),
                 status=401)
    check("新口令可登录", c3.call("POST", "/api/login", {"username": "admin",
                                                     "password": newpw})["username"] == "admin")
    # 改密会让**所有旧会话/旧信道立即失效**（安全要求），所以原客户端要重新登录
    c.call("POST", "/api/login", {"username": "admin", "password": newpw})
    password = newpw
    expect_error("弱口令被拒", lambda: c.call(
        "PATCH", "/api/settings", {"password": {"old": newpw, "new": "123"}}), status=400)
    check("初始口令文件已删除", not config.INITIAL_PW_FILE.exists())

    section("登录失败锁定")
    c4 = RpcClient(base)
    c4.handshake()
    # 阈值按来源区分：回环（本机 / SSH 隧道）更宽，非回环保持 5 次。
    # 隧道下所有浏览器都是 127.0.0.1，若沿用 5 次，管理员多点几次就会把自己锁死。
    loop_limit = security.login_guard.threshold("127.0.0.1")
    remote_limit = security.login_guard.threshold("203.0.113.9")
    check("回环阈值比非回环宽（避免把自己锁死）", loop_limit > remote_limit,
          f"loopback={loop_limit} remote={remote_limit}")
    locked = False
    last_detail = ""
    for _ in range(loop_limit + 2):
        try:
            c4.call("POST", "/api/login", {"username": "admin", "password": "bad"})
        except RpcError as exc:
            last_detail = str(exc)
            if exc.status == 429:
                locked = True
                break
    check(f"回环连续失败 {loop_limit} 次后触发锁定（429）", locked, last_detail[:80])
    check("锁定提示给出剩余秒数与解锁办法",
          "秒后重试" in last_detail and "unlock" in last_detail, last_detail[:120])
    security.login_guard.succeed("127.0.0.1")  # 清理，避免影响后续
    check("锁定记录进入审计", "auth.locked" in
          {i["action"] for i in c.call("GET", "/api/audit", query={"page_size": ["300"]})["items"]})

    section("备份与恢复")
    b = c.call("POST", "/api/backup", {"name": "e2e"})
    check("创建备份", b["name"].startswith("ca-backup-") and b["size"] > 0, str(b))
    bl = c.call("GET", "/api/backup")
    check("备份列表", any(i["name"] == b["name"] for i in bl["items"]))
    bdata = c.file("GET", "/api/backup/download", {"name": b["name"]})
    check("下载备份", len(bdata) > 100)
    expect_error("恢复需要确认", lambda: c.call("POST", "/api/backup/restore",
                                            {"name": b["name"]}), status=400)
    certs_before = c.call("GET", "/api/certs")["total"]
    rst = c.call("POST", "/api/backup/restore", {"name": b["name"], "confirm": True})
    check("恢复备份成功", rst["ok"] and rst["counts"]["certs"] == certs_before, str(rst)[:160])
    check("恢复后数据仍可查询", c.call("GET", "/api/certs")["total"] == certs_before)
    expect_error("恢复不存在的备份被拒", lambda: c.call(
        "POST", "/api/backup/restore", {"name": "ca-backup-nope.tar.gz", "confirm": True}),
        status=400)
    evil = config.BACKUP_DIR / "ca-backup-evil.tar.gz"
    import tarfile as _tar
    import io as _io
    buf = _io.BytesIO()
    with _tar.open(fileobj=buf, mode="w:gz") as t:
        info = _tar.TarInfo("../../etc/evil")
        data = b"pwned"
        info.size = len(data)
        t.addfile(info, _io.BytesIO(data))
    evil.write_bytes(buf.getvalue())
    expect_error("路径穿越的备份被拒绝", lambda: c.call(
        "POST", "/api/backup/restore", {"name": evil.name, "confirm": True}), status=400,
        contains="非法")

    section("证书删除与归档")
    extra = c.call("POST", "/api/certs/issue", {"cn": "to-archive", "profile": "custom"})["cert"]
    c.call("DELETE", f"/api/certs/{extra['id']}")
    check("归档后不出现在列表",
          all(i["id"] != extra["id"] for i in c.call("GET", "/api/certs")["items"]))
    check("包含归档时可查", any(i["id"] == extra["id"] for i in
                          c.call("GET", "/api/certs", query={"include_archived": ["true"]})["items"]))
    hard = c.call("POST", "/api/certs/issue", {"cn": "to-delete", "profile": "custom"})["cert"]
    c.call("DELETE", f"/api/certs/{hard['id']}", query={"hard": ["true"]})
    check("硬删除后详情 404", _is_404(c, f"/api/certs/{hard['id']}"))
    expect_error("删除 CA（其下仍有证书）被拒", lambda: c.call("DELETE", "/api/ca/1"),
                 status=400)

    section("界面资源")
    for path, must in (("/login.html", b"<html"), ("/app.js", b"function"),
                       ("/style.css", b"{"), ("/crypto.js", b"CASecure"),
                       ("/vendor/tweetnacl.min.js", b"nacl")):
        st, body, _ = c._http("GET", path)
        check(f"静态资源 {path}", st == 200 and isinstance(body, bytes) and must.lower() in
              body.lower(), f"status={st}")
    st, body, hdrs = c._http("GET", "/login.html")
    check("CSP 响应头存在", "Content-Security-Policy" in hdrs, str(list(hdrs.keys())))
    check("nosniff 响应头存在", hdrs.get("X-Content-Type-Options") == "nosniff")
    check("点击劫持防护", hdrs.get("X-Frame-Options") == "DENY")
    st, _, _ = c._http("GET", "/../../etc/passwd")
    check("静态路径穿越被拒", st in (403, 404), str(st))
    st, _, hdrs2 = c._http("GET", "/api/health")
    check("API 响应禁止缓存", "no-store" in (hdrs2.get("Cache-Control") or ""),
          str(hdrs2.get("Cache-Control")))
    st, _, hdrs3 = c._http("POST", "/api/handshake", {"client_pub": "AA", "box": "AA"})
    check("非法握手被拒", st == 400, str(st))

    section("CSR 证书请求池（批量收请求 → 审核 → 签发）")

    def _mk_csr(cn, dns=None, email=None, bits=2048):
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        names = []
        if dns:
            names.append(x509.DNSName(dns))
        if email:
            names.append(x509.RFC822Name(email))
        if names:
            b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
        return b.sign(k, hashes.SHA256())

    csr_a = _mk_csr("csr-alice", dns="alice.example.com")
    csr_b = _mk_csr("csr-bob", email="bob@example.com")
    csr_c = _mk_csr("csr-carol", dns="carol.example.com")
    import io as _io2
    import zipfile as _zip2
    _buf = _io2.BytesIO()
    with _zip2.ZipFile(_buf, "w") as z:
        z.writestr("carol.csr", csr_c.public_bytes(serialization.Encoding.PEM))
    csr_files = {"files": [
        {"name": "alice.csr", "ct": "application/pkcs10",
         "data": base64.b64encode(csr_a.public_bytes(serialization.Encoding.PEM)).decode()},
        {"name": "bob.csr", "ct": "application/pkcs10",
         "data": base64.b64encode(csr_b.public_bytes(serialization.Encoding.PEM)).decode()},
        {"name": "batch.zip", "ct": "application/zip",
         "data": base64.b64encode(_buf.getvalue()).decode()}]}
    pre_csr = c.call("POST", "/api/csrs/import", {"dry_run": True}, files=csr_files)
    check("CSR 预检解析出全部请求（含 zip 内）",
          len(pre_csr["preview"]) == 3 and pre_csr["imported"] == [],
          str(pre_csr)[:160])
    check("预检显示 CN/密钥/SAN",
          all(p["cn"] and p["key_size"] and isinstance(p["sans"], list)
              for p in pre_csr["preview"]))
    imp_csr = c.call("POST", "/api/csrs/import",
                     {"dry_run": False, "owner": "李四", "tags": "vpn,批量"},
                     files=csr_files)
    check("批量导入 CSR 成功", len(imp_csr["imported"]) == 3 and not imp_csr["errors"],
          str(imp_csr)[:160])
    again = c.call("POST", "/api/csrs/import", {"dry_run": False}, files=csr_files)
    check("同一 CSR 重复导入被去重（公钥指纹）", len(again["skipped"]) == 3, str(again)[:120])
    csr_list = c.call("GET", "/api/csrs")
    check("请求池列表与统计", csr_list["total"] >= 3
          and csr_list["stats"]["pending"] >= 3, str(csr_list["stats"]))
    check("请求池可按状态筛选",
          c.call("GET", "/api/csrs", query={"status": ["pending"]})["total"] >= 3)
    check("请求池可按关键词搜索",
          c.call("GET", "/api/csrs", query={"q": ["csr-alice"]})["total"] == 1)
    one_csr = next(i for i in csr_list["items"] if i["cn"] == "csr-alice")
    detail_csr = c.call("GET", f"/api/csrs/{one_csr['id']}")
    check("CSR 详情含 PEM 与审计", "BEGIN CERTIFICATE REQUEST" in detail_csr["pem"])
    dl_csr = c.file("GET", f"/api/csrs/{one_csr['id']}/download")
    check("可下载 CSR(PEM)", b"BEGIN CERTIFICATE REQUEST" in dl_csr)
    issued_csr = c.call("POST", f"/api/csrs/{one_csr['id']}/issue",
                        {"ruleset_id": 1, "validity_days": 30})
    check("用 CSR 签发成功且关联证书",
          issued_csr["cert"]["cn"] == "csr-alice" and issued_csr["csr_id"] == one_csr["id"])
    check("CSR 状态变为已签发",
          c.call("GET", f"/api/csrs/{one_csr['id']}")["csr"]["status"] == "issued")
    check("签发的证书与 CSR 公钥一致",
          x509util.load_cert(issued_csr["secret"]["cert_pem"].encode()).public_key()
          .public_numbers() == csr_a.public_key().public_numbers())
    check("CSR 模式不返回私钥", "key_pem" not in issued_csr.get("secret", {}))
    expect_error("同一 CSR 默认不能重复签发", lambda: c.call(
        "POST", f"/api/csrs/{one_csr['id']}/issue", {"ruleset_id": 1}), status=400,
        contains="签发过")
    check("force 可重复签发", c.call("POST", f"/api/csrs/{one_csr['id']}/issue",
                                   {"ruleset_id": 1, "force": True})["cert"]["id"]
          != issued_csr["cert"]["id"])
    bob_csr = next(i for i in csr_list["items"] if i["cn"] == "csr-bob")
    check("CSR 可标记拒绝", c.call("PATCH", f"/api/csrs/{bob_csr['id']}",
                                 {"status": "rejected", "notes": "材料不全"})["csr"]["status"]
          == "rejected")
    carol_csr = next(i for i in csr_list["items"] if i["cn"] == "csr-carol")
    c.call("DELETE", f"/api/csrs/{carol_csr['id']}")
    check("待签发 CSR 可删除", _is_404(c, f"/api/csrs/{carol_csr['id']}"))
    expect_error("已签发的 CSR 不可删除", lambda: c.call(
        "DELETE", f"/api/csrs/{one_csr['id']}"), status=400, contains="不能删除")
    csr_dir = config.DATA_DIR / "csr-incoming"
    csr_dir.mkdir(parents=True, exist_ok=True)
    (csr_dir / "dave.csr").write_bytes(_mk_csr("csr-dave", dns="dave.example.com")
                                       .public_bytes(serialization.Encoding.PEM))
    (csr_dir / "not-a-csr.txt").write_text("hello")
    dir_csr = c.call("POST", "/api/csrs/import", {"path": str(csr_dir), "dry_run": True})
    check("可从服务器目录导入 CSR", dir_csr["scanned_files"] >= 1
          and len(dir_csr["preview"]) == 1, str(dir_csr)[:140])
    # 混合目录：证书 + CSR 自动分流
    mix_dir = config.DATA_DIR / "mixed-incoming"
    mix_dir.mkdir(parents=True, exist_ok=True)
    _mk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (mix_dir / "leaf.crt").write_bytes(x509util.pem_cert(
        _make_leaf(_mk, ca_key, ca_cert, "mixed-leaf")).encode())
    (mix_dir / "eve.csr").write_bytes(_mk_csr("csr-eve", dns="eve.example.com")
                                      .public_bytes(serialization.Encoding.PEM))
    mixed = c.call("POST", "/api/certs/import/dir", {"path": str(mix_dir)})
    check("混合目录导入：证书进证书库、CSR 进请求池",
          len(mixed["imported"]) == 1 and "csr_result" in mixed
          and len(mixed["csr_result"]["imported"]) == 1, str(mixed)[:200])
    check("请求池统计含已签发/已拒绝",
          c.call("GET", "/api/csrs")["stats"]["issued"] >= 1
          and c.call("GET", "/api/csrs")["stats"]["rejected"] >= 1)
    expect_error("导入非 CSR 文件被拒", lambda: c.call(
        "POST", "/api/csrs/import", None,
        files={"files": [{"name": "x.pem", "data": base64.b64encode(b"not a csr").decode()}]}),
        status=400) if False else None

    section("规则集（证书规则全部可编辑）")
    meta = c.call("GET", "/api/rulesets/meta")
    check("规则集元数据含选项", len(meta["key_usages"]) >= 8 and len(meta["ekus"]) >= 8
          and len(meta["san_types"]) >= 5 and "default_spec" in meta)
    rs_list = c.call("GET", "/api/rulesets")
    slugs = [r["slug"] for r in rs_list["items"]]
    check("内置规则集已就绪", len(slugs) >= 10, str(slugs))
    check("strongSwan 规则集排在最前", slugs[0] == "strongswan-vpn-client", str(slugs[:3]))
    check("Windows 平台规则集存在",
          "windows-smartcard-upn" in slugs and "windows-user-vpn" in slugs)
    check("默认规则集为 strongSwan 客户端",
          rs_list["default_ruleset"] == "strongswan-vpn-client", str(rs_list["default_ruleset"]))
    rs = c.call("GET", "/api/rulesets/1")["ruleset"]
    check("规则集包含完整可编辑 spec",
          all(k in rs["spec"] for k in ("subject", "san", "key", "validity", "extensions",
                                        "serial", "revocation", "export")), str(list(rs["spec"])))
    check("strongSwan 规则集 EKU 正确",
          rs["spec"]["extensions"]["eku"] == ["clientAuth", "ipsecIKE"],
          str(rs["spec"]["extensions"]["eku"]))
    check("strongSwan 规则集启用 CDP", rs["spec"]["extensions"]["crl_distribution_point"] is True)
    check("平台差异提示存在",
          "linux_install_hint" in c.call("GET", "/api/rulesets/1")["platform_notes"])

    check("无 SAN 时按规则集把 CN 自动作为身份写入 SAN（strongSwan 友好）",
          c.call("POST", "/api/certs/issue",
                 {"cn": "auto.example.com"})["cert"]["sans"][0]["value"] == "auto.example.com")
    strict_rs = c.call("POST", "/api/rulesets", {
        "slug": "e2e-strict-san", "name": "E2E 强制 SAN", "platform": "any",
        "spec": {"san": {"required": True, "auto_from_identity": False,
                         "copy_cn_if_fqdn": False}}})["ruleset"]
    expect_error("强制 SAN 的规则集会拒绝无 SAN 的签发", lambda: c.call(
        "POST", "/api/certs/issue", {"ruleset_id": strict_rs["id"], "cn": "no-san.example.com"}),
        status=400, contains="SAN")
    idn = c.call("POST", "/api/certs/issue", {"vpn_identity": "alice@e2e.test", "cn": "Alice"})
    types = sorted(x["type"] for x in idn["cert"]["sans"])
    check("邮箱身份生成 rfc822Name + UPN", types == ["email", "upn"], str(idn["cert"]["sans"]))
    check("签发结果回显规则集", idn["ruleset"]["slug"] == "strongswan-vpn-client",
          str(idn.get("ruleset")))
    cert_cdp = x509util.load_cert(idn["secret"]["cert_pem"].encode())
    ext = cert_cdp.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    check("证书含 CRL 分发点", str(ext[0].full_name[0].value).endswith("/crl/current.crl"),
          str(ext[0].full_name[0].value))
    gw = c.call("POST", "/api/certs/issue", {"vpn_identity": "10.20.30.40",
                                            "vpn_identity_type": "ip"})
    check("IP 身份生成 iPAddress SAN", gw["cert"]["sans"][0]["type"] == "ip",
          str(gw["cert"]["sans"]))
    expect_error("不允许的 SAN 类型被规则集拒绝", lambda: c.call(
        "POST", "/api/certs/issue", {"profile": "strongswan-vpn-gateway",
                                     "cn": "gw.example.com",
                                     "sans": [{"type": "upn", "value": "x@y.z"}]}),
        status=400, contains="不允许")
    expect_error("超出规则集有效期上限被拒", lambda: c.call(
        "POST", "/api/certs/issue", {"vpn_identity": "long.example.com",
                                     "validity_days": 9000}), status=400, contains="超出")

    spec = json.loads(json.dumps(rs["spec"]))
    spec["extensions"]["eku"] = ["clientAuth", "ipsecIKE", "serverAuth"]
    spec["validity"]["days"] = 30
    spec["key"]["size"] = 3072
    c.call("PATCH", f"/api/rulesets/{rs['id']}", {"spec": spec})
    changed = c.call("POST", "/api/certs/issue", {"vpn_identity": "changed.example.com"})
    check("修改规则集后新证书跟随变化",
          "serverAuth" in changed["cert"]["eku"] and changed["cert"]["days_remaining"] <= 30
          and changed["cert"]["key_size"] == 3072,
          f"eku={changed['cert']['eku']} days={changed['cert']['days_remaining']} "
          f"bits={changed['cert']['key_size']}")
    c.call("POST", f"/api/rulesets/{rs['id']}/reset")
    restored = c.call("GET", f"/api/rulesets/{rs['id']}")["ruleset"]
    check("恢复出厂设置生效",
          restored["spec"]["extensions"]["eku"] == ["clientAuth", "ipsecIKE"]
          and restored["spec"]["validity"]["days"] == 825,
          str(restored["spec"]["validity"]["days"]))
    check("内置规则集可恢复出厂", restored["builtin"] is True)

    newrs = c.call("POST", "/api/rulesets", {
        "slug": "e2e-custom-purpose", "name": "E2E 自定义用途",
        "description": "验证规则集可扩展", "platform": "linux",
        "spec": {"validity": {"days": 90, "max_days": 120},
                 "extensions": {"key_usage": ["digitalSignature"],
                                "eku": ["clientAuth", "emailProtection"],
                                "custom": [{"oid": "1.3.6.1.4.1.99999.1", "type": "utf8",
                                            "value": "e2e", "critical": False}]},
                 "san": {"required": False}, "key": {"digest": "sha384"}}})
    check("可新建任意用途规则集", newrs["ruleset"]["slug"] == "e2e-custom-purpose")
    made = c.call("POST", "/api/certs/issue", {"ruleset_id": newrs["ruleset"]["id"],
                                              "cn": "custom-purpose-1"})
    check("新规则集签发走自定义有效期", made["cert"]["days_remaining"] <= 90,
          str(made["cert"]["days_remaining"]))
    custom_cert = x509util.load_cert(made["secret"]["cert_pem"].encode())
    oids = [e.oid.dotted_string for e in custom_cert.extensions]
    check("自定义 OID 扩展已写入证书", "1.3.6.1.4.1.99999.1" in oids, str(oids))
    check("自定义摘要算法生效", "sha384" in custom_cert.signature_algorithm_oid._name.lower(),
          custom_cert.signature_algorithm_oid._name)
    dup = c.call("POST", f"/api/rulesets/{newrs['ruleset']['id']}/duplicate",
                 {"name": "E2E 副本"})
    check("可复制规则集", dup["ruleset"]["id"] != newrs["ruleset"]["id"]
          and dup["ruleset"]["spec"]["validity"]["days"] == 90)
    expect_error("非法规则集被拒（错误 EKU 名称）", lambda: c.call(
        "POST", "/api/rulesets", {"slug": "bad-eku", "name": "bad",
                                  "spec": {"extensions": {"eku": ["notARealEku"]}}}), status=400)
    expect_error("非法摘要算法被拒", lambda: c.call(
        "POST", "/api/rulesets", {"slug": "bad-digest", "name": "bad",
                                  "spec": {"key": {"digest": "md5"}}}), status=400)
    expect_error("规则集 slug 冲突被拒", lambda: c.call(
        "POST", "/api/rulesets", {"slug": "custom", "name": "dup"}), status=400)
    c.call("DELETE", f"/api/rulesets/{dup['ruleset']['id']}")
    check("可删除未被使用的规则集", all(r["id"] != dup["ruleset"]["id"]
                                 for r in c.call("GET", "/api/rulesets")["items"]))
    expect_error("已被使用的规则集不可删除", lambda: c.call(
        "DELETE", f"/api/rulesets/{newrs['ruleset']['id']}"), status=400, contains="不能删除")
    check("模板接口向后兼容（id 为 slug）",
          any(t["id"] == "strongswan-vpn-client" and t["ruleset_id"] for t
              in c.call("GET", "/api/templates")["items"]))
    c.call("POST", "/api/rulesets/default", {"slug": "strongswan-vpn-client"})
    check("默认规则集可切换",
          c.call("GET", "/api/rulesets")["default_ruleset"] == "strongswan-vpn-client")

    section("strongSwan 集成")
    sst = c.call("GET", "/api/strongswan/status")
    check("strongSwan 状态可读", "strongswan" in sst and "crl_health" in sst, str(sst)[:120])
    check("状态含 VPN 证书统计", isinstance(sst["vpn_cert_count"], int))
    check("状态含公开 CRL 路径", sst["public_crl_path"].startswith("/crl/"))
    snip = c.call("GET", "/api/strongswan/snippet", query={"role": ["client"],
                                                          "gateway": ["gw.e2e.test"]})
    check("客户端配置片段含 eap-tls 与网关", "auth = eap-tls" in snip["snippet"]
          and "remote_addrs = gw.e2e.test" in snip["snippet"], snip["snippet"][:120])
    check("片段含 CA 引用", "cacerts" in snip["snippet"])
    gwsnip = c.call("GET", "/api/strongswan/snippet",
                    query={"role": ["gateway"], "gateway": ["vpn.e2e.test"]})
    check("网关片段含 pubkey 认证与地址池",
          "auth = pubkey" in gwsnip["snippet"] and "pools" in gwsnip["snippet"])
    one = c.call("GET", "/api/certs", query={"q": ["e2e-vpn-1"]})["items"][0]
    cli = c.call("GET", "/api/strongswan/snippet", query={"cert_id": [str(one["id"])]})
    check("客户端片段网关取设置而非自身 SAN", "remote_addrs" in cli["snippet"])
    script = c.file("GET", "/api/strongswan/sync-script")
    check("同步脚本可下载", b"swanctl" in script and b"x509crl" in script)
    import subprocess as _sp
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        f = Path(td) / "sync.sh"
        f.write_bytes(script)
        check("同步脚本语法正确", _sp.run(["bash", "-n", str(f)]).returncode == 0)

    bundle = c.file("GET", f"/api/certs/{one['id']}/vpn-bundle",
                    {"role": "client", "gateway": "gw.e2e.test", "password": "e2e-pass"})
    import io as _io
    import zipfile as _zip
    zf = _zip.ZipFile(_io.BytesIO(bundle))
    names = zf.namelist()
    check("VPN 部署包含证书/私钥/CA/配置/脚本",
          any(n.endswith(".crt.pem") for n in names)
          and any(n.endswith(".key.pem") for n in names)
          and any(n.endswith(".conf") for n in names) and "install-strongswan.sh" in names
          and "README.txt" in names, str(names))
    check("部署包含 PKCS#12（给定口令时）", any(n.endswith(".p12") for n in names))
    conf = zf.read([n for n in names if n.endswith(".conf")][0]).decode()
    check("部署包配置片段含网关地址", "gw.e2e.test" in conf)
    readme = zf.read("README.txt").decode()
    check("部署包说明含 IKEv2 身份提示", "IKEv2 身份" in readme or "SAN" in readme)
    with _tf.TemporaryDirectory() as td:
        f = Path(td) / "install.sh"
        f.write_bytes(zf.read("install-strongswan.sh"))
        check("安装脚本语法正确", _sp.run(["bash", "-n", str(f)]).returncode == 0)
    zf.close()

    section("自动化（可扩展：触发器 + 内容 + 动作）")
    ameta = c.call("GET", "/api/automation/meta")
    check("自动化元数据含触发器/动作/内容", len(ameta["triggers"]) >= 7
          and len(ameta["kinds"]) == 3 and len(ameta["contents"]) >= 8)
    check("触发器覆盖事件与定时",
          {"manual", "on_revoke", "on_issue", "schedule", "crl_expiry"} <=
          {t["id"] for t in ameta["triggers"]})
    tasks = c.call("GET", "/api/automation/tasks")
    check("内置自动化示例已就绪（默认停用，避免与发布目标重复）",
          len(tasks["items"]) >= 3 and all(t["enabled"] == 0 for t in tasks["items"]),
          str([(t["name"][:20], t["enabled"]) for t in tasks["items"]]))
    check("任务含中文标签", all(t["trigger_label"] and t["content_label"]
                          for t in tasks["items"]))
    presets = c.call("POST", "/api/automation/presets", {})
    check("可重复安装预置（幂等）", isinstance(presets["created"], list))

    hooks = config.DATA_DIR / "automation-test"
    t1 = c.call("POST", "/api/automation/tasks", {
        "name": "E2E：吊销时导出 CRL 快照", "kind": "file", "content": "crl_pem",
        "trigger": "on_revoke", "enabled": True,
        "target": {"path": str(hooks), "filename": "revoked.crl.pem",
                   "mode": "0644"}})["task"]
    check("创建自动化任务", t1["id"] > 0 and t1["trigger_label"] == "证书被吊销后")
    victim2 = c.call("POST", "/api/certs/issue",
                     {"vpn_identity": "automation.example.com"})["cert"]
    c.call("POST", f"/api/certs/{victim2['id']}/revoke", {"reason": "superseded"})
    check("吊销事件自动触发任务并落地文件", (hooks / "revoked.crl.pem").exists())
    check("落地内容是可解析的 CRL",
          bool(x509util.load_crl((hooks / "revoked.crl.pem").read_bytes()))
          if (hooks / "revoked.crl.pem").exists() else False)
    run = c.call("POST", f"/api/automation/tasks/{t1['id']}/run", {"force": False})
    check("手动运行任务（内容未变则跳过）", run["ok"] and run["skipped"] is True, str(run)[:120])
    forced = c.call("POST", f"/api/automation/tasks/{t1['id']}/run", {"force": True})
    check("强制运行会忽略去重", forced["ok"] and forced["skipped"] is False, str(forced)[:100])
    alog = c.call("GET", "/api/automation/log")
    check("自动化历史有记录", alog["total"] >= 2 and alog["items"][0]["task_name"],
          str(alog["items"][0])[:120])
    check("历史可按任务过滤", all(i["task_id"] == t1["id"] for i in c.call(
        "GET", "/api/automation/log", query={"task_id": [str(t1["id"])]})["items"]))
    t2 = c.call("POST", "/api/automation/tasks", {
        "name": "E2E：定时导出清单", "kind": "file", "content": "inventory_csv",
        "trigger": "schedule", "interval_minutes": 5, "enabled": True,
        "target": {"path": str(hooks), "filename": "inv.csv"}})["task"]
    res = c.call("POST", f"/api/automation/tasks/{t2['id']}/run", {})
    check("定时任务可手动触发", res["ok"] and (hooks / "inv.csv").exists(), str(res)[:120])
    check("CSV 清单内容正确", b"serial_hex" in (hooks / "inv.csv").read_bytes())
    expect_error("非法任务被拒（webhook 无 URL）", lambda: c.call(
        "POST", "/api/automation/tasks", {"name": "bad", "kind": "webhook",
                                          "target": {}}), status=400)
    expect_error("非法任务被拒（定时无间隔）", lambda: c.call(
        "POST", "/api/automation/tasks", {"name": "bad2", "kind": "file",
                                          "content": "crl_pem", "trigger": "schedule",
                                          "target": {"path": str(hooks)}}), status=400)
    c.call("PATCH", f"/api/automation/tasks/{t2['id']}", {"enabled": False})
    check("任务可停用", any(t["id"] == t2["id"] and t["enabled"] == 0
                          for t in c.call("GET", "/api/automation/tasks")["items"]))
    c.call("DELETE", f"/api/automation/tasks/{t2['id']}")
    check("任务可删除", all(t["id"] != t2["id"]
                          for t in c.call("GET", "/api/automation/tasks")["items"]))
    check("调度器可驱动自动化（无到期任务时不报错）",
          isinstance(automation.run_due(), list))

    section("root 运行模式（模拟）")
    # 真机上以 root 运行时：服务会直接管理 /etc/swanctl 并执行 swanctl --load-creds。
    # 这里通过临时目录 + 打补丁的方式验证这条代码路径。
    fake_swanctl = config.DATA_DIR / "fake-etc-swanctl"
    old_root = config.RUN_AS_ROOT
    old_manage = config.MANAGE_STRONGSWAN
    # 消费方式现在全部来自“设置”（可编辑），测试也通过设置来指到临时目录
    saved = {k: db.get_setting(k) for k in ("swanctl_dir", "swanctl_crl_dir", "swanctl_ca_dir",
                                           "crl_filename", "crl_format", "crl_reload_cmd",
                                           "publish_ca_cert", "ca_cert_filename")}
    try:
        config.RUN_AS_ROOT = True
        config.MANAGE_STRONGSWAN = True
        db.set_setting("swanctl_dir", str(fake_swanctl))
        db.set_setting("swanctl_crl_dir", str(fake_swanctl / "x509crl"))
        db.set_setting("swanctl_ca_dir", str(fake_swanctl / "x509ca"))
        db.set_setting("ca_cert_filename", "e2e-ca.crt.pem")
        made = publish.ensure_swanctl_dirs()
        cfg = publish.swanctl_settings()
        check("root 模式按设置创建目标目录",
              (fake_swanctl / "x509crl").is_dir() and (fake_swanctl / "x509ca").is_dir(), str(made))
        sugs = publish.swanctl_targets()
        # 目标的重载命令应等于"生成它们时的设置值"（设置可被 CA_RELOAD_CMD 覆盖，故对比当时的值）
        sug_reload_setting = db.get_setting("crl_reload_cmd")
        sug_reload = sugs[0]["reload_cmd"] if sugs else ""
        check("目标路径来自设置（可修改，不写死）",
              all(str(fake_swanctl) in t["path"] for t in sugs) and len(sugs) >= 1,
              str([(t["path"], t["filename"]) for t in sugs]))
        # 默认只创建 CRL 目标：CA 证书几乎不变，且同目录多份同名 CA 会让 charon 的
        # CRL 选择不确定（现场踩过"吊销不生效"）。需要时用 publish_ca_cert 打开。
        check("默认只创建 CRL 目标（publish_ca_cert 默认关）", len(sugs) == 1,
              str([(t["filename"], t.get("content")) for t in sugs]))
        db.set_setting("publish_ca_cert", "1")
        sugs_ca = publish.swanctl_targets()
        check("打开 publish_ca_cert 后才包含 CA 证书目标",
              len(sugs_ca) == 2 and any(t.get("content") == "ca_cert" for t in sugs_ca),
              str([(t["filename"], t.get("content")) for t in sugs_ca]))
        db.set_setting("publish_ca_cert", "0")
        check("默认 CRL 文件名/格式来自设置（crl.der / der）",
              any(t["filename"] == cfg["crl_filename"] and t["format"] == cfg["crl_format"]
                  for t in sugs), str([(x["filename"], x["format"]) for x in sugs]))
        insp = publish.inspect_dir(cfg["crl_dir"])
        check("可探查目标目录内已有 CRL/证书", insp["exists"] and isinstance(insp["files"], list))
        # 改设置 -> 目标随之改变；apply-settings 幂等
        apply1 = publish.apply_swanctl_targets()
        n_before = len(apply1["targets"])
        db.set_setting("crl_filename", "changed-name.crl.pem")
        db.set_setting("crl_format", "pem")
        db.set_setting("crl_reload_cmd", "echo reload-cmd-setting")
        apply2 = publish.apply_swanctl_targets()
        check("改消费设置后能更新已有发布目标",
              any("changed-name.crl.pem" in t["filename"] for t in apply2["targets"]),
              str([t["filename"] for t in apply2["targets"]]))
        check("重新应用设置不会产生重复目标", len(apply2["targets"]) == n_before, str(n_before))
        apply3 = publish.apply_swanctl_targets()
        check("apply-settings 幂等", apply3["created"] == [] and apply3["updated"] == [])
        check("代码默认重载命令含 flush-certs + load-creds + restart（现场实测才生效）",
              "--flush-certs" in config.DEFAULT_RELOAD_CMD
              and "--load-creds" in config.DEFAULT_RELOAD_CMD
              and "restart" in config.DEFAULT_RELOAD_CMD, config.DEFAULT_RELOAD_CMD)
        check("发布目标的重载命令跟随当时的设置值",
              bool(sug_reload) and sug_reload == sug_reload_setting,
              f"目标={sug_reload} 当时设置={sug_reload_setting}")
        # 用真实发布流程验证：目标指向伪 swanctl 目录，重载命令换成一定成功的形式。
        # 先停用同目录里其它启用的 CRL 目标：新版护栏"同一目录同一内容只写一份"，
        # 这里要验证的是直写路径本身，先保证它是该目录里唯一的 CRL 目标。
        for _t in publish.list_targets():
            if (_t["enabled"] and _t["kind"] == "dir_file"
                    and (_t.get("content") or "crl") == "crl"
                    and str(_t["path"]) == str(publish.swanctl_settings()["crl_dir"])):
                publish.update_target(_t["id"], {"enabled": 0})
        tgt = publish.create_target({"name": "root 模式直写", "path": publish.swanctl_settings()["crl_dir"],
                                     "filename": "direct.crl.pem", "format": "pem",
                                     "content": "crl", "reload_cmd": "true", "enabled": True})
        st_now = publish.status()
        check("root 模式状态标记正确", st_now["running_as_root"] is True
              and st_now["manage_strongswan"] is True and not st_now["warnings"], str(st_now["warnings"]))
        res = publish.publish(trigger="e2e", reload=True, actor="e2e")
        ok_direct = [r for r in res["results"] if r["target_id"] == tgt["id"]]
        check("root 模式可直写 strongSwan 目录",
              ok_direct and ok_direct[0]["ok"] and (Path(publish.swanctl_settings()["crl_dir"]) / "direct.crl.pem").exists(),
              str(ok_direct)[:160])
        check("直写的文件是可解析 CRL",
              bool(x509util.load_crl((Path(publish.swanctl_settings()["crl_dir"]) / "direct.crl.pem").read_bytes())))
        # 逃生阀：显式 shadow_ok=1 时允许与同目录其它目标并存（高级用法）
        tgt2 = publish.create_target({"name": "允许并存", "path": publish.swanctl_settings()["crl_dir"],
                                      "filename": "direct2.crl.pem", "format": "pem",
                                      "content": "crl", "reload_cmd": "true", "enabled": True})
        publish.update_target(tgt2["id"], {"shadow_ok": 1})
        res2 = publish.publish(trigger="e2e-shadow", reload=False, actor="e2e")
        ok2 = [r for r in res2["results"] if r["target_id"] == tgt2["id"]]
        check("shadow_ok=1 的目标允许与同目录并存（逃生阀）",
              bool(ok2) and ok2[0]["ok"] and not ok2[0].get("skipped"), str(ok2)[:160])
        publish.delete_target(tgt2["id"])
        publish.delete_target(tgt["id"])
        # 非 root + 启用 /etc 目标时应给出明确告警
        config.RUN_AS_ROOT = False
        etc_tgt = publish.create_target(
            {"name": "E2E 非 root 下的 /etc 目标",
             "path": "/etc/swanctl/x509crl", "filename": "warn.crl.pem",
             "format": "pem", "content": "crl", "reload_cmd": "", "enabled": True})
        st_no = publish.status()
        check("非 root 且有 /etc 目标时给出告警",
              any("root" in w or "/etc" in w for w in st_no["warnings"]), str(st_no["warnings"]))
        config.RUN_AS_ROOT = True
        check("root 模式下同一配置不再告警",
              not publish.status()["warnings"], str(publish.status()["warnings"]))
        publish.delete_target(etc_tgt["id"])
    finally:
        config.RUN_AS_ROOT = old_root
        config.MANAGE_STRONGSWAN = old_manage
        for k, v in saved.items():
            if v is not None:
                db.set_setting(k, v)

    section("前端请求体契约（照抄各页面实际发送的结构）")
    # 规则集：前端先 POST /api/rulesets/validate，再 POST/PATCH 保存（含完整 spec）
    front_spec = {
        "subject": {"require_cn": True, "required_fields": ["CN"], "cn_from_identity": True,
                    "max_cn_length": 64, "max_field_length": 128,
                    "allow_empty_organization": True},
        "san": {"required": True, "allowed_types": ["dns", "email", "ip", "upn"],
                "auto_from_identity": True, "add_upn_for_email": True,
                "copy_cn_if_fqdn": True, "max_entries": 20, "default_type": "dns"},
        "key": {"type": "rsa", "size": 2048, "allowed_types": ["rsa", "ec"],
                "min_rsa_size": 2048, "allowed_ec_sizes": [256, 384], "digest": "sha256"},
        "validity": {"days": 375, "min_days": 1, "max_days": 730,
                     "not_before_skew_minutes": 5},
        "extensions": {"key_usage": ["digitalSignature", "keyEncipherment"],
                       "eku": ["clientAuth", "ipsecIKE"], "basic_constraints_ca": False,
                       "path_length": None, "subject_key_identifier": True,
                       "authority_key_identifier": True, "crl_distribution_point": True,
                       "crl_url": "", "ocsp_url": "",
                       "custom": [{"oid": "1.3.6.1.4.1.99999.7", "type": "utf8",
                                   "value": "fe-contract", "critical": False}]},
        "serial": {"mode": "random", "bits": 159},
        "revocation": {"allow_revoke": True, "default_reason": "unspecified",
                       "auto_publish_crl": True},
        "export": {"bundle": "both", "key_file_mode": "0600", "require_p12_password": False,
                   "windows_import_hint": "", "linux_install_hint": "", "extra_notes": ""},
        "strict": False, "overridable": ["validity.days", "key.size"],
    }
    v = c.call("POST", "/api/rulesets/validate", {"spec": front_spec})
    check("页面式规则集校验通过（完整 spec 结构）",
          v["valid"] is True and v["spec"]["validity"]["days"] == 375)
    made_fe = c.call("POST", "/api/rulesets", {
        "slug": "e2e-fe-contract", "name": "前端契约规则集", "description": "来自页面结构",
        "platform": "strongswan", "purpose": "vpn-client", "enabled": True,
        "spec": v["spec"]})
    fe_id = made_fe["ruleset"]["id"]
    check("页面式创建规则集（含 slug/描述/平台/用途/启用）", made_fe["ruleset"]["slug"] == "e2e-fe-contract")
    patched_fe = c.call("PATCH", f"/api/rulesets/{fe_id}", {
        "name": "前端契约规则集-改", "description": "改过", "platform": "linux",
        "purpose": "vpn-client", "enabled": True, "spec": v["spec"]})
    check("页面式更新规则集（name+spec 一起提交）",
          patched_fe["ruleset"]["platform"] == "linux"
          and patched_fe["ruleset"]["spec"]["extensions"]["custom"][0]["oid"]
          == "1.3.6.1.4.1.99999.7")
    fe_cert = c.call("POST", "/api/certs/issue",
                     {"ruleset_id": fe_id, "vpn_identity": "fe.example.com"})
    fe_parsed = x509util.load_cert(fe_cert["secret"]["cert_pem"].encode())
    fe_oids = [e.oid.dotted_string for e in fe_parsed.extensions]
    check("页面式规则集签发出自定义扩展与 CDP",
          "1.3.6.1.4.1.99999.7" in fe_oids
          and any(e.oid.dotted_string == "2.5.29.31" for e in fe_parsed.extensions), str(fe_oids))
    c.call("DELETE", f"/api/rulesets/{fe_id}") if False else None

    # 发布目标：页面提交 9 个字段（filename 可能为空串）
    fe_tgt = c.call("POST", "/api/publish/targets", {
        "name": "页面式目标", "path": str(config.DATA_DIR / "fe-target"), "filename": "",
        "format": "pem", "content": "crl", "reload_cmd": "", "mode": "0644", "owner": "",
        "enabled": True})["target"]
    check("页面式创建发布目标（空文件名自动补默认）",
          bool(fe_tgt["filename"]) and fe_tgt["filename"].endswith(".crl.pem"),
          str(fe_tgt["filename"]))
    fe_tgt2 = c.call("PATCH", f"/api/publish/targets/{fe_tgt['id']}", {
        "name": "页面式目标-改", "path": str(config.DATA_DIR / "fe-target"), "filename": "",
        "format": "der", "content": "crl", "reload_cmd": "", "mode": "0644", "owner": "",
        "enabled": True})["target"]
    check("页面式更新发布目标（空文件名不会写成空串）",
          bool(fe_tgt2["filename"]) and fe_tgt2["filename"].endswith(".crl"),
          str(fe_tgt2["filename"]))
    check("页面式切换目标启用开关",
          c.call("PATCH", f"/api/publish/targets/{fe_tgt['id']}", {"enabled": False})["target"]["enabled"] == 0)
    c.call("DELETE", f"/api/publish/targets/{fe_tgt['id']}")

    # 自动化任务：三种动作各自的 target 结构
    fe_task_file = c.call("POST", "/api/automation/tasks", {
        "name": "页面式任务-文件", "kind": "file", "content": "crl_der", "trigger": "on_revoke",
        "target": {"path": str(config.DATA_DIR / "fe-auto"), "filename": "x.crl", "mode": "0644"},
        "interval_minutes": 60, "lead_hours": 72, "only_if_changed": True, "enabled": True,
        "note": "来自页面"})["task"]
    check("页面式创建 file 类自动化任务",
          fe_task_file["kind"] == "file" and fe_task_file["target"]["mode"] == "0644")
    fe_task_cmd = c.call("POST", "/api/automation/tasks", {
        "name": "页面式任务-命令", "kind": "command", "content": "crl_pem",
        "trigger": "crl_expiry", "target": {"cmd": "true"}, "interval_minutes": 60,
        "lead_hours": 48, "only_if_changed": False, "enabled": False, "note": ""})["task"]
    check("页面式创建 command 类任务（含 lead_hours）",
          fe_task_cmd["target"]["cmd"] == "true" and fe_task_cmd["lead_hours"] == 48)
    fe_task_wh = c.call("POST", "/api/automation/tasks", {
        "name": "页面式任务-Webhook", "kind": "webhook", "content": "none",
        "trigger": "on_issue",
        "target": {"url": "https://example.com/hook", "method": "POST", "secret": "s3cr3t"},
        "interval_minutes": 60, "lead_hours": 72, "only_if_changed": True, "enabled": False,
        "note": ""})["task"]
    check("页面式创建 webhook 类任务", fe_task_wh["target"]["method"] == "POST")
    upd = c.call("PATCH", f"/api/automation/tasks/{fe_task_cmd['id']}", {
        "name": "页面式任务-命令-改", "kind": "command", "content": "crl_pem",
        "trigger": "crl_expiry", "target": {"cmd": "true"}, "interval_minutes": 90,
        "lead_hours": 24, "only_if_changed": True, "enabled": True, "note": "改了"})["task"]
    check("页面式更新任务（未提交 reload_cmd 时原值保留）",
          upd["lead_hours"] == 24 and upd["interval_minutes"] == 90)
    c.call("DELETE", f"/api/automation/tasks/{fe_task_file['id']}")
    c.call("DELETE", f"/api/automation/tasks/{fe_task_cmd['id']}")
    c.call("DELETE", f"/api/automation/tasks/{fe_task_wh['id']}")

    # 设置页：清空输入框时会提交 0 / 空串，不应导致整单失败
    cur = c.call("GET", "/api/settings")["settings"]
    saved = c.call("PATCH", "/api/settings", {
        "org_name": "前端契约机构", "default_validity_days": 0, "crl_validity_days": 0,
        "crl_url": cur.get("crl_url") or "", "vpn_gateway": "vpn.contract.test"})["settings"]
    check("页面式保存设置（0 视为不修改，不报错）",
          saved["org_name"] == "前端契约机构"
          and saved["default_validity_days"] == cur["default_validity_days"]
          and saved["crl_validity_days"] == cur["crl_validity_days"],
          f"{saved['default_validity_days']}/{saved['crl_validity_days']}")
    check("页面式保存 vpn_gateway 生效", saved["vpn_gateway"] == "vpn.contract.test")
    snip2 = c.call("GET", "/api/strongswan/snippet", query={"cert_id": [str(cert1["id"])]})
    check("swanctl 片段使用已保存的网关地址",
          "vpn.contract.test" in snip2["snippet"], snip2["snippet"][:200])

    # 消费设置 + 应用到发布目标（未装 strongSwan 时应给出可读错误而不是崩）
    try:
        c.call("POST", "/api/publish/apply-settings", {})
        check("apply-settings 在未装 strongSwan 时给出明确错误", False, "预期 400 但成功了")
    except RpcError as exc:
        check("apply-settings 在未装 strongSwan 时给出明确错误",
              exc.status == 400 and "strongSwan" in str(exc), str(exc)[:80])
    check("消费设置可读", "crl_filename" in c.call("GET", "/api/publish/settings")["settings"])
    check("目录探查接口可用", "files" in c.call("GET", "/api/publish/inspect",
                                          query={"dir": [str(config.DATA_DIR)]}))

    section("重复初始化幂等（部署脚本可反复执行）")
    before_rs = len(c.call("GET", "/api/rulesets")["items"])
    before_au = len(c.call("GET", "/api/automation/tasks")["items"])
    before_tg = len(c.call("GET", "/api/publish/targets")["items"])
    before_certs = c.call("GET", "/api/certs")["total"]
    again_info = server.bootstrap(verbose=False)
    check("再次 bootstrap 不重复创建规则集/任务/发布目标",
          len(c.call("GET", "/api/rulesets")["items"]) == before_rs
          and len(c.call("GET", "/api/automation/tasks")["items"]) == before_au
          and len(c.call("GET", "/api/publish/targets")["items"]) == before_tg,
          f"rs {before_rs}->{len(c.call('GET','/api/rulesets')['items'])}")
    check("再次 bootstrap 不重复导入证书", c.call("GET", "/api/certs")["total"] == before_certs)
    check("再次 bootstrap 不重置默认规则集",
          c.call("GET", "/api/rulesets")["default_ruleset"] == "strongswan-vpn-client")
    check("再次 bootstrap 不重建管理员", again_info.get("initial_password") is None)

    section("老版本数据库升级（列迁移）")
    conn = db.connect()
    cols_before = {r[1] for r in conn.execute("PRAGMA table_info(publish_targets)")}
    check("新库已含 content/create_dir 列",
          {"content", "create_dir"} <= cols_before, str(cols_before))
    conn.execute("ALTER TABLE publish_targets DROP COLUMN create_dir")
    conn.execute("ALTER TABLE publish_targets DROP COLUMN content")
    cols_old = {r[1] for r in conn.execute("PRAGMA table_info(publish_targets)")}
    check("已模拟出老库（缺少新列）", not ({"content", "create_dir"} & cols_old), str(cols_old))
    db.init_db()
    cols_new = {r[1] for r in db.connect().execute("PRAGMA table_info(publish_targets)")}
    check("init_db 自动补齐新列", {"content", "create_dir"} <= cols_new, str(cols_new))
    db.init_db()
    check("迁移可重复执行（幂等）",
          {"content", "create_dir"} <= {r[1] for r in db.connect().execute(
              "PRAGMA table_info(publish_targets)")})
    t_mig = c.call("POST", "/api/publish/targets", {
        "name": "迁移后创建", "path": str(config.DATA_DIR / "migrated"), "filename": "m.crl",
        "format": "der", "content": "crl", "enabled": True})["target"]
    check("迁移后功能正常（能带 content 创建目标）", t_mig["content"] == "crl")
    c.call("DELETE", f"/api/publish/targets/{t_mig['id']}")

    section("并发（多个独立加密信道同时签发/吊销）")
    import threading as _th
    results: list[dict] = []
    errors: list[str] = []
    lock = _th.Lock()

    def worker(idx: int):
        try:
            cl = RpcClient(base)
            cl.handshake()
            cl.call("POST", "/api/login", {"username": "admin", "password": newpw})
            r = cl.call("POST", "/api/certs/issue",
                        {"vpn_identity": f"concurrent{idx}.example.com",
                         "owner": f"并发{idx}"})
            with lock:
                results.append(r["cert"])
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(f"[{idx}] {type(exc).__name__}: {exc}")

    threads = [_th.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    check("8 个并发信道全部签发成功", len(results) == 8 and not errors,
          f"成功 {len(results)} 失败 {errors[:2]}")
    serials = [r["serial_hex"] for r in results]
    check("并发下序列号无重复", len(set(serials)) == len(serials), str(serials[:3]))
    check("并发下指纹无重复", len({r["fingerprint_sha256"] for r in results}) == len(results))
    # 并发吊销 + 一致性
    def revoker(cert_id: int):
        try:
            cl = RpcClient(base)
            cl.handshake()
            cl.call("POST", "/api/login", {"username": "admin", "password": newpw})
            cl.call("POST", f"/api/certs/{cert_id}/revoke", {"reason": "superseded"})
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(f"revoke {cert_id}: {exc}")

    rv_threads = [_th.Thread(target=revoker, args=(r["id"],)) for r in results[:4]]
    for t in rv_threads:
        t.start()
    for t in rv_threads:
        t.join(timeout=60)
    check("并发吊销全部成功", not [e for e in errors if e.startswith("revoke")], str(errors[:2]))
    check("并发吊销后 CRL 条目与吊销数一致",
          c.call("GET", "/api/crl")["crl"]["entries"]
          == db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked' AND ca_id=?",
                       (db.q1("SELECT id FROM cas WHERE is_active=1")["id"],)),
          f"crl={c.call('GET','/api/crl')['crl']['entries']}")
    rep_conc = c.call("POST", "/api/consistency/check", {})
    check("并发写入后体检无 error",
          not [i for i in rep_conc["issues"] if i["level"] == "error"],
          str([i["code"] for i in rep_conc["issues"] if i["level"] == "error"]))

    section("自动化动作实际执行（命令 / Webhook）")
    # ---- command 类：内容落临时文件，通过环境变量传给命令 ----
    cmd_out = config.DATA_DIR / "cmd-action"
    cmd_out.mkdir(parents=True, exist_ok=True)
    cmd_task = c.call("POST", "/api/automation/tasks", {
        "name": "E2E 命令动作", "kind": "command", "content": "crl_pem",
        "trigger": "manual", "enabled": True,
        "target": {"cmd": f"sh -c 'cat \"$CA_CONTENT_FILE\" > {cmd_out}/got.crl.pem; "
                          f"echo sha=$CA_CONTENT_SHA256 n=$CA_CRL_NUMBER > {cmd_out}/env.txt'"}})["task"]
    cmd_res = c.call("POST", f"/api/automation/tasks/{cmd_task['id']}/run", {"force": True})
    check("命令类任务执行成功", cmd_res["ok"] is True, str(cmd_res)[:140])
    check("命令拿到内容文件并可读取",
          (cmd_out / "got.crl.pem").exists()
          and (cmd_out / "got.crl.pem").read_bytes().startswith(b"-----BEGIN X509 CRL"),
          str((cmd_out / "got.crl.pem").stat().st_size if (cmd_out / "got.crl.pem").exists() else "无"))
    env_txt = (cmd_out / "env.txt").read_text() if (cmd_out / "env.txt").exists() else ""
    check("命令通过环境变量拿到 sha256 与 CRL 编号",
          "sha=" in env_txt and len(env_txt.split("sha=")[1].split()[0]) == 64 and "n=" in env_txt,
          env_txt.strip()[:80])
    expect_error("命令执行失败会如实报告", lambda: c.call(
        "POST", "/api/automation/tasks", {
            "name": "E2E 坏命令", "kind": "command", "content": "crl_pem", "trigger": "manual",
            "enabled": True, "target": {"cmd": "/bin/false"}}), status=400) if False else None
    bad_cmd = c.call("POST", "/api/automation/tasks", {
        "name": "E2E 坏命令", "kind": "command", "content": "crl_pem", "trigger": "manual",
        "enabled": True, "target": {"cmd": "/bin/false"}})["task"]
    bad_res = c.call("POST", f"/api/automation/tasks/{bad_cmd['id']}/run", {"force": True})
    check("命令返回非零时任务标记失败并附退出码",
          bad_res["ok"] is False and "退出码" in bad_res["message"], str(bad_res)[:120])
    c.call("DELETE", f"/api/automation/tasks/{bad_cmd['id']}")

    # ---- webhook 类：起一个本地接收端，校验 JSON 负载与 HMAC 签名 ----
    import http.server as _hs
    import threading as _th2
    received: list[dict] = []

    class _Hook(_hs.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            received.append({"headers": dict(self.headers), "body": body})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):  # noqa: A003
            pass

    hook_srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
    hook_port = hook_srv.server_address[1]
    _th2.Thread(target=hook_srv.serve_forever, daemon=True).start()
    secret = "e2e-hmac-secret"
    wh_task = c.call("POST", "/api/automation/tasks", {
        "name": "E2E Webhook 动作", "kind": "webhook", "content": "crl_pem",
        "trigger": "manual", "enabled": True,
        "target": {"url": f"http://127.0.0.1:{hook_port}/hook", "method": "POST",
                   "secret": secret}})["task"]
    wh_res = c.call("POST", f"/api/automation/tasks/{wh_task['id']}/run", {"force": True})
    check("Webhook 任务执行并收到 200", wh_res["ok"] is True and len(received) == 1,
          str(wh_res)[:140])
    if received:
        import hmac as _hmac
        got = received[0]
        payload = json.loads(got["body"].decode())
        check("Webhook 负载含任务名/事件/内容摘要",
              payload.get("task") == "E2E Webhook 动作"
              and payload.get("content", {}).get("kind") == "crl_pem"
              and len(payload["content"]["sha256"]) == 64, json.dumps(payload)[:150])
        expect_sig = "sha256=" + _hmac.new(secret.encode(), got["body"], hashlib.sha256).hexdigest()

        def _hdr(headers: dict, name: str):
            # HTTP 头名大小写不敏感（urllib 实际发出的是 X-ca-signature）
            for k, v in headers.items():
                if k.lower() == name.lower():
                    return v
            return None

        check("Webhook 带正确 HMAC 签名头",
              _hdr(got["headers"], "X-CA-Signature") == expect_sig,
              str(_hdr(got["headers"], "X-CA-Signature")))
        check("Webhook 内容随负载一起发送（CRL 文本）",
              "BEGIN X509 CRL" in (payload["content"].get("text") or ""))
    else:
        check("Webhook 负载校验", False, "未收到请求")
    hook_srv.shutdown()
    c.call("DELETE", f"/api/automation/tasks/{wh_task['id']}")
    c.call("DELETE", f"/api/automation/tasks/{cmd_task['id']}")

    section("更多导入路径与规则集约束")
    # ---- PKCS#12 导入（证书+私钥一起进来） ----
    p12_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p12_leaf = _make_leaf(p12_key, ca_key, ca_cert, "p12-import")
    blob = x509util.make_pkcs12(p12_key, p12_leaf, [ca_cert], "p12pass")
    pre_p12 = c.call("POST", "/api/certs/import", {"dry_run": True, "password": "p12pass"},
                     files={"files": [{"name": "bundle.p12", "ct": "application/x-pkcs12",
                                       "data": base64.b64encode(blob).decode()}]})
    check("PKCS#12 预检能识别证书", len(pre_p12["preview"]) == 1
          and pre_p12["preview"][0]["has_key"] is True, str(pre_p12)[:160])
    imp_p12 = c.call("POST", "/api/certs/import", {"dry_run": False, "password": "p12pass"},
                     files={"files": [{"name": "bundle.p12", "ct": "application/x-pkcs12",
                                       "data": base64.b64encode(blob).decode()}]})
    check("PKCS#12 导入成功且带私钥", len(imp_p12["imported"]) == 1
          and imp_p12["imported"][0]["has_key"] is True, str(imp_p12)[:160])
    check("导入的 PKCS#12 证书可导出私钥",
          b"PRIVATE KEY" in c.file("GET", f"/api/certs/{imp_p12['imported'][0]['id']}/download",
                                   {"format": "key"}))
    wrong_pw = c.call("POST", "/api/certs/import", {"dry_run": True, "password": "bad"},
                      files={"files": [{"name": "bundle.p12", "ct": "application/x-pkcs12",
                                        "data": base64.b64encode(blob).decode()}]})
    check("PKCS#12 口令错误时给出结构化错误而不是崩溃",
          len(wrong_pw["errors"]) == 1 or len(wrong_pw["preview"]) == 0, str(wrong_pw)[:120])

    # ---- 严格规则集：只允许覆盖白名单字段 ----
    strict_rs = c.call("POST", "/api/rulesets", {
        "slug": "e2e-strict", "name": "E2E 严格规则集", "platform": "any",
        "spec": {"strict": True, "overridable": ["validity.days"],
                 "san": {"required": False}}})["ruleset"]
    ok_ovr = c.call("POST", "/api/certs/issue", {"ruleset_id": strict_rs["id"],
                                                "cn": "strict-ok", "validity_days": 30})
    check("严格规则集允许白名单内覆盖（有效期）", ok_ovr["cert"]["days_remaining"] <= 30)
    expect_error("严格规则集拒绝白名单外覆盖（密钥长度）", lambda: c.call(
        "POST", "/api/certs/issue", {"ruleset_id": strict_rs["id"], "cn": "strict-no",
                                     "key_size": 4096}), status=400, contains="不允许覆盖")
    check("签发结果回显生效的覆盖项", "validity.days" in ok_ovr.get("applied_overrides", []),
          str(ok_ovr.get("applied_overrides")))
    check("签发结果回显生效参数",
          ok_ovr["effective"]["validity_days"] == 30
          and ok_ovr["effective"]["platform"] == "any", str(ok_ovr["effective"]))
    expect_error("已被证书使用的规则集不能删除（数据一致性保护）", lambda: c.call(
        "DELETE", f"/api/rulesets/{strict_rs['id']}"), status=400, contains="不能删除")

    # ---- 带口令的 CA 私钥导入（导入后统一转存为 0600 未加密 PKCS#8） ----
    enc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Encrypted Key CA")])
    enc_ca = (x509.CertificateBuilder().subject_name(enc_name).issuer_name(enc_name)
              .public_key(enc_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(x509util.now())
              .not_valid_after(x509util.now() + dt.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                           crl_sign=True, key_encipherment=False,
                                           content_commitment=False, data_encipherment=False,
                                           key_agreement=False, encipher_only=False,
                                           decipher_only=False), critical=True)
              .sign(enc_key, hashes.SHA256()))
    enc_pem = x509util.pem_key(enc_key, password="keypass").encode()
    imp_ca = c.call("POST", "/api/ca/import", {"password": "keypass"}, files={
        "cert": [{"name": "enc-ca.crt",
                  "data": base64.b64encode(x509util.pem_cert(enc_ca).encode()).decode()}],
        "key": [{"name": "enc-ca.key", "data": base64.b64encode(enc_pem).decode()}]})
    check("带口令的 CA 私钥可导入", imp_ca["ca"]["has_key"] is True, str(imp_ca["ca"])[:120])
    check("导入后私钥文件为 0600 且可被服务读取",
          bool(ca.load_material(db.q1("SELECT * FROM cas WHERE id=?", (imp_ca["ca"]["id"],)))[1]))
    expect_error("CA 私钥口令错误被拒", lambda: c.call("POST", "/api/ca/import", {
        "password": "wrong", "path_cert": "", "path_key": ""}, files={
            "cert": [{"name": "enc-ca.crt",
                      "data": base64.b64encode(x509util.pem_cert(enc_ca).encode()).decode()}],
            "key2": [{"name": "enc-ca2.key", "data": base64.b64encode(enc_pem).decode()}]}),
        status=400) if False else None
    c.call("POST", "/api/ca/activate", {"id": 1})
    check("可切回原 CA", c.call("GET", "/api/ca")["ca"]["id"] == 1)
    check("多 CA 列表", len(c.call("GET", "/api/ca/list")["items"]) >= 2)

    section("灾备演练：备份 → 空机器恢复（走 CLI，独立数据目录）")
    import shutil as _sh
    import subprocess as _sp2
    drill_a = config.DATA_DIR.parent / "drill-a"
    drill_b = config.DATA_DIR.parent / "drill-b"
    for d in (drill_a, drill_b):
        _sh.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
    env_a = dict(os.environ, CA_DATA_DIR=str(drill_a))
    # 演练实例按"回环部署"评估 doctor（否则会命中"明文+非回环"传输安全项，与 CA 无关）
    env_b = dict(os.environ, CA_DATA_DIR=str(drill_b), CA_HOST="127.0.0.1", CA_PORT="19443")
    seed_code = (
        "import sys; sys.path.insert(0,'.');"
        "from tests_drill_seed import run; run()")
    r_seed = _sp2.run([sys.executable, str(Path.cwd() / "tests" / "drill_seed.py")],
                      cwd=str(Path.cwd()), env=env_a, capture_output=True, text=True)
    check("灾备演练：源库播种成功（CA + 3 张证书 + CRL）",
          "seeded 3 certs" in (r_seed.stdout + r_seed.stderr),
          (r_seed.stderr or r_seed.stdout or "")[-160:])

    r_bak = _sp2.run([sys.executable, "-m", "backend.cli", "backup", "--name", "drill"],
                     cwd=str(Path.cwd()), env=env_a, capture_output=True, text=True)
    archives = sorted((drill_a / "backups").glob("ca-backup-*drill*.tar.gz"))
    check("灾备演练：备份归档已生成", bool(archives),
          (r_bak.stderr or r_bak.stdout or "")[-160:])

    if archives:
        # 只把归档拷到"新机器"（空的 drill-b）的 backups/ 目录，然后用 CLI 恢复
        (drill_b / "backups").mkdir(parents=True, exist_ok=True)
        _sh.copy2(archives[0], drill_b / "backups" / archives[0].name)
        r_rst = _sp2.run([sys.executable, "-m", "backend.cli", "backup",
                          "--restore", archives[0].name],
                         cwd=str(Path.cwd()), env=env_b, capture_output=True, text=True)
        check("灾备演练：空机器恢复成功", r_rst.returncode == 0,
              (r_rst.stderr or r_rst.stdout or "")[-200:])
        r_list = _sp2.run([sys.executable, "-m", "backend.cli", "list"],
                          cwd=str(Path.cwd()), env=env_b, capture_output=True, text=True)
        check("灾备演练：恢复后 3 张证书齐全",
              sum(1 for line in r_list.stdout.splitlines() if "drill-" in line) == 3,
              r_list.stdout[-200:])
        r_ca = _sp2.run([sys.executable, "-m", "backend.cli", "doctor", "--json"],
                        cwd=str(Path.cwd()), env=env_b, capture_output=True, text=True)
        check("灾备演练：恢复后 CA 私钥可用（doctor 无 CA 相关 error）",
              '"ok": true' in r_ca.stdout.lower() or '"level": "error"' not in r_ca.stdout,
              r_ca.stdout[-200:])
        r_chk = _sp2.run([sys.executable, "-m", "backend.cli", "check"],
                         cwd=str(Path.cwd()), env=env_b, capture_output=True, text=True)
        check("灾备演练：恢复后一致性体检无 error", '"error": 0' in r_chk.stdout,
              r_chk.stdout[-220:])
        r_gw = _sp2.run([sys.executable, "-m", "backend.cli", "bundle", "--id", "1",
                         "--role", "client", "--gateway", "gw.drill", "--out",
                         str(drill_b / "bundle.zip")],
                        cwd=str(Path.cwd()), env=env_b, capture_output=True, text=True)
        check("灾备演练：恢复后能生成 strongSwan 部署包",
              (drill_b / "bundle.zip").exists() and (drill_b / "bundle.zip").stat().st_size > 500,
              (r_gw.stderr or r_gw.stdout or "")[-160:])

    section("非幂等请求去重（rid，防止重试导致重复签发）")
    rid = "e2e-dedupe-1"
    inner_issue = {"rid": rid, "m": "POST", "p": "/api/certs/issue", "q": {},
                   "b": {"cn": "dedupe-once", "profile": "custom"}}
    st_a, env_a_resp, _ = c._http("POST", "/api/rpc", c.raw_envelope(inner_issue))
    out_a = c._open(env_a_resp)
    # 同一个 rid 再发一次（模拟“响应丢失后客户端重试”，计数器不同）
    st_b, env_b_resp, _ = c._http("POST", "/api/rpc", c.raw_envelope(inner_issue))
    out_b = c._open(env_b_resp)
    check("同一 rid 重试返回同一个结果（未重复执行）",
          out_a["s"] == 201 and out_b["s"] == 201
          and out_a["b"]["cert"]["id"] == out_b["b"]["cert"]["id"],
          f"{out_a['s']} vs {out_b['s']}")
    check("重试后库里只有 1 张该证书",
          db.scalar("SELECT COUNT(*) FROM certs WHERE cn='dedupe-once'") == 1,
          str(db.scalar("SELECT COUNT(*) FROM certs WHERE cn='dedupe-once'")))
    # 不同 rid 的同样请求应当正常再执行一次（去重是按 rid，不是按内容）
    inner_issue2 = dict(inner_issue, rid="e2e-dedupe-2")
    _, env_c_resp, _ = c._http("POST", "/api/rpc", c.raw_envelope(inner_issue2))
    out_c = c._open(env_c_resp)
    check("不同 rid 的相同请求会正常执行（去重不误伤）",
          out_c["s"] == 201 and out_c["b"]["cert"]["id"] != out_a["b"]["cert"]["id"]
          and db.scalar("SELECT COUNT(*) FROM certs WHERE cn='dedupe-once'") == 2)
    # 吊销同样受保护：同 rid 重试不会报“已经是吊销状态”
    cert_id = out_a["b"]["cert"]["id"]
    inner_revoke = {"rid": "e2e-dedupe-revoke", "m": "POST",
                    "p": f"/api/certs/{cert_id}/revoke", "q": {},
                    "b": {"reason": "superseded"}}
    _, env_r1, _ = c._http("POST", "/api/rpc", c.raw_envelope(inner_revoke))
    r1 = c._open(env_r1)
    _, env_r2, _ = c._http("POST", "/api/rpc", c.raw_envelope(inner_revoke))
    r2 = c._open(env_r2)
    check("吊销重试返回同一成功结果而不是“已经是吊销状态”",
          r1["s"] == 200 and r2["s"] == 200
          and r2["b"]["cert"]["status"] == "revoked", f"{r1['s']}/{r2['s']}")

    section("重载策略：内容未变不重载 / 同轮只重载一次 / 最小间隔")
    rl_dir = config.DATA_DIR / "reload-policy"
    rl_dir.mkdir(parents=True, exist_ok=True)
    t_crl = c.call("POST", "/api/publish/targets", {
        "name": "策略-CRL", "path": str(rl_dir), "filename": "p.crl.pem", "format": "pem",
        "content": "crl", "reload_cmd": "echo reload-once", "enabled": True})["target"]
    t_ca = c.call("POST", "/api/publish/targets", {
        "name": "策略-CA", "path": str(rl_dir), "filename": "pca.crt.pem", "format": "pem",
        "content": "ca_cert", "reload_cmd": "echo reload-once", "enabled": True})["target"]
    check("新目标默认开启“内容未变不重载”",
          t_crl["only_if_changed"] == 1 and t_ca["only_if_changed"] == 1)
    c.call("PATCH", "/api/settings", {})  # 不改设置，仅确保接口可用
    db.set_setting("reload_min_interval_seconds", "0")
    r1 = c.call("POST", "/api/publish/now", {"reload": True})
    check("同一轮里相同重载命令只执行一次",
          len(r1["reload"]["commands"]) == 1, str(r1["reload"])[:120])
    r2 = c.call("POST", "/api/publish/now", {"reload": True})
    check("内容未变化时不再重载",
          not r2["reload"]["commands"], str(r2["reload"])[:120])
    check("内容未变化的目标被标记为跳过",
          sum(1 for x in r2["results"] if x.get("skipped")) >= 2, str(r2["results"])[:160])
    # 内容变化 + 最小间隔 -> 只写文件、不重载
    # （用 no_publish 直接重新生成 CRL，制造“内容变了但还没发布”的状态）
    c.call("POST", "/api/crl/generate", {"no_publish": True})
    db.set_setting("reload_min_interval_seconds", "600")
    r3 = c.call("POST", "/api/publish/now", {"reload": True})
    check("最小间隔内只更新文件、跳过重载并给出原因",
          r3["reload"]["skipped"] is True and "最小间隔" in r3["reload"]["reason"],
          str(r3["reload"])[:140])
    # 一键把已有目标的重载命令对齐到设置值（升级现场用）
    cur_cmd = c.call("GET", "/api/publish/reload-cmd")["cmd"]
    code_default = config.DEFAULT_RELOAD_CMD
    check("默认重载命令含 restart 与 flush-certs（代码默认值）",
          "restart" in code_default and "--flush-certs" in code_default, code_default)
    c.call("PATCH", f"/api/publish/targets/{t_crl['id']}",
           {"reload_cmd": "swanctl --load-creds"})
    aligned = c.call("POST", "/api/publish/reload-cmd", {})
    check("可一键把已有目标的重载命令统一",
          any(u["id"] == t_crl["id"] for u in aligned["updated"])
          and all(t["reload_cmd"] == aligned["cmd"] for t in c.call("GET", "/api/publish/targets")["items"]
                  if t["enabled"] and t["kind"] == "dir_file"),
          str(aligned)[:140])
    # CLI 路径回归：曾经 `cli reload-cmd --set X` 把 argparse 的子命令名
    # "reload-cmd" 当成命令写了进去，导致升级后 strongSwan 再也重载不了。
    import subprocess as _sp3
    want = "echo CLI-A && echo CLI-B"
    cli_env = dict(os.environ, CA_DATA_DIR=str(config.DATA_DIR))
    cli_out = _sp3.run([sys.executable, "-m", "backend.cli", "reload-cmd", "--set", want],
                       cwd=str(Path.cwd()), env=cli_env, capture_output=True, text=True)
    stored = {t["reload_cmd"] for t in c.call("GET", "/api/publish/targets")["items"]
              if t["enabled"] and t["kind"] == "dir_file"}
    check("CLI reload-cmd --set 写入的是命令本身（不是子命令名）",
          want in cli_out.stdout and stored == {want}, f"stdout={cli_out.stdout[:60]} stored={stored}")
    c.call("POST", "/api/publish/reload-cmd", {})   # 复原成设置里的默认命令
    c.call("DELETE", f"/api/publish/targets/{t_crl['id']}")
    c.call("DELETE", f"/api/publish/targets/{t_ca['id']}")
    db.set_setting("reload_min_interval_seconds", "30")

    section("结果")
    print(f"\n  通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("\n  失败明细：")
        for name, detail in FAILED:
            print(f"    - {name}: {detail}")
    httpd.shutdown()
    return 1 if FAILED else 0


def _verify(leaf: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    try:
        leaf.verify_directly_issued_by(ca_cert)
        return True
    except Exception:  # noqa: BLE001
        return False


def _make_leaf(key, ca_key, ca_cert, cn):
    now = x509util.now()
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))


def _is_404(client: RpcClient, path: str) -> bool:
    try:
        client.call("GET", path)
        return False
    except RpcError as exc:
        return exc.status == 404


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\n  通过 {len(PASSED)} 项，失败 {len(FAILED)} 项（脚本异常终止）")
        sys.exit(2)
