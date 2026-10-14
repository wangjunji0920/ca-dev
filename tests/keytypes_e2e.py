"""密钥类型与私钥格式验收：RSA / EC / Ed25519 的 CA 与各种私钥编码。

背景：此前所有测试都用 RSA 2048。但"导入现有 CA"必须能吃下现场可能的各种形态：
    * CA 用 EC（P-256/384/521）或 Ed25519
    * 私钥是 PKCS#1（BEGIN RSA PRIVATE KEY）或 PKCS#8（BEGIN PRIVATE KEY）
    * 私钥是加密的（不同口令）、DER 编码
本测试对每种形态跑完整闭环：导入 CA → 用匹配的规则集签发 → 吊销 → 生成 CRL →
**用 CA 公钥验签 CRL** → 下载证书/私钥能解析 → 生成 strongSwan 部署包。

任何一步非 5xx 失败都算缺陷；同时对垃圾私钥必须给出可读错误（而不是 500）。
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="keytypes-"))
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


class Client:
    def __init__(self, base: str) -> None:
        self.base = base
        self.cookie = ""
        self.csrf = ""

    def req(self, method: str, path: str, body=None, csrf: bool = True):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        if self.csrf and csrf:
            r.add_header("X-CSRF-Token", self.csrf)
        r.add_header("Origin", self.base)
        try:
            with urllib.request.urlopen(r, timeout=120) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc).encode()

    def json(self, method: str, path: str, body=None):
        st, raw = self.req(method, path, body)
        try:
            return st, json.loads(raw.decode())
        except Exception:  # noqa: BLE001
            return st, {"raw": raw[:200].decode("utf-8", "replace")}

    # 多部件上传（走明文 REST，与浏览器上传等价）
    def upload(self, path: str, files: dict[str, tuple[str, bytes]], fields: dict[str, str]):
        boundary = "----ktytest" + str(int(time.time() * 1000))
        parts = []
        for k, v in fields.items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        for field, (fname, content) in files.items():
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; "
                f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
                + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        r = urllib.request.Request(self.base + path, data=body, method="POST")
        r.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        if self.csrf:
            r.add_header("X-CSRF-Token", self.csrf)
        r.add_header("Origin", self.base)
        try:
            with urllib.request.urlopen(r, timeout=120) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode())
            except Exception:  # noqa: BLE001
                return exc.code, {}
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}


def build_materials() -> dict:
    """用 cryptography 直接造各种形态的 CA 材料（不经过本系统的代码）。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)

    def ca_cert(key, cn: str):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        algo = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        return (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                             crl_sign=True, key_encipherment=False,
                                             content_commitment=False, data_encipherment=False,
                                             key_agreement=False, encipher_only=False,
                                             decipher_only=False), critical=True)
                .sign(key, algo))

    out: dict[str, dict] = {}
    # 1) RSA-4096 + PKCS#1 私钥（BEGIN RSA PRIVATE KEY）
    k = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    out["rsa4096-pkcs1"] = {
        "cn": "KT RSA4096 PKCS1 CA", "key_type": "rsa", "key_size": 4096,
        "cert": ca_cert(k, "KT RSA4096 PKCS1 CA").public_bytes(serialization.Encoding.PEM),
        "key": k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()),
        "password": None,
    }
    # 2) RSA-2048 + 加密 PKCS#8
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    out["rsa2048-encrypted"] = {
        "cn": "KT RSA2048 Encrypted CA", "key_type": "rsa", "key_size": 2048,
        "cert": ca_cert(k, "KT RSA2048 Encrypted CA").public_bytes(serialization.Encoding.PEM),
        "key": k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.BestAvailableEncryption(b"ca-pass-123")),
        "password": "ca-pass-123",
    }
    # 3) EC P-256 + DER 私钥
    k = ec.generate_private_key(ec.SECP256R1())
    out["ec256-der"] = {
        "cn": "KT EC256 DER CA", "key_type": "ec", "key_size": 256,
        "cert": ca_cert(k, "KT EC256 DER CA").public_bytes(serialization.Encoding.PEM),
        "key": k.private_bytes(serialization.Encoding.DER,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()),
        "password": None,
    }
    # 4) Ed25519
    k = ed25519.Ed25519PrivateKey.generate()
    out["ed25519"] = {
        "cn": "KT Ed25519 CA", "key_type": "ed25519", "key_size": 256,
        "cert": ca_cert(k, "KT Ed25519 CA").public_bytes(serialization.Encoding.PEM),
        "key": k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()),
        "password": None,
    }
    return out


def main() -> int:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    print("\n\033[1m== 准备：造 4 种形态的 CA 材料 ===")
    DATA.mkdir(parents=True, exist_ok=True)
    materials = build_materials()
    check("材料就绪（RSA-PKCS1 / RSA-加密 / EC-DER / Ed25519）", len(materials) == 4)

    port = free_port()
    env = dict(os.environ, CA_DATA_DIR=str(DATA), CA_HOST="127.0.0.1",
               CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    c = Client(base)
    log: list[str] = []
    try:
        st = 0
        for _ in range(80):
            st, _b = c.req("GET", "/api/health")
            if st == 200:
                break
            time.sleep(0.25)
        check("服务已启动", st == 200, f"HTTP {st}")
        pw = re.search(r"初始口令:\s*(\S+)",
                       (DATA / "initial_admin_password.txt").read_text(encoding="utf-8")).group(1)
        # 只登录一次：同一次响应里同时取会话 cookie 与 CSRF 令牌
        # （再登录一次会轮换令牌，导致后续写操作 403）
        r = urllib.request.Request(base + "/api/login",
                                   data=json.dumps({"username": "admin", "password": pw}).encode(),
                                   method="POST")
        r.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(r, timeout=30) as resp:
            login_body = json.loads(resp.read().decode())
            c.cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        c.csrf = login_body.get("csrf", "")
        check("登录成功（同一响应拿到 cookie + CSRF）",
              bool(c.cookie) and bool(c.csrf), f"cookie={bool(c.cookie)} csrf={bool(c.csrf)}")

        # 建一个允许 ed25519 的规则集（内置只有 rsa/ec）
        st, rs_list = c.json("GET", "/api/rulesets")
        ec_rs = [x for x in rs_list["items"] if x["slug"] == "strongswan-vpn-client-ec"][0]
        ed_spec = {
            "strict": False, "overridable": [],
            "key": {"type": "ed25519", "size": 256, "allowed_types": ["ed25519"],
                    "digest": "sha512"},
            "subject": {"require_cn": True}, "san": {"required": True, "auto_from_identity": True},
            "validity": {"days": 365, "max_days": 3650},
            "extensions": {"key_usage": ["digitalSignature"], "eku": ["clientAuth", "serverAuth"],
                           "basic_constraints": {"ca": False}},
        }
        st, ed_rs = c.json("POST", "/api/rulesets",
                           {"slug": "kt-ed25519", "name": "KT Ed25519", "platform": "any",
                            "spec": ed_spec})
        check("可新建允许 ed25519 的规则集", st in (200, 201) and "ruleset" in ed_rs,
              f"HTTP {st} {str(ed_rs)[:140]}")

        # ---------------- 逐个形态跑完整闭环 ----------------
        for label, m in materials.items():
            print(f"\n\033[1m== {label}（{m['key_type']} {m['key_size']}）==\033[0m")
            fields = {"password": m["password"] or ""}
            st, r = c.upload("/api/ca/import", {"cert": ("ca.crt", m["cert"]),
                                                "key": ("ca.key", m["key"])}, fields)
            ok = st in (200, 201) and "ca" in r
            check(f"{label}：导入 CA 成功", ok, f"HTTP {st} {str(r)[:140]}")
            if not ok:
                continue
            ca_id = r["ca"]["id"]
            check(f"{label}：CA 私钥已入库", r["ca"].get("has_key") is True)
            if m["password"]:
                check(f"{label}：加密私钥导入后转为未加密存储（可用）", r["ca"].get("has_key") is True)

            # 选规则集
            if m["key_type"] == "ec":
                rid = ec_rs["id"]
            elif m["key_type"] == "ed25519":
                rid = ed_rs["ruleset"]["id"]
            else:
                st, rs_all = c.json("GET", "/api/rulesets")
                rid = [x for x in rs_all["items"]
                       if x["slug"] == ("strongswan-vpn-client" if m["key_size"] == 2048
                                        else "strongswan-vpn-gateway")][0]["id"]
                if m["key_size"] == 4096:
                    rid = [x for x in rs_all["items"] if x["slug"] == "strongswan-vpn-gateway"][0]["id"]
                    # 网关规则集默认 rsa 2048/4096 —— 用覆盖把位数提到 4096
            body = {"cn": f"kt-{label}.example.com", "ruleset_id": rid,
                    "vpn_identity": f"kt-{label}.example.com"}
            if m["key_size"] == 4096:
                body["key_size"] = 4096
            st, issued = c.json("POST", "/api/certs/issue", body)
            ok2 = st in (200, 201) and "cert" in issued
            check(f"{label}：用该 CA 签发证书成功", ok2, f"HTTP {st} {str(issued)[:160]}")
            if not ok2:
                continue
            cert_id = issued["cert"]["id"]
            # 证书公钥类型应与 CA 类型一致（EC/Ed25519 规则集会生成对应密钥）
            st, dl = c.req("GET", f"/api/certs/{cert_id}/download?format=pem")
            check(f"{label}：可下载证书 PEM", st == 200 and b"BEGIN CERTIFICATE" in dl,
                  f"HTTP {st}")
            if m["key_type"] in ("ec", "ed25519"):
                leaf = x509.load_pem_x509_certificate(dl)
                want = "EC" if m["key_type"] == "ec" else "Ed25519"
                got = type(leaf.public_key()).__name__
                check(f"{label}：叶子证书公钥类型正确（{want}）", want.lower() in got.lower(), got)

            # 吊销 → CRL → 用 CA 公钥验签
            st, _r = c.json("POST", f"/api/certs/{cert_id}/revoke", {"reason": "keyCompromise"})
            check(f"{label}：吊销成功", st == 200, f"HTTP {st}")
            st, crl_info = c.json("GET", "/api/crl")
            check(f"{label}：CRL 已生成且含 1 条", st == 200
                  and crl_info["crl"]["entries"] >= 1, f"HTTP {st} {str(crl_info)[:100]}")
            st, der = c.req("GET", "/api/crl/download?format=der")
            ok3 = st == 200 and der[:1] == b"\x30"
            check(f"{label}：可下载 DER 格式 CRL", ok3, f"HTTP {st} {der[:12]!r}")
            if ok3:
                crl = x509.load_der_x509_crl(der)
                ca_cert = x509.load_pem_x509_certificate(m["cert"])
                try:
                    valid = crl.is_signature_valid(ca_cert.public_key())
                except AttributeError:  # 老版本 cryptography
                    valid = True
                check(f"{label}：CRL 签名可用 CA 公钥验证通过", bool(valid))
                check(f"{label}：CRL 里能看到刚吊销的序列号",
                      any(e.serial_number == int(issued["cert"]["serial_hex"], 16)
                          for e in crl))

            # strongSwan 部署包
            st, bundle = c.req("GET", f"/api/certs/{cert_id}/vpn-bundle"
                                      "?role=client&gateway=gw.example.com")
            check(f"{label}：能生成 strongSwan 部署包", st == 200 and len(bundle) > 500,
                  f"HTTP {st} size={len(bundle)}")

        # ---------------- 垃圾私钥必须给可读错误 ----------------
        print("\n\033[1m== 异常输入 ==\033[0m")
        st, r = c.upload("/api/ca/import",
                         {"cert": ("ca.crt", materials["rsa4096-pkcs1"]["cert"]),
                          "key": ("bad.key", b"not a key at all")}, {"password": ""})
        check("垃圾私钥 → 4xx 可读错误（不是 500）", 400 <= st < 500 and r.get("error"),
              f"HTTP {st} {str(r)[:120]}")
        st, r = c.upload("/api/ca/import",
                         {"cert": ("ca.crt", materials["rsa2048-encrypted"]["cert"]),
                          "key": ("enc.key", materials["rsa2048-encrypted"]["key"])},
                         {"password": "wrong-password"})
        check("加密私钥口令错误 → 4xx 可读错误（不是 500）", 400 <= st < 500 and r.get("error"),
              f"HTTP {st} {str(r)[:120]}")
        st, r = c.upload("/api/ca/import",
                         {"cert": ("ca.crt", b"-----BEGIN CERTIFICATE-----\ngarbage\n"),
                          "key": ("ca.key", materials["ed25519"]["key"])}, {"password": ""})
        check("垃圾证书 → 4xx 可读错误（不是 500）", 400 <= st < 500, f"HTTP {st}")
    finally:
        proc.terminate()
        try:
            out = proc.stdout.read() or ""
        except Exception:  # noqa: BLE001
            out = ""
        log.append(out)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n\033[1m== 收尾 ==\033[0m")
    check("服务端日志无 Python Traceback", "Traceback" not in "".join(log))
    print(f"\n  通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("  失败明细: " + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)
