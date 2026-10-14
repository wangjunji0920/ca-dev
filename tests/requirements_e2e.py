"""三条明确要求的落地验证：

A) **不依赖外部 openssl**：把服务器进程的 PATH 清空后，导入/签发/吊销/CRL/发布/index.txt
   全流程仍然可用（代码只用 cryptography，不 shell 出 openssl）。
B) **Windows / Linux 差异确实生效**：不同平台规则集签发出来的证书，EKU / KeyUsage /
   有效期真的不同（Windows 智能卡规则集必须带 msSmartcardLogin，Linux 规则集不带）。
C) **规则集完全可定制**：自定义一个"每个字段都非默认"的规则集，签发后逐项核对
   （EC-384 + sha384、KeyUsage、EKU、CRL 分发点、OCSP、自定义 OID 扩展、SAN 策略、
   顺序序列号、有效期上限），证明没有写死的 openssl/固定参数。
D) **自动化引擎通用**：schedule 与 crl_expiry 两种触发器 + file/command 两种动作真的会执行。
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
sys.path.insert(0, str(ROOT))          # 让本进程也能 import backend（B/C/D 段）
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="req-e2e-"))
EMPTY_BIN = TMP / "empty-bin"          # 故意空的 PATH
EMPTY_BIN.mkdir(parents=True, exist_ok=True)

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

    def req(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        if self.csrf:
            r.add_header("X-CSRF-Token", self.csrf)
        r.add_header("Origin", self.base)
        try:
            with urllib.request.urlopen(r, timeout=120) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc).encode(), {}

    def json(self, method: str, path: str, body=None):
        st, raw, _h = self.req(method, path, body)
        try:
            return st, json.loads(raw.decode())
        except Exception:  # noqa: BLE001
            return st, {"raw": raw[:200].decode("utf-8", "replace")}

    def upload(self, path: str, files: dict, fields: dict):
        boundary = "----reqtest" + str(int(time.time() * 1000))
        parts = []
        for k, v in fields.items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        for field, (fname, content) in files.items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; "
                         f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
                         + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        r = urllib.request.Request(self.base + path, data=b"".join(parts), method="POST")
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


def make_ca(cn: str = "Req CA"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


# ====================================================================== A
def section_a() -> None:
    print("\n\033[1m== A) 不依赖外部 openssl（PATH 清空）==\033[0m")
    data = TMP / "data-a"
    data.mkdir(parents=True, exist_ok=True)
    port = free_port()
    # 关键：PATH 指向一个空目录 —— openssl/swanctl/tar/curl 全都找不到
    env = {"CA_DATA_DIR": str(data), "CA_HOST": "127.0.0.1", "CA_PORT": str(port),
           "CA_LEGACY_API": "loopback", "PATH": str(EMPTY_BIN), "HOME": str(TMP),
           "PYTHONPATH": str(ROOT), "LANG": "C.UTF-8"}
    proc = subprocess.Popen([str(PY), "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    c = Client(f"http://127.0.0.1:{port}")
    try:
        st = 0
        for _ in range(80):
            st, _b, _h = c.req("GET", "/api/health")
            if st == 200:
                break
            time.sleep(0.25)
        check("PATH 清空后服务仍能启动", st == 200, f"HTTP {st}")
        pw = re.search(r"初始口令:\s*(\S+)",
                       (data / "initial_admin_password.txt").read_text(encoding="utf-8")).group(1)
        r = urllib.request.Request(f"http://127.0.0.1:{port}/api/login",
                                   data=json.dumps({"username": "admin", "password": pw}).encode(),
                                   method="POST")
        r.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(r, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            c.cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        c.csrf = body.get("csrf", "")
        check("PATH 清空后仍可登录", bool(c.cookie and c.csrf))

        cert_pem, key_pem = make_ca("Req NoOpenSSL CA")
        st, r = c.upload("/api/ca/import", {"cert": ("ca.crt", cert_pem),
                                            "key": ("ca.key", key_pem)}, {"password": ""})
        check("无 openssl：导入 CA 成功", st in (200, 201), f"HTTP {st} {str(r)[:100]}")
        st, issued = c.json("POST", "/api/certs/issue",
                            {"cn": "noopenssl.example.com",
                             "vpn_identity": "noopenssl.example.com"})
        check("无 openssl：签发证书成功", st in (200, 201) and "cert" in issued,
              f"HTTP {st} {str(issued)[:120]}")
        cert_id = (issued.get("cert") or {}).get("id")
        st, _r = c.json("POST", f"/api/certs/{cert_id}/revoke", {"reason": "keyCompromise"})
        check("无 openssl：吊销成功", st == 200, f"HTTP {st}")
        st, crl = c.json("GET", "/api/crl")
        check("无 openssl：CRL 生成成功", st == 200 and crl["crl"]["entries"] >= 1, f"HTTP {st}")
        st, pem, _h = c.req("GET", "/api/crl/download?format=pem")
        check("无 openssl：CRL PEM 可下载", st == 200 and b"BEGIN X509 CRL" in pem, f"HTTP {st}")
        st, _r = c.json("POST", "/api/publish/now", {"reload": False})
        check("无 openssl：发布成功", st == 200, f"HTTP {st}")
        st, idx, _h = c.req("GET", "/api/crl/index")
        check("无 openssl：OpenSSL 风格 index.txt 由纯 Python 生成",
              st == 200 and b"V" in idx or b"R" in idx, f"HTTP {st} {idx[:60]!r}")
        # 部署自检：HTTP 上没有该路由，用 CLI 在同样"清空 PATH"的环境里跑
        doc = subprocess.run([str(PY), "-m", "backend.cli", "preflight", "--json"],
                             cwd=ROOT, env=env, capture_output=True, text=True)
        try:
            dres = json.loads(doc.stdout).get("results", [])
        except Exception:  # noqa: BLE001
            dres = []
        check("无 openssl：部署前自检仍可运行（CLI）", bool(dres),
              (doc.stderr or doc.stdout)[-120:])
        check("无 openssl：自检没有因为缺外部命令而报 error",
              not [r for r in dres if r.get("level") == "error"],
              str([r.get("item") for r in dres if r.get("level") == "error"]))
        missing = [r for r in dres if r.get("item", "").startswith("命令 ")
                   and r.get("detail") == "不存在"]
        check("自检如实报告 PATH 里缺少外部命令（证明环境确实被清空）", bool(missing),
              str([r.get("item") for r in dres][:6]))
    finally:
        proc.terminate()
        try:
            out = proc.stdout.read() or ""
        except Exception:  # noqa: BLE001
            out = ""
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        check("A 段服务端日志无 Traceback", "Traceback" not in out)


# ====================================================================== B/C/D
def section_bcd() -> None:
    data = TMP / "data-bcd"
    os.environ["CA_DATA_DIR"] = str(data)
    data.mkdir(parents=True, exist_ok=True)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    from backend import automation, ca, config, db, publish, rules, server, x509util

    server.bootstrap(verbose=False)
    cert_pem, key_pem = make_ca("Req BCD CA")
    ca_row = ca.import_ca(cert_pem, key_pem)

    # ---------------- B) 平台差异 ----------------
    print("\n\033[1m== B) Windows / Linux 规则集差异确实生效 ==\033[0m")
    ms_oid = "1.3.6.1.4.1.311.20.2.2"          # msSmartcardLogin
    cases = {
        "windows-smartcard-upn": {"need_ms": True},
        "linux-vpn-client": {"need_ms": False},
        "strongswan-vpn-client": {"need_ms": False},
        "windows-user-vpn": {"need_ms": False},
    }
    for slug, exp in cases.items():
        rs = [r for r in rules.list_all() if r["slug"] == slug][0]
        ident = f"{slug}.example.com"
        res = ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn=f"{slug}-cn",
                                   vpn_identity=ident)
        row = db.q1("SELECT * FROM certs WHERE id=?", (res["cert"]["id"],))
        leaf = x509.load_pem_x509_certificate((config.DATA_DIR / row["cert_path"]).read_bytes())
        ekus = {e.dotted_string for e in leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value}
        spec_eku = {x509util.EKU_MAP[e][0].dotted_string
                    for e in rs["spec"]["extensions"]["eku"] if e in x509util.EKU_MAP}
        check(f"{slug}：EKU 与规则集一致", ekus == spec_eku or ekus == ({ms_oid} | spec_eku),
              f"证书={sorted(ekus)} 规则集={sorted(spec_eku)}")
        check(f"{slug}：{'带' if exp['need_ms'] else '不带'} msSmartcardLogin",
              (ms_oid in ekus) == exp["need_ms"], f"{sorted(ekus)}")
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        want_ku = set(rs["spec"]["extensions"]["key_usage"])
        got_ku = {n for n, v in (("digitalSignature", ku.digital_signature),
                                 ("keyEncipherment", ku.key_encipherment),
                                 ("keyAgreement", ku.key_agreement),
                                 ("dataEncipherment", ku.data_encipherment)) if v}
        check(f"{slug}：KeyUsage 与规则集一致", got_ku == want_ku, f"{got_ku} vs {want_ku}")
        days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
        check(f"{slug}：有效期符合规则集（{rs['spec']['validity']['days']} 天）",
              abs(days - rs["spec"]["validity"]["days"]) <= 1, f"{days} 天")
        check(f"{slug}：CN 为显式给定的值", x509util.get_name(leaf.subject, NameOID.COMMON_NAME)
              == f"{slug}-cn", str(x509util.get_name(leaf.subject, NameOID.COMMON_NAME)))
        san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ident_in_san = ident in san_ext.get_values_for_type(x509.DNSName) \
            or any(ident in str(v) for v in san_ext.get_values_for_type(x509.OtherName)) \
            or any(ident == v for v in san_ext.get_values_for_type(x509.RFC822Name))
        check(f"{slug}：VPN 身份按规则集写入 SAN", ident_in_san, str(san_ext)[:120])
    win = [r for r in rules.list_all() if r["slug"] == "windows-smartcard-upn"][0]
    lin = [r for r in rules.list_all() if r["slug"] == "linux-vpn-client"][0]
    check("Windows 与 Linux 规则集本身就不相同（平台差异是配置而非写死）",
          win["platform"] == "windows" and lin["platform"] == "linux"
          and win["spec"]["extensions"]["eku"] != lin["spec"]["extensions"]["eku"])

    # ---------------- C) 完全可定制 ----------------
    print("\n\033[1m== C) 规则集每个字段都可定制并真实生效 ==\033[0m")
    custom = {
        "strict": True, "overridable": ["validity.days"],
        "subject": {"require_cn": True, "required_fields": ["CN"], "cn_from_identity": False,
                    "max_cn_length": 40, "max_field_length": 64,
                    "allow_empty_organization": True},
        "san": {"required": True, "allowed_types": ["dns", "upn"], "auto_from_identity": True,
                "add_upn_for_email": False, "copy_cn_if_fqdn": True, "max_entries": 5,
                "default_type": "dns"},
        "key": {"type": "ec", "size": 384, "allowed_types": ["ec"],
                "min_rsa_size": 2048, "allowed_ec_sizes": [256, 384, 521], "digest": "sha384"},
        "validity": {"days": 100, "min_days": 1, "max_days": 200,
                     "not_before_skew_minutes": 5},
        "extensions": {"key_usage": ["digitalSignature", "keyAgreement"], "eku": ["clientAuth"],
                       "basic_constraints_ca": False, "path_length": None,
                       "subject_key_identifier": True, "authority_key_identifier": True,
                       "crl_distribution_point": True,
                       "crl_url": "http://crl.example.com/req.crl",
                       "ocsp_url": "http://ocsp.example.com/",
                       "custom": [{"oid": "1.2.3.4.5.6.7.8", "type": "utf8",
                                   "value": "req-custom-ext", "critical": False}]},
        "serial": {"mode": "sequential", "bits": 159},
        "revocation": {"allow_revoke": True, "default_reason": "unspecified",
                       "auto_publish_crl": True},
        "export": {"bundle": "pem", "key_file_mode": "0600", "require_p12_password": False,
                   "windows_import_hint": "", "linux_install_hint": "", "extra_notes": ""},
    }
    problems = rules.validate(custom)[1] if isinstance(rules.validate(custom), tuple) else []
    check("自定义规则集通过校验（无问题项）", not problems, str(problems[:3]))
    rs = rules.create({"slug": "req-custom", "name": "Req 自定义", "platform": "any",
                       "purpose": "custom", "spec": custom})
    # 该规则集刻意设为 cn_from_identity=False：只给身份、不给 CN 必须被明确拒绝（策略生效）
    try:
        ca.issue_certificate(ca_row=ca_row, ruleset=rs, vpn_identity="only-identity.example.com")
        cn_policy_ok = False
    except Exception as exc:  # noqa: BLE001
        cn_policy_ok = "CN" in str(exc)
    check("C：cn_from_identity=False 时，只给身份会被明确拒绝", cn_policy_ok)
    res1 = ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn="custom1.example.com",
                                vpn_identity="custom1.example.com")
    res2 = ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn="custom2.example.com",
                                vpn_identity="custom2.example.com")
    row1 = db.q1("SELECT * FROM certs WHERE id=?", (res1["cert"]["id"],))
    row2 = db.q1("SELECT * FROM certs WHERE id=?", (res2["cert"]["id"],))
    leaf1 = x509.load_pem_x509_certificate((config.DATA_DIR / row1["cert_path"]).read_bytes())
    leaf2 = x509.load_pem_x509_certificate((config.DATA_DIR / row2["cert_path"]).read_bytes())

    check("C：密钥类型/曲线 = EC P-384",
          isinstance(leaf1.public_key(), ec.EllipticCurvePublicKey)
          and leaf1.public_key().curve.name == "secp384r1",
          type(leaf1.public_key()).__name__)
    check("C：签名摘要 = sha384",
          leaf1.signature_hash_algorithm.name == "sha384",
          str(leaf1.signature_hash_algorithm))
    ku = leaf1.extensions.get_extension_for_class(x509.KeyUsage).value
    check("C：KeyUsage = digitalSignature + keyAgreement（不多不少）",
          ku.digital_signature and ku.key_agreement and not ku.key_encipherment
          and not ku.data_encipherment)
    ekus = {e.dotted_string for e in leaf1.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage).value}
    check("C：EKU = 仅 clientAuth", ekus == {ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string},
          str(sorted(ekus)))
    days = (leaf1.not_valid_after_utc - leaf1.not_valid_before_utc).days
    check("C：有效期 = 100 天", abs(days - 100) <= 1, f"{days}")
    check("C：SKI / AKI 都在",
          leaf1.extensions.get_extension_for_class(x509.SubjectKeyIdentifier) is not None
          and leaf1.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier) is not None)
    try:
        cdp = leaf1.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls = [u.value for dp in cdp for u in dp.full_name]
    except x509.ExtensionNotFound:
        urls = []
    check("C：CRL 分发点 URL 生效", "http://crl.example.com/req.crl" in urls, str(urls))
    try:
        aia = leaf1.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp = [d.access_location.value for d in aia
                if d.access_method == x509.AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        ocsp = []
    check("C：OCSP 地址生效", "http://ocsp.example.com/" in ocsp, str(ocsp))
    try:
        found = leaf1.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("1.2.3.4.5.6.7.8"))
        raw = found.value.value if hasattr(found.value, "value") else b""
        custom_ok = found.critical is False and b"req-custom-ext" in raw
    except x509.ExtensionNotFound:
        custom_ok = False
    check("C：自定义 OID 扩展生效（非 critical，内容正确）", custom_ok)
    sans = leaf1.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = sans.get_values_for_type(x509.DNSName)
    check("C：SAN 按 auto_from_identity + copy_cn_if_fqdn 生成",
          "custom1.example.com" in dns, str(dns))
    s1, s2 = int(row1["serial_hex"], 16), int(row2["serial_hex"], 16)
    check("C：顺序序列号按 1 递增（可定制序列号策略）", s2 == s1 + 1, f"{s1} -> {s2}")
    # 覆盖白名单：允许覆盖 validity.days，不允许覆盖 key.size
    ok = ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn="custom3.example.com",
                              vpn_identity="custom3.example.com", validity_days=30)
    d3 = (dt.datetime.fromisoformat(ok["cert"]["not_after"])
          - dt.datetime.fromisoformat(ok["cert"]["not_before"])).days
    check("C：白名单内覆盖生效（有效期→30 天）", abs(d3 - 30) <= 1, f"{d3}")
    try:
        ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn="custom4.example.com",
                             vpn_identity="custom4.example.com", key_size=256)
        blocked = False
    except Exception as exc:  # noqa: BLE001
        blocked = "覆盖" in str(exc) or "allow" in str(exc).lower()
    check("C：白名单外覆盖被拒", blocked)

    # ---- 其余可定制开关：每个都要真的起作用 ----
    # ① 关掉 SKI/AKI
    spec_no_id = json.loads(json.dumps(custom))
    spec_no_id["extensions"]["subject_key_identifier"] = False
    spec_no_id["extensions"]["authority_key_identifier"] = False
    spec_no_id["extensions"].pop("custom", None)
    spec_no_id["extensions"]["ocsp_url"] = ""
    spec_no_id["extensions"]["crl_distribution_point"] = False
    rs2 = rules.create({"slug": "req-noid", "name": "Req 无 SKI/AKI", "platform": "any",
                        "spec": spec_no_id})
    res_no = ca.issue_certificate(ca_row=ca_row, ruleset=rs2, cn="noid.example.com",
                                  vpn_identity="noid.example.com")
    row_no = db.q1("SELECT * FROM certs WHERE id=?", (res_no["cert"]["id"],))
    leaf_no = x509.load_pem_x509_certificate((config.DATA_DIR / row_no["cert_path"]).read_bytes())
    has_ski = True
    has_aki = True
    try:
        leaf_no.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        has_ski = False
    try:
        leaf_no.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        has_aki = False
    check("C：SKI/AKI 开关关闭后证书里确实没有这两个扩展", not has_ski and not has_aki,
          f"ski={has_ski} aki={has_aki}")

    # ② email 身份 + add_upn_for_email -> SAN 里同时有 email 与 UPN(OtherName)
    spec_upn = json.loads(json.dumps(custom))
    spec_upn["san"]["add_upn_for_email"] = True
    spec_upn["san"]["allowed_types"] = ["dns", "email", "upn", "othername"]
    rs3 = rules.create({"slug": "req-upn", "name": "Req UPN", "platform": "any",
                        "spec": spec_upn})
    res_upn = ca.issue_certificate(ca_row=ca_row, ruleset=rs3,
                                   cn="upn@example.com", vpn_identity="upn@example.com")
    row_upn = db.q1("SELECT * FROM certs WHERE id=?", (res_upn["cert"]["id"],))
    leaf_upn = x509.load_pem_x509_certificate((config.DATA_DIR / row_upn["cert_path"]).read_bytes())
    sans_upn = leaf_upn.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    emails = sans_upn.get_values_for_type(x509.RFC822Name)
    others = sans_upn.get_values_for_type(x509.OtherName)
    check("C：email 身份同时写入 email SAN 与 UPN(OtherName)",
          "upn@example.com" in emails and bool(others),
          f"emails={emails} othername={len(others)}")

    # ③ SAN 类型白名单：不允许的 dns 必须被拒
    spec_ipsan = json.loads(json.dumps(custom))
    spec_ipsan["san"]["allowed_types"] = ["ip"]
    rs4 = rules.create({"slug": "req-ipsan", "name": "Req 仅 IP", "platform": "any",
                        "spec": spec_ipsan})
    try:
        ca.issue_certificate(ca_row=ca_row, ruleset=rs4, cn="iponly.example.com",
                             vpn_identity="iponly.example.com")
        dns_blocked = False
    except Exception as exc:  # noqa: BLE001
        dns_blocked = "SAN" in str(exc) or "允许" in str(exc)
    check("C：SAN 类型白名单生效（不允许的 DNS 身份被拒）", dns_blocked)

    # ④ CN 长度上限生效
    try:
        ca.issue_certificate(ca_row=ca_row, ruleset=rs, cn="x" * 60,
                             vpn_identity="x" * 60 + ".example.com")
        cn_blocked = False
    except Exception as exc:  # noqa: BLE001
        cn_blocked = "CN" in str(exc) or "长度" in str(exc)
    check("C：CN 长度上限（max_cn_length=40）生效", cn_blocked)

    # ---------------- D) 自动化引擎 ----------------
    print("\n\033[1m== D) 自动化触发器与动作确实执行 ==\033[0m")
    outdir = TMP / "automation-out"
    outdir.mkdir(parents=True, exist_ok=True)
    # ① schedule 触发器 + file 动作
    t1 = automation.create_task({
        "name": "Req 定时导出", "trigger": "schedule", "kind": "file",
        "content": "inventory_csv", "interval_minutes": 1, "enabled": True,
        "target": {"path": str(outdir), "filename": "scheduled.csv", "format": "csv"}})
    db.connect().execute("UPDATE automation_tasks SET last_run=NULL WHERE id=?", (t1["id"],))
    ran = automation.run_due()
    check("D：schedule 触发器被执行", any(x["task_id"] == t1["id"] for x in ran), str(ran)[:140])
    produced = list(outdir.glob("*"))
    check("D：file 动作真的写出了文件", bool(produced), str(produced))
    if produced:
        check("D：导出内容含证书清单表头",
              b"cn" in produced[0].read_bytes().lower() or "序列号" in produced[0].read_text(
                  encoding="utf-8", errors="replace"),
              produced[0].name)
    again = automation.run_due()
    check("D：未到间隔不重复执行", not any(x["task_id"] == t1["id"] for x in again), str(again)[:100])

    # ② crl_expiry 触发器 + command 动作（先确保有 CRL 可供内容使用）
    ca.generate_crl(actor="test", source="test")
    r = db.q1("SELECT * FROM certs WHERE status='valid' LIMIT 1")
    if r:
        ca.revoke(r["id"], reason="superseded")     # 让 CRL 有内容且更贴近真实
    sentinel = outdir / "crl-expiry-ran.txt"
    t2 = automation.create_task({
        "name": "Req CRL 到期动作", "trigger": "crl_expiry", "kind": "command",
        "content": "crl_pem", "lead_hours": 99999, "enabled": True,
        "target": {"cmd": f"sh -c 'cat \"$CA_CONTENT_FILE\" > {sentinel}'"}})
    ran2 = automation.run_due()
    hit = [x for x in ran2 if x["task_id"] == t2["id"]]
    check("D：crl_expiry 触发器被执行", bool(hit), str(ran2)[:140])
    check("D：任务执行结果为成功（而非 ERROR）",
          bool(hit) and "ERROR" not in str(hit[0].get("result", "")),
          str(hit[0].get("result"))[:160] if hit else "未执行")
    check("D：command 动作拿到内容文件并写出结果", sentinel.is_file()
          and b"BEGIN X509 CRL" in sentinel.read_bytes(),
          f"exists={sentinel.is_file()}")
    hist = automation.history(page_size=5)
    check("D：自动化执行留有历史", bool(hist.get("items")), str(hist)[:120])
    check("D：触发器/内容/动作类型可枚举（供界面渲染）",
          len(automation.TRIGGERS) >= 8 and len(automation.CONTENTS) >= 8
          and len(automation.KINDS) >= 3,
          f"triggers={len(automation.TRIGGERS)} contents={len(automation.CONTENTS)} kinds={len(automation.KINDS)}")


def main() -> int:
    print("\n\033[1m== 准备 ==\033[0m")
    check("故意清空的 PATH 目录已就绪", EMPTY_BIN.is_dir() and not list(EMPTY_BIN.iterdir()))
    section_a()
    section_bcd()
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
