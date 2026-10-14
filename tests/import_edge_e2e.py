"""批量导入与规模边界验收。

已有测试覆盖了 CERT/KEY/PKCS#12/ZIP/CSV/CRL 的"正常导入"。这里专攻**边界**：

  1) CRL 导入：未知签发者 / 空 CRL / 畸形内容 / 大量条目；
  2) 幂等：同一批文件导入两次，第二次必须全部 skipped，库内不产生重复；
  3) 脏 CSV：BOM + CRLF + 字段内引号与逗号 + 重复 CN + 中文；
  4) 混合目录：证书/私钥/PKCS#12/CSR/CRL/垃圾文件混在一起，要逐文件给出结果且不崩；
  5) 规模：几百张证书后，列表/导出/CRL（含全部吊销条目）仍然正确。
"""
from __future__ import annotations

import datetime as dt
import io
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
import zipfile
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="import-edge-"))
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

    def json(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        if self.csrf:
            r.add_header("X-CSRF-Token", self.csrf)
        r.add_header("Origin", self.base)
        try:
            with urllib.request.urlopen(r, timeout=180) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode())
            except Exception:  # noqa: BLE001
                return exc.code, {}
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}

    def upload(self, path: str, files: dict, fields: dict | None = None):
        boundary = "----imp" + str(int(time.time() * 1000))
        parts = []
        for k, v in (fields or {}).items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        for field, items in files.items():
            for fname, content in items:
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
            with urllib.request.urlopen(r, timeout=180) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode())
            except Exception:  # noqa: BLE001
                return exc.code, {}
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}


def _revoked_count(c) -> int:
    """库内已吊销数量（该套件只看 HTTP，不直接连库）。"""
    st, res = c.json("GET", "/api/certs?status=revoked")
    items = (res or {}).get("items", []) if isinstance(res, dict) else []
    return len(items)


def build_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Imp Edge CA")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert, key, name, now,
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def leaf_pem(ca_cert, ca_key, cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject).public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            k.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def main() -> int:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    print("\n\033[1m== 准备 ==\033[0m")
    DATA.mkdir(parents=True, exist_ok=True)
    port = free_port()
    env = dict(os.environ, CA_DATA_DIR=str(DATA), CA_HOST="127.0.0.1",
               CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    c = Client(f"http://127.0.0.1:{port}")
    log: list[str] = []
    try:
        st = 0
        for _ in range(80):
            st, _ = c.json("GET", "/api/health")
            if st == 200:
                break
            time.sleep(0.25)
        check("服务已启动", st == 200, f"HTTP {st}")
        pw = re.search(r"初始口令:\s*(\S+)",
                       (DATA / "initial_admin_password.txt").read_text(encoding="utf-8")).group(1)
        r = urllib.request.Request(f"http://127.0.0.1:{port}/api/login",
                                   data=json.dumps({"username": "admin", "password": pw}).encode(),
                                   method="POST")
        r.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(r, timeout=30) as resp:
            lb = json.loads(resp.read().decode())
            c.cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        c.csrf = lb["csrf"]
        check("登录成功", bool(c.cookie and c.csrf))

        ca_cert, ca_key, ca_name, now, ca_pem, ca_key_pem = build_ca()
        st, r = c.upload("/api/ca/import", {"cert": [("ca.crt", ca_pem)],
                                            "key": [("ca.key", ca_key_pem)]})
        check("导入 CA 成功", st in (200, 201), f"HTTP {st} {str(r)[:120]}")

        # ---------------- 1) CRL 导入边界 ----------------
        print("\n\033[1m== 1) CRL 导入边界 ==\033[0m")
        # ① 未知签发者的 CRL：不匹配任何本地序列号
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Other CA")])
        other_cert = (x509.CertificateBuilder().subject_name(other_name).issuer_name(other_name)
                      .public_key(other_key.public_key())
                      .serial_number(x509.random_serial_number())
                      .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                      .sign(other_key, hashes.SHA256()))
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(0xDEADBEEF).revocation_date(now)
                 .build())
        foreign_crl = (x509.CertificateRevocationListBuilder()
                       .issuer_name(other_name).last_update(now)
                       .next_update(now + dt.timedelta(days=7))
                       .add_revoked_certificate(entry)
                       .sign(other_key, hashes.SHA256()))
        revoked_before = _revoked_count(c)
        st, res = c.upload("/api/crl/import",
                           {"file": [("other.crl", foreign_crl.public_bytes(serialization.Encoding.PEM))]})
        # 安全要求（审查 ⑧）：无关签发者/无关密钥造的 CRL 必须被**拒绝**，
        # 否则任何人都能用伪造 CRL 把有效证书标成已吊销。
        check("导入未知签发者的 CRL：被拒绝（验签 + 签发者校验）",
              st == 400 and "不是本 CA" in str(res.get("error", "")),
              f"HTTP {st} {str(res)[:140]}")
        check("被拒绝后没有产生任何吊销变更",
              not res.get("updated")
              and _revoked_count(c) == revoked_before, str(res)[:120])
        # ② 空 CRL（没有吊销条目）
        empty_crl = (x509.CertificateRevocationListBuilder()
                     .issuer_name(ca_name).last_update(now)
                     .next_update(now + dt.timedelta(days=7))
                     .sign(ca_key, hashes.SHA256()))
        st, res = c.upload("/api/crl/import",
                           {"file": [("empty.crl", empty_crl.public_bytes(serialization.Encoding.PEM))]})
        check("导入空 CRL：成功且 0 条更新",
              st == 200 and not res.get("updated"), f"HTTP {st} {str(res)[:120]}")
        # ③ 畸形 CRL
        st, res = c.upload("/api/crl/import", {"file": [("bad.crl", b"-----BEGIN X509 CRL-----\nnope\n")]})
        check("导入畸形 CRL：4xx 可读错误（不是 500）",
              400 <= st < 500 and res.get("error"), f"HTTP {st} {str(res)[:120]}")

        # ---------------- 2) 幂等导入 ----------------
        print("\n\033[1m== 2) 重复导入幂等 ==219\033[0m".replace("219", ""))
        impdir = TMP / "batch"
        impdir.mkdir(exist_ok=True)
        pairs = [leaf_pem(ca_cert, ca_key, f"edge-{i}") for i in (1, 2)]
        for i, (crt, key) in enumerate(pairs, start=1):
            (impdir / f"edge-{i}.crt").write_bytes(crt)
            (impdir / f"edge-{i}.key").write_bytes(key)
        st, first = c.json("POST", "/api/certs/import/dir", {"path": str(impdir)})
        check("首次目录导入：2 张证书入库", st == 200 and len(first.get("imported", [])) == 2,
              f"HTTP {st} {str(first)[:140]}")
        st, second = c.json("POST", "/api/certs/import/dir", {"path": str(impdir)})
        check("再次导入同一批：全部 skipped、不新增",
              st == 200 and len(second.get("imported", [])) == 0
              and len(second.get("skipped", [])) == 2,
              f"HTTP {st} {str(second)[:160]}")
        st, certs = c.json("GET", "/api/certs?page_size=100")
        edge_count = len([x for x in certs["items"] if x["cn"].startswith("edge-")])
        check("库内没有重复证书（幂等）", edge_count == 2, f"count={edge_count}")

        # ---------------- 3) 脏 CSV ----------------
        print("\n\033[1m== 3) 脏 CSV：批量编辑（BOM/CRLF/引号逗号/中文/坏行）==\033[0m")
        # 3a) 编辑型 CSV：按 serial_hex 定位已有证书
        st, page = c.json("GET", "/api/certs?page_size=5&q=edge-1")
        target = (page.get("items") or [{}])[0]
        serial = target.get("serial_hex")
        check("取到用于编辑的证书序列号", bool(serial), str(page)[:120])
        edit_csv = ("\ufeffserial_hex,owner,notes,tags,status\r\n"
                    f"{serial},\"张三, 运维部\",\"备注里有,逗号\",vpn;prod,valid\r\n"
                    "DEADBEEFDEADBEEF,李四,不存在,,\r\n"
                    f"{serial},王五,bad-status-row,,nonsense\r\n")
        st, pre = c.json("POST", "/api/certs/import/csv",
                         {"csv_text": edit_csv, "dry_run": True})
        check("编辑型 CSV 预检成功（BOM+CRLF 可解析）", st == 200, f"HTTP {st} {str(pre)[:140]}")
        errs = pre.get("errors") or []
        check("找不到的序列号被逐行报错", any("找不到" in str(e) for e in errs), str(errs)[:140])
        check("非法状态值被逐行报错",
              any("状态" in str(e) for e in errs), str(errs)[:140])
        st, app = c.json("POST", "/api/certs/import/csv", {"csv_text": edit_csv})
        check("编辑型 CSV 可实际应用", st == 200 and len(app.get("applied", [])) >= 1,
              f"HTTP {st} {str(app)[:160]}")
        st, detail = c.json("GET", f"/api/certs/{target.get('id')}")
        got = detail.get("cert") or {}
        check("带引号的逗号字段被正确写入（owner）",
              "张三, 运维部" in str(got.get("owner")), str(got.get("owner"))[:60])
        check("中文备注被正确写入", "逗号" in str(got.get("notes")), str(got.get("notes"))[:60])

        # 3b) 批量签发 API 的边界行（CSV 解析在界面侧，这里验证服务端对脏行的处理）
        st, bat = c.json("POST", "/api/certs/issue/batch", {
            "rows": [
                {"cn": "batch-cn-中文.example.com", "o": "公司, 分部", "validity_days": "30",
                 "profile": "custom"},
                {"cn": "batch-novalidity.example.com", "profile": "custom"},
                {"o": "只有组织没有CN", "profile": "custom"},
                {"cn": "batch-dup.example.com", "profile": "custom"},
                {"cn": "batch-dup.example.com", "profile": "custom"},
            ], "dry_run": True})
        check("批量签发 API 预检不崩（含中文/缺列/重复行）", st == 200,
              f"HTTP {st} {str(bat)[:160]}")
        check("批量签发预检逐行给出结果",
              len(bat.get("preview") or bat.get("rows") or []) >= 3, str(bat)[:160])
        st, bat2 = c.json("POST", "/api/certs/issue/batch", {
            "rows": [
                {"cn": "batch-中文.example.com", "o": "公司, 分部", "validity_days": "30",
                 "profile": "custom"},
                {"o": "只有组织没有CN", "profile": "custom"},
            ]})
        created = bat2.get("created") or bat2.get("imported") or bat2.get("issued") or []
        check("批量签发实际执行：好行签发、坏行报错（不整体失败）",
              st in (200, 201) and len(created) >= 1, f"HTTP {st} {str(bat2)[:200]}")
        check("批量签发的坏行被单独报出（不影响好行）",
              bool(bat2.get("failed")), str(bat2.get("failed"))[:160])

        # ---------------- 4) 混合目录 ----------------
        print("\n\033[1m== 4) 混合目录（证书/私钥/P12/CSR/CRL/垃圾）==\033[0m")
        mixed = TMP / "mixed"
        mixed.mkdir(exist_ok=True)
        crt3, key3 = leaf_pem(ca_cert, ca_key, "mixed-leaf")
        (mixed / "leaf.crt").write_bytes(crt3)
        (mixed / "leaf.key").write_bytes(key3)
        # PKCS#12
        from cryptography.hazmat.primitives.serialization import pkcs12
        leaf_key_obj = serialization.load_pem_private_key(key3, password=None)
        p12 = pkcs12.serialize_key_and_certificates(
            b"mixed", leaf_key_obj, x509.load_pem_x509_certificate(crt3), None,
            serialization.BestAvailableEncryption(b"p12pass"))
        (mixed / "bundle.p12").write_bytes(p12)
        # CSR
        ck = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "mixed-csr")]))
               .sign(ck, hashes.SHA256()))
        (mixed / "req.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        (mixed / "notes.txt").write_bytes(b"this is not a certificate\n")
        (mixed / "broken.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nbroken\n")
        st, mres = c.json("POST", "/api/certs/import/dir", {"path": str(mixed)})
        check("混合目录导入不崩（HTTP 200）", st == 200, f"HTTP {st} {str(mres)[:160]}")
        errs = mres.get("errors") or []
        check("垃圾/损坏文件被逐条报错（不静默）", len(errs) >= 1, str(errs)[:160])
        check("混合目录里的正常证书被导入",
              any("mixed-leaf" in str(x) for x in (mres.get("imported") or [])),
              str(mres.get("imported"))[:160])
        # CSR 不在证书导入范围内：要么入池、要么被明确报告，但绝不能静默或崩溃
        csr_reported = (db_csr_count(DATA, "mixed-csr") >= 1
                        or any("csr" in str(e).lower() for e in errs)
                        or any("csr" in str(x).lower() for x in (mres.get("skipped") or [])))
        check("混合目录里的 CSR 被优雅处理（入池或明确报告，不静默）", csr_reported,
              f"errors={str(errs)[:100]} skipped={str(mres.get('skipped'))[:100]}")

        # ---------------- 5) 规模 ----------------
        print("\n\033[1m== 5) 规模（300 张证书 + 全部吊销进 CRL）==\033[0m")
        code = (
            "import sys, time; sys.path.insert(0, '.')\n"
            "from backend import db, ca, publish\n"
            "row = ca.active_ca_row()\n"
            "t0 = time.time()\n"
            "for i in range(300):\n"
            "    ca.issue_certificate(ca_row=row, vpn_identity='bulk%d.example.com' % i,\n"
            "                         cn='bulk-%d' % i)\n"
            "t1 = time.time()\n"
            "ids = [r['id'] for r in db.q(\"SELECT id FROM certs WHERE cn LIKE 'bulk-%'\")]\n"
            "for cid in ids[:200]:\n"
            "    db.connect().execute(\"UPDATE certs SET status='revoked', revocation_reason='superseded', \"\n"
            "                         \"revoked_at=? WHERE id=?\", ('2026-01-01T00:00:00+00:00', cid))\n"
            "db.connect().commit()\n"
            "t2 = time.time()\n"
            "ca.generate_crl(actor='bulk', source='bulk')\n"
            "publish.publish(trigger='test', reload=False)\n"
            "print('issue=%.1fs revoke=%.1fs total=%d' % (t1-t0, t2-t1, len(ids)))\n")
        r = subprocess.run([str(PY), "-c", code], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=900)
        check("300 张证书签发完成", "total=300" in r.stdout, (r.stdout + r.stderr)[-200:])
        st, certs = c.json("GET", "/api/certs?page_size=1")
        check("规模下证书总数正确", st == 200 and certs["total"] >= 300, str(certs.get("total")))
        st, crl = c.json("GET", "/api/crl")
        check("CRL 覆盖全部 200 条吊销", st == 200 and crl["crl"]["entries"] == 200,
              str(crl.get("crl", {}).get("entries")))
        st, der = c.json("GET", "/api/crl")  # 再取一次确认稳定
        st2, raw = c.json("POST", "/api/export/csv", {}) if False else (0, {})
        # 导出 CSV：用 GET 接口，断言行数
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/certs/export?format=csv")
        req.add_header("Cookie", c.cookie)
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read().decode("utf-8", "replace")
        lines = [l for l in body.splitlines() if l.strip()]
        check("规模下导出 CSV 行数与证书数匹配", len(lines) >= 300, f"lines={len(lines)}")
        m = re.search(r"issue=([\d.]+)s revoke=([\d.]+)s", r.stdout)
        if m:
            print(f"    （参考：签发 300 张 {m.group(1)}s，标记 200 张吊销 {m.group(2)}s）")

        st, rep = c.json("POST", "/api/consistency/check", {})
        errs = [i for i in rep.get("issues", []) if i.get("level") == "error"]
        check("规模操作后一致性体检无 error", not errs, str(errs[:2]))
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

    check("服务端日志无 Python Traceback", "Traceback" not in "".join(log))
    print(f"\n  通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("  失败明细: " + "、".join(FAIL))
    return 1 if FAIL else 0


def db_csr_count(data: Path, cn: str) -> int:
    r = subprocess.run([str(PY), "-c",
                        "import sys; sys.path.insert(0,'.')\n"
                        "from backend import db\n"
                        f"print(db.scalar(\"SELECT COUNT(*) FROM csrs WHERE cn='{cn}'\"))"],
                       cwd=str(ROOT), env=dict(os.environ, CA_DATA_DIR=str(data)),
                       capture_output=True, text=True)
    try:
        return int(r.stdout.strip())
    except Exception:  # noqa: BLE001
        return -1


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)
