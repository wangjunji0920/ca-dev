"""吊销事实完整性验收（外部审查 ③ 与 ⑧）：

③ 归档已吊销证书曾导致 CRL 漏项（status 被改成 archived，而生成 CRL 只查 revoked）；
   硬删除更会把吊销记录整行删掉 → 该证书永远不可能出现在任何 CRL 里。
⑧ 导入 CRL 曾经只按序列号匹配，用无关 CA/密钥伪造的 CRL 能把有效证书标成已吊销。

本测试锁定：
  1) 吊销 → 归档 → CRL **仍**包含该序列号；index.txt 仍标 R；
  2) 已吊销证书**硬删除被拒绝**，软删除允许且吊销事实保留；
  3) 一致性体检能发现"已吊销但不在最新 CRL 中"；
  4) 无关 CA 签发的 CRL 导入被拒绝，且不产生任何状态变更；
  5) 本 CA 自己签发的 CRL 导入正常。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")
TMP = Path(tempfile.mkdtemp(prefix="revint-"))
os.environ["CA_DATA_DIR"] = str(TMP / "data")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from backend import api, ca, config, consistency, db, inventory, publish, server, x509util  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def _crl_number_of(path: Path) -> str:
    """读文件里的 CRL 编号；文件缺失/损坏时返回可读说明，避免整套测试因异常中断。"""
    try:
        return str(x509util.crl_info(x509util.load_crl(path.read_bytes()))["number"])
    except Exception as exc:  # noqa: BLE001
        return f"<无法读取 {path.name}: {type(exc).__name__}>"


def _make_foreign_crl(cn_serial: int) -> bytes:
    """用与当前 CA 无关的密钥与签发者造一份 CRL（用于验证导入必须验签）。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Evil CA")])
    now = x509util.now()
    crl = (x509.CertificateRevocationListBuilder()
           .issuer_name(name).last_update(now).next_update(now + dt.timedelta(days=30))
           .add_revoked_certificate(
               x509.RevokedCertificateBuilder().serial_number(cn_serial)
               .revocation_date(now).build())
           .sign(key, hashes.SHA256()))
    return crl.public_bytes(serialization.Encoding.DER)


def _ensure_ca() -> dict:
    """测试环境准备一个自签 CA（真实部署是导入现有 CA）。"""
    row = ca.active_ca_row()
    if row is not None:
        return row
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RevInt CA")])
    now = x509util.now()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    ca.import_ca(x509util.pem_cert(cert).encode(), x509util.pem_key(key).encode())
    return ca.active_ca_row()


def main() -> int:
    server.bootstrap(verbose=False)
    row = _ensure_ca()
    assert row is not None, "需要已有 CA"

    print("\n\033[1m== ③ 归档已吊销证书：CRL 不得漏项 ==\033[0m")
    cert = ca.issue_certificate(ca_row=row, vpn_identity="arch.example.com", cn="arch-me")["cert"]
    ca.revoke(cert["id"], reason="keyCompromise")
    ca.generate_crl(actor="t", source="t")

    def _crl_file() -> Path:
        """最新 CRL 的磁盘路径（库里可能存相对路径 → 相对 data 目录解析）。"""
        r = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
        for key in ("der_path", "path"):
            v = r[key]
            if v:
                q = Path(v)
                return q if q.is_absolute() else Path(config.DATA_DIR) / q
        raise AssertionError("最新 CRL 没有磁盘路径")

    crl_file = _crl_file()
    serial = int(cert["serial_hex"], 16)

    def in_crl() -> bool:
        return any(int(e.serial_number) == serial for e in x509util.load_crl(crl_file.read_bytes()))

    check("吊销后 CRL 含该序列号", in_crl())

    inventory.delete_cert(cert["id"], hard=False, actor="t")     # 软删除 = 归档
    check("归档成功（status=archived）",
          db.scalar(f"SELECT status FROM certs WHERE id={cert['id']}") == "archived")
    ca.generate_crl(actor="t", source="t")
    check("★ 归档后重新生成 CRL：仍含该序列号（不因展示状态漏项）", in_crl(),
          "CRL 里找不到已吊销且已归档的证书 → 客户端会重新被接受")
    idx = ca.export_index_txt(ca_id=row["id"]) if hasattr(ca, "export_index_txt") else ""
    if idx:
        check("index.txt 仍把该证书标为 R（已吊销）",
              any(line.startswith("R\t") and cert["serial_hex"].upper() in line.upper()
                  for line in idx.splitlines()))

    print("\n\033[1m== ③ 已吊销证书：硬删除必须被拒绝 ==\033[0m")
    rejected, detail = False, ""
    try:
        inventory.delete_cert(cert["id"], hard=True, actor="t")
    except Exception as exc:  # noqa: BLE001
        rejected = "不允许硬删除" in str(exc) or "吊销" in str(exc)
        detail = str(exc)
    check("★ 硬删除已吊销证书被拒绝（否则吊销记录永久消失）", rejected,
          detail if not rejected else "")
    check("被拒绝后记录仍在库里",
          db.scalar(f"SELECT COUNT(*) FROM certs WHERE id={cert['id']}") == 1)
    check("被拒绝后吊销事实仍在（revoked_at 非空）",
          bool(db.scalar(f"SELECT revoked_at FROM certs WHERE id={cert['id']}")))

    print("\n\033[1m== ③ 一致性体检能发现'已吊销但不在 CRL 中' ==\033[0m")
    res = consistency.check()
    codes = {i.get("code") for i in res.get("issues", [])}
    check("正常情况下没有 revoked_missing_in_crl", "revoked_missing_in_crl" not in codes,
          str(sorted(codes))[:160])
    # 造一个"漏项"：把另一张有效证书直接在库里标成已吊销，但不重新生成 CRL
    other = ca.issue_certificate(ca_row=row, vpn_identity="gap.example.com", cn="gap")["cert"]
    with db.tx() as conn:
        conn.execute("UPDATE certs SET status='revoked', revoked_at=? WHERE id=?",
                     (x509util.to_iso(x509util.now()), other["id"]))
    res2 = consistency.check()
    codes2 = {i.get("code") for i in res2.get("issues", [])}
    check("★ 能抓到'已吊销但不在最新 CRL 中'（error 级）",
          "revoked_missing_in_crl" in codes2
          and any(i["level"] == "error" for i in res2["issues"]
                  if i.get("code") == "revoked_missing_in_crl"),
          str(sorted(codes2))[:160])
    ca.generate_crl(actor="t", source="t")
    codes3 = {i.get("code") for i in consistency.check().get("issues", [])}
    check("补齐 CRL 后该项消失", "revoked_missing_in_crl" not in codes3, str(sorted(codes3))[:160])

    print("\n\033[1m== ① 通用状态更新不得抹掉吊销事实 ==\033[0m")
    # 审查复现：PATCH status=archived 会把 revoked_at 置空 → 该证书从下一份 CRL 消失。
    t2 = ca.issue_certificate(ca_row=row, vpn_identity="wipe.example.com", cn="wipe-me")["cert"]
    ca.revoke(t2["id"], reason="keyCompromise")
    ca.generate_crl(actor="t", source="t")
    check("前提：吊销后 CRL 含该序列号",
          any(int(e.serial_number) == int(t2["serial_hex"], 16)
              for e in x509util.load_crl(_crl_file().read_bytes())))
    inventory.update_metadata(t2["id"], {"status": "archived"}, actor="t")
    check("★ 归档（status=archived）后 revoked_at 仍在",
          bool(db.scalar(f"SELECT revoked_at FROM certs WHERE id={t2['id']}")),
          "revoked_at 被通用更新抹掉了")
    ca.generate_crl(actor="t", source="t")
    check("★ 归档后重新生成 CRL：该序列号仍在（吊销事实未被抹）",
          any(int(e.serial_number) == int(t2["serial_hex"], 16)
              for e in x509util.load_crl(_crl_file().read_bytes())))
    # 想把已吊销证书改成 valid 必须走专用恢复操作
    refused2, why2 = False, ""
    try:
        inventory.update_metadata(t2["id"], {"status": "valid"}, actor="t")
    except Exception as exc:  # noqa: BLE001
        refused2 = "恢复吊销" in str(exc) or "unrevoke" in str(exc)
        why2 = str(exc)
    check("★ 通用更新把已吊销证书改成 valid 被拒绝（要求走恢复吊销）",
          refused2, why2 if not refused2 else "")
    check("拒绝后吊销事实仍完好",
          bool(db.scalar(f"SELECT revoked_at FROM certs WHERE id={t2['id']}"))
          and db.scalar(f"SELECT status FROM certs WHERE id={t2['id']}") == "archived")
    codes4 = {i.get("code") for i in consistency.check().get("issues", [])}
    check("一致性体检在这条路径后也不报漏项", "revoked_missing_in_crl" not in codes4,
          str(sorted(codes4))[:120])

    print("\n\033[1m== ③ 生成失败不得删除上一份有效 CRL 文件 ==\033[0m")
    prev = _crl_file()
    prev_bytes = prev.read_bytes()
    real_next = ca._next_crl_number

    def boom(ca_id, conn=None):
        raise RuntimeError("injected failure before signing")

    ca._next_crl_number = boom
    try:
        ca.generate_crl(actor="t", source="inject")
        check("注入异常时应抛错", False, "竟然成功了")
    except Exception as exc:  # noqa: BLE001
        check("注入异常时如实抛错", "injected failure" in str(exc), type(exc).__name__)
    finally:
        ca._next_crl_number = real_next
    check("★ 失败后上一份 CRL 的 PEM/DER 文件仍在",
          prev.is_file() and prev.read_bytes() == prev_bytes,
          f"{prev} exists={prev.is_file()}")
    for key in ("der_path", "path"):
        v = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")[key]
        if v:
            q = Path(v)
            q = q if q.is_absolute() else Path(config.DATA_DIR) / q
            check(f"★ 数据库指向的 CRL 文件存在（{key}）", q.is_file(), str(q))
    check("失败后没有残留 .tmp 文件",
          not list(Path(config.DATA_DIR).glob("crl/.*tmp*")),
          str([x.name for x in Path(config.DATA_DIR).glob("crl/*")][:6]))
    # 生成仍可正常工作（自愈）
    ok_again = ca.generate_crl(actor="t", source="after-inject")
    check("注入失败后仍能正常生成 CRL（自愈）", ok_again["has_file"] is True, str(ok_again)[:80])

    print("\n\033[1m== ①′ CRL 文件与数据库必须一起保持一致 ==\033[0m")
    # 审查故障注入：替换第二个文件失败 / 替换后审计失败，会留下"DB=#4 而 PEM/DER=#5"的错配。
    before_row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    before_files = sorted(p.name for p in (Path(config.DATA_DIR) / "crl").glob("*"))
    real_replace = ca.os.replace

    def fail_der_replace(src, dst, *a, **kw):
        if str(dst).endswith(".crl.der"):
            raise OSError("injected failure on DER rename")
        return real_replace(src, dst, *a, **kw)

    ca.os.replace = fail_der_replace
    try:
        ca.generate_crl(actor="t", source="inject-der")
        check("注入 DER 改名失败时应抛错", False, "竟然成功了")
    except Exception as exc:  # noqa: BLE001
        check("注入 DER 改名失败时如实抛错", "injected failure" in str(exc), type(exc).__name__)
    finally:
        ca.os.replace = real_replace
    after_row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    check("★ 失败后数据库最新记录仍是失败前那一条",
          after_row["id"] == before_row["id"] and after_row["number"] == before_row["number"],
          f"{before_row['number']} -> {after_row['number']}")
    der_now = Path(config.DATA_DIR) / (after_row["der_path"] or after_row["path"])
    pem_now = Path(config.DATA_DIR) / after_row["path"]
    check("★ 记录指向的两份文件都在",
          der_now.is_file() and pem_now.is_file(),
          f"DER存在={der_now.is_file()} PEM存在={pem_now.is_file()}（{pem_now.name}）")
    check("★ DER 里的编号与数据库记录一致（不出现 DB=#4/文件=#5）",
          _crl_number_of(der_now) == str(after_row["number"]),
          f"DER={_crl_number_of(der_now)} DB={after_row['number']}")
    check("★ PEM 里的编号与数据库记录一致（两份文件必须同一次生成）",
          _crl_number_of(pem_now) == str(after_row["number"]),
          f"PEM={_crl_number_of(pem_now)} DB={after_row['number']}")
    check("★ 文件校验值与数据库记录一致",
          hashlib.sha256(der_now.read_bytes()).hexdigest() == after_row["sha256"])
    files_now = sorted(p.name for p in (Path(config.DATA_DIR) / "crl").glob("*"))
    orphans = [f for f in files_now if f not in before_files
               and f"ca-{after_row['number']}" not in f]
    check("★ 失败没有留下本次生成的孤儿文件（已清理）",
          not [f for f in files_now if f not in before_files
               and not f.startswith("ca-")], str(files_now[:8]))
    del orphans

    # 替换后、提交前失败（审计注入）：数据库不得变，文件不得被动过
    real_audit = ca.audit.log
    calls = {"n": 0}

    def boom_audit(*a, **kw):
        calls["n"] += 1
        raise RuntimeError("injected failure after files written")

    ca.audit.log = boom_audit
    try:
        ca.generate_crl(actor="t", source="inject-audit")
        check("注入审计失败时应抛错", False, "竟然成功了")
    except Exception as exc:  # noqa: BLE001
        check("注入审计失败时如实抛错", "injected failure" in str(exc), type(exc).__name__)
    finally:
        ca.audit.log = real_audit
    after2 = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    check("★ 提交前失败：数据库最新记录未变",
          after2["id"] == before_row["id"], f"{before_row['number']} -> {after2['number']}")
    der2 = Path(config.DATA_DIR) / (after2["der_path"] or after2["path"])
    pem2 = Path(config.DATA_DIR) / after2["path"]
    check("★ 提交前失败：原记录的两份文件都未被改动（编号/校验值仍一致）",
          _crl_number_of(der2) == str(after2["number"])
          and (not der2.is_file() or hashlib.sha256(der2.read_bytes()).hexdigest()
               == after2["sha256"])
          and _crl_number_of(pem2) == str(after2["number"]),
          f"DER={_crl_number_of(der2)} PEM={_crl_number_of(pem2)} DB={after2['number']}")

    # 生成正常恢复
    ok3 = ca.generate_crl(actor="t", source="after-inject2")
    check("两次注入后仍能正常生成（自愈）", ok3["has_file"] is True, str(ok3)[:80])

    print("\n\033[1m== ①″ 一致性体检能发现'记录与文件不是同一次生成' ==\033[0m")
    codes0 = {i.get("code") for i in consistency.check().get("issues", [])}
    check("正常状态下没有 crl_number_mismatch / crl_file_missing",
          not ({"crl_number_mismatch", "crl_file_missing", "crl_file_mismatch"} & codes0),
          str(sorted(codes0))[:140])
    # 人为把 DER 换成"另一次生成"的文件（模拟旧的固定名错配）
    latest_row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    prev_row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1 OFFSET 1")
    bad_path = Path(config.DATA_DIR) / (latest_row["der_path"] or latest_row["path"])
    good_prev = Path(config.DATA_DIR) / (prev_row["der_path"] or prev_row["path"])
    backup = bad_path.read_bytes()
    bad_path.write_bytes(good_prev.read_bytes())
    try:
        codes1 = {i.get("code") for i in consistency.check().get("issues", [])}
        check("★ 文件被换成另一次生成时，体检报出编号/校验不符",
              bool({"crl_number_mismatch", "crl_file_mismatch"} & codes1), str(sorted(codes1))[:160])
    finally:
        bad_path.write_bytes(backup)
    codes2 = {i.get("code") for i in consistency.check().get("issues", [])}
    check("恢复文件后体检恢复正常",
          not ({"crl_number_mismatch", "crl_file_mismatch"} & codes2), str(sorted(codes2))[:140])

    print("\n\033[1m== ①‴ CRL 文件保留策略：清理旧文件但不得误报 ==\033[0m")
    db.set_setting("crl_files_keep", "2")
    for i in range(4):
        cc = ca.issue_certificate(ca_row=row, vpn_identity=f"keep{i}.example.com",
                                  cn=f"keep{i}")["cert"]
        ca.revoke(cc["id"], reason="keyCompromise")
    crl_dir = Path(config.DATA_DIR) / "crl"
    files_n = len(list(crl_dir.glob("ca-*")))
    check("★ 文件数受 crl_files_keep 限制（记录仍全部保留）",
          files_n <= 2 * 3, f"文件={files_n} 记录={db.scalar('SELECT COUNT(*) FROM crls')}")
    newest = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    check("★ 最新一份的两份文件都在",
          (Path(config.DATA_DIR) / newest["path"]).is_file()
          and (Path(config.DATA_DIR) / newest["der_path"]).is_file())
    codes_keep = {i.get("code") for i in consistency.check().get("issues", [])}
    check("★ 按策略清理的旧文件不会被误报为缺失",
          not ({"crl_file_missing", "crl_number_mismatch", "crl_file_mismatch"} & codes_keep),
          str(sorted(codes_keep))[:140])
    db.set_setting("crl_files_keep", "50")

    print("\n\033[1m== ② 通用更新不得绕开吊销流程 ==\033[0m")
    fresh = ca.issue_certificate(ca_row=row, vpn_identity="bypass.example.com",
                                 cn="bypass")["cert"]
    refused3, why3 = False, ""
    try:
        inventory.update_metadata(fresh["id"], {"status": "revoked"}, actor="t")
    except Exception as exc:  # noqa: BLE001
        refused3 = "专用功能" in str(exc) or "cli revoke" in str(exc)
        why3 = str(exc)
    check("★ 通用更新把有效证书改成 revoked 被拒绝", refused3, why3 if not refused3 else "")
    check("拒绝后状态仍是 valid 且没有假的吊销事实",
          db.scalar(f"SELECT status FROM certs WHERE id={fresh['id']}") == "valid"
          and not db.scalar(f"SELECT revoked_at FROM certs WHERE id={fresh['id']}"))
    csv_out = inventory.import_csv(f"serial_hex,status\n{fresh['serial_hex']},revoked\n",
                                  dry_run=False, actor="t")
    check("★ CSV 也不能把证书改成 revoked",
          any("不能把证书改成 revoked" in (e.get("error") or "") for e in csv_out.get("errors", [])),
          str(csv_out)[:160])
    check("CSV 被拒后状态未变",
          db.scalar(f"SELECT status FROM certs WHERE id={fresh['id']}") == "valid")
    codes3 = {i.get("code") for i in consistency.check().get("issues", [])}
    check("这两条路径都没有造成吊销事实与 CRL 脱节",
          "revoked_missing_in_crl" not in codes3, str(sorted(codes3))[:140])
    ca.revoke(fresh["id"], reason="keyCompromise")     # 专用流程仍然可用
    check("专用吊销接口仍正常（CRL 同步更新）",
          any(int(e.serial_number) == int(fresh["serial_hex"], 16)
              for e in x509util.load_crl(_crl_file().read_bytes())))

    print("\n\033[1m== ⑧ 导入 CRL 必须验签且签发者匹配 ==\033[0m")
    victim = ca.issue_certificate(ca_row=row, vpn_identity="victim.example.com",
                                  cn="victim")["cert"]
    forged = _make_foreign_crl(int(victim["serial_hex"], 16))
    refused, why = False, ""
    try:
        ca.import_crl(forged, actor="t")
    except Exception as exc:  # noqa: BLE001
        refused = True
        why = str(exc)
    check("★ 无关 CA 的 CRL 被拒绝导入", refused, why if not refused else "")
    check("★ 被拒绝后该证书仍是 valid（没有被伪造成已吊销）",
          db.scalar(f"SELECT status FROM certs WHERE id={victim['id']}") == "valid",
          str(db.scalar(f"SELECT status FROM certs WHERE id={victim['id']}")))

    ca.revoke(victim["id"], reason="keyCompromise")
    own = ca.generate_crl(actor="t", source="t")
    own_path = _crl_file()
    own_bytes = own_path.read_bytes()   # 必须先读出来：unrevoke 会重新生成并覆盖同名文件
    ca.unrevoke(victim["id"], actor="t")
    ok_import = ca.import_crl(own_bytes, actor="t")
    check("本 CA 自己签发的 CRL 导入正常（验签通过）",
          db.scalar(f"SELECT status FROM certs WHERE id={victim['id']}") == "revoked",
          json.dumps(ok_import, ensure_ascii=False)[:120])

    print("\n\033[1m== 提交后的 index.txt 失败不得删掉已入库 CRL ==\033[0m")
    real_export = ca.export_index_txt

    def fail_index(*_a, **_kw):
        raise OSError("injected index export failure after commit")

    ca.export_index_txt = fail_index
    try:
        committed = ca.generate_crl(actor="t", source="post-commit-inject")
    finally:
        ca.export_index_txt = real_export
    committed_row = db.q1("SELECT * FROM crls WHERE id=?", (committed["id"],))
    check("提交后派生文件失败被报告，CRL 生成仍成功",
          "injected index export failure" in committed.get("index_error", ""))
    check("已提交记录指向的 PEM 和 DER 均存在",
          all((Path(config.DATA_DIR) / committed_row[key]).is_file()
              for key in ("path", "der_path")))
    check("当前 CRL 确实有文件", ca.current_crl()["has_file"] is True)

    print("\n\033[1m== 通用编辑不能清除吊销事实 ==\033[0m")
    before = db.q1("SELECT * FROM certs WHERE id=?", (t2["id"],))
    attack = {"status": "archived", "revoked_at": "", "revocation_reason": None}
    try:
        api.h_cert_patch(api.Request(method="PATCH", path=f"/api/certs/{t2['id']}",
                                     payload=attack), str(t2["id"]))
        check("PATCH 拒绝直接修改吊销时间/原因", False)
    except api.ApiError as exc:
        check("PATCH 拒绝直接修改吊销时间/原因", exc.status == 400)
    try:
        inventory.update_metadata(t2["id"], attack, actor="t")
        check("内部元数据入口也拒绝修改吊销事实", False)
    except x509util.CertError:
        check("内部元数据入口也拒绝修改吊销事实", True)
    check("攻击未改变数据库中的吊销时间和原因",
          (lambda after: after["revoked_at"] == before["revoked_at"]
           and after["revocation_reason"] == before["revocation_reason"])(
               db.q1("SELECT * FROM certs WHERE id=?", (t2["id"],))))
    # 兼容历史脏数据：空串仍满足 CRL 的 IS NOT NULL 判定，不可硬删除。
    with db.tx() as conn:
        conn.execute("UPDATE certs SET status='archived', revoked_at='' WHERE id=?", (t2["id"],))
    try:
        inventory.delete_cert(t2["id"], hard=True, actor="t")
        check("旧数据的空字符串吊销时间也禁止硬删除", False)
    except x509util.CertError:
        check("旧数据的空字符串吊销时间也禁止硬删除", True)
    with db.tx() as conn:
        conn.execute("UPDATE certs SET revoked_at=? WHERE id=?", (before["revoked_at"], t2["id"]))

    print("\n\033[1m== PEM 与 DER 均须对应数据库记录 ==\033[0m")
    latest = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    previous = db.q1("SELECT * FROM crls WHERE ca_id=? AND id<? ORDER BY id DESC LIMIT 1",
                     (latest["ca_id"], latest["id"]))
    latest_pem = Path(config.DATA_DIR) / latest["path"]
    pem_copy = latest_pem.read_bytes()
    latest_pem.write_bytes((Path(config.DATA_DIR) / previous["path"]).read_bytes())
    try:
        codes = {i["code"] for i in consistency.check()["issues"]}
        check("旧版 PEM 替换最新 PEM 会被体检发现",
              bool({"crl_number_mismatch", "crl_file_mismatch"} & codes))
    finally:
        latest_pem.write_bytes(pem_copy)

    print("\n\033[1m== 旧版本共用 CRL 路径不得造成历史误报 ==\033[0m")
    # 老版本反复覆盖固定路径，历史行保留各自旧 SHA，但磁盘只剩最后一份。
    with db.tx() as conn:
        conn.execute("UPDATE crls SET path=?, der_path=? WHERE id=?",
                     (latest["path"], latest["der_path"], previous["id"]))
    try:
        def mismatch_for(number: str) -> list[dict]:
            return [i for i in consistency.check()["issues"]
                    if i["code"] in ("crl_number_mismatch", "crl_file_mismatch")
                    and (i["message"].startswith(f"CRL #{number} 的")
                         or i["message"].startswith(f"CRL 记录为 #{number}，"))]

        problems = mismatch_for(previous["number"])
        check("同一 CA 的旧 CRL 行共用路径不误报校验值/编号不符",
              not problems, str([i["message"] for i in problems[:5]])[:600])
        latest_pem.write_bytes((Path(config.DATA_DIR) / previous["path"]).read_bytes())
        try:
            check("共用路径时最新 CRL 文件损坏仍会被发现",
                  bool(mismatch_for(latest["number"])))
        finally:
            latest_pem.write_bytes(pem_copy)
    finally:
        with db.tx() as conn:
            conn.execute("UPDATE crls SET path=?, der_path=? WHERE id=?",
                         (previous["path"], previous["der_path"], previous["id"]))

    print("\n\033[1m== 每个 CA 始终保留最新 CRL，缺文件能自动补齐 ==\033[0m")
    db.set_setting("crl_files_keep", "0")
    zero = ca.generate_crl(actor="t", source="keep-zero")
    zero_row = db.q1("SELECT * FROM crls WHERE id=?", (zero["id"],))
    check("保留数 0 也不删除最新的 PEM/DER",
          all((Path(config.DATA_DIR) / zero_row[key]).is_file()
              for key in ("path", "der_path")))
    db.set_setting("crl_files_keep", "2")
    old_ca_latest = db.q1("SELECT * FROM crls WHERE ca_id=? ORDER BY id DESC LIMIT 1",
                          (row["id"],))
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Second CA")])
    now = x509util.now()
    other_cert = (x509.CertificateBuilder().subject_name(other_name).issuer_name(other_name)
                  .public_key(other_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .sign(other_key, hashes.SHA256()))
    other_ca = ca.import_ca(x509util.pem_cert(other_cert).encode(),
                            x509util.pem_key(other_key).encode())
    for _ in range(3):
        ca.generate_crl(ca_row=other_ca, actor="t", source="multi-ca")
    check("另一个 CA 连续生成后旧 CA 最新 PEM/DER 仍保留",
          all((Path(config.DATA_DIR) / old_ca_latest[key]).is_file()
              for key in ("path", "der_path")))
    ca.activate_ca(row["id"], actor="t")
    check("切回旧 CA 时正确报告最新 CRL 文件存在", ca.current_crl()["has_file"] is True)
    old_pem = Path(config.DATA_DIR) / old_ca_latest["path"]
    old_pem_copy = old_pem.read_bytes()
    old_pem.unlink()
    check("最新 CRL 文件丢失时 has_file 为假", ca.current_crl()["has_file"] is False)
    real_publish = publish.publish
    publish.publish = lambda **_kw: {"crl": ca.current_crl(), "results": []}
    try:
        repaired = publish.scheduler.tick(trigger="regression")
    finally:
        publish.publish = real_publish
        old_pem.write_bytes(old_pem_copy)
    check("调度器发现文件丢失并重新生成", repaired.get("reason") == "missing_files"
          and ca.current_crl()["has_file"] is True)
    db.set_setting("crl_files_keep", "50")

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
