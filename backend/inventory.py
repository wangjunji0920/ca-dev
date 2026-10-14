"""数据导入 / 导出 / 编辑 / 续期。

支持的数据来源（“方便导入各种数据”）：
* 单个 PEM / DER / CRT / CER 证书（含多证书拼接的链文件）
* ZIP 压缩包（批量导入）
* PKCS#12 (.p12/.pfx)：证书 + 私钥一起导入
* 单独的私钥文件：会按公钥指纹自动匹配到同批次导入的证书
* 外部 CRL（见 ``ca.import_crl``）
* CSV 元数据：按序列号/指纹批量修改已有记录（所有者、标签、备注、用途、归档状态）

一致性要点：
* 指纹唯一索引 + 批次内去重，重复导入不会产生脏数据，只会报告“已跳过”。
* 导入的证书如果签发者等于当前 CA，会自动挂到该 CA 下；否则 ca_id 为空但仍可管理。
* 预检(dry_run) 与正式导入走完全相同的解析路径，预检看到什么，导入就做什么。
"""
from __future__ import annotations

import csv
import hashlib
import io
import zipfile
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import audit, ca, config, db, x509util
from .x509util import CertError

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_ZIP_MEMBERS = 2000


# ------------------------------------------------------------------ 工具
def spki_fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _norm_tags(tags) -> list[str]:
    if tags is None:
        return []
    if isinstance(tags, str):
        parts = [t.strip() for t in tags.replace("，", ",").split(",")]
    else:
        parts = [str(t).strip() for t in tags]
    out, seen = [], set()
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _expand(files: Iterable[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """把 zip 展开成 (虚拟文件名, 内容) 列表。"""
    out: list[tuple[str, bytes]] = []
    for name, blob in files:
        if len(blob) > MAX_FILE_BYTES:
            out.append((name, blob[:0]))  # 占位，稍后报错
            continue
        if zipfile.is_zipfile(io.BytesIO(blob)):
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    for info in zf.infolist()[:MAX_ZIP_MEMBERS]:
                        if info.is_dir():
                            continue
                        out.append((f"{name}!{info.filename}", zf.read(info)))
            except zipfile.BadZipFile as exc:
                raise CertError(f"{name}: 无法解压 ZIP ({exc})") from exc
        else:
            out.append((name, blob))
    return out


# ------------------------------------------------------------------ 批量导入
def import_bundle(files: list[tuple[str, bytes]], *, dry_run: bool = True,
                  mark_revoked: bool = False, revoke_reason: str = "unspecified",
                  owner: str | None = None, tags: list[str] | None = None,
                  profile: str | None = None, password: str | None = None,
                  notes: str | None = None, actor: str = "admin") -> dict:
    ca_row = ca.active_ca_row()
    ca_subject = ca_row["subject"] if ca_row else None
    tags = _norm_tags(tags)

    expanded = _expand(files)
    cert_items: list[dict] = []       # {name, cert, key}
    key_items: list[tuple[str, Any]] = []
    errors: list[dict] = []

    for name, blob in expanded:
        if not blob:
            errors.append({"name": name, "error": "文件为空或超过 20MB 限制"})
            continue
        handled = False
        # 1) PKCS#12
        try:
            key, cert, extra = x509util.read_pkcs12(blob, password)
            if cert is not None:
                cert_items.append({"name": name, "cert": cert, "key": key,
                                   "extra": extra or []})
                handled = True
        except Exception:  # noqa: BLE001 - 不是 p12 就继续尝试其它格式
            pass
        if handled:
            continue
        # 2) 纯私钥
        try:
            k = x509util.load_key(blob, password)
            key_items.append((name, k))
            continue
        except Exception:  # noqa: BLE001
            pass
        # 3) CSR（不做导入，只提示）
        try:
            csr = x509util.load_csr(blob)
            errors.append({"name": name, "error": "这是 CSR（证书请求），不是证书；"
                                                  "请用「CSR 证书请求」页批量导入并签发",
                           "cn": x509util.get_name(
                               csr.subject,
                               __import__("cryptography.x509.oid", fromlist=["x"])
                               .NameOID.COMMON_NAME)})
            continue
        except Exception:  # noqa: BLE001
            pass
        # 4) 证书（可能是一个链）
        certs = x509util.load_certs(blob)
        if certs:
            for i, c in enumerate(certs):
                cert_items.append({"name": name if len(certs) == 1 else f"{name}#{i + 1}",
                                   "cert": c, "key": None, "extra": []})
            continue
        errors.append({"name": name, "error": "无法识别文件内容（支持证书/私钥/PKCS#12/ZIP）"})

    # 私钥按公钥指纹匹配到证书
    key_by_fp = {spki_fingerprint(k.public_key()): k for _n, k in key_items}
    used_keys: set[str] = set()

    preview: list[dict] = []
    now = x509util.now()
    for item in cert_items:
        cert: x509.Certificate = item["cert"]
        info = x509util.cert_to_dict(cert)
        fp = info["fingerprint_sha256"]
        key = item.get("key")
        if key is None:
            match_fp = spki_fingerprint(cert.public_key())
            if match_fp in key_by_fp:
                key = key_by_fp[match_fp]
                used_keys.add(match_fp)
        exists = db.q1("SELECT id,status FROM certs WHERE fingerprint=?", (fp,))
        belongs = bool(ca_subject) and info["issuer"] == ca_subject
        expired = (x509util.parse_iso(info["not_after"]) or now) < now
        status = "revoked" if mark_revoked else ("expired" if expired else "valid")
        preview.append({
            "name": item["name"],
            "cn": info["cn"],
            "subject": info["subject"],
            "serial_hex": info["serial_hex"],
            "issuer": info["issuer"],
            "not_before": info["not_before"],
            "not_after": info["not_after"],
            "fingerprint_sha256": fp,
            "is_ca": info["is_ca"],
            "belongs_to_ca": belongs,
            "expired": expired,
            "duplicate": bool(exists),
            "duplicate_id": exists["id"] if exists else None,
            "has_key": key is not None,
            "status": status if not exists else exists["status"],
            "will_import": (not exists) and (not info["is_ca"]),
            "skip_reason": ("数据库中已存在（指纹重复）" if exists else
                            "这是 CA 证书，请在「CA 管理」中导入" if info["is_ca"] else None),
            "_cert": cert, "_key": key,
        })

    if dry_run:
        return {"preview": [{k: v for k, v in p.items() if not k.startswith("_")}
                            for p in preview],
                "imported": [], "skipped": [], "errors": errors}

    imported, skipped = [], []
    for p in preview:
        if not p["will_import"]:
            skipped.append({"name": p["name"], "cn": p["cn"], "serial_hex": p["serial_hex"],
                            "reason": p["skip_reason"]})
            continue
        ca_link = ca_row if p["belongs_to_ca"] else None
        revoked_at = x509util.to_iso(now) if mark_revoked else None
        try:
            res = ca.store_certificate(
                p["_cert"], key=p["_key"], ca_row=ca_link, profile=profile, owner=owner,
                tags=tags, notes=notes, source="imported", actor=actor,
                status_hint="revoked" if mark_revoked else None,
                revoked_at=revoked_at,
                revocation_reason=revoke_reason if mark_revoked else None)
            imported.append({"name": p["name"], **res["cert"]})
        except Exception as exc:  # noqa: BLE001 - 单条失败不影响其余
            errors.append({"name": p["name"], "error": f"{type(exc).__name__}: {exc}"})

    unmatched_keys = [{"name": n} for n, k in key_items
                      if spki_fingerprint(k.public_key()) not in used_keys]
    result = {"preview": [], "imported": imported, "skipped": skipped, "errors": errors,
              "unmatched_keys": unmatched_keys, "dry_run": False,
              "mark_revoked": mark_revoked}
    # 导入改变了吊销状态 -> 立刻刷新并发布 CRL（API/CLI 行为一致）
    if mark_revoked or any(i.get("status") == "revoked" for i in imported):
        result.update(ca.refresh_crl_and_publish(actor=actor, source="import"))
    return result


def import_directory(path: str, *, dry_run: bool = True, mark_revoked: bool = False,
                     revoke_reason: str = "unspecified", owner: str | None = None,
                     tags: list[str] | None = None, recursive: bool = True,
                     actor: str = "admin") -> dict:
    """从服务器本地目录导入（方便把历史证书一次性收编）。"""
    root = ca._path(path) if not str(path).startswith("/") else None
    from pathlib import Path
    base = Path(path).expanduser().resolve() if str(path).startswith("/") else root
    if base is None or not base.exists():
        raise CertError(f"路径不存在: {path}")
    if base.is_file():
        candidates = [base]
    else:
        pattern = "**/*" if recursive else "*"
        candidates = [p for p in base.glob(pattern) if p.is_file()]
    allowed = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".zip", ".csr", ".req"}
    files: list[tuple[str, bytes]] = []
    for p in sorted(candidates):
        if p.suffix.lower() not in allowed:
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            files.append((str(p), p.read_bytes()))
        except OSError:
            continue
    if not files:
        raise CertError(f"该路径下没有可导入的证书文件（支持 "
                        f"{', '.join(sorted(allowed))}）: {base}")
    # 目录里混有 CSR 时自动分流到 CSR 池，避免整目录导入时报错
    csr_files = [f for f in files if f[0].lower().endswith((".csr", ".req", ".p10"))]
    cert_files = [f for f in files if f not in csr_files]
    result = import_bundle(cert_files, dry_run=dry_run, mark_revoked=mark_revoked,
                           revoke_reason=revoke_reason, owner=owner, tags=tags, actor=actor)         if cert_files else {"preview": [], "imported": [], "skipped": [], "errors": [],
                            "dry_run": dry_run}
    if csr_files:
        from . import csrs as csrs_mod
        result["csr_result"] = csrs_mod.import_csrs(csr_files, dry_run=dry_run, owner=owner,
                                                   tags=tags, actor=actor)
    result["scanned_dir"] = str(base)
    result["scanned_files"] = len(files)
    return result


# ------------------------------------------------------------------ CSV 元数据
CSV_FIELDS = ["serial_hex", "fingerprint", "cn", "owner", "tags", "notes", "profile",
              "status", "revocation_reason", "revoked_at"]


def import_csv(text: str, *, dry_run: bool = True, actor: str = "admin") -> dict:
    """按序列号或指纹批量修改元数据；吊销状态只能通过专用操作改变。"""
    # Excel「另存为 CSV」默认带 UTF-8 BOM；不去掉会把首列名变成 "\ufeffserial_hex"，
    # 于是报"必须包含 serial_hex 列"这种让人摸不着头脑的错误。
    if text and text[0] == "\ufeff":
        text = text[1:]
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise CertError("CSV 缺少表头")
    fields = {f.strip().lower() for f in reader.fieldnames}
    if not ({"serial_hex", "fingerprint"} & fields):
        raise CertError("CSV 必须包含 serial_hex 或 fingerprint 列以定位证书")

    preview, applied, errors = [], [], []
    for lineno, row in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        serial = row.get("serial_hex", "").replace(":", "").strip().upper()
        fp = row.get("fingerprint", "").upper()
        target = None
        if serial:
            target = db.q1("SELECT * FROM certs WHERE UPPER(serial_hex)=?", (serial,))
        if target is None and fp:
            target = db.q1("SELECT * FROM certs WHERE UPPER(fingerprint)=?", (fp,))
        if target is None:
            errors.append({"row": lineno, "error": f"找不到证书（serial={serial or '-'} "
                                                   f"fingerprint={fp or '-'}）"})
            continue
        changes: dict[str, Any] = {}
        for key in ("cn", "owner", "notes", "profile"):
            if row.get(key):
                changes[key] = row[key]
        if row.get("tags"):
            changes["tags"] = _norm_tags(row["tags"])
        status = (row.get("status") or "").lower()
        if status:
            if status not in ("valid", "revoked", "archived", "expired"):
                errors.append({"row": lineno, "error": f"状态取值非法: {status}"})
                continue
            changes["status"] = status
            if status == "revoked":
                # 同上：CSV 不能用来吊销（否则 CRL 不会刷新）
                errors.append({"row": lineno,
                               "error": "CSV 不能把证书改成 revoked：吊销会改变 CRL，"
                                        "请用「吊销」/ cli revoke --serial <序列号>"})
                continue
            elif status == "valid" and (target["revoked_at"] is not None
                                         or target["status"] == "revoked"):
                # CSV 里把状态写成 valid ≠ 恢复吊销：那会抹掉吊销事实（证书从 CRL 消失）。
                # 恢复必须走专用操作（恢复吊销 / cli unrevoke），它会重新生成并发布 CRL。
                errors.append({"row": lineno,
                               "error": "该证书已被吊销：CSV 不能直接改成 valid，"
                                        "请改用「恢复吊销」/ cli unrevoke"})
                continue
            # 归档/过期都不清吊销事实（由 update_metadata 保证只改 status）
        if not changes:
            errors.append({"row": lineno, "error": "该行没有任何可更新的字段"})
            continue
        preview.append({"row": lineno, "id": target["id"], "cn": target["cn"],
                        "serial_hex": target["serial_hex"], "changes": changes})
        if not dry_run:
            try:
                update_metadata(target["id"], changes, actor=actor, action="cert.csv_update")
                applied.append({"row": lineno, "id": target["id"], "changes": changes})
            except Exception as exc:  # noqa: BLE001
                errors.append({"row": lineno, "error": f"{type(exc).__name__}: {exc}"})

    if not dry_run and applied:
        changed_revocation = any("status" in (p["changes"] or {}) for p in preview)
        if changed_revocation:
            ca.refresh_crl_and_publish(actor=actor, source="csv_update")
    return {"preview": preview, "applied": applied, "errors": errors, "dry_run": dry_run}


# ------------------------------------------------------------------ 编辑
EDITABLE = ("cn", "owner", "notes", "profile")


def update_metadata(cert_id: int, changes: dict, *, actor: str = "admin",
                    action: str = "cert.update") -> dict:
    if "revoked_at" in changes or "revocation_reason" in changes:
        raise CertError("吊销时间和原因只能通过专用吊销或恢复吊销操作修改")
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM certs WHERE id=?", (cert_id,)).fetchone()
        if row is None:
            raise CertError("证书不存在")
        sets, args, before, after = [], [], {}, {}
        for key in EDITABLE:
            if key in changes and changes[key] is not None:
                sets.append(f"{key}=?")
                args.append(str(changes[key]))
                before[key], after[key] = row[key], str(changes[key])
        if "tags" in changes and changes["tags"] is not None:
            sets.append("tags_json=?")
            args.append(db.json.dumps(_norm_tags(changes["tags"]), ensure_ascii=False))
            before["tags"] = db.json_load(row["tags_json"], [])
            after["tags"] = _norm_tags(changes["tags"])
        if "status" in changes and changes["status"] is not None:
            status = str(changes["status"])
            if status not in ("valid", "revoked", "expired", "archived"):
                raise CertError(f"状态取值非法: {status}")
            has_fact = row["revoked_at"] is not None or row["status"] == "revoked"
            if status == "revoked" and not has_fact:
                raise CertError(
                    "吊销必须使用专用功能（会重新生成并发布 CRL）："
                    "界面「吊销」/ cli revoke，不要用通用更新改 status")
            if status == "valid" and has_fact:
                raise CertError(
                    f"该证书存在吊销事实（revoked_at={row['revoked_at'] or 'status=revoked'}），"
                    f"不能用通用更新改成 valid：请使用「恢复吊销」/ cli unrevoke（会重新生成并发布 CRL）")
            sets.append("status=?")
            args.append(status)
            before["status"], after["status"] = row["status"], status
        if not sets:
            raise CertError("没有提供任何可修改的字段")
        sets.append("updated_at=?")
        args += [x509util.to_iso(x509util.now()), cert_id]
        conn.execute(f"UPDATE certs SET {', '.join(sets)} WHERE id=?", args)
        audit.log(action, target_type="cert", target_id=cert_id,
                  target_label=row["cn"] or row["subject"], actor=actor,
                  detail={"before": before, "after": after}, conn=conn)
    return ca.get_cert(cert_id)


def delete_cert(cert_id: int, *, hard: bool = False, actor: str = "admin") -> dict:
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM certs WHERE id=?", (cert_id,)).fetchone()
        if row is None:
            raise CertError("证书不存在")
        # 与 CRL 查询使用相同的吊销事实判定，连旧数据中的空字符串也不能绕过。
        revoked_fact = row["revoked_at"] is not None or row["status"] == "revoked"
        if hard and revoked_fact:
            raise CertError(
                f"证书 {row['cn'] or row['subject']}（serial {row['serial_hex']}）已被吊销，"
                f"不允许硬删除：删除后它不会再出现在 CRL 中，等于让吊销失效。"
                f"如只是不想在列表里看到它，请用软删除（归档）——吊销事实仍会保留在 CRL 里。")
        if hard:
            conn.execute("DELETE FROM certs WHERE id=?", (cert_id,))
        else:
            conn.execute("UPDATE certs SET status='archived', updated_at=? WHERE id=?",
                         (x509util.to_iso(x509util.now()), cert_id))
        audit.log("cert.delete" if hard else "cert.archive", target_type="cert", target_id=cert_id,
                  target_label=row["cn"] or row["subject"], actor=actor,
                  detail={"hard": hard, "serial": row["serial_hex"],
                          "revoked_fact": revoked_fact,
                          "still_in_crl": revoked_fact}, conn=conn)
    if hard:
        for rel in (row["cert_path"], row["key_path"]):
            if rel:
                try:
                    (config.DATA_DIR / rel).unlink()
                except OSError:
                    pass
    return {"ok": True, "id": cert_id, "hard": hard}


# ------------------------------------------------------------------ 续期
def renew(cert_id: int, validity_days: int | None = None, actor: str = "admin") -> dict:
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    if row is None:
        raise CertError("证书不存在")
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA")
    if row["ca_id"] and row["ca_id"] != ca_row["id"]:
        raise CertError("该证书不是由当前活动 CA 签发的，无法续期")
    try:
        old = x509util.load_cert((config.DATA_DIR / row["cert_path"]).read_bytes())
    except OSError as exc:
        raise CertError(f"原证书文件不可读: {exc}") from exc

    from cryptography.x509.oid import NameOID
    result = ca.issue_certificate(
        ca_row=ca_row,
        cn=x509util.get_name(old.subject, NameOID.COMMON_NAME),
        o=x509util.get_name(old.subject, NameOID.ORGANIZATION_NAME),
        ou=x509util.get_name(old.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        c=x509util.get_name(old.subject, NameOID.COUNTRY_NAME),
        st=x509util.get_name(old.subject, NameOID.STATE_OR_PROVINCE_NAME),
        l=x509util.get_name(old.subject, NameOID.LOCALITY_NAME),
        sans=db.json_load(row["sans_json"], []),
        validity_days=validity_days or db.get_setting("default_validity_days", "365"),
        key_type=row["key_type"] or "rsa", key_size=row["key_size"] or 2048,
        key_usage=db.json_load(row["key_usage_json"], []),
        eku=db.json_load(row["eku_json"], []),
        profile=row["profile"], owner=row["owner"],
        tags=db.json_load(row["tags_json"], []),
        notes=f"由证书 #{cert_id} 续期生成", source="renewed", actor=actor)

    new_id = result["id"]
    ts = x509util.to_iso(x509util.now())
    with db.tx() as conn:
        conn.execute("UPDATE certs SET replaces_id=? WHERE id=?", (cert_id, new_id))
        conn.execute("UPDATE certs SET replaced_by_id=?, updated_at=? WHERE id=?",
                     (new_id, ts, cert_id))
        audit.log("cert.renew", target_type="cert", target_id=new_id,
                  target_label=result["cert"]["cn"], actor=actor,
                  detail={"replaces": cert_id, "old_serial": row["serial_hex"],
                          "new_serial": result["cert"]["serial_hex"]}, conn=conn)
    # 重新读取，保证返回的证书对象包含刚写入的替换关系（否则响应里是旧快照）
    result["cert"] = ca.get_cert(new_id)
    result["replaces_id"] = cert_id
    ca.refresh_crl_and_publish(actor=actor, source="renew")
    try:
        from . import automation
        automation.fire("cert.renewed", {
            "cert_id": new_id, "profile": row["profile"],
            "summary": f"续期 {result['cert']['cn']}（原证书 #{cert_id}）"}, actor=actor)
    except Exception:  # noqa: BLE001
        pass
    return result


# ------------------------------------------------------------------ 导出
def export_rows() -> list[dict]:
    rows = db.q("SELECT * FROM certs ORDER BY id")
    out = []
    for r in rows:
        d = ca.cert_to_dict(r)
        d["tags"] = ",".join(d["tags"] or [])
        d["sans"] = "; ".join(f"{s['type']}={s['value']}" for s in (d["sans"] or []))
        d["key_usage"] = ",".join(d["key_usage"] or [])
        d["eku"] = ",".join(d["eku"] or [])
        out.append(d)
    return out


def export_csv() -> str:
    cols = ["id", "serial_hex", "serial_dec", "status", "cn", "subject", "issuer",
            "not_before", "not_after", "days_remaining", "revoked_at", "revocation_reason",
            "profile", "key_type", "key_size", "signature_algorithm", "sans", "key_usage",
            "eku", "owner", "tags", "notes", "fingerprint_sha256", "has_key", "source"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for row in export_rows():
        writer.writerow(row)
    return buf.getvalue()


def import_csv_template() -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_FIELDS)
    writer.writerow(["53D23121E4AA0882EB4843D1B662A30854312FC0", "", "test", "张三",
                     "vpn,研发", "用于 VPN 登录", "vpn_client", "revoked", "keyCompromise",
                     "2026-10-12T12:00:10+00:00"])
    return buf.getvalue()
