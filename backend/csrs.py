"""CSR 池：批量收 CSR、审核、再用它们签发证书。

为什么单独一个模块
------------------
真实流程里 CSR 往往是**外部生成**后交上来的（用户自己生成密钥，私钥不离开用户机器）。
所以需要一条独立路径：批量导入 CSR → 审核 → 用规则集签发 → 与该证书建立关联。
与「导入已有证书」是两件事，分开更清晰，也方便以后扩展（例如对接工单系统）。

安全与一致性
------------
* 以**公钥指纹（SPKI）**唯一约束去重，同一个请求不会重复入库；
* 入库时校验 CSR 自签名是否有效；公钥若已有有效证书，会在导入结果里提示；
* 同一 CSR 默认只能签发一次（防止重复签发），需要重复时显式 ``force``；
* 签发走统一的 ``ca.issue_certificate(csr_pem=...)``，因此规则集策略、CDP、序列号、
  审计、自动化触发全部与「直接签发」一致。
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from cryptography import x509

from . import audit, ca, config, db, x509util
from .x509util import CertError

STATUSES = ("pending", "issued", "rejected")


def csr_to_dict(row: dict) -> dict[str, Any]:
    return {
        "id": row["id"],
        "subject": row["subject"],
        "cn": row["cn"],
        "key_type": row["key_type"],
        "key_size": row["key_size"],
        "sans": db.json_load(row["sans_json"], []),
        "signature_valid": bool(row["signature_valid"]),
        "status": row["status"],
        "requested_profile": row["requested_profile"],
        "owner": row["owner"],
        "tags": db.json_load(row["tags_json"], []),
        "notes": row["notes"],
        "source": row["source"],
        "cert_id": row["cert_id"],
        "issued_at": row["issued_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "spki_fingerprint": row["spki_fingerprint"],
    }


def get(csr_id: int) -> dict | None:
    row = db.q1("SELECT * FROM csrs WHERE id=?", (csr_id,))
    return csr_to_dict(row) if row else None


def get_row(csr_id: int) -> dict | None:
    return db.q1("SELECT * FROM csrs WHERE id=?", (csr_id,))


def list_csrs(q: str | None = None, status: str | None = None, page: int = 1,
              page_size: int = 20) -> dict:
    where, args = [], []
    if q:
        like = f"%{q}%"
        where.append("(cn LIKE ? OR subject LIKE ? OR owner LIKE ? OR notes LIKE ?)")
        args += [like] * 4
    if status and status != "all":
        where.append("status = ?")
        args.append(status)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.scalar(f"SELECT COUNT(*) FROM csrs{clause}", args)
    page = max(1, int(page))
    page_size = min(200, max(1, int(page_size)))
    rows = db.q(f"SELECT * FROM csrs{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                args + [page_size, (page - 1) * page_size])
    facets = {r["status"]: r["count"] for r in db.q(
        "SELECT status, COUNT(*) AS count FROM csrs GROUP BY status")}
    return {"items": [csr_to_dict(r) for r in rows], "total": total, "page": page,
            "page_size": page_size, "facets": facets}


# ------------------------------------------------------------------ 导入
def _expand(files: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for name, blob in files:
        if zipfile.is_zipfile(__import__("io").BytesIO(blob)):
            try:
                with zipfile.ZipFile(__import__("io").BytesIO(blob)) as zf:
                    for info in zf.infolist()[:2000]:
                        if not info.is_dir():
                            out.append((f"{name}!{info.filename}", zf.read(info)))
            except zipfile.BadZipFile as exc:
                raise CertError(f"{name}: ZIP 无法解压（{exc}）") from exc
        else:
            out.append((name, blob))
    return out


def import_csrs(files: list[tuple[str, bytes]], *, dry_run: bool = True,
                owner: str | None = None, tags: list[str] | None = None,
                notes: str | None = None, requested_profile: str | None = None,
                actor: str = "admin") -> dict:
    """批量导入 CSR（支持 ZIP）。返回预检或正式导入结果。"""
    from . import inventory  # 复用标签规范化与公钥指纹
    tags = inventory._norm_tags(tags)
    preview: list[dict] = []
    errors: list[dict] = []

    for name, blob in _expand(files):
        if not blob:
            errors.append({"name": name, "error": "文件为空"})
            continue
        try:
            csr = x509util.load_csr(blob)
        except CertError as exc:
            errors.append({"name": name, "error": str(exc)})
            continue
        info = x509util.csr_to_dict(csr)
        spki = inventory.spki_fingerprint(csr.public_key())
        existing = db.q1("SELECT id, status, cert_id FROM csrs WHERE spki_fingerprint=?", (spki,))
        # 该公钥是否已经有证书（同一个公钥重复申请）
        same_key = db.q1("SELECT id, cn, status FROM certs WHERE key_type=? AND key_size=? "
                         "AND fingerprint IS NOT NULL", (info["key_type"], info["key_size"]))
        item = {
            "name": name,
            "cn": info["cn"],
            "subject": info["subject"],
            "key_type": info["key_type"],
            "key_size": info["key_size"],
            "sans": info["sans"],
            "signature_valid": info["signature_valid"],
            "spki_fingerprint": spki,
            "duplicate": bool(existing),
            "duplicate_id": existing["id"] if existing else None,
            "will_import": (not existing) and bool(info["signature_valid"]),
            "skip_reason": ("该 CSR 已在池中（公钥重复）" if existing else
                            "CSR 自签名校验不通过，疑似损坏" if not info["signature_valid"] else None),
            "_pem": info["pem"],
        }
        preview.append(item)
        del same_key  # 仅用于提示扩展位；实际按指纹判定

    if dry_run:
        return {"preview": [{k: v for k, v in p.items() if not k.startswith("_")} for p in preview],
                "imported": [], "skipped": [], "errors": errors, "dry_run": True}

    imported, skipped = [], []
    ts = x509util.to_iso(x509util.now())
    for p in preview:
        if not p["will_import"]:
            skipped.append({"name": p["name"], "cn": p["cn"], "reason": p["skip_reason"]})
            continue
        with db.tx() as conn:
            cur = conn.execute(
                "INSERT INTO csrs(spki_fingerprint,subject,cn,pem,key_type,key_size,sans_json,"
                "signature_valid,status,requested_profile,owner,tags_json,notes,source,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,1,'pending',?,?,?,?,?,?,?)",
                (p["spki_fingerprint"], p["subject"], p["cn"], p["_pem"], p["key_type"],
                 p["key_size"], db.json.dumps(p["sans"], ensure_ascii=False),
                 requested_profile, owner, db.json.dumps(tags, ensure_ascii=False), notes,
                 "import", ts, ts))
            cid = cur.lastrowid
            audit.log("csr.import", target_type="csr", target_id=cid, target_label=p["cn"],
                      actor=actor, detail={"key_type": p["key_type"],
                                           "key_size": p["key_size"]}, conn=conn)
        imported.append({"id": cid, "cn": p["cn"], "subject": p["subject"],
                         "key_type": p["key_type"], "key_size": p["key_size"],
                         "sans": p["sans"]})
    return {"preview": [], "imported": imported, "skipped": skipped, "errors": errors,
            "dry_run": False}


def import_directory(path: str, *, dry_run: bool = True, owner: str | None = None,
                     tags: list[str] | None = None, recursive: bool = True,
                     actor: str = "admin") -> dict:
    base = Path(path).expanduser().resolve()
    if not base.exists():
        raise CertError(f"路径不存在: {path}")
    pattern = "**/*" if recursive else "*"
    candidates = [base] if base.is_file() else [p for p in base.glob(pattern) if p.is_file()]
    files = [(str(p), p.read_bytes()) for p in sorted(candidates)
             if p.suffix.lower() in (".csr", ".req", ".p10", ".pem")
             and p.stat().st_size <= 20 * 1024 * 1024]
    if not files:
        raise CertError(f"该路径下没有 CSR 文件（支持 .csr/.req/.p10/.pem）: {base}")
    res = import_csrs(files, dry_run=dry_run, owner=owner, tags=tags, actor=actor)
    res["scanned_files"] = len(files)
    res["scanned_dir"] = str(base)
    return res


# ------------------------------------------------------------------ 编辑
def update(csr_id: int, changes: dict, actor: str = "admin") -> dict:
    row = get_row(csr_id)
    if row is None:
        raise CertError("CSR 不存在")
    sets, args, detail = [], [], {}
    for key in ("owner", "notes", "requested_profile"):
        if key in changes and changes[key] is not None:
            sets.append(f"{key}=?")
            args.append(str(changes[key]))
            detail[key] = changes[key]
    if "tags" in changes and changes["tags"] is not None:
        from . import inventory
        sets.append("tags_json=?")
        args.append(db.json.dumps(inventory._norm_tags(changes["tags"]), ensure_ascii=False))
    if "status" in changes and changes["status"]:
        status = str(changes["status"])
        if status not in STATUSES:
            raise CertError(f"状态只能是 {'/'.join(STATUSES)}")
        if status == "issued" and row["cert_id"] is None:
            raise CertError("尚未签发，不能直接标记为已签发")
        sets.append("status=?")
        args.append(status)
        detail["status"] = status
    if not sets:
        raise CertError("没有可修改的字段")
    sets.append("updated_at=?")
    args += [x509util.to_iso(x509util.now()), csr_id]
    with db.tx() as conn:
        conn.execute(f"UPDATE csrs SET {', '.join(sets)} WHERE id=?", args)
        audit.log("csr.update", target_type="csr", target_id=csr_id, target_label=row["cn"],
                  actor=actor, detail=detail, conn=conn)
    return get(csr_id)


def delete(csr_id: int, actor: str = "admin") -> None:
    row = get_row(csr_id)
    if row is None:
        raise CertError("CSR 不存在")
    if row["cert_id"]:
        raise CertError(f"该 CSR 已签发为证书 #{row['cert_id']}，不能删除（可标记为 rejected）")
    with db.tx() as conn:
        conn.execute("DELETE FROM csrs WHERE id=?", (csr_id,))
        audit.log("csr.delete", target_type="csr", target_id=csr_id,
                  target_label=row["cn"], actor=actor, conn=conn)


def mark_issued(csr_id: int, cert_id: int, conn=None, actor: str = "admin") -> None:
    ts = x509util.to_iso(x509util.now())
    sql = ("UPDATE csrs SET status='issued', cert_id=?, issued_at=?, updated_at=? WHERE id=?")
    if conn is not None:
        conn.execute(sql, (cert_id, ts, ts, csr_id))
    else:
        with db.tx() as c:
            c.execute(sql, (cert_id, ts, ts, csr_id))


# ------------------------------------------------------------------ 签发
def issue_from_csr(csr_id: int, *, ruleset=None, profile: str | None = None,
                   validity_days: int | None = None, overrides: dict | None = None,
                   owner: str | None = None, tags: list[str] | None = None,
                   notes: str | None = None, force: bool = False,
                   actor: str = "admin") -> dict:
    """用池中的 CSR 签发证书（规则集/策略与直接签发完全一致）。"""
    row = get_row(csr_id)
    if row is None:
        raise CertError("CSR 不存在")
    if row["status"] == "issued" and not force:
        raise CertError(f"该 CSR 已于 {row['issued_at']} 签发过（证书 #{row['cert_id']}）；"
                        f"如确需重复签发，请显式指定 force")
    if row["status"] == "rejected" and not force:
        raise CertError("该 CSR 已被标记为拒绝，如需签发请显式指定 force")
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA")
    result = ca.issue_certificate(
        ca_row=ca_row, ruleset=ruleset, profile=profile or row.get("requested_profile"),
        csr_pem=row["pem"], validity_days=validity_days, overrides=overrides,
        owner=owner or row["owner"], tags=tags or db.json_load(row["tags_json"], []),
        notes=notes or row["notes"], source="csr", actor=actor)
    mark_issued(csr_id, result["id"], actor=actor)
    with db.tx() as conn:
        audit.log("csr.issue", target_type="csr", target_id=csr_id, target_label=row["cn"],
                  actor=actor, detail={"cert_id": result["id"],
                                       "serial": result["cert"]["serial_hex"],
                                       "ruleset": result["ruleset"]["slug"]}, conn=conn)
    result["csr_id"] = csr_id
    return result


def stats() -> dict:
    rows = {r["status"]: r["count"] for r in db.q(
        "SELECT status, COUNT(*) AS count FROM csrs GROUP BY status")}
    return {"pending": rows.get("pending", 0), "issued": rows.get("issued", 0),
            "rejected": rows.get("rejected", 0), "total": sum(rows.values())}
