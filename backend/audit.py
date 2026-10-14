"""审计日志：所有写操作都要留痕。

审计表只追加不修改。可在调用方事务内写入（传入 conn），保证“业务变更 + 日志”原子提交。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import db, x509util


def log(action: str, *, target_type: str | None = None, target_id: Any = None,
        target_label: str | None = None, actor: str = "admin",
        detail: dict | None = None, conn: sqlite3.Connection | None = None) -> None:
    ts = x509util.to_iso(x509util.now())
    payload = json.dumps(detail or {}, ensure_ascii=False, default=str)
    args = (ts, action, target_type, str(target_id) if target_id is not None else None,
            target_label, actor, payload)
    sql = ("INSERT INTO audit(ts,action,target_type,target_id,target_label,actor,detail_json) "
           "VALUES(?,?,?,?,?,?,?)")
    if conn is not None:
        conn.execute(sql, args)
    else:
        with db.tx() as c:
            c.execute(sql, args)


def recent(limit: int = 10) -> list[dict]:
    rows = db.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        r["detail"] = db.json_load(r.pop("detail_json"), {})
    return rows


def query(page: int = 1, page_size: int = 50, action: str | None = None,
          q_text: str | None = None) -> dict:
    where, args = [], []
    if action:
        where.append("action = ?")
        args.append(action)
    if q_text:
        where.append("(target_label LIKE ? OR action LIKE ? OR detail_json LIKE ?)")
        args += [f"%{q_text}%"] * 3
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.scalar(f"SELECT COUNT(*) FROM audit{clause}", args)
    page = max(1, int(page))
    page_size = min(200, max(1, int(page_size)))
    rows = db.q(
        f"SELECT * FROM audit{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [page_size, (page - 1) * page_size])
    for r in rows:
        r["detail"] = db.json_load(r.pop("detail_json"), {})
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


def actions() -> list[str]:
    return [r["action"] for r in db.q("SELECT DISTINCT action FROM audit ORDER BY action")]
