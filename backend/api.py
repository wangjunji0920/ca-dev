"""REST API 实现。路由表见文件末尾 ``ROUTES``。

约定
----
* 所有返回都是 JSON（除文件下载与公开 CRL 端点）。
* 出错抛 ``ApiError(status, message)``，由 server 统一转成 ``{"error": "..."}``。
* 需要认证的路由在 ROUTES 里标 ``auth=True``；写方法另外要求 CSRF 令牌。
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import (audit, automation, backup, ca, config, consistency, csrs as csrs_mod, db,
               inventory, publish, rules as rules_mod, security, strongswan, x509util)
from .security import Session
from .x509util import CertError

SAFE_NAME = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff-]+")


# ---------------------------------------------------------------- 请求/响应
@dataclass
class FilePart:
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    files: dict[str, list[FilePart]] = field(default_factory=dict)
    payload: Any = None
    session: Session | None = None
    ip: str = "unknown"
    host: str = ""
    # 走加密信道（/api/rpc）时为 True：此时“信道本身”就是身份，
    # 不需要 cookie，也不需要 CSRF 令牌（攻击者无法跨站知道信道密钥）。
    rpc: bool = False
    on_login: Callable[[str], str] | None = None     # 登录成功回调，返回会话 csrf
    on_logout: Callable[[], None] | None = None

    def q(self, name: str, default: str | None = None) -> str | None:
        vals = self.query.get(name)
        if not vals:
            return default
        if isinstance(vals, str):     # 容错：调用方直接传了裸字符串
            return vals
        return vals[0]

    def q_int(self, name: str, default: int) -> int:
        try:
            return int(self.q(name) or default)
        except (TypeError, ValueError):
            return default

    def q_bool(self, name: str, default: bool = False) -> bool:
        v = self.q(name)
        if v is None:
            return default
        return str(v).lower() in ("1", "true", "yes", "on")

    @property
    def data(self) -> dict:
        if isinstance(self.payload, dict):
            return self.payload
        return {}

    def field(self, name: str, default=None):
        """同时支持 JSON body 与表单字段。"""
        if name in self.data and self.data[name] is not None:
            return self.data[name]
        if name in self.form and self.form[name] != "":
            return self.form[name]
        return default

    def all_files(self) -> list[FilePart]:
        out: list[FilePart] = []
        for parts in self.files.values():
            out.extend(parts)
        return out

    @property
    def actor(self) -> str:
        return self.session.username if self.session else "anonymous"


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Resp:
    status: int = 200
    json: Any = None
    body: bytes | None = None
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    file: Path | None = None
    filename: str | None = None
    download: bool = True


def ok(data: Any = None, status: int = 200) -> Resp:
    return Resp(status=status, json={"ok": True} if data is None else data)


def download(path: Path, filename: str | None = None,
             content_type: str = "application/octet-stream") -> Resp:
    if not path.exists():
        raise ApiError(404, f"文件不存在: {path.name}")
    return Resp(file=path, filename=filename or path.name, content_type=content_type,
                download=True)


def safe_filename(text: str, default: str = "cert") -> str:
    name = SAFE_NAME.sub("_", (text or "").strip())[:80]
    return name or default


def _int_or_none(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if value.strip().startswith("["):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else [value]
            except ValueError:
                pass
        return [v.strip() for v in value.replace("，", ",").split(",") if v.strip()]
    return [value]


# ---------------------------------------------------------------- 认证
def h_login(req: Request) -> Resp:
    username = (req.field("username") or "").strip()
    password = req.field("password") or ""
    if security.consume_guard_reset():
        audit.log("auth.unlocked", target_type="user", actor=req.ip,
                  detail={"by": "cli unlock (marker file)"})
    wait = security.login_guard.check(req.ip)
    if wait:
        raise ApiError(429, f"登录失败次数过多，已临时锁定，请 {wait} 秒后重试"
                            f"（管理员可在服务器执行： cli unlock 立即解锁）")
    row = db.q1("SELECT * FROM users WHERE username=?", (username,))
    if row is None or not security.verify_password(password, row["password_hash"]):
        security.login_guard.fail(req.ip)
        audit.log("auth.login_failed", target_type="user", target_label=username or "(空)",
                  actor=req.ip, detail={"ip": req.ip})
        limit = security.login_guard.threshold(req.ip)
        st = security.login_guard._state.get(req.ip) or {}
        left = max(0, limit - int(st.get("failures") or 0))
        raise ApiError(401, f"用户名或口令不正确（本次会话还可尝试 {left} 次，"
                            f"超过 {limit} 次将临时锁定）")
    security.login_guard.succeed(req.ip)
    if req.rpc and req.on_login is not None:
        # 加密信道模式：不发放 cookie（避免明文 HTTP 上出现可被窃取的 bearer token），
        # 直接把身份绑定到当前信道。
        csrf = req.on_login(username)
        return ok({"username": username, "csrf": csrf, "channel": True})
    sess = security.sessions.create(username, req.ip,
                                    req.field("user_agent") or "")
    resp = Resp(json={"username": username, "csrf": sess.csrf,
                      "expires_in": config.SESSION_TTL})
    resp.headers["Set-Cookie"] = security.cookie(
        config.SESSION_COOKIE, sess.sid, max_age=config.SESSION_TTL,
        secure=config.TLS_ENABLED)
    return resp


def h_logout(req: Request) -> Resp:
    if req.rpc and req.on_logout is not None:
        req.on_logout()
        return ok({"ok": True, "channel": True})
    sid = req.field("_sid")
    security.sessions.destroy(sid, reason="logout")
    resp = Resp(json={"ok": True})
    resp.headers["Set-Cookie"] = security.cookie(
        config.SESSION_COOKIE, "", max_age=0, secure=config.TLS_ENABLED)
    return resp


def h_me(req: Request) -> Resp:
    if req.session is None:
        raise ApiError(401, "unauthorized")
    return ok({"username": req.session.username, "csrf": req.session.csrf,
               "role": "admin"})


def h_health(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    return ok({"status": "ok", "version": config.VERSION,
               "time": x509util.to_iso(x509util.now()),
               "ca_ready": bool(ca_row and ca_row["has_key"])})


# ---------------------------------------------------------------- 概览
def h_overview(req: Request) -> Resp:
    now = x509util.now()
    total = db.scalar("SELECT COUNT(*) FROM certs WHERE status!='archived'")
    revoked = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked'")
    expired = db.scalar("SELECT COUNT(*) FROM certs WHERE status!='revoked' "
                        "AND status!='archived' AND not_after < ?",
                        (x509util.to_iso(now),))
    valid = db.scalar("SELECT COUNT(*) FROM certs WHERE status='valid' AND not_after >= ?",
                      (x509util.to_iso(now),))
    exp30 = db.scalar("SELECT COUNT(*) FROM certs WHERE status='valid' AND not_after >= ? "
                      "AND not_after <= ?",
                      (x509util.to_iso(now), x509util.to_iso(now + x509util._dt.timedelta(days=30))))
    exp90 = db.scalar("SELECT COUNT(*) FROM certs WHERE status='valid' AND not_after >= ? "
                      "AND not_after <= ?",
                      (x509util.to_iso(now), x509util.to_iso(now + x509util._dt.timedelta(days=90))))
    ca_row = ca.active_ca_row()
    by_profile = db.q("SELECT COALESCE(NULLIF(profile,''),'未分类') AS profile, COUNT(*) AS count "
                      "FROM certs WHERE status!='archived' GROUP BY profile ORDER BY count DESC")
    expiring = [ca.cert_to_dict(r) for r in db.q(
        "SELECT * FROM certs WHERE status='valid' AND not_after >= ? AND not_after <= ? "
        "ORDER BY not_after LIMIT 10",
        (x509util.to_iso(now), x509util.to_iso(now + x509util._dt.timedelta(days=90))))]
    return ok({
        "total": total, "valid": valid, "revoked": revoked, "expired": expired,
        "expiring_30d": exp30, "expiring_90d": exp90,
        "ca": ca.ca_to_dict(ca_row) if ca_row else None,
        "recent": audit.recent(10),
        "by_profile": by_profile,
        "expiring": expiring,
        "crl_health": publish.status()["health"],
    })


# ---------------------------------------------------------------- CA
def h_ca_get(req: Request) -> Resp:
    row = ca.active_ca_row()
    return ok({"ca": ca.ca_to_dict(row) if row else None})


def h_ca_list(req: Request) -> Resp:
    return ok({"items": [ca.ca_to_dict(r) for r in db.q("SELECT * FROM cas ORDER BY id DESC")]})


def h_ca_import(req: Request) -> Resp:
    files = req.all_files()
    cert_data = key_data = chain_data = None
    # 1) 优先按 multipart 字段名识别
    for field_name, parts in req.files.items():
        if not parts:
            continue
        if field_name in ("cert", "certificate", "ca_cert"):
            cert_data = parts[0].content
        elif field_name in ("key", "private_key", "ca_key"):
            key_data = parts[0].content
        elif field_name in ("chain", "ca_chain"):
            chain_data = parts[0].content
    # 2) 退而求其次：按内容特征识别（私钥/PKCS#12/证书）
    if cert_data is None or key_data is None:
        for f in files:
            is_key = b"PRIVATE KEY" in f.content
            if is_key and key_data is None:
                key_data = f.content
            elif not is_key and cert_data is None:
                cert_data = f.content
    password = req.field("password") or None

    # 服务器本地路径导入（用户已有 CA 材料在别处时最方便）
    path_cert = req.field("path_cert")
    path_key = req.field("path_key")
    path_chain = req.field("path_chain")
    if path_cert and cert_data is None and not path_cert.startswith("http"):
        cert_data = _read_local(path_cert)
        if path_key:
            key_data = _read_local(path_key)
        if path_chain:
            chain_data = _read_local(path_chain)
    if cert_data is None:
        raise ApiError(400, "请上传或指定 CA 证书文件")
    row = ca.import_ca(cert_data, key_data, chain_data, password=password,
                       source="path" if path_cert else "upload", actor=req.actor)
    return ok({"ca": ca.ca_to_dict(row)}, status=201)


def _read_local(path: str) -> bytes:
    p = Path(path).expanduser()
    if not str(path).startswith("/"):
        p = config.DATA_DIR / path
    if not p.exists():
        raise ApiError(400, f"文件不存在: {path}")
    if p.stat().st_size > config.MAX_BODY_BYTES:
        raise ApiError(400, f"文件过大: {path}")
    return p.read_bytes()


def h_ca_activate(req: Request) -> Resp:
    ca_id = _int_or_none(req.data.get("id") or req.field("id"))
    if not ca_id:
        raise ApiError(400, "缺少参数 id")
    return ok({"ca": ca.ca_to_dict(ca.activate_ca(ca_id, actor=req.actor))})


def h_ca_download(req: Request, ca_id: str) -> Resp:
    row = ca.get_ca(int(ca_id))
    if row is None:
        raise ApiError(404, "CA 不存在")
    fmt = (req.q("format") or "pem").lower()
    if fmt == "der":
        cert = x509util.load_cert((config.DATA_DIR / row["cert_path"]).read_bytes())
        return Resp(body=x509util.der_cert(cert),
                    content_type="application/pkix-cert",
                    filename=f"{safe_filename(row['cn'] or 'ca')}.der")
    path = config.DATA_DIR / row["cert_path"]
    return download(path, f"{safe_filename(row['cn'] or 'ca')}-ca.crt", "application/x-pem-file")


def h_ca_delete(req: Request, ca_id: str) -> Resp:
    row = ca.get_ca(int(ca_id))
    if row is None:
        raise ApiError(404, "CA 不存在")
    if db.scalar("SELECT COUNT(*) FROM certs WHERE ca_id=?", (row["id"],)):
        raise ApiError(400, "该 CA 下仍有证书记录，请先归档或删除相关证书")
    with db.tx() as conn:
        conn.execute("DELETE FROM cas WHERE id=?", (row["id"],))
        audit.log("ca.delete", target_type="ca", target_id=row["id"],
                  target_label=row["subject"], actor=req.actor, conn=conn)
    return ok()


# ---------------------------------------------------------------- 证书签发
ISSUE_FIELDS = ("profile", "cn", "o", "ou", "c", "st", "l", "email", "validity_days",
                "key_type", "key_size", "serial_mode", "owner", "notes", "csr_pem",
                "vpn_identity", "vpn_identity_type")


def _issue_kwargs(req: Request, data: dict | None = None) -> dict:
    src = data if data is not None else req
    get = (lambda k, d=None: src.get(k, d)) if data is not None else req.field

    def as_list(key):
        value = get(key)
        if value is None and data is None:
            value = (req.data or {}).get(key)
        return _list(value)

    sans_raw = get("sans") or []
    if isinstance(sans_raw, str):
        try:
            sans_raw = json.loads(sans_raw)
        except ValueError:
            sans_raw = [{"type": "dns", "value": v.strip()}
                        for v in sans_raw.replace("，", ",").split(",") if v.strip()]
    sans = []
    for item in sans_raw if isinstance(sans_raw, list) else []:
        if isinstance(item, dict) and item.get("value"):
            sans.append({"type": (item.get("type") or "dns").lower(), "value": item["value"]})
        elif isinstance(item, str) and item.strip():
            sans.append({"type": "dns", "value": item.strip()})
    kwargs = {k: get(k) for k in ISSUE_FIELDS if k != "csr_pem"}
    cf = req.field if data is None else (lambda k, d=None: src.get(k, d))
    kwargs["csr_pem"] = cf("csr_pem")
    kwargs["sans"] = sans
    kwargs["key_usage"] = as_list("key_usage")
    kwargs["eku"] = as_list("eku")
    kwargs["tags"] = _list(cf("tags"))
    for numeric in ("validity_days", "key_size"):
        if kwargs.get(numeric) in ("", None):
            kwargs[numeric] = None
        else:
            try:
                kwargs[numeric] = int(kwargs[numeric])
            except (TypeError, ValueError):
                raise ApiError(400, f"{numeric} 必须是整数")
    return {k: v for k, v in kwargs.items() if v is not None or k in ("key_size",
                                                                     "validity_days")}


def h_issue(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise ApiError(400, "尚未导入 CA，无法签发证书")
    kwargs = _issue_kwargs(req)
    # 规则集：优先 ruleset_id（规则集页选中），否则用 profile（规则集 slug）
    rid = req.field("ruleset_id")
    if rid not in (None, "", 0, "0"):
        rs = rules_mod.get(int(rid))
        if rs is None:
            raise ApiError(400, f"规则集不存在: {rid}")
        kwargs.pop("profile", None)
        kwargs["ruleset"] = rs
    overrides = req.field("overrides")
    if isinstance(overrides, str) and overrides.strip():
        try:
            overrides = json.loads(overrides)
        except ValueError:
            raise ApiError(400, "overrides 必须是 JSON 对象")
    if isinstance(overrides, dict) and overrides:
        kwargs["overrides"] = overrides
    csr_file = (req.files.get("csr_file") or req.files.get("csr") or [None])[0]
    if kwargs.get("csr_pem"):
        kwargs["csr_pem"] = _csr_text(kwargs["csr_pem"])
    elif csr_file is not None:
        kwargs["csr_pem"] = _csr_text(csr_file.content)
    kwargs["ca_row"] = ca_row
    kwargs["actor"] = req.actor
    result = ca.issue_certificate(**kwargs)
    return ok(result, status=201)


def _csr_text(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "ignore")
    text = str(value).strip()
    if "-----BEGIN" in text:
        return text
    raise ApiError(400, "CSR 内容格式不正确（需要 PEM 编码）")


def h_issue_csr(req: Request) -> Resp:
    file = (req.files.get("csr_file") or req.files.get("csr") or [None])[0]
    if file is None:
        raise ApiError(400, "请上传 CSR 文件")
    req.payload = dict(req.data)
    req.payload["csr_pem"] = file.content.decode("utf-8", "ignore")
    return h_issue(req)


def h_issue_batch(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise ApiError(400, "尚未导入 CA，无法签发证书")
    rows = req.data.get("rows") or []
    if isinstance(rows, str):
        try:
            rows = json.loads(rows)
        except ValueError:
            raise ApiError(400, "rows 必须是数组")
    if not rows:
        raise ApiError(400, "没有可签发的数据行")
    dry_run = bool(req.data.get("dry_run") or req.q_bool("dry_run"))
    created, failed, preview = [], [], []
    for idx, row in enumerate(rows, start=1):
        try:
            kwargs = _issue_kwargs(req, row)
            kwargs["ca_row"] = ca_row
            kwargs["actor"] = req.actor
            kwargs.pop("csr_pem", None)
            if dry_run:
                # 预检：生成密钥与主题构造都走一遍，但不落库
                x509util.build_name(cn=kwargs.get("cn"), o=kwargs.get("o"), ou=kwargs.get("ou"),
                                    c=kwargs.get("c"), st=kwargs.get("st"), l=kwargs.get("l"),
                                    email=kwargs.get("email"))
                x509util.build_san(kwargs.get("sans") or [])
                preview.append({"row": idx, "cn": kwargs.get("cn"),
                                "sans": kwargs.get("sans"),
                                "validity_days": kwargs.get("validity_days") or
                                db.get_setting("default_validity_days", "365"),
                                "ok": True})
                continue
            res = ca.issue_certificate(**kwargs)
            created.append(res["cert"])
        except Exception as exc:  # noqa: BLE001 - 逐行报告，不中断整批
            failed.append({"row": idx, "cn": (row or {}).get("cn"), "error": str(exc)})
    return ok({"created": created, "failed": failed, "preview": preview,
               "dry_run": dry_run}, status=200 if dry_run else 201)


# ---------------------------------------------------------------- 证书查询
SORTABLE = {"id": "id", "cn": "cn", "not_after": "not_after", "not_before": "not_before",
            "created_at": "created_at", "status": "status", "serial_hex": "serial_hex",
            "profile": "profile", "owner": "owner"}


def h_certs_list(req: Request) -> Resp:
    where: list[str] = []
    args: list[Any] = []
    text = (req.q("q") or "").strip()
    if text:
        like = f"%{text}%"
        where.append("(cn LIKE ? OR subject LIKE ? OR serial_hex LIKE ? OR fingerprint LIKE ? "
                     "OR owner LIKE ? OR notes LIKE ? OR sans_json LIKE ? OR tags_json LIKE ?)")
        args += [like] * 8
    status = (req.q("status") or "").strip()
    if status and status != "all":
        if status == "expired":
            where.append("not_after < ? AND status NOT IN ('revoked','archived')")
            args.append(x509util.to_iso(x509util.now()))
        else:
            where.append("status = ?")
            args.append(status)
    if (req.q("profile") or "").strip():
        where.append("profile = ?")
        args.append(req.q("profile"))
    tag = (req.q("tag") or "").strip()
    if tag:
        where.append("tags_json LIKE ?")
        args.append(f"%{tag}%")
    owner = (req.q("owner") or "").strip()
    if owner:
        where.append("owner LIKE ?")
        args.append(f"%{owner}%")
    if req.q("expires_before"):
        dt = x509util.parse_iso(req.q("expires_before"))
        if dt:
            where.append("not_after <= ?")
            args.append(x509util.to_iso(dt))
    if req.q("expires_after"):
        dt = x509util.parse_iso(req.q("expires_after"))
        if dt:
            where.append("not_after >= ?")
            args.append(x509util.to_iso(dt))
    if req.q("ca_id"):
        where.append("ca_id = ?")
        args.append(_int_or_none(req.q("ca_id")))
    if not req.q_bool("include_archived"):
        where.append("status != 'archived'")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.scalar(f"SELECT COUNT(*) FROM certs{clause}", args)
    sort = SORTABLE.get((req.q("sort") or "id").lower(), "id")
    order = "ASC" if (req.q("order") or "desc").lower() == "asc" else "DESC"
    page = max(1, req.q_int("page", 1))
    page_size = min(200, max(1, req.q_int("page_size", 20)))
    rows = db.q(f"SELECT * FROM certs{clause} ORDER BY {sort} {order} LIMIT ? OFFSET ?",
                args + [page_size, (page - 1) * page_size])
    facets = {
        "status": {r["status"]: r["count"] for r in db.q(
            "SELECT status, COUNT(*) AS count FROM certs GROUP BY status")},
        "profile": {r["profile"] or "未分类": r["count"] for r in db.q(
            "SELECT profile, COUNT(*) AS count FROM certs GROUP BY profile")},
    }
    tags: set[str] = set()
    for r in db.q("SELECT tags_json FROM certs"):
        tags.update(db.json_load(r["tags_json"], []))
    facets["tags"] = sorted(tags)
    return ok({"items": [ca.cert_to_dict(r) for r in rows], "total": total,
               "page": page, "page_size": page_size, "facets": facets})


def h_cert_get(req: Request, cert_id: str) -> Resp:
    cid = int(cert_id)
    cert = ca.get_cert(cid)
    if cert is None:
        raise ApiError(404, "证书不存在")
    rows = db.q("SELECT * FROM audit WHERE target_type='cert' AND target_id=? "
                "ORDER BY id DESC LIMIT 50", (str(cid),))
    for r in rows:
        r["detail"] = db.json_load(r.pop("detail_json"), {})
    return ok({"cert": cert, "audit": rows})


def h_cert_patch(req: Request, cert_id: str) -> Resp:
    if "revoked_at" in req.data or "revocation_reason" in req.data:
        raise ApiError(400, "吊销时间和原因只能通过专用吊销或恢复吊销操作修改")
    changes = {k: v for k, v in req.data.items()
               if k in ("cn", "owner", "notes", "profile", "tags", "status")}
    if not changes:
        raise ApiError(400, "没有可修改的字段")
    return ok({"cert": inventory.update_metadata(int(cert_id), changes, actor=req.actor)})


def h_cert_delete(req: Request, cert_id: str) -> Resp:
    hard = req.q_bool("hard", False) if req.method == "DELETE" else bool(req.data.get("hard"))
    return ok(inventory.delete_cert(int(cert_id), hard=hard, actor=req.actor))


def h_cert_revoke(req: Request, cert_id: str) -> Resp:
    reason = req.field("reason") or "unspecified"
    when = req.field("revocation_date")
    if isinstance(when, str) and not when.strip():
        when = None
    notes = req.field("notes")
    result = ca.revoke(int(cert_id), reason=reason, revocation_date=when, notes=notes,
                       actor=req.actor)
    if result.get("crl") is not None and db.get_setting("auto_publish", "1") == "1":
        try:
            pub = publish.publish(trigger="revoke", reload=db.get_setting("auto_reload", "1") == "1",
                                  reload_urgent=True,
                                  actor=req.actor)
            result["publish"] = pub["results"]
        except Exception as exc:  # noqa: BLE001
            result["publish_error"] = str(exc)
    return ok(result)


def h_cert_unrevoke(req: Request, cert_id: str) -> Resp:
    if not (req.data.get("confirm") or req.field("confirm") in (True, "true", "1")):
        raise ApiError(400, "该操作需要在请求中显式确认（confirm=true）")
    result = ca.unrevoke(int(cert_id), actor=req.actor)
    if result.get("crl") is not None and db.get_setting("auto_publish", "1") == "1":
        try:
            result["publish"] = publish.publish(
                trigger="unrevoke", reload=db.get_setting("auto_reload", "1") == "1",
                actor=req.actor)["results"]
        except Exception as exc:  # noqa: BLE001
            result["publish_error"] = str(exc)
    return ok(result)


def h_cert_renew(req: Request, cert_id: str) -> Resp:
    days = _int_or_none(req.data.get("validity_days") or req.field("validity_days"))
    return ok(inventory.renew(int(cert_id), validity_days=days, actor=req.actor), status=201)


def h_cert_download(req: Request, cert_id: str) -> Resp:
    cid = int(cert_id)
    row = db.q1("SELECT * FROM certs WHERE id=?", (cid,))
    if row is None:
        raise ApiError(404, "证书不存在")
    fmt = (req.q("format") or "pem").lower()
    base = safe_filename(row["cn"] or row["subject"], f"cert-{cid}")
    if fmt == "der":
        cert = x509util.load_cert((config.DATA_DIR / row["cert_path"]).read_bytes())
        return Resp(body=x509util.der_cert(cert), content_type="application/pkix-cert",
                    filename=f"{base}.der")
    if fmt == "pem":
        return download(config.DATA_DIR / row["cert_path"], f"{base}.crt",
                        "application/x-pem-file")
    if fmt == "key":
        if not row["key_path"]:
            raise ApiError(404, "本系统没有保存该证书的私钥（导入的证书通常不含私钥）")
        audit.log("cert.download_key", target_type="cert", target_id=cid,
                  target_label=row["cn"], actor=req.actor, detail={"ip": req.ip})
        return download(config.DATA_DIR / row["key_path"], f"{base}.key",
                        "application/x-pem-file")
    if fmt == "chain":
        ca_row = ca.get_ca(row["ca_id"]) if row["ca_id"] else ca.active_ca_row()
        text = ""
        if ca_row:
            text += (config.DATA_DIR / ca_row["cert_path"]).read_text()
            if ca_row.get("chain_path") and (config.DATA_DIR / ca_row["chain_path"]).exists():
                text += (config.DATA_DIR / ca_row["chain_path"]).read_text()
        return Resp(body=text.encode(), content_type="application/x-pem-file",
                    filename=f"{base}-chain.crt")
    if fmt in ("p12", "pfx"):
        if not row["key_path"]:
            raise ApiError(404, "本系统没有保存该证书的私钥，无法导出 PKCS#12")
        password = req.q("password") or ""
        if len(password) < 4:
            raise ApiError(400, "请提供至少 4 位的 PKCS#12 导出保护口令")
        cert = x509util.load_cert((config.DATA_DIR / row["cert_path"]).read_bytes())
        key = x509util.load_key((config.DATA_DIR / row["key_path"]).read_bytes())
        ca_row = ca.get_ca(row["ca_id"]) if row["ca_id"] else ca.active_ca_row()
        chain = []
        if ca_row:
            chain.append(x509util.load_cert((config.DATA_DIR / ca_row["cert_path"]).read_bytes()))
        blob = x509util.make_pkcs12(key, cert, chain, password)
        audit.log("cert.download_p12", target_type="cert", target_id=cid,
                  target_label=row["cn"], actor=req.actor, detail={"ip": req.ip})
        return Resp(body=blob, content_type="application/x-pkcs12", filename=f"{base}.p12")
    raise ApiError(400, f"不支持的导出格式: {fmt}")


# ---------------------------------------------------------------- 批量导入
def _refresh_crl_after_change(actor: str, source: str) -> dict:
    """导入导致吊销状态变化后刷新 CRL（实现统一在 ca.refresh_crl_and_publish）。"""
    return ca.refresh_crl_and_publish(actor=actor, source=source)


def _import_result(result: dict) -> Resp:
    if not result.get("dry_run") and (
            any(i.get("status") == "revoked" for i in result.get("imported") or [])
            or result.get("mark_revoked")):
        result.update(_refresh_crl_after_change("admin", "import"))
    return ok(result)


def h_import_files(req: Request) -> Resp:
    files = [(f.filename, f.content) for f in req.all_files()]
    if not files:
        raise ApiError(400, "请至少上传一个文件")
    return _import_result(inventory.import_bundle(
        files,
        dry_run=req.q_bool("dry_run", str(req.field("dry_run", "false")).lower() == "true"),
        mark_revoked=str(req.field("mark_revoked", "false")).lower() == "true",
        revoke_reason=req.field("revoke_reason") or "unspecified",
        owner=req.field("owner"), tags=req.field("tags"),
        profile=req.field("profile"), password=req.field("password") or None,
        notes=req.field("notes"), actor=req.actor))


def h_import_dir(req: Request) -> Resp:
    path = req.field("path")
    if not path:
        raise ApiError(400, "请填写服务器上的目录或文件路径")
    return _import_result(inventory.import_directory(
        path,
        dry_run=bool(req.data.get("dry_run") or req.q_bool("dry_run")),
        mark_revoked=bool(req.data.get("mark_revoked")),
        revoke_reason=req.field("revoke_reason") or "unspecified",
        owner=req.field("owner"), tags=req.field("tags"),
        recursive=not (str(req.field("recursive", "true")).lower() == "false"),
        actor=req.actor))


def h_import_csv(req: Request) -> Resp:
    file = (req.files.get("file") or req.files.get("files") or [None])[0]
    text = req.field("csv_text")
    if file is not None:
        text = file.content.decode("utf-8-sig", "ignore")
    if not text:
        raise ApiError(400, "请上传 CSV 文件或粘贴 CSV 内容")
    dry_run = bool(req.data.get("dry_run") or req.q_bool("dry_run")
                   or str(req.field("dry_run", "")).lower() == "true")
    return ok(inventory.import_csv(text, dry_run=dry_run, actor=req.actor))


def h_export(req: Request) -> Resp:
    fmt = (req.q("format") or "csv").lower()
    stamp = x509util.now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        rows = inventory.export_rows()
        body = json.dumps({"exported_at": x509util.to_iso(x509util.now()), "items": rows},
                          ensure_ascii=False, indent=2).encode()
        return Resp(body=body, content_type="application/json",
                    filename=f"ca-certs-{stamp}.json")
    return Resp(body=inventory.export_csv().encode("utf-8-sig"),
                content_type="text/csv; charset=utf-8", filename=f"ca-certs-{stamp}.csv")


def h_csv_template(req: Request) -> Resp:
    return Resp(body=inventory.import_csv_template().encode("utf-8-sig"),
                content_type="text/csv; charset=utf-8", filename="cert-metadata-template.csv")


# ---------------------------------------------------------------- CRL
def h_crl_get(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    if ca_row is None:
        return ok({"crl": None, "revoked": []})
    revoked = [ca.cert_to_dict(r) for r in db.q(
        "SELECT * FROM certs WHERE ca_id=? AND status='revoked' ORDER BY revoked_at DESC",
        (ca_row["id"],))]
    return ok({"crl": ca.current_crl(), "revoked": revoked,
               "crl_url": db.get_setting("crl_url") or ""})


def h_crl_generate(req: Request) -> Resp:
    days = _int_or_none(req.data.get("validity_days") or req.data.get("next_update_days"))
    digest = req.data.get("digest") or "sha256"
    crl = ca.generate_crl(validity_days=days, digest=digest, actor=req.actor)
    result = {"crl": crl}
    if db.get_setting("auto_publish", "1") == "1" and not req.data.get("no_publish"):
        try:
            result["publish"] = publish.publish(
                trigger="manual", reload=db.get_setting("auto_reload", "1") == "1",
                actor=req.actor)["results"]
        except Exception as exc:  # noqa: BLE001
            result["publish_error"] = str(exc)
    return ok(result)


def h_crl_download(req: Request) -> Resp:
    crl = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if crl is None:
        raise ApiError(404, "尚未生成 CRL")
    fmt = (req.q("format") or "pem").lower()
    rel = crl["path"] if fmt == "pem" else crl["der_path"]
    name = f"ca-{crl['ca_id'] or 0}.crl" + (".pem" if fmt == "pem" else "")
    return download(config.DATA_DIR / rel, name,
                    "application/x-pem-file" if fmt == "pem" else "application/pkix-crl")


def h_crl_import(req: Request) -> Resp:
    file = (req.files.get("file") or req.files.get("files") or [None])[0]
    if file is None:
        raise ApiError(400, "请上传 CRL 文件")
    return ok(ca.import_crl(file.content, actor=req.actor))


def h_crl_index(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise ApiError(400, "尚未导入 CA")
    text = ca.export_index_txt(ca_row["id"])
    return Resp(body=text.encode(), content_type="text/plain; charset=utf-8",
                filename=f"index-ca{ca_row['id']}.txt")


# ---------------------------------------------------------------- 一致性
def h_check(req: Request) -> Resp:
    return ok(consistency.check())


def h_repair(req: Request) -> Resp:
    codes = req.data.get("codes")
    if isinstance(codes, str):
        codes = [codes]
    return ok(consistency.repair(codes, actor=req.actor))


# ---------------------------------------------------------------- 审计
def h_audit(req: Request) -> Resp:
    result = audit.query(page=req.q_int("page", 1), page_size=req.q_int("page_size", 50),
                         action=req.q("action"), q_text=req.q("q"))
    result["actions"] = audit.actions()
    return ok(result)


# ---------------------------------------------------------------- 设置
SETTING_KEYS = ("org_name", "default_validity_days", "crl_validity_days", "crl_url",
                "serial_mode", "key_type", "key_size", "vpn_gateway",
                # CRL 的消费方式（可编辑；改了以后用 /api/publish/apply-settings 应用到发布目标）
                "swanctl_dir", "swanctl_crl_dir", "swanctl_ca_dir", "crl_filename",
                "crl_format", "crl_reload_cmd", "publish_ca_cert", "ca_cert_filename")


def _settings_view() -> dict:
    data = db.settings_dict()
    view = {k: data.get(k) for k in SETTING_KEYS}
    view["crl_url"] = data.get("crl_url") or ""
    st = publish.status()
    view["auto_publish"] = st["auto_publish"]
    view["lead_hours"] = st["lead_hours"]
    view["interval_minutes"] = st["interval_minutes"]
    view["auto_reload"] = st["auto_reload"]
    view["tls_enabled"] = config.TLS_ENABLED
    view["host"] = config.HOST
    view["port"] = config.PORT
    view["version"] = config.VERSION
    view["data_dir"] = str(config.DATA_DIR)
    ca_row = ca.active_ca_row()
    view["public_crl_url"] = (f"/crl/ca-{ca_row['id']}.crl" if ca_row else "/crl/current.crl")
    return view


def h_settings_get(req: Request) -> Resp:
    return ok({"settings": _settings_view()})


def h_settings_patch(req: Request) -> Resp:
    data = req.data
    changed = {}
    for key in SETTING_KEYS:
        if key not in data or data[key] is None:
            continue
        value = str(data[key]).strip()
        # 前端把“清空”的数值输入框提交为 0/空串；这些值对设置本身无意义，
        # 视为“本次不修改”，而不是让整个保存失败。
        if key.endswith("_days") or key == "key_size":
            if value in ("", "0"):
                continue
        if key in ("default_validity_days", "crl_validity_days", "key_size"):
            try:
                num = int(value)
            except ValueError:
                raise ApiError(400, f"{key} 必须是整数")
            if key == "crl_validity_days" and not (1 <= num <= 3650):
                raise ApiError(400, "CRL 有效期需在 1~3650 天之间")
            if key == "default_validity_days" and not (1 <= num <= 36500):
                raise ApiError(400, "默认有效期需在 1~36500 天之间")
        if key == "key_type" and value not in ("rsa", "ec"):
            raise ApiError(400, "密钥类型只能是 rsa 或 ec")
        if key == "serial_mode" and value not in ("random", "sequential"):
            raise ApiError(400, "序列号模式只能是 random 或 sequential")
        if key == "crl_format" and value not in ("der", "pem"):
            raise ApiError(400, "CRL 格式只能是 der 或 pem")
        if key in ("publish_ca_cert",):
            changed[key] = "1" if str(data[key]) in ("1", "true", "True", "yes", True) else "0"
            continue
        if key in ("swanctl_crl_dir", "swanctl_ca_dir") and value and not value.startswith("/"):
            raise ApiError(400, f"{key} 需要是绝对路径")
        if key == "vpn_gateway" and value and (" " in value or "\t" in value):
            raise ApiError(400, "VPN 网关地址不能包含空白字符（域名或 IP 即可）")
        if key == "crl_url" and value and not (value.startswith("http://")
                                              or value.startswith("https://")):
            raise ApiError(400, "CRL 分发点 URL 需以 http:// 或 https:// 开头")
        changed[key] = value
    if "auto_publish" in data or "lead_hours" in data or "interval_minutes" in data \
            or "auto_reload" in data:
        for src, dest in (("auto_publish", "auto_publish"), ("lead_hours",
                                                             "auto_publish_lead_hours"),
                          ("interval_minutes", "auto_publish_interval_minutes"),
                          ("auto_reload", "auto_reload")):
            if src in data and data[src] is not None:
                if src == "auto_publish" or src == "auto_reload":
                    changed[dest] = "1" if data[src] in (True, "true", "1", 1) else "0"
                else:
                    try:
                        num = int(data[src])
                    except (TypeError, ValueError):
                        raise ApiError(400, f"{src} 必须是整数")
                    if src == "lead_hours" and not (1 <= num <= 8760):
                        raise ApiError(400, "提前小时数需在 1~8760 之间")
                    if src == "interval_minutes" and not (1 <= num <= 1440):
                        raise ApiError(400, "检查间隔需在 1~1440 分钟之间")
                    changed[dest] = str(num)

    if changed:
        with db.tx() as conn:
            for key, value in changed.items():
                conn.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                             "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            audit.log("settings.update", target_type="settings", actor=req.actor,
                      detail=changed, conn=conn)

    password = data.get("password") or {}
    if password:
        old = password.get("old") or ""
        new = password.get("new") or ""
        try:
            security.change_password(old, new, actor=req.actor)
        except (PermissionError, ValueError) as exc:
            raise ApiError(400 if isinstance(exc, ValueError) else 403, str(exc))
    return ok({"settings": _settings_view(), "changed": sorted(changed)})


# ---------------------------------------------------------------- 模板
# ---------------------------------------------------------------- 备份
def h_backup_list(req: Request) -> Resp:
    return ok({"items": backup.list_backups()})


def h_backup_create(req: Request) -> Resp:
    info = backup.create(name=(req.data or {}).get("name"), actor=req.actor)
    info.pop("path", None)
    info.pop("manifest", None)
    return ok(info, status=201)


def h_backup_download(req: Request) -> Resp:
    path = backup.resolve_backup(req.q("name") or "")
    return download(path, path.name, "application/gzip")


def h_backup_restore(req: Request) -> Resp:
    if str(req.field("confirm", "")).lower() not in ("true", "1", "yes"):
        raise ApiError(400, "恢复操作需要显式确认（confirm=true）")
    file = (req.files.get("file") or req.files.get("files") or [None])[0]
    name = req.field("name")
    if file is not None:
        target = config.BACKUP_DIR / f"ca-backup-uploaded-{x509util.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
        config.atomic_write(target, file.content)
        name = target.name
    if not name:
        raise ApiError(400, "请选择或上传要恢复的备份文件")
    return ok(backup.restore(name, actor=req.actor))


def h_backup_delete(req: Request, name: str) -> Resp:
    return ok(backup.delete_backup(name, actor=req.actor))


# ---------------------------------------------------------------- CRL 自动发布
def h_publish_status(req: Request) -> Resp:
    return ok(publish.status())


def h_publish_targets(req: Request) -> Resp:
    return ok({"items": publish.list_targets(),
               "detected": {"swanctl": publish.detect_strongswan()["swanctl"],
                            "ipsec": publish.detect_strongswan()["ipsec"],
                            "dirs": {"swanctl": publish.detect_strongswan()["swanctl_dir"],
                                     "ipsec": publish.detect_strongswan()["ipsec_dir"]}},
               "suggested": publish.suggested_targets(),
               "staging_dir": str(publish.STAGING_DIR)})


def h_publish_target_create(req: Request) -> Resp:
    return ok({"target": publish.create_target(req.data)}, status=201)


def h_publish_target_patch(req: Request, tid: str) -> Resp:
    return ok({"target": publish.update_target(int(tid), req.data)})


def h_publish_target_delete(req: Request, tid: str) -> Resp:
    publish.delete_target(int(tid))
    return ok()


def h_publish_target_test(req: Request, tid: str) -> Resp:
    return ok(publish.test_target(int(tid)))


def h_publish_now(req: Request) -> Resp:
    reload_flag = req.data.get("reload")
    if reload_flag is None:
        reload_flag = db.get_setting("auto_reload", "1") == "1"
    return ok(publish.publish(trigger="manual", reload=bool(reload_flag), actor=req.actor))


def h_publish_auto(req: Request) -> Resp:
    data = req.data
    mapping = {"auto_publish": "auto_publish", "lead_hours": "auto_publish_lead_hours",
               "interval_minutes": "auto_publish_interval_minutes", "auto_reload": "auto_reload"}
    with db.tx() as conn:
        for src, dest in mapping.items():
            if src not in data or data[src] is None:
                continue
            if src in ("auto_publish", "auto_reload"):
                value = "1" if data[src] in (True, "true", "1", 1) else "0"
            else:
                try:
                    value = str(int(data[src]))
                except (TypeError, ValueError):
                    raise ApiError(400, f"{src} 必须是整数")
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (dest, value))
        audit.log("publish.auto_update", target_type="settings", actor=req.actor, detail=data,
                  conn=conn)
    return ok(publish.status())


def h_publish_log(req: Request) -> Resp:
    page = max(1, req.q_int("page", 1))
    page_size = min(200, max(1, req.q_int("page_size", 20)))
    total = db.scalar("SELECT COUNT(*) FROM publish_log")
    rows = db.q("SELECT * FROM publish_log ORDER BY id DESC LIMIT ? OFFSET ?",
                (page_size, (page - 1) * page_size))
    return ok({"items": rows, "total": total, "page": page, "page_size": page_size})


def h_serial_status(req: Request) -> Resp:
    ca_row = ca.active_ca_row()
    if ca_row is None:
        return ok({"counter": None})
    row = db.q1("SELECT next_serial FROM serial_counter WHERE ca_id=?", (ca_row["id"],))
    return ok({"counter": row["next_serial"] if row else 1,
               "mode": db.get_setting("serial_mode", "random")})


# ---------------------------------------------------------------- CSR 证书请求池
def h_csr_list(req: Request) -> Resp:
    result = csrs_mod.list_csrs(q=req.q("q"), status=req.q("status"),
                                page=req.q_int("page", 1), page_size=req.q_int("page_size", 20))
    result["stats"] = csrs_mod.stats()
    return ok(result)


def h_csr_import(req: Request) -> Resp:
    """批量导入 CSR：上传文件（可 zip），或指定服务器路径。"""
    path = req.field("path")
    dry_run = bool(req.data.get("dry_run") or req.q_bool("dry_run")
                   or str(req.field("dry_run", "")).lower() == "true")
    if path and not req.all_files():
        res = csrs_mod.import_directory(path, dry_run=dry_run, owner=req.field("owner"),
                                        tags=req.field("tags"), actor=req.actor)
    else:
        files = [(f.filename, f.content) for f in req.all_files()]
        if not files:
            raise ApiError(400, "请上传 CSR 文件（支持 .csr/.req/.p10/.pem 与 zip）")
        res = csrs_mod.import_csrs(files, dry_run=dry_run, owner=req.field("owner"),
                                   tags=req.field("tags"), notes=req.field("notes"),
                                   requested_profile=req.field("requested_profile"),
                                   actor=req.actor)
    return ok(res)


def h_csr_get(req: Request, cid: str) -> Resp:
    item = csrs_mod.get(int(cid))
    if item is None:
        raise ApiError(404, "CSR 不存在")
    row = csrs_mod.get_row(int(cid))
    audit_rows = db.q("SELECT * FROM audit WHERE target_type='csr' AND target_id=? "
                      "ORDER BY id DESC LIMIT 20", (str(cid),))
    for r in audit_rows:
        r["detail"] = db.json_load(r.pop("detail_json"), {})
    return ok({"csr": item, "pem": row["pem"], "audit": audit_rows})


def h_csr_patch(req: Request, cid: str) -> Resp:
    return ok({"csr": csrs_mod.update(int(cid), req.data, actor=req.actor)})


def h_csr_delete(req: Request, cid: str) -> Resp:
    csrs_mod.delete(int(cid), actor=req.actor)
    return ok()


def h_csr_issue(req: Request, cid: str) -> Resp:
    if ca.active_ca_row() is None:
        raise ApiError(400, "尚未导入 CA，无法签发证书")
    rid = req.data.get("ruleset_id") or req.field("ruleset_id")
    ruleset = None
    if rid not in (None, "", 0, "0"):
        ruleset = rules_mod.get(int(rid))
        if ruleset is None:
            raise ApiError(400, f"规则集不存在: {rid}")
    overrides = req.data.get("overrides")
    if isinstance(overrides, str) and overrides.strip():
        try:
            overrides = json.loads(overrides)
        except ValueError:
            raise ApiError(400, "overrides 必须是 JSON 对象")
    days = _int_or_none(req.data.get("validity_days") or req.field("validity_days"))
    return ok(csrs_mod.issue_from_csr(
        int(cid), ruleset=ruleset, profile=req.data.get("profile") or req.field("profile"),
        validity_days=days, overrides=overrides if isinstance(overrides, dict) else None,
        owner=req.data.get("owner") or req.field("owner"),
        tags=req.data.get("tags") or req.field("tags"),
        notes=req.data.get("notes") or req.field("notes"),
        force=bool(req.data.get("force")), actor=req.actor), status=201)


def h_csr_download(req: Request, cid: str) -> Resp:
    row = csrs_mod.get_row(int(cid))
    if row is None:
        raise ApiError(404, "CSR 不存在")
    name = f"{safe_filename(row['cn'] or 'request', 'request')}.csr"
    return Resp(body=row["pem"].encode(), content_type="application/pkcs10",
                filename=name)


# ---------------------------------------------------------------- 规则集
def h_ruleset_meta(req: Request) -> Resp:
    return ok({
        "platforms": [{"id": p, "label": {"strongswan": "strongSwan / IKEv2",
                                          "linux": "Linux", "windows": "Windows",
                                          "macos": "macOS", "any": "通用"}[p]}
                      for p in rules_mod.PLATFORMS],
        "digests": list(rules_mod.DIGESTS),
        "bundles": [{"id": b, "label": {"pem": "PEM 分离文件", "p12": "PKCS#12",
                                        "both": "两者都导出"}[b]}
                    for b in rules_mod.BUNDLES],
        "san_types": [{"id": t, "label": {"dns": "DNS 域名 (FQDN)", "ip": "IP 地址",
                                          "email": "邮箱 (rfc822Name)",
                                          "upn": "Windows UPN (otherName)",
                                          "uri": "URI", "othername": "其它 otherName"}[t]}
                      for t in rules_mod.SAN_TYPES],
        "key_usages": [{"id": f, "label": f"{label}（{f}）"}
                       for _a, f, label in x509util.KEY_USAGE_FIELDS],
        "ekus": [{"id": name, "label": f"{label}（{name}）", "oid": oid.dotted_string}
                 for name, (oid, label) in x509util.EKU_MAP.items()],
        "reasons": [{"id": k, "label": v} for k, v in x509util.REASONS.items()],
        "default_spec": rules_mod.DEFAULT_SPEC,
        "default_ruleset": db.get_setting("default_ruleset"),
    })


def h_rulesets(req: Request) -> Resp:
    if req.method == "POST":
        return ok({"ruleset": rules_mod.create(req.data)}, status=201)
    items = rules_mod.list_all(include_disabled=req.q_bool("all", True))
    counts = {r["profile"]: r["count"] for r in db.q(
        "SELECT profile, COUNT(*) AS count FROM certs GROUP BY profile")}
    for item in items:
        item["used_by"] = counts.get(item["slug"], 0)
    return ok({"items": items, "default_ruleset": db.get_setting("default_ruleset"),
               "platform_notes": {rs["slug"]: rules_mod.platform_notes(rs) for rs in items},
               "swanctl": publish.swanctl_settings()})


def h_ruleset_get(req: Request, rid: str) -> Resp:
    rs = rules_mod.get(int(rid))
    if rs is None:
        raise ApiError(404, "规则集不存在")
    return ok({"ruleset": rs, "platform_notes": rules_mod.platform_notes(rs),
               "used_by": db.scalar("SELECT COUNT(*) FROM certs WHERE profile=?", (rs["slug"],))})


def h_ruleset_patch(req: Request, rid: str) -> Resp:
    return ok({"ruleset": rules_mod.update(int(rid), req.data)})


def h_ruleset_delete(req: Request, rid: str) -> Resp:
    rules_mod.delete(int(rid))
    return ok()


def h_ruleset_duplicate(req: Request, rid: str) -> Resp:
    return ok({"ruleset": rules_mod.duplicate(int(rid), req.data.get("name"))}, status=201)


def h_ruleset_validate(req: Request) -> Resp:
    spec = rules_mod.validate(req.data.get("spec") or req.data)
    return ok({"valid": True, "spec": spec})


def h_ruleset_reset(req: Request, rid: str) -> Resp:
    """把内置规则集恢复成出厂 spec（管理员改坏了的兜底）。"""
    rs = rules_mod.get(int(rid))
    if rs is None:
        raise ApiError(404, "规则集不存在")
    seed = next((s for s in rules_mod.SEEDS if s["slug"] == rs["slug"]), None)
    if seed is None:
        raise ApiError(400, "只有内置规则集可以恢复出厂设置")
    return ok({"ruleset": rules_mod.update(int(rid), {"spec": seed["spec"]})})


def h_templates(req: Request) -> Resp:
    """兼容旧接口：返回扁平化的规则集视图（前端签发页用它填下拉框）。"""
    return ok({"items": rules_mod.template_view()})


def h_set_default_ruleset(req: Request) -> Resp:
    slug = req.data.get("slug") or req.field("slug")
    if not slug or rules_mod.get(slug) is None:
        raise ApiError(400, "规则集不存在")
    db.set_setting("default_ruleset", str(slug))
    audit.log("ruleset.set_default", target_type="ruleset", target_label=str(slug),
              actor=req.actor)
    return ok({"default_ruleset": slug})


# ---------------------------------------------------------------- 自动化
def h_automation_meta(req: Request) -> Resp:
    return ok({
        "triggers": [{"id": k, "label": v} for k, v in automation.TRIGGERS.items()],
        "kinds": [{"id": k, "label": v} for k, v in automation.KINDS.items()],
        "contents": [{"id": k, "label": v} for k, v in automation.CONTENTS.items()],
        "staging_dir": str(publish.STAGING_DIR),
        "note": "CRL/CA 向 strongSwan 目录落地由「内容发布目标」负责；"
                "本页用于扩展其它自动化（通知、归档、多网关分发等）。",
    })


def h_automation_tasks(req: Request) -> Resp:
    if req.method == "POST":
        return ok({"task": automation.create_task(req.data)}, status=201)
    return ok({"items": automation.list_tasks()})


def h_automation_task_patch(req: Request, tid: str) -> Resp:
    return ok({"task": automation.update_task(int(tid), req.data)})


def h_automation_task_delete(req: Request, tid: str) -> Resp:
    automation.delete_task(int(tid))
    return ok()


def h_automation_task_run(req: Request, tid: str) -> Resp:
    task = automation.get_task(int(tid))
    if task is None:
        raise ApiError(404, "自动化任务不存在")
    force = req.data.get("force")
    res = automation.run_task(task, trigger="manual", actor=req.actor,
                              force=True if force is None else bool(force))
    return ok({"ok": res.ok, "message": res.message, "sha256": res.sha256,
               "output": res.output, "skipped": res.skipped})


def h_automation_log(req: Request) -> Resp:
    return ok(automation.history(page=req.q_int("page", 1),
                                 page_size=req.q_int("page_size", 50),
                                 task_id=_int_or_none(req.q("task_id"))))


def h_automation_presets(req: Request) -> Resp:
    created = automation.install_presets(force=req.q_bool("force", False))
    return ok({"created": created, "items": automation.list_tasks()})


# ---------------------------------------------------------------- strongSwan
def h_publish_settings(req: Request) -> Resp:
    """读取/修改 CRL 的“消费方式”设置。"""
    if req.method == "PATCH":
        return h_settings_patch(req)
    return ok({"settings": publish.swanctl_settings(),
               "keys": ["swanctl_dir", "swanctl_crl_dir", "swanctl_ca_dir", "crl_filename",
                        "crl_format", "crl_reload_cmd", "publish_ca_cert", "ca_cert_filename"]})


def h_publish_apply_settings(req: Request) -> Resp:
    """按当前消费设置创建/更新发布目标（改了目录/文件名/格式后点一下即可）。"""
    return ok(publish.apply_swanctl_targets())


def h_publish_reload_cmd(req: Request) -> Resp:
    """查看/统一设置所有发布目标的重载命令（默认：swanctl + systemctl reload strongswan）。"""
    if req.method == "POST":
        cmd = req.data.get("cmd")
        result = publish.apply_reload_cmd(cmd)
        audit.log("publish.reload_cmd", target_type="settings", actor=req.actor,
                  detail={"cmd": result["cmd"], "updated": len(result["updated"])})
        return ok(result)
    return ok({"cmd": db.get_setting("crl_reload_cmd")})


def h_publish_inspect(req: Request) -> Resp:
    """探查目录里已有的证书/CRL（确认现场文件、避免重复 CRL）。"""
    directory = req.q("dir") or str(config.SWANCTL_CRL_DIR)
    return ok(publish.inspect_dir(directory))


def h_ss_status(req: Request) -> Resp:
    return ok(strongswan.status())


def h_ss_snippet(req: Request) -> Resp:
    cert_id = _int_or_none(req.q("cert_id"))
    return ok(strongswan.snippet_for(cert_id, role=req.q("role"),
                                     gateway=req.q("gateway"),
                                     identity=req.q("identity")))


def h_ss_sync_script(req: Request) -> Resp:
    return Resp(body=strongswan.sync_script().encode(), content_type="text/x-shellscript",
                filename="ca-strongswan-sync.sh")


def h_vpn_bundle(req: Request, cert_id: str) -> Resp:
    password = req.q("password") or ""
    if password and len(password) < 4:
        raise ApiError(400, "PKCS#12 口令至少 4 位")
    blob, filename = strongswan.build_bundle(
        int(cert_id), password=password or None, gateway=req.q("gateway"),
        role=req.q("role"), eap_identity=req.q("identity"))
    audit.log("cert.vpn_bundle", target_type="cert", target_id=cert_id,
              target_label=filename, actor=req.actor,
              detail={"role": req.q("role"), "with_p12": bool(password)})
    return Resp(body=blob, content_type="application/zip", filename=filename)


# ---------------------------------------------------------------- 路由表
ROUTES: list[tuple[str, str, Callable, bool]] = [
    ("POST", r"^/api/login$", h_login, False),
    ("POST", r"^/api/logout$", h_logout, False),
    ("GET", r"^/api/me$", h_me, False),
    ("GET", r"^/api/health$", h_health, False),

    ("GET", r"^/api/overview$", h_overview, True),

    ("GET", r"^/api/ca$", h_ca_get, True),
    ("GET", r"^/api/ca/list$", h_ca_list, True),
    ("POST", r"^/api/ca/import$", h_ca_import, True),
    ("POST", r"^/api/ca/activate$", h_ca_activate, True),
    ("GET", r"^/api/ca/(?P<ca_id>\d+)/download$", h_ca_download, True),
    ("DELETE", r"^/api/ca/(?P<ca_id>\d+)$", h_ca_delete, True),

    ("POST", r"^/api/certs/issue$", h_issue, True),
    ("POST", r"^/api/certs/issue/csr$", h_issue_csr, True),
    ("POST", r"^/api/certs/issue/batch$", h_issue_batch, True),
    ("POST", r"^/api/certs/import$", h_import_files, True),
    ("POST", r"^/api/certs/import/dir$", h_import_dir, True),
    ("POST", r"^/api/certs/import/csv$", h_import_csv, True),
    ("GET", r"^/api/certs/export$", h_export, True),
    ("GET", r"^/api/certs/csv-template$", h_csv_template, True),
    ("GET", r"^/api/certs$", h_certs_list, True),
    ("GET", r"^/api/certs/(?P<cert_id>\d+)$", h_cert_get, True),
    ("PATCH", r"^/api/certs/(?P<cert_id>\d+)$", h_cert_patch, True),
    ("DELETE", r"^/api/certs/(?P<cert_id>\d+)$", h_cert_delete, True),
    ("POST", r"^/api/certs/(?P<cert_id>\d+)/revoke$", h_cert_revoke, True),
    ("POST", r"^/api/certs/(?P<cert_id>\d+)/unrevoke$", h_cert_unrevoke, True),
    ("POST", r"^/api/certs/(?P<cert_id>\d+)/renew$", h_cert_renew, True),
    ("GET", r"^/api/certs/(?P<cert_id>\d+)/download$", h_cert_download, True),

    ("GET", r"^/api/crl$", h_crl_get, True),
    ("POST", r"^/api/crl/generate$", h_crl_generate, True),
    ("GET", r"^/api/crl/download$", h_crl_download, True),
    ("POST", r"^/api/crl/import$", h_crl_import, True),
    ("GET", r"^/api/crl/index$", h_crl_index, True),

    ("POST", r"^/api/consistency/check$", h_check, True),
    ("POST", r"^/api/consistency/repair$", h_repair, True),

    ("GET", r"^/api/audit$", h_audit, True),

    ("GET", r"^/api/settings$", h_settings_get, True),
    ("PATCH", r"^/api/settings$", h_settings_patch, True),
    ("GET", r"^/api/templates$", h_templates, True),

    ("GET", r"^/api/backup$", h_backup_list, True),
    ("POST", r"^/api/backup$", h_backup_create, True),
    ("GET", r"^/api/backup/download$", h_backup_download, True),
    ("POST", r"^/api/backup/restore$", h_backup_restore, True),
    ("DELETE", r"^/api/backup/(?P<name>[A-Za-z0-9._-]+)$", h_backup_delete, True),

    ("GET", r"^/api/publish/status$", h_publish_status, True),
    ("GET", r"^/api/publish/inspect$", h_publish_inspect, True),
    ("GET", r"^/api/publish/reload-cmd$", h_publish_reload_cmd, True),
    ("POST", r"^/api/publish/reload-cmd$", h_publish_reload_cmd, True),
    ("GET", r"^/api/publish/settings$", h_publish_settings, True),
    ("PATCH", r"^/api/publish/settings$", h_publish_settings, True),
    ("POST", r"^/api/publish/apply-settings$", h_publish_apply_settings, True),
    ("GET", r"^/api/publish/targets$", h_publish_targets, True),
    ("POST", r"^/api/publish/targets$", h_publish_target_create, True),
    ("PATCH", r"^/api/publish/targets/(?P<tid>\d+)$", h_publish_target_patch, True),
    ("DELETE", r"^/api/publish/targets/(?P<tid>\d+)$", h_publish_target_delete, True),
    ("POST", r"^/api/publish/targets/(?P<tid>\d+)/test$", h_publish_target_test, True),
    ("POST", r"^/api/publish/now$", h_publish_now, True),
    ("POST", r"^/api/publish/auto$", h_publish_auto, True),
    ("GET", r"^/api/publish/log$", h_publish_log, True),
    ("GET", r"^/api/serial$", h_serial_status, True),

    # ---- CSR 证书请求池 ----
    ("GET", r"^/api/csrs$", h_csr_list, True),
    ("POST", r"^/api/csrs/import$", h_csr_import, True),
    ("GET", r"^/api/csrs/(?P<cid>\d+)$", h_csr_get, True),
    ("PATCH", r"^/api/csrs/(?P<cid>\d+)$", h_csr_patch, True),
    ("DELETE", r"^/api/csrs/(?P<cid>\d+)$", h_csr_delete, True),
    ("POST", r"^/api/csrs/(?P<cid>\d+)/issue$", h_csr_issue, True),
    ("GET", r"^/api/csrs/(?P<cid>\d+)/download$", h_csr_download, True),

    # ---- 规则集：证书怎么签，全部是可编辑数据（见 rules.py） ----
    ("GET", r"^/api/rulesets$", h_rulesets, True),
    ("POST", r"^/api/rulesets$", h_rulesets, True),
    ("GET", r"^/api/rulesets/meta$", h_ruleset_meta, True),
    ("POST", r"^/api/rulesets/validate$", h_ruleset_validate, True),
    ("POST", r"^/api/rulesets/default$", h_set_default_ruleset, True),
    ("GET", r"^/api/rulesets/(?P<rid>\d+)$", h_ruleset_get, True),
    ("PATCH", r"^/api/rulesets/(?P<rid>\d+)$", h_ruleset_patch, True),
    ("DELETE", r"^/api/rulesets/(?P<rid>\d+)$", h_ruleset_delete, True),
    ("POST", r"^/api/rulesets/(?P<rid>\d+)/duplicate$", h_ruleset_duplicate, True),
    ("POST", r"^/api/rulesets/(?P<rid>\d+)/reset$", h_ruleset_reset, True),

    # ---- 自动化（可扩展：触发器 + 内容 + 动作，见 automation.py） ----
    ("GET", r"^/api/automation/meta$", h_automation_meta, True),
    ("GET", r"^/api/automation/tasks$", h_automation_tasks, True),
    ("POST", r"^/api/automation/tasks$", h_automation_tasks, True),
    ("GET", r"^/api/automation/log$", h_automation_log, True),
    ("POST", r"^/api/automation/presets$", h_automation_presets, True),
    ("PATCH", r"^/api/automation/tasks/(?P<tid>\d+)$", h_automation_task_patch, True),
    ("DELETE", r"^/api/automation/tasks/(?P<tid>\d+)$", h_automation_task_delete, True),
    ("POST", r"^/api/automation/tasks/(?P<tid>\d+)/run$", h_automation_task_run, True),

    # ---- strongSwan：状态、配置片段、一键部署包 ----
    ("GET", r"^/api/strongswan/status$", h_ss_status, True),
    ("GET", r"^/api/strongswan/snippet$", h_ss_snippet, True),
    ("GET", r"^/api/strongswan/sync-script$", h_ss_sync_script, True),
    ("GET", r"^/api/certs/(?P<cert_id>\d+)/vpn-bundle$", h_vpn_bundle, True),
]

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def route_api(req: Request) -> Resp:
    """按路由表分发一个已构造好的请求。

    HTTP 明文入口与 ``/api/rpc`` 加密入口共用这一份逻辑，避免两套代码产生安全差异。
    认证（``req.session``）由调用方负责准备：
    * 明文 HTTP：从 cookie 会话得到；
    * 加密信道：信道本身即会话（登录后绑定）。
    """
    method_mismatch = False
    for route_method, pattern, handler, needs_auth in ROUTES:
        m = re.match(pattern, req.path)
        if not m:
            continue
        if route_method != req.method:
            method_mismatch = True
            continue
        if needs_auth and req.session is None:
            return Resp(status=401, json={"error": "unauthorized"})
        try:
            return handler(req, **m.groupdict())
        except CertError as exc:
            # 用户输入/文件内容的问题统一按 400 返回，避免把“用错文件”当成服务器故障
            raise ApiError(400, str(exc)) from exc
    if method_mismatch:
        raise ApiError(405, "该接口不支持此 HTTP 方法")
    raise ApiError(404, f"接口不存在: {req.path}")
