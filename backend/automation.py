"""通用自动化引擎（CRL/strongSwan 只是它的第一个预设）。

为什么要做成通用引擎
--------------------
需求是「CRL 自动化目前只服务 strongSwan，但任何功能都要能扩展出别的自动化」。
所以这里不把“发布 CRL 到 /etc/swanctl”写死成唯一能力，而是抽象成：

    **触发器(trigger) + 内容(content) + 动作(action) + 条件(condition)**

* **触发器**：``manual`` 手动、``on_revoke`` 吊销后、``on_unrevoke`` 恢复后、
  ``on_issue`` 签发后、``on_renew`` 续期后、``on_import`` 导入后、
  ``schedule`` 定时、``crl_expiry`` CRL 到期前（提前 ``lead_hours`` 小时）。
* **内容**：``crl_der`` / ``crl_pem`` / ``ca_cert_pem`` / ``ca_cert_der`` /
  ``ca_chain_pem`` / ``index_txt`` / ``inventory_csv`` / ``cert_pem`` / ``cert_key`` / ``none``。
* **动作**：``file`` 写到指定目录（原子替换 + 权限 + 属主）、
  ``command`` 执行命令（内容路径通过环境变量传入，可 scp/rsync/curl）、
  ``webhook`` HTTP POST JSON（可带 HMAC 签名，用于通知/对接其它系统）。
* **条件**：``only_if_changed``（内容 sha256 未变则跳过）、``enabled``、
  连续失败计数（避免静默失败）。

于是：
* strongSwan 的 CRL/CA 同步 = 两条内置 ``file`` 任务（``crl_expiry`` + ``on_revoke``）；
* 想把 CRL 推到另一台网关 = 加一条 ``command`` 任务（scp + swanctl 重载）；
* 想在吊销时通知企业微信/Slack = 加一条 ``webhook`` 任务；
* 想每天导出证书清单归档 = 加一条 ``schedule`` + ``inventory_csv`` 的 ``file`` 任务。

新增能力只需要加内容类型/动作类型，不需要动已有任务的逻辑。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import audit, ca, config, db, publish, x509util
from .x509util import CertError

# ------------------------------------------------------------------ 可选值
TRIGGERS = {
    "manual": "手动执行",
    "on_revoke": "证书被吊销后",
    "on_unrevoke": "恢复吊销后",
    "on_issue": "签发证书后",
    "on_renew": "续期证书后",
    "on_import": "批量导入后",
    "schedule": "定时执行",
    "crl_expiry": "CRL 到期前自动续签",
}
KINDS = {"file": "写入文件", "command": "执行命令", "webhook": "HTTP 通知 (Webhook)"}
CONTENTS = {
    "none": "无内容（仅执行动作）",
    "crl_der": "CRL（DER 二进制）",
    "crl_pem": "CRL（PEM 文本）",
    "ca_cert_pem": "CA 证书（PEM）",
    "ca_cert_der": "CA 证书（DER）",
    "ca_chain_pem": "CA 证书链（PEM）",
    "index_txt": "OpenSSL 风格 index.txt（互操作用，可选）",
    "inventory_csv": "证书清单 CSV",
    "cert_pem": "事件相关证书（PEM）",
    "cert_key": "事件相关证书私钥（PEM）",
}
EVENT_MAP = {
    "cert.revoked": "on_revoke",
    "cert.unrevoked": "on_unrevoke",
    "cert.issued": "on_issue",
    "cert.renewed": "on_renew",
    "cert.imported": "on_import",
    "crl.generated": "crl_expiry",
}


def now_iso() -> str:
    return x509util.to_iso(x509util.now())


# ------------------------------------------------------------------ 内容生成
def content_bytes(content: str, cfg: dict | None = None, context: dict | None = None) -> bytes:
    """按内容类型生成要发布的字节流。"""
    cfg = cfg or {}
    context = context or {}
    content = (content or "none").lower()
    if content == "none":
        return b""
    if content in ("crl_der", "crl_pem"):
        fmt = "der" if content.endswith("der") else "pem"
        return publish.payload_bytes({"content": "crl", "format": fmt})
    if content in ("ca_cert_pem", "ca_cert_der", "ca_chain_pem"):
        return publish.payload_bytes({
            "content": "ca_chain" if content == "ca_chain_pem" else "ca_cert",
            "format": "der" if content.endswith("der") else "pem"})
    if content == "index_txt":
        ca_row = ca.active_ca_row()
        if ca_row is None:
            raise CertError("尚未导入 CA")
        return ca.export_index_txt(ca_row["id"]).encode()
    if content == "inventory_csv":
        from . import inventory
        return inventory.export_csv().encode("utf-8-sig")
    if content in ("cert_pem", "cert_key"):
        cert_id = context.get("cert_id") or cfg.get("cert_id")
        if not cert_id:
            raise CertError(f"{content} 需要指定证书（事件里没有 cert_id）")
        row = db.q1("SELECT * FROM certs WHERE id=?", (int(cert_id),))
        if row is None:
            raise CertError(f"证书不存在: {cert_id}")
        if content == "cert_pem":
            return ca._path(row["cert_path"]).read_bytes()
        if not row["key_path"] or not ca._path(row["key_path"]).exists():
            raise CertError("该证书没有保存私钥")
        return ca._path(row["key_path"]).read_bytes()
    raise CertError(f"未知的内容类型: {content}")


def content_description(content: str) -> str:
    return CONTENTS.get((content or "none").lower(), content or "none")


# ------------------------------------------------------------------ 任务模型
@dataclass
class Result:
    ok: bool
    message: str
    sha256: str = ""
    output: str = ""
    skipped: bool = False


def _default_filename(content: str, kind: str) -> str:
    ca_row = ca.active_ca_row()
    slug = "ca"
    if ca_row and ca_row.get("cn"):
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in ca_row["cn"])[:40]
    mapping = {
        "crl_der": f"{slug}.crl", "crl_pem": f"{slug}.crl.pem",
        "ca_cert_pem": f"{slug}.crt.pem", "ca_cert_der": f"{slug}.crt",
        "ca_chain_pem": f"{slug}-chain.pem", "index_txt": "index.txt",
        "inventory_csv": "cert-inventory.csv", "cert_pem": "cert.pem",
        "cert_key": "cert.key",
    }
    return mapping.get(content, f"{slug}.{kind}" if kind != "file" else f"{slug}.out")


# ------------------------------------------------------------------ CRUD
def list_tasks() -> list[dict]:
    rows = db.q("SELECT * FROM automation_tasks ORDER BY id")
    out = []
    for r in rows:
        item = dict(r)
        item["target"] = db.json_load(r["target_json"], {})
        item.pop("target_json", None)
        item["enabled"] = int(r["enabled"])
        item["only_if_changed"] = int(r["only_if_changed"])
        item["trigger_label"] = TRIGGERS.get(r["trigger"], r["trigger"])
        item["kind_label"] = KINDS.get(r["kind"], r["kind"])
        item["content_label"] = content_description(r["content"])
        out.append(item)
    return out


def get_task(tid: int) -> dict | None:
    for t in list_tasks():
        if t["id"] == tid:
            return t
    return None


def _validate(data: dict) -> dict:
    name = (data.get("name") or "").strip()
    if not name:
        raise CertError("任务名称不能为空")
    kind = (data.get("kind") or "file").lower()
    if kind not in KINDS:
        raise CertError(f"动作类型只能是 {'/'.join(KINDS)}")
    content = (data.get("content") or "none").lower()
    if content not in CONTENTS:
        raise CertError(f"内容类型只能是 {'/'.join(CONTENTS)}")
    trigger = (data.get("trigger") or "manual").lower()
    if trigger not in TRIGGERS:
        raise CertError(f"触发器只能是 {'/'.join(TRIGGERS)}")
    target = dict(data.get("target") or {})
    if kind == "file":
        if not target.get("path"):
            raise CertError("写入文件类任务必须填写目标目录或文件路径")
        target.setdefault("format", "der" if content.endswith("der") else "pem")
        target.setdefault("mode", "0644")
    elif kind == "command":
        if not (target.get("cmd") or data.get("cmd")):
            raise CertError("命令类任务必须填写要执行的命令")
        target["cmd"] = target.get("cmd") or data.get("cmd")
    elif kind == "webhook":
        url = target.get("url") or data.get("url")
        if not url or not str(url).startswith(("http://", "https://")):
            raise CertError("Webhook 必须填写 http:// 或 https:// 开头的 URL")
        target["url"] = url
    if trigger == "schedule" and int(data.get("interval_minutes") or 0) < 1:
        raise CertError("定时任务的间隔至少 1 分钟")
    if trigger == "crl_expiry" and int(data.get("lead_hours") or 0) < 1:
        raise CertError("CRL 到期前触发需填写提前小时数（≥1）")
    if content in ("cert_pem", "cert_key") and not target.get("cert_id"):
        raise CertError("内容为“事件相关证书”时，非事件触发的任务必须指定证书 ID")
    return {"name": name, "kind": kind, "content": content, "trigger": trigger,
            "target": target,
            "interval_minutes": int(data.get("interval_minutes") or 0),
            "lead_hours": int(data.get("lead_hours") or 0),
            "only_if_changed": 1 if data.get("only_if_changed", True) else 0,
            "reload_cmd": (data.get("reload_cmd") or "").strip(),
            "enabled": 1 if data.get("enabled", True) else 0,
            "note": (data.get("note") or "").strip()}


def create_task(data: dict) -> dict:
    v = _validate(data)
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO automation_tasks(name,kind,content,trigger,target_json,"
            "interval_minutes,lead_hours,only_if_changed,reload_cmd,enabled,note,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (v["name"], v["kind"], v["content"], v["trigger"],
             json.dumps(v["target"], ensure_ascii=False), v["interval_minutes"],
             v["lead_hours"], v["only_if_changed"], v["reload_cmd"], v["enabled"],
             v["note"], now_iso()))
        tid = cur.lastrowid
        audit.log("automation.create", target_type="automation", target_id=tid,
                  target_label=v["name"],
                  detail={"kind": v["kind"], "trigger": v["trigger"],
                          "content": v["content"]}, conn=conn)
    return get_task(tid)


def update_task(tid: int, data: dict) -> dict:
    row = db.q1("SELECT * FROM automation_tasks WHERE id=?", (tid,))
    if row is None:
        raise CertError("自动化任务不存在")
    merged = {
        "name": data.get("name", row["name"]),
        "kind": data.get("kind", row["kind"]),
        "content": data.get("content", row["content"]),
        "trigger": data.get("trigger", row["trigger"]),
        "target": data.get("target") if data.get("target") is not None
        else db.json_load(row["target_json"], {}),
        "interval_minutes": data.get("interval_minutes", row["interval_minutes"]),
        "lead_hours": data.get("lead_hours", row["lead_hours"]),
        "only_if_changed": data.get("only_if_changed", bool(row["only_if_changed"])),
        "reload_cmd": data.get("reload_cmd", row["reload_cmd"] or ""),
        "enabled": data.get("enabled", bool(row["enabled"])),
        "note": data.get("note", row["note"] or ""),
    }
    v = _validate(merged)
    with db.tx() as conn:
        conn.execute(
            "UPDATE automation_tasks SET name=?,kind=?,content=?,trigger=?,target_json=?,"
            "interval_minutes=?,lead_hours=?,only_if_changed=?,reload_cmd=?,enabled=?,note=? "
            "WHERE id=?",
            (v["name"], v["kind"], v["content"], v["trigger"],
             json.dumps(v["target"], ensure_ascii=False), v["interval_minutes"],
             v["lead_hours"], v["only_if_changed"], v["reload_cmd"], v["enabled"], v["note"],
             tid))
        audit.log("automation.update", target_type="automation", target_id=tid,
                  target_label=v["name"], detail={"trigger": v["trigger"],
                                                  "content": v["content"]}, conn=conn)
    return get_task(tid)


def delete_task(tid: int) -> None:
    row = db.q1("SELECT * FROM automation_tasks WHERE id=?", (tid,))
    if row is None:
        raise CertError("自动化任务不存在")
    with db.tx() as conn:
        conn.execute("DELETE FROM automation_tasks WHERE id=?", (tid,))
        audit.log("automation.delete", target_type="automation", target_id=tid,
                  target_label=row["name"], conn=conn)


def enable_task(tid: int, enabled: bool) -> dict:
    return update_task(tid, {"enabled": bool(enabled)})


# ------------------------------------------------------------------ 执行
def _log(tid: int | None, name: str, trigger: str, result: Result, sha: str = "",
         actor: str = "system") -> None:
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO automation_log(ts,task_id,task_name,trigger,ok,skipped,message,"
            "sha256,output,actor) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), tid, name, trigger, 1 if result.ok else 0,
             1 if result.skipped else 0, result.message[:2000], sha,
             (result.output or "")[:4000], actor))


def run_task(task: dict, *, trigger: str = "manual", context: dict | None = None,
             actor: str = "system", force: bool = False) -> Result:
    context = context or {}
    try:
        payload = content_bytes(task["content"], task.get("target"), context)
    except CertError as exc:
        res = Result(False, f"内容生成失败：{exc}")
        _log(task["id"], task["name"], trigger, res, actor=actor)
        return res

    sha = hashlib.sha256(payload).hexdigest() if payload else ""
    if task.get("only_if_changed") and sha:
        last = db.q1("SELECT sha256 FROM automation_log WHERE task_id=? AND ok=1 "
                     "ORDER BY id DESC LIMIT 1", (task["id"],))
        if last and last["sha256"] == sha and not force:
            res = Result(True, "内容未变化，已跳过（only_if_changed）", sha, skipped=True)
            return res

    target = task.get("target") or {}
    kind = task["kind"]
    try:
        if kind == "file":
            res = _run_file(task, target, payload, sha, context)
        elif kind == "command":
            res = _run_command_task(task, target, payload, sha, context)
        elif kind == "webhook":
            res = _run_webhook(task, target, payload, sha, context)
        else:  # pragma: no cover
            res = Result(False, f"不支持的动作类型: {kind}")
    except Exception as exc:  # noqa: BLE001 - 单任务失败不影响其它任务
        res = Result(False, f"{type(exc).__name__}: {exc}", sha)

    # 文件类任务成功后可选执行重载命令
    if res.ok and kind == "file" and task.get("reload_cmd"):
        rc, out = publish._run_command(task["reload_cmd"], _env_for(payload, sha, task, context))
        res.output = (res.output + "\n" + out).strip()
        if rc != 0:
            res.ok = False
            res.message += f"；重载命令失败（退出码 {rc}）"

    _log(task["id"], task["name"], trigger, res, sha=sha, actor=actor)
    with db.tx() as conn:
        conn.execute("UPDATE automation_tasks SET last_run=?, last_ok=?, last_message=? "
                     "WHERE id=?", (now_iso(), 1 if res.ok else 0, res.message[:500],
                                    task["id"]))
    if not res.ok and not res.skipped:
        audit.log("automation.failed", target_type="automation", target_id=task["id"],
                  target_label=task["name"], actor=actor,
                  detail={"trigger": trigger, "message": res.message})
    return res


def _env_for(payload: bytes, sha: str, task: dict, context: dict) -> dict[str, str]:
    env = {"CA_AUTOMATION_TASK": task["name"], "CA_AUTOMATION_ID": str(task["id"]),
           "CA_CONTENT_KIND": task["content"], "CA_CONTENT_SHA256": sha,
           "CA_EVENT": str(context.get("event") or ""),
           "CA_CRL_NUMBER": "", "CA_CERT_ID": str(context.get("cert_id") or "")}
    row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if row is not None:
        env["CA_CRL_NUMBER"] = str(row["number"] or "")
        env["CA_CRL_PEM_FILE"] = str(config.DATA_DIR / row["path"]) if row["path"] else ""
        env["CA_CRL_DER_FILE"] = str(config.DATA_DIR / row["der_path"]) if row["der_path"] else ""
    return env


def _write_payload(path: Path, payload: bytes, mode: str, owner: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(tmp, int(str(mode or "0644"), 8))
    except (OSError, ValueError):
        pass
    if owner:
        try:
            import grp
            import pwd
            user, _, group = str(owner).partition(":")
            os.chown(tmp, pwd.getpwnam(user).pw_uid,
                     grp.getgrnam(group).gr_gid if group else -1)
        except Exception:  # noqa: BLE001 - 非 root 时忽略
            pass
    os.replace(tmp, path)


def _run_file(task: dict, target: dict, payload: bytes, sha: str,
              context: dict) -> Result:
    raw = str(target["path"])
    expanded = Path(os.path.expandvars(os.path.expanduser(raw)))
    if expanded.is_dir() or raw.endswith(("/", os.sep)) or not expanded.suffix:
        expanded.mkdir(parents=True, exist_ok=True)
        filename = target.get("filename") or _default_filename(task["content"], "file")
        path = expanded / filename
    else:
        path = expanded
    if not payload:
        return Result(False, "该任务没有可写入的内容")
    _write_payload(path, payload, target.get("mode", "0644"), target.get("owner"))
    return Result(True, f"已写入 {path}（{len(payload)} 字节）", sha)


def _run_command_task(task: dict, target: dict, payload: bytes, sha: str,
                      context: dict) -> Result:
    env_extra = _env_for(payload, sha, task, context)
    # 内容落一个临时文件，命令可以通过环境变量直接引用
    if payload:
        tmp = config.TMP_DIR / f"automation-{task['id']}-{sha[:12]}.bin"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)
        env_extra["CA_CONTENT_FILE"] = str(tmp)
    rc, out = publish._run_command(str(target["cmd"]), env_extra)
    msg = "命令执行成功" if rc == 0 else f"命令失败（退出码 {rc}）"
    return Result(rc == 0, msg, sha, output=out)


def _run_webhook(task: dict, target: dict, payload: bytes, sha: str,
                 context: dict) -> Result:
    body = json.dumps({
        "task": task["name"], "trigger": task["trigger"],
        "event": context.get("event") or "", "time": now_iso(),
        "content": {"kind": task["content"], "sha256": sha,
                    "size": len(payload),
                    "text": payload.decode("utf-8", "replace")[:20000]
                    if payload and len(payload) < 200000 and task["content"] != "cert_key"
                    else None},
        "summary": context.get("summary") or "",
        "cert": context.get("cert") or None,
    }, ensure_ascii=False).encode()
    headers = {str(k): str(v) for k, v in (target.get("headers") or {}).items()}
    headers.setdefault("Content-Type", "application/json; charset=utf-8")
    secret = target.get("secret") or ""
    if secret:
        headers["X-CA-Signature"] = "sha256=" + hmac.new(
            str(secret).encode(), body, hashlib.sha256).hexdigest()
    method = (target.get("method") or "POST").upper()
    req = urllib.request.Request(str(target["url"]), data=body, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read()[:2000].decode("utf-8", "replace")
            ok = 200 <= resp.status < 300
            return Result(ok, f"HTTP {resp.status}", sha, output=text)
    except urllib.error.HTTPError as exc:
        return Result(False, f"HTTP {exc.code}: {exc.reason}", sha,
                      output=exc.read()[:1000].decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        return Result(False, f"{type(exc).__name__}: {exc}", sha)


# ------------------------------------------------------------------ 触发
def tasks_for(trigger: str) -> list[dict]:
    return [t for t in list_tasks() if t["enabled"] and t["trigger"] == trigger]


def fire(event: str, context: dict | None = None, actor: str = "system") -> list[dict]:
    """业务事件触发（吊销/签发/续期/导入/生成 CRL 后调用）。"""
    trigger = EVENT_MAP.get(event)
    if trigger is None:
        return []
    context = dict(context or {})
    context["event"] = event
    out = []
    for task in tasks_for(trigger):
        if not _context_matches(task, context):
            continue
        try:
            res = run_task(task, trigger=trigger, context=context, actor=actor)
            out.append({"task": task["name"], "task_id": task["id"], "ok": res.ok,
                        "skipped": res.skipped, "message": res.message})
        except Exception as exc:  # noqa: BLE001 - 自动化绝不能影响主流程
            out.append({"task": task["name"], "task_id": task["id"], "ok": False,
                        "message": f"{type(exc).__name__}: {exc}"})
    return out


def _context_matches(task: dict, context: dict) -> bool:
    """任务可用 target.filter 限定只处理某些规则集/平台/证书。"""
    flt = (task.get("target") or {}).get("filter") or {}
    if not flt:
        return True
    if flt.get("profiles") and context.get("profile") not in flt["profiles"]:
        return False
    if flt.get("platforms"):
        from . import rules
        rs = rules.get(context.get("profile"))
        if rs is None or rs["platform"] not in flt["platforms"]:
            return False
    return True


# ------------------------------------------------------------------ 调度
def run_due(actor: str = "scheduler") -> list[dict]:
    """由调度线程周期性调用：处理 schedule 与 crl_expiry 两类触发器。"""
    out: list[dict] = []
    for task in list_tasks():
        if not task["enabled"]:
            continue
        try:
            if task["trigger"] == "schedule":
                if _schedule_due(task):
                    out.append({"task": task["name"], "task_id": task["id"],
                                "result": run_task(task, trigger="schedule",
                                                   actor=actor).message})
            elif task["trigger"] == "crl_expiry":
                if _crl_expiry_due(task):
                    out.append({"task": task["name"], "task_id": task["id"],
                                "result": run_task(task, trigger="crl_expiry",
                                                   actor=actor).message})
        except Exception as exc:  # noqa: BLE001
            out.append({"task": task["name"], "task_id": task["id"],
                        "result": f"ERROR {type(exc).__name__}: {exc}"})
    return out


def _schedule_due(task: dict) -> bool:
    minutes = max(1, int(task["interval_minutes"] or 60))
    last = task.get("last_run") or db.q1(
        "SELECT ts FROM automation_log WHERE task_id=? ORDER BY id DESC LIMIT 1",
        (task["id"],))
    last_ts = last["ts"] if isinstance(last, dict) else last
    if not last_ts:
        return True
    dt = x509util.parse_iso(last_ts)
    if dt is None:
        return True
    return (x509util.now() - dt).total_seconds() >= minutes * 60


def _crl_expiry_due(task: dict) -> bool:
    """CRL 需要续签时才触发（与 publish 调度器同样的判定，但作用在通用任务上）。"""
    crl = ca.current_crl()
    ca_row = ca.active_ca_row()
    if ca_row is None or not ca_row["has_key"]:
        return False
    lead = max(1, int(task["lead_hours"] or 72))
    if crl is None:
        return True
    nu = x509util.parse_iso(crl["next_update"])
    if nu is None or (nu - x509util.now()).total_seconds() < lead * 3600:
        return True
    newer = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked' AND ca_id=? "
                      "AND revoked_at > ?", (ca_row["id"], crl["this_update"]))
    return bool(newer)


# ------------------------------------------------------------------ 历史
def history(page: int = 1, page_size: int = 50, task_id: int | None = None) -> dict:
    where, args = "", []
    if task_id:
        where, args = " WHERE task_id=?", [task_id]
    total = db.scalar(f"SELECT COUNT(*) FROM automation_log{where}", args)
    page = max(1, int(page))
    page_size = min(200, max(1, int(page_size)))
    rows = db.q(f"SELECT * FROM automation_log{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                args + [page_size, (page - 1) * page_size])
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


# ------------------------------------------------------------------ 预设
def install_presets(force: bool = False) -> list[str]:
    """安装内置自动化预设。

    注意：**CRL/CA 向 strongSwan 目录落地由「内容发布目标」负责**（publish 模块，
    已内置到期前自动续签 + 吊销后自动发布）。这里只放“其它用途”的扩展示例，
    默认全部停用，避免与发布目标重复执行。想启用哪条，勾一下即可。
    """
    created: list[str] = []
    ca_row = ca.active_ca_row()
    slug = "example-ca"
    if ca_row and ca_row.get("cn"):
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in ca_row["cn"])[:40]

    presets: list[dict] = [
        {
            "name": "示例：证书被吊销时发送 Webhook 通知",
            "kind": "webhook", "content": "none", "trigger": "on_revoke",
            "target": {"url": "https://example.com/ca-hook", "method": "POST", "secret": ""},
            "enabled": False,
            "note": "改成你们的企业微信/Slack/自建接口地址即可。系统 POST JSON，"
                    "并在填了 secret 时带上 X-CA-Signature: sha256=<HMAC> 供对方校验。",
        },
        {
            "name": "示例：每天导出证书清单 CSV 到归档目录",
            "kind": "file", "content": "inventory_csv", "trigger": "schedule",
            "interval_minutes": 1440,
            "target": {"path": str(config.BACKUP_DIR / "inventory"), "mode": "0600"},
            "enabled": False,
            "note": "定时把全部证书清单导出成 CSV，便于审计/对账。",
        },
        {
            "name": "示例：CRL 到期前推送到远端网关（scp + 重载）",
            "kind": "command", "content": "crl_pem", "trigger": "crl_expiry",
            "lead_hours": 72,
            "target": {"cmd": "sh -c 'scp -q \"$CA_CONTENT_FILE\" root@gw2:"
                              f"/etc/swanctl/x509crl/{slug}.crl.pem && "
                              "ssh -q root@gw2 \"swanctl --flush-certs && swanctl --load-creds\"'"},
            "enabled": False,
            "note": "多网关/异地部署时用。命令里可用环境变量：CA_CONTENT_FILE、"
                    "CA_CONTENT_SHA256、CA_CRL_NUMBER、CA_EVENT。用免密 SSH 密钥。",
        },
        {
            "name": "示例：签发新证书后同步导出 CA 证书链",
            "kind": "file", "content": "ca_chain_pem", "trigger": "on_issue",
            "target": {"path": str(publish.STAGING_DIR), "filename": f"{slug}-chain.pem",
                       "mode": "0644"},
            "enabled": False,
            "note": "需要把完整链分发给客户端时使用（only_if_changed 会自动跳过无变化的情况）。",
        },
    ]

    existing = {t["name"] for t in list_tasks()}
    for p in presets:
        if p["name"] in existing and not force:
            continue
        try:
            create_task(p)
            created.append(p["name"])
        except CertError:
            continue
    # 并发 bootstrap（服务首次启动 + 管理员同时跑 cli）时，"存在即跳过"可能被同时穿透，
    # 于是同名示例被插入两次。这里做一次幂等收尾：同名示例只保留 id 最小的那个。
    if not force:
        try:
            with db.tx() as conn:
                conn.execute(
                    "DELETE FROM automation_tasks WHERE name LIKE '示例：%' AND id NOT IN ("
                    "  SELECT MIN(id) FROM automation_tasks WHERE name LIKE '示例：%'"
                    "  GROUP BY name)")
        except Exception:  # noqa: BLE001 - 收尾失败不影响主流程
            pass
    return created
