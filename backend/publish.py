"""CRL 自动发布引擎（面向 strongSwan）。

为什么需要它
------------
strongSwan 的 revocation 插件会校验 CRL 的有效期：一旦 CRL 的 ``nextUpdate`` 过期，
它会把该 CRL 视为不可用，从而拒绝（或按配置忽略）连接。因此 CRL 绝不能只靠人工更新。
本模块保证：

1. **按时续签**：后台线程定期检查，在 ``nextUpdate`` 到期前 ``lead_hours`` 小时自动重新生成 CRL。
2. **秒级同步吊销**：任何一次吊销都会立即重新生成 CRL 并（可选）自动发布。
3. **原子发布**：写入 strongSwan 目录时先写临时文件再 rename，charon 永远不会读到半截 CRL。
4. **自动重载**：发布后执行配置的清缓存、加载凭据及重启命令，失败会如实记录。
5. **可对外分发**：服务另外提供公开的 CRL 下载端点（见 server.py），可填到证书的
   CRL Distribution Point 扩展里，让远端 strongSwan 通过 HTTP 自动拉取。

发布目标有两种：
* ``dir_file``：把 CRL 写入某个目录（``/etc/swanctl/x509crl``、``/etc/ipsec.d/crls`` …）。
* ``command`` ：执行自定义命令，并通过环境变量把 CRL 文件路径传出去
  （例如 ``scp`` 到另一台 VPN 网关，或调用 ``swanctl --import``）。
"""
from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import audit, ca, config, db, x509util
from .x509util import CertError

STAGING_DIR = config.DATA_DIR / "publish"

DEFAULT_CA_NAME = "example-ca"


def _now() -> str:
    return x509util.to_iso(x509util.now())


def _log(**kw) -> None:
    cols = ("ts", "target_id", "target_name", "path", "sha256", "ok", "message",
            "reload_output", "trigger", "crl_id", "actor")
    values = [kw.get(c) for c in cols]
    values[0] = values[0] or _now()
    with db.tx() as conn:
        conn.execute(f"INSERT INTO publish_log({','.join(cols)}) "
                     f"VALUES({','.join('?' * len(cols))})", values)


# ------------------------------------------------------------------ strongSwan 探测
def detect_strongswan() -> dict:
    info = {
        "swanctl": bool(shutil.which("swanctl")),
        "ipsec": bool(shutil.which("ipsec")),
        "swanctl_dir": Path("/etc/swanctl/x509crl").is_dir(),
        "ipsec_dir": Path("/etc/ipsec.d/crls").is_dir(),
        "reload_cmd": "",
    }
    if info["swanctl"]:
        info["reload_cmd"] = config.DEFAULT_RELOAD_CMD
    elif info["ipsec"]:
        info["reload_cmd"] = "ipsec rereadcrls"
    return info


def _within_data(path: Path) -> bool:
    """路径是否位于本系统数据目录内（数据目录里的文件可以自由创建）。"""
    try:
        Path(path).resolve().relative_to(config.DATA_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def swanctl_available() -> bool:
    """本机是否真的装了 strongSwan：只看配置目录是否存在，**绝不凭空创建**。"""
    try:
        return Path(swanctl_settings()["dir"]).is_dir()
    except Exception:  # noqa: BLE001
        return False


def swanctl_settings() -> dict:
    """CRL 的“消费方式”设置（全部来自数据库，可在界面修改）。

    代码里只有初始默认值；运行期一律以设置为准，所以目录/文件名/格式/重载命令都能改。
    """
    s = db.settings_dict()
    return {
        "dir": str(s.get("swanctl_dir") or config.SWANCTL_DIR),
        "crl_dir": str(s.get("swanctl_crl_dir") or config.SWANCTL_CRL_DIR),
        "ca_dir": str(s.get("swanctl_ca_dir") or config.SWANCTL_CA_DIR),
        "crl_filename": str(s.get("crl_filename") or ""),
        "crl_format": str(s.get("crl_format") or "der").lower(),
        "reload_cmd": str(s.get("crl_reload_cmd") if s.get("crl_reload_cmd") is not None
                          else config.DEFAULT_RELOAD_CMD),
        "publish_ca_cert": str(s.get("publish_ca_cert", "1")) in ("1", "true", "yes"),
        "ca_cert_filename": str(s.get("ca_cert_filename") or ""),
        "running_as_root": config.RUN_AS_ROOT,
        "manage_strongswan": config.MANAGE_STRONGSWAN,
    }


def ensure_swanctl_dirs() -> dict:
    """按设置创建 strongSwan 目标目录（幂等）。

    安全约定：**只有本机确实装了 strongSwan（配置根目录已存在）**，
    或目标目录就位于本系统数据目录内（测试/自定义用途）时才创建；
    绝不会在没有 strongSwan 的机器上凭空造出 /etc/swanctl。
    """
    cfg = swanctl_settings()
    root = Path(cfg["dir"])
    allowed = _within_data(root) or (config.RUN_AS_ROOT and config.MANAGE_STRONGSWAN
                                     and root.is_dir())
    info = {"attempted": bool(allowed), "created": [], "errors": [],
            "dirs": [cfg["crl_dir"], cfg["ca_dir"]],
            "reason": "" if allowed else
            f"{root} 不存在（本机可能未安装 strongSwan），已跳过目录创建"}
    if not allowed:
        return info
    for d in (Path(cfg["crl_dir"]), Path(cfg["ca_dir"])):
        try:
            if not d.exists():
                d.mkdir(parents=True, exist_ok=True)
                info["created"].append(str(d))
            os.chmod(d, 0o755)
        except OSError as exc:
            info["errors"].append(f"{d}: {exc}")
    return info


def inspect_dir(path: str | Path) -> dict:
    """探查目录里已有的证书/CRL 文件，用于“沿用现场文件名、避免重复 CRL”。

    返回每条的：文件名、类型、主题/签发者、指纹、CRL 的本次/下次更新时间，
    以及是否属于当前 CA（is_our_ca）——如果目录里已经有本 CA 的 CRL，
    就应该**覆盖同一个文件名**，否则 strongSwan 会看到同一 CA 的两份 CRL。
    """
    from . import ca as _ca
    directory = Path(os.path.expandvars(os.path.expanduser(str(path))))
    out: dict = {"path": str(directory), "exists": directory.is_dir(), "files": [],
                 "our_ca_subject": None, "our_ca_fingerprint": None,
                 "existing_crl_filename": None, "existing_ca_filename": None,
                 "other_crls_same_issuer": [], "errors": []}
    ca_row = _ca.active_ca_row()
    if ca_row:
        out["our_ca_subject"] = ca_row["subject"]
        out["our_ca_fingerprint"] = ca_row["fingerprint"]
    if not out["exists"]:
        return out
    for p in sorted(directory.iterdir()):
        if not p.is_file() or p.name.startswith("."):
            continue
        item = {"name": p.name, "size": p.stat().st_size, "kind": "other"}
        try:
            blob = p.read_bytes()
        except OSError as exc:
            out["errors"].append(f"{p.name}: {exc}")
            continue
        try:
            crl = x509util.load_crl(blob)
            issuer = x509util.name_to_str(crl.issuer)
            is_ours = bool(out["our_ca_subject"]) and issuer == out["our_ca_subject"]
            last = getattr(crl, "last_update_utc", None) or crl.last_update
            nxt = getattr(crl, "next_update_utc", None) or crl.next_update
            item.update({"kind": "crl", "issuer": issuer,
                         "this_update": x509util.to_iso(last),
                         "next_update": x509util.to_iso(nxt),
                         "entries": len(list(crl)), "is_our_ca": is_ours})
            if is_ours:
                out["existing_crl_filename"] = p.name
            out["all_crls"] = (out.get("all_crls") or []) + [p.name]
        except Exception:  # noqa: BLE001 - 不是 CRL 就看是不是证书
            try:
                cert = x509util.load_cert(blob)
                item.update({
                    "kind": "cert",
                    "subject": x509util.name_to_str(cert.subject),
                    "issuer": x509util.name_to_str(cert.issuer),
                    "fingerprint_sha256": x509util.fingerprint(cert),
                    "is_ca": x509util.cert_to_dict(cert)["is_ca"],
                    "is_our_ca": bool(out["our_ca_fingerprint"]) and
                    x509util.fingerprint(cert) == out["our_ca_fingerprint"],
                })
                if item["is_our_ca"]:
                    out["existing_ca_filename"] = p.name
            except Exception:  # noqa: BLE001
                item["kind"] = "other"
        out["files"].append(item)
    return out


def swanctl_targets() -> list[dict]:
    """按“消费设置”生成发布目标（CRL + 可选 CA 证书）。

    文件名规则：
      * 设置了 ``crl_filename`` -> 用它（这是可修改的，默认 crl.der）；
      * 留空 -> 自动沿用目标目录里已有的本 CA 的 CRL 文件名，避免同一 CA 两份 CRL。
    """
    cfg = swanctl_settings()
    reload_cmd = cfg["reload_cmd"]
    crl_dir, ca_dir = Path(cfg["crl_dir"]), Path(cfg["ca_dir"])
    crl_name = cfg["crl_filename"].strip()
    crl_fmt = cfg["crl_format"] if cfg["crl_format"] in ("der", "pem") else "der"
    if not crl_name:
        try:
            found = inspect_dir(crl_dir).get("existing_crl_filename")
        except Exception:  # noqa: BLE001
            found = None
        crl_name = found or f"{DEFAULT_CA_NAME}.{crl_fmt}"
        if found:
            crl_fmt = "der" if crl_name.lower().endswith(".der") else "pem"

    ca_name = cfg["ca_cert_filename"].strip()
    if not ca_name:
        try:
            ca_name = inspect_dir(ca_dir).get("existing_ca_filename") or ""
        except Exception:  # noqa: BLE001
            ca_name = ""
        ca_name = ca_name or f"{DEFAULT_CA_NAME}.crt.pem"

    fmt_label = "DER" if crl_fmt == "der" else "PEM"
    targets = [{
        "name": f"strongSwan — CRL 直写 {crl_dir}/{crl_name}（{fmt_label}）",
        "kind": "dir_file", "path": str(crl_dir), "filename": crl_name,
        "format": crl_fmt, "content": "crl", "reload_cmd": reload_cmd, "enabled": 1,
        "mode": "0644", "owner": None}]
    if cfg["publish_ca_cert"]:
        targets.append({
            "name": f"strongSwan — CA 证书直写 {ca_dir}/{ca_name}", "kind": "dir_file",
            "path": str(ca_dir), "filename": ca_name, "format": "pem",
            "content": "ca_cert", "reload_cmd": reload_cmd, "enabled": 1,
            "mode": "0644", "owner": None})
    return targets


def apply_reload_cmd(cmd: str | None = None) -> dict:
    """把所有启用目标的重载命令统一成指定命令（默认取设置里的 crl_reload_cmd）。

    升级/改现场约定时用：已有目标不会自动跟随设置变化，这个动作一键对齐。
    """
    cmd = (cmd if cmd is not None else db.get_setting("crl_reload_cmd") or "").strip()
    updated, skipped = [], []
    for t in list_targets():
        if not t["enabled"] or t["kind"] != "dir_file":
            skipped.append(t["name"])
            continue
        if (t.get("reload_cmd") or "") == cmd:
            skipped.append(t["name"])
            continue
        update_target(t["id"], {"reload_cmd": cmd})
        updated.append({"id": t["id"], "name": t["name"], "reload_cmd": cmd})
    if cmd:
        db.set_setting("crl_reload_cmd", cmd)
    return {"cmd": cmd, "updated": updated, "unchanged": skipped}


def apply_swanctl_targets() -> dict:
    """按当前“消费设置”创建或**更新**发布目标（可反复执行，不产生重复目标）。

    这样“CRL 怎么被消费”完全由设置驱动：改目录/文件名/格式/重载命令后点一下即可生效。
    """
    if not (swanctl_available() or _within_data(Path(swanctl_settings()["crl_dir"]))):
        raise CertError(
            f"未检测到 strongSwan：{swanctl_settings()['dir']} 不存在。"
            f"本机若未安装 strongSwan，请不要添加 /etc/swanctl 目标；"
            f"如要自定义消费方式，可把目录改到本系统数据目录内，或在目标机上再执行本操作。")
    created, updated, unchanged = [], [], []
    for want in swanctl_targets():
        row = db.q1("SELECT * FROM publish_targets WHERE path=? AND content=?",
                    (want["path"], want["content"]))
        if row is None:
            created.append(create_target(want)["name"])
            continue
        needs = (row["filename"] != want["filename"] or row["format"] != want["format"]
                 or (row["reload_cmd"] or "") != want["reload_cmd"])
        if needs:
            update_target(row["id"], {"filename": want["filename"], "format": want["format"],
                                      "reload_cmd": want["reload_cmd"], "name": want["name"],
                                      "enabled": 1})
            updated.append(want["name"])
        else:
            unchanged.append(want["name"])
    return {"created": created, "updated": updated, "unchanged": unchanged,
            "settings": swanctl_settings(), "targets": list_targets()}


def suggested_targets() -> list[dict]:
    detected = detect_strongswan()
    swanctl_reload = swanctl_settings()["reload_cmd"]
    out: list[dict] = []
    # 以 root 运行：优先直接写 strongSwan 目录，自动化闭环最短
    if config.RUN_AS_ROOT and config.MANAGE_STRONGSWAN:
        out.extend(swanctl_targets())
    if detected["swanctl_dir"] or detected["swanctl"]:
        out.append({"name": "strongSwan swanctl — CRL (PEM)", "kind": "dir_file",
                    "path": "/etc/swanctl/x509crl", "filename": f"{DEFAULT_CA_NAME}.crl.pem",
                    "format": "pem", "content": "crl", "reload_cmd": swanctl_reload,
                    "enabled": 1, "mode": "0644", "owner": None})
        out.append({"name": "strongSwan swanctl — CA 证书 (PEM)", "kind": "dir_file",
                    "path": "/etc/swanctl/x509ca", "filename": f"{DEFAULT_CA_NAME}.crt.pem",
                    "format": "pem", "content": "ca_cert", "reload_cmd": swanctl_reload,
                    "enabled": 1, "mode": "0644", "owner": None})
    # 只在**确实存在 legacy 布局**时才建议 ipsec.d 目标：
    # 机器上装了 ipsec 命令不等于在用 ipsec.d（Debian 的 strongswan-starter 会带它），
    # 否则会在 swanctl 布局的机器上凭空造出两个必然失败的发布目标。
    if Path("/etc/ipsec.d").is_dir():
        out.append({"name": "strongSwan legacy ipsec.d — CRL (DER)", "kind": "dir_file",
                    "path": "/etc/ipsec.d/crls", "filename": f"{DEFAULT_CA_NAME}.crl",
                    "format": "der", "content": "crl", "reload_cmd": "ipsec rereadcrls",
                    "enabled": 1, "mode": "0644", "owner": None})
        out.append({"name": "strongSwan legacy ipsec.d — CA 证书 (DER)", "kind": "dir_file",
                    "path": "/etc/ipsec.d/cacerts", "filename": f"{DEFAULT_CA_NAME}.crt",
                    "format": "der", "content": "ca_cert", "reload_cmd": "ipsec rereadcacerts",
                    "enabled": 1, "mode": "0644", "owner": None})
    # 本地暂存目录始终可用，保证在无 root 权限时自动化仍然成立
    out.append({"name": "本地暂存目录 — CRL (DER)", "kind": "dir_file",
                "path": str(STAGING_DIR), "filename": f"{DEFAULT_CA_NAME}.crl",
                "format": "der", "content": "crl", "reload_cmd": "", "enabled": 1,
                "mode": "0644", "owner": None})
    out.append({"name": "本地暂存目录 — CRL (PEM)", "kind": "dir_file",
                "path": str(STAGING_DIR), "filename": f"{DEFAULT_CA_NAME}.crl.pem",
                "format": "pem", "content": "crl", "reload_cmd": "", "enabled": 0,
                "mode": "0644", "owner": None})
    out.append({"name": "本地暂存目录 — CA 证书", "kind": "dir_file",
                "path": str(STAGING_DIR), "filename": f"{DEFAULT_CA_NAME}.crt.pem",
                "format": "pem", "content": "ca_cert", "reload_cmd": "", "enabled": 1,
                "mode": "0644", "owner": None})
    return out


def ensure_default_targets() -> None:
    """首次运行时自动落一个可用目标，避免“装了但没发布”。"""
    if db.scalar("SELECT COUNT(*) FROM publish_targets"):
        return
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    detected = detect_strongswan()
    dirs = ensure_swanctl_dirs()
    if dirs["errors"]:
        print(f"[警告] 创建 strongSwan 目录失败：{dirs['errors']}")
    picked = []
    for t in suggested_targets():
        if t["path"] == str(STAGING_DIR):
            picked.append(t)
    # 只有本机确实装了 strongSwan 才自动加 /etc 目标（否则会指向不存在的目录）
    if config.RUN_AS_ROOT and config.MANAGE_STRONGSWAN and swanctl_available():
        for t in swanctl_targets():
            picked.append(t)
    # 注意：这里**故意不**把 suggested_targets() 里的 /etc 变体自动写进去。
    # 否则首次安装会在 /etc/swanctl 里同时生成
    #   · 设置驱动的直写目标（crl.der 等，正在用的那份）
    #   · 建议目标里的 PEM/legacy 变体（example-ca.crl.pem、example-ca.crt.pem…）
    # 同一 CA 出现多份 CRL/CA 证书会让 charon 的 CRL 选择变得不确定（现场踩过：
    # 编号更大的旧 CRL 遮蔽新 CRL，"吊销了但重连照样通过"）。
    # 建议目标仍然可以在界面上按需勾选创建。
    with db.tx() as conn:
        conn.executemany(
            "INSERT INTO publish_targets(name,kind,path,filename,format,content,reload_cmd,"
            "enabled,mode,owner,create_dir,only_if_changed,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(t["name"], t["kind"], t["path"], t["filename"], t["format"],
              t.get("content", "crl"), t["reload_cmd"], t["enabled"], t["mode"],
              t["owner"], 1 if t.get("create_dir") else 0,
              1 if t.get("only_if_changed", True) else 0, _now()) for t in picked])


# ------------------------------------------------------------------ 目标 CRUD
def list_targets() -> list[dict]:
    rows = db.q("SELECT * FROM publish_targets ORDER BY id")
    for r in rows:
        r["enabled"] = int(r["enabled"])
        last = db.q1("SELECT * FROM publish_log WHERE target_id=? ORDER BY id DESC LIMIT 1",
                     (r["id"],))
        r["last_publish_at"] = last["ts"] if last else None
        r["last_ok"] = bool(last["ok"]) if last else None
        r["last_message"] = last["message"] if last else None
    return rows


def get_target(tid: int) -> dict | None:
    return db.q1("SELECT * FROM publish_targets WHERE id=?", (tid,))


def default_filename(content: str, fmt: str) -> str:
    """按内容类型与格式给出默认文件名（创建/更新发布目标共用）。"""
    content = (content or "crl").lower()
    fmt = (fmt or "der").lower()
    return {
        "crl": f"{DEFAULT_CA_NAME}.crl.pem" if fmt == "pem" else f"{DEFAULT_CA_NAME}.crl",
        "ca_cert": (f"{DEFAULT_CA_NAME}.crt.pem" if fmt == "pem"
                    else f"{DEFAULT_CA_NAME}.crt"),
        "ca_chain": (f"{DEFAULT_CA_NAME}-chain.pem" if fmt == "pem"
                     else f"{DEFAULT_CA_NAME}.crt"),
    }.get(content, f"{DEFAULT_CA_NAME}.out")


def create_target(data: dict) -> dict:
    name = (data.get("name") or "").strip()
    path = (data.get("path") or "").strip()
    if not name or not path:
        raise CertError("名称与路径不能为空")
    fmt = (data.get("format") or "der").lower()
    if fmt not in ("der", "pem"):
        raise CertError("格式只能是 der 或 pem")
    content = (data.get("content") or "crl").lower()
    if content not in CONTENTS:
        raise CertError(f"发布内容只能是 {'/'.join(CONTENTS)}")
    filename = (data.get("filename") or "").strip() or default_filename(content, fmt)
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO publish_targets(name,kind,path,filename,format,content,reload_cmd,"
            "enabled,mode,owner,create_dir,only_if_changed,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, data.get("kind") or "dir_file", path, filename, fmt, content,
             (data.get("reload_cmd") or "").strip(), 1 if data.get("enabled", True) else 0,
             str(data.get("mode") or "0644"), (data.get("owner") or "").strip() or None,
             1 if data.get("create_dir") else 0,
             1 if data.get("only_if_changed", True) else 0, _now()))
        tid = cur.lastrowid
        audit.log("publish.target.create", target_type="publish_target", target_id=tid,
                  target_label=name, detail={"path": path, "filename": filename, "format": fmt,
                                             "content": content}, conn=conn)
    return get_target(tid)


def update_target(tid: int, data: dict) -> dict:
    row = get_target(tid)
    if row is None:
        raise CertError("发布目标不存在")
    if data.get("content") and str(data["content"]).lower() not in CONTENTS:
        raise CertError(f"发布内容只能是 {'/'.join(CONTENTS)}")
    if data.get("format") and str(data["format"]).lower() not in ("der", "pem"):
        raise CertError("格式只能是 der 或 pem")
    fields, args = [], []
    # 文件名/格式允许留空：留空时按（可能同时变更的）内容与格式推导默认值，
    # 避免把 filename 写成空串——那样会试图把文件写到目录自身而失败。
    new_content = str(data.get("content") or row["content"]).lower()
    new_format = str(data.get("format") or row["format"]).lower()
    if "filename" in data and not str(data.get("filename") or "").strip():
        data = dict(data, filename=default_filename(new_content, new_format))
    if "format" in data and not str(data.get("format") or "").strip():
        data = dict(data, format=new_format)
    if "format" in data:
        data = dict(data, format=str(data["format"]).lower())
    if "content" in data:
        data = dict(data, content=str(data["content"]).lower())
    for key in ("name", "kind", "path", "filename", "format", "content", "reload_cmd", "mode",
                "owner"):
        if key in data and data[key] is not None:
            fields.append(f"{key}=?")
            args.append(str(data[key]))
    if "enabled" in data:
        fields.append("enabled=?")
        args.append(1 if data["enabled"] else 0)
    if "create_dir" in data:
        fields.append("create_dir=?")
        args.append(1 if data["create_dir"] else 0)
    if "only_if_changed" in data:
        fields.append("only_if_changed=?")
        args.append(1 if data["only_if_changed"] else 0)
    if "shadow_ok" in data:
        fields.append("shadow_ok=?")
        args.append(1 if data["shadow_ok"] else 0)
    if not fields:
        return row
    args.append(tid)
    with db.tx() as conn:
        conn.execute(f"UPDATE publish_targets SET {', '.join(fields)} WHERE id=?", args)
        audit.log("publish.target.update", target_type="publish_target", target_id=tid,
                  target_label=row["name"], detail=data, conn=conn)
    return get_target(tid)


def delete_target(tid: int) -> None:
    row = get_target(tid)
    if row is None:
        raise CertError("发布目标不存在")
    with db.tx() as conn:
        conn.execute("DELETE FROM publish_targets WHERE id=?", (tid,))
        audit.log("publish.target.delete", target_type="publish_target", target_id=tid,
                  target_label=row["name"], conn=conn)


def test_target(tid: int) -> dict:
    row = get_target(tid)
    if row is None:
        raise CertError("发布目标不存在")
    if row["kind"] == "command":
        return {"ok": True, "writable": True, "resolved_path": row["path"],
                "message": "命令型目标，将在发布时执行"}
    resolved = _resolve_dir(row["path"])
    exists = resolved.is_dir()
    writable = (os.access(resolved, os.W_OK) if exists
                else os.access(resolved.parent if resolved.parent.exists() else resolved, os.W_OK))
    msg = []
    if not exists and writable:
        msg.append(f"目录尚不存在，但父目录可写，发布时会自动创建：{resolved}")
    elif not exists:
        msg.append(f"目录不存在且父目录不可写：{resolved}")
    if not writable:
        msg.append("当前服务用户对该目录没有写权限（需要 root 或改用暂存目录 + 同步脚本）")
    if not msg:
        msg.append(f"目录可写：{resolved}")
    return {"ok": bool(writable), "writable": bool(writable), "exists": exists,
            "resolved_path": str(resolved), "message": "；".join(msg)}


def _resolve_dir(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()


# ------------------------------------------------------------------ 发布
def _crl_bytes(fmt: str) -> bytes:
    row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if row is None:
        raise CertError("尚未生成任何 CRL")
    rel = row["path"] if fmt == "pem" else row["der_path"]
    target = config.DATA_DIR / rel
    if not target.exists():
        raise CertError(f"CRL 文件缺失: {target}")
    return target.read_bytes()


CONTENTS = ("crl", "ca_cert", "ca_chain")


def content_label(content: str) -> str:
    return {"crl": "CRL 吊销列表", "ca_cert": "CA 证书",
            "ca_chain": "CA 证书链"}.get(content or "crl", content)


def _unchanged(target: dict, resolved, payload: bytes) -> bool:
    """目标文件已存在且内容一致 -> 视为未变化（跳过写入与重载）。"""
    if str(target.get("only_if_changed", 1)) in ("0", "False", "false"):
        return False
    try:
        path = Path(resolved) / str(target.get("filename") or "")
        if not path.is_file():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == \
            hashlib.sha256(payload).hexdigest()
    except OSError:
        return False


def last_reload_at() -> str | None:
    return db.get_setting("last_reload_at")


def _last_reload_failed() -> bool:
    """上一次重载是否失败（失败就要重试，且不受最小间隔限制）。"""
    return str(db.get_setting("last_reload_ok", "1")) == "0"


def _reload_allowed(urgent: bool = False) -> tuple[bool, str]:
    """最小间隔保护：避免短时间内反复重载 strongSwan。

    ``urgent=True``（吊销/导入 CRL 导致的变化）**不受最小间隔限制**：
    吊销的意义就是"立刻失效"，若被节流挡掉，charon 会继续用旧 CRL，
    表现为"吊销了但对方还能连"（现场踩过：只有手动重启 strongSwan 才生效）。
    """
    try:
        gap = int(db.get_setting("reload_min_interval_seconds", "30") or 30)
    except ValueError:
        gap = 30
    if gap <= 0 or urgent or _last_reload_failed():
        return True, ""
    last = x509util.parse_iso(last_reload_at())
    if last is None:
        return True, ""
    elapsed = (x509util.now() - last).total_seconds()
    if elapsed < gap:
        return False, (f"距上次重载仅 {int(elapsed)} 秒（最小间隔 {gap} 秒），"
                       f"本次只更新文件、不重载 strongSwan")
    return True, ""


def payload_bytes(target: dict) -> bytes:
    """按目标配置取出要发布的内容（CRL / CA 证书 / CA 证书链）。"""
    content = (target.get("content") or "crl").lower()
    fmt = (target.get("format") or "der").lower()
    if content == "crl":
        return _crl_bytes(fmt)
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA")
    cert = ca.x509util.load_cert(ca._path(ca_row["cert_path"]).read_bytes())
    if content == "ca_cert":
        return (ca.x509util.pem_cert(cert).encode() if fmt == "pem"
                else ca.x509util.der_cert(cert))
    if content == "ca_chain":
        text = ca.x509util.pem_cert(cert)
        if ca_row.get("chain_path") and ca._path(ca_row["chain_path"]).exists():
            text += ca._path(ca_row["chain_path"]).read_text()
        if fmt == "pem":
            return text.encode()
        return ca.x509util.der_cert(cert)   # DER 只能承载单张证书
    raise CertError(f"未知的发布内容类型: {content}")


def guard_skips(targets: list[dict]) -> dict[int, str]:
    """返回本轮会被跳过的目录目标；暂存目录允许不同文件名并存。"""
    def _norm(d: str) -> str:
        try:
            return str(os.path.normpath(str(_resolve_dir(d))))
        except Exception:  # noqa: BLE001
            return str(d)

    cfg_now = swanctl_settings()
    staging_dir = _norm(str(STAGING_DIR))
    prefer = {("crl", _norm(str(cfg_now["crl_dir"]))): str(cfg_now.get("crl_filename") or ""),
              ("ca_cert", _norm(str(cfg_now["ca_dir"]))): str(cfg_now.get("ca_cert_filename") or "")}
    skipped: dict[int, str] = {}
    winner: dict[tuple[str, ...], dict] = {}
    for t in targets:
        if t["kind"] != "dir_file":
            continue
        content = t.get("content") or "crl"
        if content == "ca_cert" and not cfg_now.get("publish_ca_cert"):
            skipped[t["id"]] = (
                "设置 publish_ca_cert=0（默认不发布 CA 证书），本目标已跳过；"
                "需要把 CA 证书分发到 strongSwan 时，在「CRL 自动发布」页勾选，"
                "或 cli targets --disable <id> 停用该目标")
            continue
        if t.get("shadow_ok"):
            continue
        directory = _norm(str(t["path"]))
        # 暂存目录不由 charon 扫描；同步单元只取设置指定格式的一个文件。
        # DER/PEM 可在这里并存，相同文件名仍只能由一个目标写入。
        key = ((content, directory, str(t["filename"])) if directory == staging_dir
               else (content, directory))
        cur = winner.get(key)
        if cur is None:
            winner[key] = t
            continue
        want_name = prefer.get((content, directory), "")
        cur_matches = bool(want_name) and cur["filename"] == want_name
        new_matches = bool(want_name) and t["filename"] == want_name
        keep_new = new_matches and not cur_matches
        lose = cur if keep_new else t
        win = t if keep_new else cur
        if keep_new:
            winner[key] = t
        if directory == staging_dir:
            skipped[lose["id"]] = (
                f"暂存目录中 {win['filename']} 已由另一个目标写入；"
                f"同名目标 {lose['filename']} 已跳过。请停用或删除重复目标")
        else:
            skipped[lose["id"]] = (
                f"同一目录已有一份{content_label(content)}（{win['filename']}）；"
                f"为避免 charon 在「用哪一份」上产生不确定，本目标（{lose['filename']}）已跳过。"
                f"请停用或删除该目标： cli targets  /  cli targets --keep-single")
    return skipped


def publish(trigger: str = "manual", reload: bool = True, actor: str = "admin",
            reload_urgent: bool | None = None) -> dict:
    """把 CRL / CA 证书发布到所有启用的目标，并（可选）重载 strongSwan。"""
    targets = [t for t in list_targets() if t["enabled"]]
    crl = ca.current_crl()
    if crl is None and any((t.get("content") or "crl") == "crl" for t in targets):
        raise CertError("尚未生成 CRL，请先生成 CRL（或先关闭 CRL 类型的发布目标）")
    # 吊销/导入 CRL 类触发源一律视为"紧急"，不受最小重载间隔限制
    if reload_urgent is None:
        # 吊销、**恢复**、导入 CRL、临期 都必须立即生效，不受最小重载间隔限制
        reload_urgent = any(k in str(trigger).lower()
                            for k in ("revoke", "unrevoke", "import", "expire"))
    results: list[dict] = []
    env_extra = {"CA_CRL_ID": str(crl["id"]) if crl else "",
                 "CA_CRL_NUMBER": str(crl["number"]) if crl else ""}
    # 同一轮里相同命令只重载一次（之前每个目标各重载一次，是"总是重载"的主因之一）
    pending_reloads: list[str] = []

    # 同一 strongSwan 目录出现多份 CRL 会使 charon 的选择不确定。
    # 暂存目录例外：同步脚本只读取设置指定的一份 CRL。
    guard_skip = guard_skips(targets)
    staging_dir = str(_resolve_dir(str(STAGING_DIR)))

    for t in targets:
        sha = ""
        path_display = t["path"]
        if t["id"] in guard_skip:
            msg = guard_skip[t["id"]]
            _log(target_id=t["id"], target_name=t["name"], path=path_display, sha256="",
                 ok=1, message=msg, reload_output="", trigger=trigger,
                 crl_id=crl["id"] if crl else None, actor=actor)
            results.append({"target_id": t["id"], "target_name": t["name"],
                            "path": path_display, "content": t.get("content") or "crl",
                            "sha256": "", "ok": True, "message": msg,
                            "reload_output": "", "skipped": True, "shadow_guard": True})
            continue
        reload_output = ""
        try:
            payload = payload_bytes(t)
            sha = hashlib.sha256(payload).hexdigest()
            if t["kind"] == "command":
                rc, out = _run_command(t["path"], env_extra | {"CA_CRL_SHA256": sha})
                ok = rc == 0
                message = "命令执行成功" if ok else f"命令退出码 {rc}"
                reload_output = out
            else:
                resolved = _resolve_dir(t["path"])
                if not resolved.is_dir():
                    if t.get("create_dir") or _within_data(resolved):
                        resolved.mkdir(parents=True, exist_ok=True)
                    else:
                        # 目录不存在 = 本机不用这种布局（例如 swanctl 布局下的 /etc/ipsec.d）
                        # → 记为"跳过"，不要报成红色失败，否则真问题会被淹没
                        ok, message, path_display = True, (
                            f"目标目录不存在（{resolved}），本机不使用该布局，已跳过"), ""
                        _log(target_id=t["id"], target_name=t["name"], path=str(resolved),
                             sha256="", ok=1, message=f"[{content_label(t.get('content'))}] "
                             "目标目录不存在，已跳过", reload_output="", trigger=trigger,
                             crl_id=crl["id"] if crl else None, actor=actor)
                        results.append({"target_id": t["id"], "target_name": t["name"],
                                        "path": str(resolved),
                                        "content": t.get("content") or "crl", "sha256": "",
                                        "ok": True, "message": message, "reload_output": "",
                                        "skipped": True, "unavailable": True})
                        continue
                if _unchanged(t, resolved, payload):
                    # 内容与磁盘一致：不写；通常也不重载。
                    # 例外：**上一次重载失败过**（退出码非 0）→ 文件是新但 charon 没加载，
                    # 必须重试重载，否则会永久停留在"文件新、charon 旧"的状态（审查发现）。
                    ok = True
                    if reload and _last_reload_failed():
                        cmd = (t.get("reload_cmd") or "").strip()
                        if cmd and cmd not in pending_reloads:
                            pending_reloads.append(cmd)
                        message = "内容未变化，但上次重载失败 → 重试重载"
                    else:
                        message = "内容未变化，已跳过（不重载）"
                    path_display = str(resolved / str(t.get("filename") or ""))
                    _log(target_id=t["id"], target_name=t["name"], path=path_display,
                         sha256=sha, ok=1, message=f"[{content_label(t.get('content'))}] {message}",
                         reload_output="", trigger=trigger,
                         crl_id=crl["id"] if crl else None, actor=actor)
                    results.append({"target_id": t["id"], "target_name": t["name"],
                                    "path": path_display, "content": t.get("content") or "crl",
                                    "sha256": sha, "ok": True, "message": message,
                                    "reload_output": "", "skipped": True})
                    continue
                final = resolved / t["filename"]
                # 原子写：临时文件 + rename，避免 charon 读到半截 CRL
                tmp = final.with_name(f".{final.name}.tmp{os.getpid()}")
                with open(tmp, "wb") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                try:
                    os.chmod(tmp, int(str(t["mode"] or "0644"), 8))
                except (OSError, ValueError):
                    pass
                if t.get("owner"):
                    try:
                        import grp
                        import pwd
                        user, _, group = str(t["owner"]).partition(":")
                        os.chown(tmp, pwd.getpwnam(user).pw_uid,
                                 grp.getgrnam(group).gr_gid if group else -1)
                    except Exception:  # noqa: BLE001 - 非 root 时忽略
                        pass
                os.replace(tmp, final)
                ok, message, path_display = True, "已写入", str(final)
                cmd = (t.get("reload_cmd") or "").strip()
                if reload and cmd:
                    reload_output = "（待统一重载）"
                    if cmd not in pending_reloads:
                        pending_reloads.append(cmd)
        except Exception as exc:  # noqa: BLE001 - 逐个目标独立成败
            ok, message = False, f"{type(exc).__name__}: {exc}"
            # EROFS / EPERM / EACCES / 伪文件系统拒绝创建（如 /proc，返回 ENOENT）
            if isinstance(exc, OSError) and exc.errno in (30, 13, 1, 2):
                message = (
                    f"目标目录不可写：{path_display}（{exc.strerror or exc}）。"
                    f"服务以 systemd 沙箱运行（ProtectSystem=strict），只有"
                    f" ReadWritePaths 里的目录可写。若本机确实使用该布局，请把该目录加入"
                    f"服务的可写路径（例如 deploy/ca-admin-root.service 里的"
                    f" ReadWritePaths=-/etc/ipsec.d），或在本页停用/删除该目标。"
                    f"原始错误：{type(exc).__name__}: {exc}")

        _log(target_id=t["id"], target_name=t["name"], path=path_display, sha256=sha,
             ok=1 if ok else 0, message=f"[{content_label(t.get('content'))}] {message}",
             reload_output=reload_output, trigger=trigger,
             crl_id=crl["id"] if crl else None, actor=actor)
        results.append({"target_id": t["id"], "target_name": t["name"], "path": path_display,
                        "content": t.get("content") or "crl", "sha256": sha, "ok": ok,
                        "message": message, "reload_output": reload_output})

    # ---- 统一重载：去重 + 最小间隔，避免反复重载 strongSwan ----
    reload_report = {"commands": [], "skipped": False, "reason": ""}
    changed = [r for r in results if r["ok"] and not r.get("skipped")]
    # 上次重载失败时，即使本轮文件内容都没变，也必须重试重载（否则永久"文件新/charon 旧"）
    if reload and pending_reloads and (changed or _last_reload_failed()):
        allowed, why = _reload_allowed(urgent=reload_urgent)
        if allowed:
            for cmd in pending_reloads:
                rc, out = _run_command(cmd, env_extra)
                reload_report["commands"].append({"cmd": cmd, "rc": rc, "output": out,
                                                  "ok": rc == 0})
                for r in results:
                    if r["ok"] and not r.get("skipped"):
                        r["reload_output"] = out if r["reload_output"] == "（待统一重载）" else \
                            (r["reload_output"] or out)
                if rc != 0:
                    for r in results:
                        if r["ok"] and not r.get("skipped"):
                            r["message"] += f"；重载命令失败（退出码 {rc}）"
            all_ok = bool(reload_report["commands"]) and all(
                c["ok"] for c in reload_report["commands"])
            # 只有**真正重载成功**才推进"上次重载时间"：否则节流会把重试挡在 30 秒外，
            # 而"文件内容未变"的判定又会让它永远不再尝试重载。
            if all_ok:
                db.set_setting("last_reload_at", x509util.to_iso(x509util.now()))
                db.set_setting("last_reload_ok", "1")
            else:
                db.set_setting("last_reload_ok", "0")
                reload_report["failed"] = True
        else:
            reload_report["skipped"] = True
            reload_report["reason"] = why
            for r in results:
                if r["ok"] and not r.get("skipped"):
                    r["reload_output"] = why
        # 重载结果补写审计（便于排查"为什么反复重载"）
        audit.log("crl.reload", target_type="crl", target_id=(crl["id"] if crl else None),
                  actor=actor, detail={"trigger": trigger, "commands": reload_report["commands"],
                                       "skipped": reload_report["skipped"],
                                       "reason": reload_report["reason"]})
    elif reload and pending_reloads and not changed:
        reload_report["skipped"] = True
        reload_report["reason"] = "所有目标内容均未变化，无需重载"

    notices: list[str] = []
    for t in targets:
        if t["kind"] != "dir_file" or (t.get("content") or "crl") != "crl":
            continue
        if str(_resolve_dir(str(t["path"]))) == staging_dir:
            continue  # 暂存目录可同时保存 DER/PEM，不是 strongSwan 消费目录
        info = inspect_dir(t["path"])
        extra = [f for f in info["files"]
                 if f["kind"] == "crl" and f["name"] != t["filename"]]
        if extra:
            notices.append(
                f"{t['path']} 里还有其它 CRL 文件：{', '.join(f['name'] for f in extra)}；"
                f"如果它们属于同一个 CA，请在 strongSwan 侧删掉或让本系统改为覆盖同一文件名，"
                f"否则可能出现“同一 CA 两份 CRL”。")
    if trigger != "auto" or any(r["ok"] for r in results):
        audit.log("crl.publish", target_type="crl", target_id=(crl["id"] if crl else None),
                  target_label=f"CRL #{crl['number']}" if crl else "CA 证书同步", actor=actor,
                  detail={"trigger": trigger, "results": [
                      {"target": r["target_name"], "ok": r["ok"], "message": r["message"]}
                      for r in results]})
    return {"crl": crl, "results": results, "notices": notices, "reload": reload_report}


def _run_command(cmd: str, env_extra: dict[str, str]) -> tuple[int, str]:
    env = dict(os.environ)
    env.update({k: str(v) for k, v in env_extra.items()})
    row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if row is not None:
        env["CA_CRL_PEM_FILE"] = str(config.DATA_DIR / row["path"]) if row["path"] else ""
        env["CA_CRL_DER_FILE"] = str(config.DATA_DIR / row["der_path"]) if row["der_path"] else ""
    # 含 shell 元字符（&& ; | $ 等）时用 sh -c 执行，便于配置
    # "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan" 这类组合命令
    use_shell = any(ch in cmd for ch in ";&|<>$`")
    argv = ["sh", "-c", cmd] if use_shell else shlex.split(cmd)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                              env=env, shell=False)
    except FileNotFoundError:
        return 127, f"命令不存在: {cmd.split()[0]}"
    except subprocess.TimeoutExpired:
        return 124, "命令执行超时（60s）"
    except Exception as exc:  # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode, out[:4000]


# ------------------------------------------------------------------ 健康状态
def status() -> dict:
    crl = ca.current_crl()
    lead = int(db.get_setting("auto_publish_lead_hours", "72") or 72)
    auto = db.get_setting("auto_publish", "1") == "1"
    interval = int(db.get_setting("auto_publish_interval_minutes", "60") or 60)
    auto_reload = db.get_setting("auto_reload", "1") == "1"
    revoked_count = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked' AND ca_id=?",
                              ((ca.active_ca_row() or {}).get("id", -1),))
    due_in_hours = None
    health = "ok"
    problems: list[str] = []
    ca_row = ca.active_ca_row()

    if crl is None:
        health, due_in_hours = "critical", None
        problems.append("尚未生成 CRL，strongSwan 无法判断吊销状态")
    else:
        nu = x509util.parse_iso(crl["next_update"])
        if nu is None:
            health = "warning"
            problems.append("CRL 的 nextUpdate 无法解析")
        else:
            due_in_hours = round((nu - x509util.now()).total_seconds() / 3600, 1)
            if due_in_hours < 0:
                health = "critical"
                problems.append(f"CRL 已过期 {abs(due_in_hours):.1f} 小时，strongSwan 会判定其不可用")
            elif due_in_hours < lead:
                health = "critical" if due_in_hours < 6 else "warning"
                problems.append(f"CRL 将在 {due_in_hours} 小时后过期，自动续签阈值为 {lead} 小时")
        if crl["entries"] != revoked_count:
            if health == "ok":
                health = "warning"
            problems.append(f"CRL 条目数({crl['entries']})与已吊销证书数({revoked_count})不一致，"
                            f"需重新生成")
    if ca_row is None:
        health = "critical"
        problems.append("尚未导入 CA")
    elif not ca_row["has_key"]:
        health = "critical"
        problems.append("CA 私钥未导入，无法生成或续签 CRL")

    last = db.q1("SELECT * FROM publish_log ORDER BY id DESC LIMIT 1")
    enabled = db.scalar("SELECT COUNT(*) FROM publish_targets WHERE enabled=1")
    if enabled == 0 and health == "ok":
        health = "warning"
        problems.append("没有任何启用的 CRL 发布目标")
    elif last is None and enabled:
        if health == "ok":
            health = "warning"
        problems.append("从未发布过 CRL")
    elif last is not None and not last["ok"]:
        if health == "ok":
            health = "warning"
        problems.append(f"上次发布失败：{last['message']}")

    cfg = swanctl_settings()
    warnings: list[str] = []
    if config.RUN_AS_ROOT and not config.MANAGE_STRONGSWAN:
        warnings.append("以 root 运行但 CA_MANAGE_STRONGSWAN=0，不会直接写 /etc/swanctl")
    if not config.RUN_AS_ROOT:
        etc_targets = [t for t in list_targets()
                       if t["enabled"] and str(t["path"]).startswith("/etc/")]
        if etc_targets:
            warnings.append("当前以非 root 运行，但存在启用的 /etc 发布目标，这些目标会失败；"
                            "请以 root 运行，或改用暂存目录 + ca-strongswan-sync 单元。")
    return {
        "running_as_root": config.RUN_AS_ROOT,
        "manage_strongswan": config.MANAGE_STRONGSWAN,
        "swanctl_dir": cfg["dir"],
        "consumption": cfg,
        "warnings": warnings,
        "auto_publish": auto,
        "lead_hours": lead,
        "interval_minutes": interval,
        "auto_reload": auto_reload,
        "crl": crl,
        "due_in_hours": due_in_hours,
        "health": health,
        "problems": problems,
        "revoked_count": revoked_count,
        "enabled_targets": enabled,
        "strongswan": detect_strongswan(),
        "last_publish": ({"ts": last["ts"], "target_name": last["target_name"],
                          "ok": bool(last["ok"]), "message": last["message"],
                          "trigger": last["trigger"]} if last else None),
    }


# ------------------------------------------------------------------ 自动续签调度
class Scheduler:
    """轻量后台调度器：定期检查 CRL 是否需要重新生成/发布。"""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_check: str | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="crl-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    @property
    def last_check(self) -> str | None:
        return self._last_check

    def _loop(self) -> None:
        # 启动后稍等，避免和初始化抢锁
        self._stop.wait(5)
        while not self._stop.is_set():
            try:
                self.tick("auto")
            except Exception as exc:  # noqa: BLE001 - 调度线程绝不能死
                try:
                    db.set_setting("last_auto_error", f"{_now()} {type(exc).__name__}: {exc}")
                except Exception:  # noqa: BLE001
                    pass
            # 通用自动化任务（定时 / CRL 到期前）由同一个线程驱动，避免多线程竞争
            try:
                from . import automation
                automation.run_due()
            except Exception as exc:  # noqa: BLE001
                try:
                    db.set_setting("last_automation_error",
                                   f"{_now()} {type(exc).__name__}: {exc}")
                except Exception:  # noqa: BLE001
                    pass
            interval = 60
            try:
                interval = max(1, int(db.get_setting("auto_publish_interval_minutes", "60") or 60))
            except ValueError:
                pass
            self._stop.wait(interval * 60)

    def tick(self, trigger: str = "auto") -> dict:
        """执行一次检查；返回做了什么。"""
        self._last_check = _now()
        db.set_setting("last_auto_check", self._last_check)
        if db.get_setting("auto_publish", "1") != "1":
            return {"action": "disabled"}
        ca_row = ca.active_ca_row()
        if ca_row is None or not ca_row["has_key"]:
            return {"action": "no_key"}

        lead = int(db.get_setting("auto_publish_lead_hours", "72") or 72)
        crl = ca.current_crl()
        need = None
        if crl is None:
            need = "missing"
        elif not crl["has_file"]:
            need = "missing_files"
        else:
            nu = x509util.parse_iso(crl["next_update"])
            if nu is None or (nu - x509util.now()).total_seconds() < lead * 3600:
                need = "expiring"
            else:
                newer = db.scalar(
                    "SELECT COUNT(*) FROM certs WHERE status='revoked' AND ca_id=? "
                    "AND revoked_at > ?", (ca_row["id"], crl["this_update"]))
                if newer:
                    need = "revocations_changed"
        if need is None:
            return {"action": "up_to_date"}

        ca.generate_crl(ca_row=ca_row, actor="scheduler", source=f"auto:{need}")
        reload_flag = db.get_setting("auto_reload", "1") == "1"
        result = publish(trigger=trigger, reload=reload_flag, actor="scheduler")
        return {"action": "regenerated_and_published", "reason": need,
                "crl": result["crl"], "results": result["results"]}


scheduler = Scheduler()
