"""数据一致性体检与自动修复。

系统的一致性模型
----------------
事实来源是 SQLite；磁盘上是证书/密钥/CRL 的 PEM 文件；外部还有 strongSwan 的 CRL 副本。
任何两者之间都可能“跑偏”，本模块负责把所有跑偏找出来并尽量修好：

* 库 → 盘：证书文件缺失、CRL 文件缺失
* 盘 → 库：孤儿文件、文件内容与库中指纹不符
* CA 与证书：签发者不匹配、签名验证失败、不是活动 CA 签发
* 吊销状态：CRL 条目数与已吊销数不一致、CRL 过期、CRL 未发布到 strongSwan
* 时间：状态为 valid 但已过期、吊销但缺吊销时间
* 安全：私钥文件权限过宽
* 序列号：顺序模式下计数器落后于已用序列号

每条问题都带 ``code`` / ``level`` / ``fixable``，前端可据此提供“一键修复”。
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import audit, ca, config, db, publish, x509util
from .x509util import CertError

LEVELS = ("error", "warning", "info")


def _issue(code: str, level: str, message: str, *, entity: str | None = None,
           fixable: bool = False, fix: str | None = None, extra: dict | None = None) -> dict:
    return {"code": code, "level": level, "message": message, "entity": entity,
            "fixable": fixable, "fix": fix, "extra": extra or {}}


def check() -> dict:
    issues: list[dict] = []
    ca_row = ca.active_ca_row()
    now = x509util.now()
    # 所有“被数据库引用”的文件都必须登记在这里，否则会被误判为孤儿文件
    referenced: set[str] = set()
    referenced_ca_files: set[str] = set()
    if ca_row:
        for rel in (ca_row.get("cert_path"), ca_row.get("key_path"), ca_row.get("chain_path")):
            if rel:
                p = ca._path(rel)
                if p.exists():
                    referenced_ca_files.add(str(p.resolve()))

    # ---- CA 自身
    if ca_row is None:
        issues.append(_issue("no_ca", "error", "尚未导入任何 CA 证书，系统无法签发与吊销",
                             fix="在「CA 管理」页导入 CA 证书与私钥"))
    else:
        ca_cert = None
        try:
            ca_cert, _, _chain = ca.load_material(ca_row)
        except Exception as exc:  # noqa: BLE001
            issues.append(_issue("ca_cert_unreadable", "error",
                                 f"CA 证书文件无法读取: {exc}", entity=ca_row["subject"]))
        if not ca_row["has_key"]:
            issues.append(_issue("ca_key_missing", "error",
                                 "CA 私钥未导入，无法签发证书、生成或续签 CRL",
                                 entity=ca_row["subject"], fix="在「CA 管理」导入 CA 私钥"))
        else:
            try:
                key_path = ca._path(ca_row["key_path"])
                key = x509util.load_key(key_path.read_bytes())
                if ca_cert is not None and x509util.fingerprint(ca_cert) != ca_row["fingerprint"]:
                    issues.append(_issue("ca_cert_mismatch", "error",
                                         "CA 证书文件与数据库记录不一致",
                                         entity=ca_row["subject"], fixable=True,
                                         fix="用磁盘文件刷新数据库记录"))
                from cryptography.hazmat.primitives import serialization
                a = key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
                b = ca_cert.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo)
                if a != b:
                    issues.append(_issue("ca_key_mismatch", "error",
                                         "CA 私钥与 CA 证书不匹配，签发出来的证书无法通过校验",
                                         entity=ca_row["subject"]))
                referenced_ca_files.add(str(key_path.resolve()))
                _check_key_permissions(key_path, issues, "CA 私钥")
            except Exception as exc:  # noqa: BLE001
                issues.append(_issue("ca_key_unreadable", "error",
                                     f"CA 私钥无法读取或口令不对: {exc}",
                                     entity=ca_row["subject"]))
        if x509util.days_remaining(x509util.parse_iso(ca_row["not_after"]) or now) < 0:
            issues.append(_issue("ca_expired", "error", "CA 证书已过期，必须更换 CA",
                                 entity=ca_row["subject"]))

    # ---- 证书与文件
    certs = db.q("SELECT * FROM certs ORDER BY id")
    for row in certs:
        label = f"#{row['id']} {row['cn'] or row['subject']}"
        cert_path = config.DATA_DIR / row["cert_path"] if row["cert_path"] else None
        if cert_path is None or not cert_path.exists():
            issues.append(_issue("cert_file_missing", "error",
                                 f"证书文件缺失，无法导出或校验：{row['cert_path']}",
                                 entity=label, extra={"cert_id": row["id"]}))
            continue
        referenced.add(str(cert_path.resolve()))
        if row["key_path"]:
            key_path = config.DATA_DIR / row["key_path"]
            # 私钥文件也必须登记，否则会被孤儿文件清理误删（曾出现的严重问题）
            if key_path.exists():
                referenced.add(str(key_path.resolve()))
            elif row["has_key"]:
                issues.append(_issue("key_file_missing", "error",
                                     f"数据库标记该证书有私钥，但私钥文件缺失：{row['key_path']}",
                                     entity=label, extra={"cert_id": row["id"]}))
        try:
            cert = x509util.load_cert(cert_path.read_bytes())
        except CertError as exc:
            issues.append(_issue("cert_file_invalid", "error", f"证书文件损坏: {exc}",
                                 entity=label, extra={"cert_id": row["id"]}))
            continue
        disk_fp = x509util.fingerprint(cert)
        if disk_fp != row["fingerprint"]:
            issues.append(_issue("fingerprint_mismatch", "error",
                                 f"磁盘证书指纹与数据库不一致（库 {row['fingerprint'][:23]}… / "
                                 f"盘 {disk_fp[:23]}…）", entity=label, fixable=True,
                                 fix="以磁盘文件为准刷新数据库", extra={"cert_id": row["id"]}))
        if row["status"] == "revoked" and not row["revoked_at"]:
            issues.append(_issue("revoked_without_date", "warning",
                                 "证书状态为已吊销但缺少吊销时间，CRL 会用当前时间代替",
                                 entity=label, fixable=True, fix="把吊销时间补为当前时间",
                                 extra={"cert_id": row["id"]}))
        na = x509util.parse_iso(row["not_after"]) or now
        if row["status"] == "valid" and na < now:
            issues.append(_issue("expired_but_valid", "warning",
                                 f"证书已于 {row['not_after']} 过期，但状态仍为“有效”",
                                 entity=label, fixable=True, fix="把状态更新为“已过期”",
                                 extra={"cert_id": row["id"]}))
        if row["ca_id"] and ca_row and row["ca_id"] != ca_row["id"]:
            issues.append(_issue("foreign_ca", "info",
                                 "该证书由历史上的其它 CA 签发，当前活动 CA 无法为其续期",
                                 entity=label, extra={"cert_id": row["id"]}))
        if row["key_path"]:
            kp = config.DATA_DIR / row["key_path"]
            if kp.exists():
                _check_key_permissions(kp, issues, f"证书私钥 {label}")
        # 签名校验（只在属于活动 CA 时做，避免历史 CA 误报）
        if ca_row and (row["ca_id"] == ca_row["id"] or row["issuer"] == ca_row["subject"]):
            res = ca.verify_cert(row, ca_row)
            if not res["ok"]:
                issues.append(_issue("signature_invalid", "error",
                                     f"证书签名校验失败：{res['reason']}", entity=label,
                                     extra={"cert_id": row["id"]}))

    # ---- 孤儿文件（只清理证书目录下既不在库里、也不是任何私钥的文件）
    referenced.add(str(config.DB_PATH.resolve()))
    referenced |= referenced_ca_files
    if config.CERT_DIR.exists():
        for p in config.CERT_DIR.rglob("*"):
            if p.is_file() and str(p.resolve()) not in referenced:
                issues.append(_issue("orphan_file", "warning",
                                     f"磁盘上存在数据库未登记的文件：{p.name}",
                                     entity=p.name, fixable=True, fix="删除该孤儿文件",
                                     extra={"path": str(p)}))

    # ---- CRL
    crl = ca.current_crl()
    revoked_count = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked' AND ca_id=?",
                              ((ca_row or {}).get("id", -1),))
    if crl is None:
        issues.append(_issue("crl_missing", "warning", "尚未生成 CRL，strongSwan 无法判断吊销状态",
                             fixable=bool(ca_row and ca_row["has_key"]),
                             fix="立即生成并发布 CRL"))
    else:
        if crl["entries"] != revoked_count:
            issues.append(_issue("crl_entries_mismatch", "warning",
                                 f"CRL 条目数({crl['entries']}) 与已吊销证书数({revoked_count}) "
                                 f"不一致，说明有吊销动作未反映到 CRL",
                                 fixable=True, fix="重新生成 CRL"))
        nu = x509util.parse_iso(crl["next_update"])
        if nu is None or nu < now:
            issues.append(_issue("crl_expired", "error",
                                 "CRL 已过期，strongSwan 会拒绝使用该 CRL",
                                 fixable=True, fix="重新生成并发布 CRL"))
        elif (nu - now).total_seconds() < 6 * 3600:
            issues.append(_issue("crl_expiring_soon", "warning",
                                 f"CRL 将在 {round((nu - now).total_seconds() / 3600, 1)} 小时后过期",
                                 fixable=True, fix="提前重新生成并发布 CRL"))
        row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
        for rel in ((row or {}).get("path"), (row or {}).get("der_path")):
            if rel and not (config.DATA_DIR / rel).exists():
                issues.append(_issue("crl_file_missing", "error",
                                     f"CRL 文件缺失：{rel}", fixable=True,
                                     fix="重新生成 CRL"))

    # ---- 发布到 strongSwan
    st = publish.status()
    if st["enabled_targets"] == 0:
        issues.append(_issue("no_publish_target", "warning",
                             "没有启用的 CRL 发布目标，strongSwan 拿不到最新 CRL",
                             fix="在「CRL 自动发布」页添加目标"))
    else:
        last_ok = db.q1("SELECT * FROM publish_log WHERE ok=1 ORDER BY id DESC LIMIT 1")
        if last_ok is None:
            issues.append(_issue("crl_never_published", "warning", "CRL 从未成功发布过",
                                 fixable=True, fix="立即发布 CRL"))
        elif crl and last_ok["crl_id"] != crl["id"]:
            issues.append(_issue("crl_not_published", "warning",
                                 f"当前 CRL #{crl['number']} 尚未发布到所有目标",
                                 fixable=True, fix="立即发布 CRL"))
        last = db.q1("SELECT * FROM publish_log ORDER BY id DESC LIMIT 1")
        if last is not None and not last["ok"]:
            issues.append(_issue("publish_failed", "warning",
                                 f"上次发布失败：{last['message']}",
                                 entity=last["target_name"], fixable=True, fix="重试发布"))
        enabled = [t for t in publish.list_targets() if t["enabled"]]
        shadowed = publish.guard_skips(enabled)
        for t in enabled:
            if not t["enabled"] or t["kind"] != "dir_file":
                continue
            res = publish.test_target(t["id"])
            if not res["ok"]:
                issues.append(_issue("publish_target_unwritable", "warning",
                                     f"发布目标「{t['name']}」不可写：{res['message']}",
                                     entity=t["name"], extra={"target_id": t["id"]}))
            if (t.get("content") or "crl") != "crl":
                continue
            if t["id"] in shadowed:
                issues.append(_issue("crl_target_skipped", "warning",
                                     f"启用的目标「{t['name']}」被发布护栏跳过：{shadowed[t['id']]}",
                                     entity=t["name"], extra={"target_id": t["id"]}))
                continue
            if crl is None:
                continue
            folder = publish._resolve_dir(t["path"])
            if not folder.is_dir():
                continue  # 与发布和 crl-info 一致：本机不用这种目录布局
            target_file = folder / t["filename"]
            try:
                wanted = publish.payload_bytes(t)
            except (CertError, OSError, ValueError) as exc:
                issues.append(_issue("crl_target_check_failed", "warning",
                                     f"无法核对目标「{t['name']}」的应发布内容：{exc}",
                                     entity=t["name"], extra={"target_id": t["id"]}))
                continue
            try:
                actual = target_file.read_bytes()
            except FileNotFoundError:
                issues.append(_issue("crl_target_missing", "error",
                                     f"启用的 CRL 目标「{t['name']}」文件缺失：{target_file}",
                                     entity=t["name"], fixable=True, fix="重新发布当前 CRL",
                                     extra={"target_id": t["id"]}))
                continue
            except OSError as exc:
                issues.append(_issue("crl_target_unreadable", "error",
                                     f"启用的 CRL 目标「{t['name']}」无法读取：{exc}",
                                     entity=t["name"], extra={"target_id": t["id"]}))
                continue
            if actual != wanted:
                issues.append(_issue("crl_target_mismatch", "error",
                                     f"启用的 CRL 目标「{t['name']}」与当前 CRL 内容不一致："
                                     f"{target_file}", entity=t["name"], fixable=True,
                                     fix="重新发布当前 CRL", extra={"target_id": t["id"]}))
    if ca_row and not (db.get_setting("crl_url") or "").strip():
        issues.append(_issue("crl_url_unset", "info",
                             "未设置 CRL 分发点(CDP) URL，新签发证书不会包含 CRL 下载地址，"
                             "远端 strongSwan 只能依赖手动分发的 CRL",
                             fix="在「设置」中填写 CRL 分发点 URL"))

    # ---- 数据目录与敏感文件权限（其他用户不得读取 root 的数据） ----
    try:
        import stat as _stat
        mode = _stat.S_IMODE(config.DATA_DIR.stat().st_mode)
        if mode & 0o077:
            issues.append(_issue("data_dir_permissions", "warning",
                                 f"数据目录权限过宽（{oct(mode)}），其他用户可能读到私钥/会话密钥",
                                 entity=str(config.DATA_DIR), fixable=True,
                                 fix="收紧为 0700（必要时 chown root:root）"))
        for p in (config.CHANNEL_KEY_FILE, config.SECRET_FILE, config.INITIAL_PW_FILE):
            if p.exists() and (_stat.S_IMODE(p.stat().st_mode) & 0o077):
                issues.append(_issue("secret_file_permissions", "warning",
                                     f"敏感文件权限过宽：{p.name}",
                                     entity=str(p), fixable=True, fix="收紧为 0600"))
    except OSError:
        pass

    # ---- 序列号计数器
    if ca_row:
        counter = db.q1("SELECT next_serial FROM serial_counter WHERE ca_id=?", (ca_row["id"],))
        if counter:
            max_seq = db.scalar(
                "SELECT MAX(CAST(serial_hex AS INTEGER)) FROM certs WHERE ca_id=? "
                "AND LENGTH(serial_hex)<=15", (ca_row["id"],))
            try:
                if max_seq and int(counter["next_serial"]) <= int(max_seq):
                    issues.append(_issue("serial_counter_behind", "warning",
                                         f"顺序序列号计数器({counter['next_serial']})不大于已用最大值"
                                         f"({max_seq})，继续签发可能重号", fixable=True,
                                         fix="把计数器推进到最大值之后"))
            except (TypeError, ValueError):
                pass

    # CRL 编号唯一性（跨进程取号竞态的历史遗留；编号重复会让 strongSwan 无法替换 CRL）
    try:
        dup = db.q("SELECT ca_id, number, COUNT(*) AS n FROM crls GROUP BY ca_id, number "
                   "HAVING n > 1")
        if dup:
            issues.append(_issue("crl_number_duplicate", "error",
                                 "存在重复的 CRL 编号（strongSwan 只按编号大小替换，"
                                 "重复会导致某份 CRL 永远不生效）："
                                 + "、".join(f"ca={d['ca_id']} #{d['number']}×{d['n']}"
                                             for d in dup[:5]),
                                 fix="重新生成一份 CRL 即可继续递增（旧重复行可保留）"))
        if db.get_setting("crl_number_duplicate_index_failed"):
            issues.append(_issue("crl_number_unique_index_missing", "warning",
                                 "crls 表上的唯一索引未能建立（历史重复编号）",
                                 fix="确认上面没有重复编号后重启一次服务即可自动建立"))
    except Exception as exc:  # noqa: BLE001
        issues.append(_issue("crl_number_check_failed", "warning",
                             f"未能检查 CRL 编号唯一性：{exc}"))

    # 每条 CRL 记录指向的文件必须存在，且**文件里的编号/校验值与数据库一致**
    # （审查故障注入：DB=#4 而 PEM/DER 已是 #5 时，旧检查发现不了）
    try:
        # 核对保留期内的记录，以及每个 CA 最新一份：旧文件按 CA 独立清理。
        try:
            keep = int(db.get_setting("crl_files_keep", "50") or 50)
        except (TypeError, ValueError):
            keep = 50
        retained_rows = db.q("SELECT * FROM crls ORDER BY id DESC LIMIT ?",
                             (max(1, min(keep, 20)),))
        latest_per_ca = db.q("SELECT * FROM crls WHERE id IN "
                             "(SELECT MAX(id) FROM crls GROUP BY ca_id)")
        # 老版本每次生成都会覆盖 ca-<id>.crl.pem/der，但历史记录仍引用同一路径。
        # 旧记录的 SHA/编号不可能再与这个文件相等；同一个 CA 的同一路径
        # 只检查最后引用它的记录。每个 CA 最新记录仍始终参与核对。
        newest_by_file: dict[tuple[int | None, str], int] = {}
        for record in db.q("SELECT id, ca_id, path, der_path FROM crls ORDER BY id DESC"):
            for value in (record["path"], record["der_path"]):
                if value:
                    newest_by_file.setdefault((record["ca_id"], value), record["id"])
        for r in {r["id"]: r for r in [*retained_rows, *latest_per_ca]}.values():
            for key in ("path", "der_path"):
                v = r[key]
                if not v or newest_by_file[(r["ca_id"], v)] != r["id"]:
                    continue
                q = Path(v)
                q = q if q.is_absolute() else Path(config.DATA_DIR) / q
                if not q.is_file():
                    issues.append(_issue("crl_file_missing", "error",
                                         f"CRL #{r['number']} 的文件缺失：{v}",
                                         fix="重新生成并发布 CRL： cli gencrl && cli publish"))
                    continue
                try:
                    data = q.read_bytes()
                    parsed = x509util.load_crl(data)
                    # DER 用原始字节校验；PEM 解码为同一份 DER 后校验签名内容。
                    der = data if key == "der_path" else parsed.public_bytes(
                        serialization.Encoding.DER)
                    if r["sha256"] and hashlib.sha256(der).hexdigest() != r["sha256"]:
                        issues.append(_issue(
                            "crl_file_mismatch", "error",
                            f"CRL #{r['number']} 的 {key} 文件内容与数据库校验值不符"
                            f"（文件可能来自另一次生成）",
                            fix="重新生成并发布 CRL： cli gencrl && cli publish"))
                    inner = x509util.crl_info(parsed)
                    if str(inner.get("number")) != str(r["number"]):
                        issues.append(_issue(
                            "crl_number_mismatch", "error",
                            f"CRL 记录为 #{r['number']}，但 {key} 文件里是 #{inner.get('number')}"
                            f"（数据库与文件不是同一次生成）",
                            fix="重新生成并发布 CRL： cli gencrl && cli publish"))
                except Exception as exc:  # noqa: BLE001
                    issues.append(_issue("crl_file_unreadable", "error",
                                         f"CRL #{r['number']} 的 {key} 无法读取或解析：{exc}"))
    except Exception as exc:  # noqa: BLE001
        issues.append(_issue("crl_file_check_failed", "warning",
                             f"未能核对 CRL 文件与记录：{exc}"))

    # 吊销事实必须体现在最新 CRL 里（审查发现：归档会让已吊销证书从 CRL 漏掉）
    try:
        latest = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
        revoked_rows = db.q("SELECT serial_hex, cn, status FROM certs "
                           "WHERE revoked_at IS NOT NULL OR status='revoked'")
        crl_path = None
        if latest is not None:
            for key in ("der_path", "path"):
                v = latest[key] if key in latest.keys() else None
                if v:
                    q = Path(v)
                    # 库里可能存相对路径 → 相对 data 目录解析（否则 is_file() 永远为假，
                    # 这项检查会静默失效）
                    q = q if q.is_absolute() else Path(config.DATA_DIR) / q
                    if q.is_file():
                        crl_path = q
                        break
        if latest is not None and crl_path is not None and revoked_rows:
            in_crl = {int(e.serial_number) for e in x509util.load_crl(crl_path.read_bytes())}
            missing = [r for r in revoked_rows
                       if int(str(r["serial_hex"]), 16) not in in_crl]
            if missing:
                issues.append({"level": "error", "code": "revoked_missing_in_crl",
                               "message": f"{len(missing)} 张已吊销证书不在最新 CRL 中"
                                          f"（吊销会失效）："
                                          + "、".join(str(r["cn"] or r["serial_hex"])
                                                      for r in missing[:5]),
                               "fix": "重新生成并发布 CRL： cli gencrl && cli publish"})
    except Exception as exc:  # noqa: BLE001
        issues.append({"level": "warn", "code": "crl_check_failed",
                       "message": f"未能核对 CRL 与吊销记录：{exc}"})

    summary = {lvl: sum(1 for i in issues if i["level"] == lvl) for lvl in LEVELS}
    return {"checked_at": x509util.to_iso(now), "issues": issues, "summary": summary,
            "total": len(issues)}


def _check_key_permissions(path: Path, issues: list[dict], label: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return
    if mode & 0o077:
        issues.append(_issue("key_permissions", "warning",
                             f"{label} 权限过宽（{oct(mode)}），其它用户可读",
                             entity=str(path), fixable=True, fix="收紧为 0600",
                             extra={"path": str(path)}))


# ------------------------------------------------------------------ 修复
def repair(codes: list[str] | None = None, actor: str = "admin") -> dict:
    report = check()
    wanted = set(codes) if codes else None
    done: list[dict] = []
    for issue in report["issues"]:
        if not issue["fixable"]:
            continue
        if wanted is not None and issue["code"] not in wanted:
            continue
        try:
            detail = _apply(issue, actor)
            done.append({"code": issue["code"], "entity": issue["entity"], "result": detail})
        except Exception as exc:  # noqa: BLE001 - 单个修复失败不影响其它
            done.append({"code": issue["code"], "entity": issue["entity"],
                         "error": f"{type(exc).__name__}: {exc}"})
    return {"repaired": done, "remaining": check()}


def _apply(issue: dict, actor: str):
    code = issue["code"]
    extra = issue.get("extra") or {}
    if code == "orphan_file":
        p = Path(extra["path"])
        if p.exists():
            p.unlink()
        return f"已删除孤儿文件 {p.name}"
    if code == "key_permissions":
        p = Path(extra["path"])
        os.chmod(p, 0o600)
        return f"已把 {p.name} 权限收紧为 0600"
    if code == "data_dir_permissions":
        os.chmod(config.DATA_DIR, 0o700)
        return f"已把数据目录 {config.DATA_DIR} 权限收紧为 0700"
    if code == "secret_file_permissions":
        os.chmod(Path(issue["entity"]), 0o600)
        return f"已把 {Path(issue['entity']).name} 权限收紧为 0600"
    if code in ("crl_missing", "crl_entries_mismatch", "crl_expired", "crl_expiring_soon",
                "crl_file_missing", "crl_not_published", "crl_never_published",
                "publish_failed", "crl_target_missing", "crl_target_mismatch"):
        ca_row = ca.active_ca_row()
        if ca_row is None:
            raise CertError("没有可用 CA")
        detail = ""
        if code not in ("crl_not_published", "crl_target_missing", "crl_target_mismatch"):
            # 文件内容陈旧时重发即可，不需要增加 CRL 编号。
            crl = ca.generate_crl(ca_row=ca_row, actor=actor, source="repair")
            detail = f"已重新生成 CRL #{crl['number']}（{crl['entries']} 条吊销记录）"
        res = publish.publish(trigger="repair", reload=True, actor=actor)
        ok = sum(1 for r in res["results"] if r["ok"])
        return f"{detail}；已发布到 {ok}/{len(res['results'])} 个目标"
    if code == "fingerprint_mismatch":
        cert_id = extra["cert_id"]
        row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
        cert = x509util.load_cert((config.DATA_DIR / row["cert_path"]).read_bytes())
        info = x509util.cert_to_dict(cert)
        with db.tx() as conn:
            conn.execute(
                "UPDATE certs SET fingerprint=?, serial_hex=?, serial_dec=?, subject=?, cn=?, "
                "issuer=?, not_before=?, not_after=?, key_type=?, key_size=?, "
                "signature_algorithm=?, sans_json=?, key_usage_json=?, eku_json=?, updated_at=? "
                "WHERE id=?",
                (info["fingerprint_sha256"], info["serial_hex"], info["serial_dec"],
                 info["subject"], info["cn"], info["issuer"], info["not_before"],
                 info["not_after"], info["key_type"], info["key_size"],
                 info["signature_algorithm"], db.json.dumps(info["sans"], ensure_ascii=False),
                 db.json.dumps(info["key_usage"], ensure_ascii=False),
                 db.json.dumps(info["eku"], ensure_ascii=False),
                 x509util.to_iso(x509util.now()), cert_id))
            audit.log("repair.fingerprint_sync", target_type="cert", target_id=cert_id,
                      target_label=row["cn"], actor=actor, conn=conn)
        return "已以磁盘证书为准刷新数据库记录"
    if code == "expired_but_valid":
        cert_id = extra["cert_id"]
        with db.tx() as conn:
            conn.execute("UPDATE certs SET status='expired', updated_at=? WHERE id=?",
                         (x509util.to_iso(x509util.now()), cert_id))
            audit.log("repair.expired_status", target_type="cert", target_id=cert_id,
                      actor=actor, conn=conn)
        return "状态已更新为“已过期”"
    if code == "revoked_without_date":
        cert_id = extra["cert_id"]
        with db.tx() as conn:
            conn.execute("UPDATE certs SET revoked_at=?, updated_at=? WHERE id=?",
                         (x509util.to_iso(x509util.now()), x509util.to_iso(x509util.now()),
                          cert_id))
            audit.log("repair.revoked_date", target_type="cert", target_id=cert_id,
                      actor=actor, conn=conn)
        return "已补齐吊销时间"
    if code == "serial_counter_behind":
        ca_row = ca.active_ca_row()
        max_seq = db.scalar(
            "SELECT MAX(CAST(serial_hex AS INTEGER)) FROM certs WHERE ca_id=? "
            "AND LENGTH(serial_hex)<=15", (ca_row["id"],))
        with db.tx() as conn:
            conn.execute("INSERT INTO serial_counter(ca_id,next_serial) VALUES(?,?) "
                         "ON CONFLICT(ca_id) DO UPDATE SET next_serial=excluded.next_serial",
                         (ca_row["id"], int(max_seq or 0) + 1))
            audit.log("repair.serial_counter", target_type="ca", target_id=ca_row["id"],
                      actor=actor, detail={"next_serial": int(max_seq or 0) + 1}, conn=conn)
        return f"计数器已推进到 {int(max_seq or 0) + 1}"
    if code == "ca_cert_mismatch":
        ca_row = ca.active_ca_row()
        cert = x509util.load_cert((config.DATA_DIR / ca_row["cert_path"]).read_bytes())
        info = x509util.cert_to_dict(cert, status_hint="valid")
        with db.tx() as conn:
            conn.execute("UPDATE cas SET subject=?, cn=?, serial_hex=?, fingerprint=?, "
                         "not_before=?, not_after=?, key_type=?, key_size=? WHERE id=?",
                         (info["subject"], info["cn"], info["serial_hex"],
                          info["fingerprint_sha256"], info["not_before"], info["not_after"],
                          info["key_type"], info["key_size"], ca_row["id"]))
            audit.log("repair.ca_cert_sync", target_type="ca", target_id=ca_row["id"],
                      actor=actor, conn=conn)
        return "已以磁盘文件为准刷新 CA 记录"
    raise CertError(f"暂不支持自动修复该问题: {code}")
