"""命令行工具：运维与自动化入口（GUI 之外的第二条路径）。

用法示例
--------
    # 查看加密信道指纹（首次在浏览器打开时核对用）
    .venv/bin/python -m backend.cli fingerprint

    # 导入已有 CA（证书 + 私钥；私钥可加密，提供口令）
    .venv/bin/python -m backend.cli import-ca --cert ~/ca.cert.pem --key ~/ca.key.pem

    # 批量收编历史证书（目录/文件），并直接把它们标记为已吊销
    .venv/bin/python -m backend.cli import --path ~/certs --revoked --reason keyCompromise

    # 按规则集签发（默认 strongSwan VPN 客户端），导出到目录
    .venv/bin/python -m backend.cli issue --identity vpn1.example.com --out /tmp/vpn1

    # 吊销 + 重新生成并发布 CRL（strongSwan 立刻生效）
    .venv/bin/python -m backend.cli revoke --serial 53D2... --reason keyCompromise
    .venv/bin/python -m backend.cli publish

    # 一致性体检（可自动修复）
    .venv/bin/python -m backend.cli check --repair

    # 导出证书清单 / 生成 strongSwan 部署包
    .venv/bin/python -m backend.cli export --format csv --out /tmp/certs.csv
    .venv/bin/python -m backend.cli bundle --id 3 --gateway vpn.example.com --out /tmp/vpn3.zip

    # 部署自检（强烈建议在服务器上先跑这个）
    .venv/bin/python -m backend.cli doctor

    # 修改管理员口令（交互输入，不走命令行参数，避免进 shell 历史）
    .venv/bin/python -m backend.cli passwd
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from . import (assetguard, automation, backup, ca, config, consistency, db, inventory, publish, rules,
               secure_channel)
from . import security, server, strongswan, x509util
from .x509util import CertError


def _emit(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def cmd_fingerprint(args) -> int:
    server.bootstrap(verbose=False)
    import backend.secure_channel as sc  # 局部导入避免循环
    print(sc.identity.fingerprint)


def cmd_init(args) -> int:
    info = server.bootstrap(verbose=True)
    if info.get("initial_password"):
        print(f"管理员初始口令: {info['initial_password']}")
    return 0


def cmd_import_ca(args) -> int:
    server.bootstrap(verbose=False)
    cert = Path(args.cert).expanduser().read_bytes()
    key = Path(args.key).expanduser().read_bytes() if args.key else None
    chain = Path(args.chain).expanduser().read_bytes() if args.chain else None
    row = ca.import_ca(cert, key, chain, password=args.password, source="cli")
    _emit(ca.ca_to_dict(row))
    if not row["has_key"]:
        print("\n注意：未导入 CA 私钥，暂时无法签发证书/生成 CRL。"
              "\n      请用 --key 指定私钥文件（加密私钥请配合 --password）。", file=sys.stderr)
    return 0


def cmd_import(args) -> int:
    server.bootstrap(verbose=False)
    res = inventory.import_directory(
        args.path, dry_run=args.dry_run, mark_revoked=args.revoked,
        revoke_reason=args.reason, owner=args.owner,
        tags=[t for t in (args.tags or "").split(",") if t], recursive=not args.no_recursive)
    summary = {
        "scanned_files": res.get("scanned_files"),
        "preview": len(res.get("preview") or []),
        "imported": len(res.get("imported") or []),
        "skipped": len(res.get("skipped") or []),
        "errors": res.get("errors"),
        "imported_items": [{"id": i["id"], "cn": i["cn"], "serial": i["serial_hex"],
                            "status": i["status"]} for i in (res.get("imported") or [])],
    }
    if res.get("crl"):
        summary["crl_entries"] = res["crl"]["entries"]
    if res.get("publish"):
        summary["published_targets"] = [{"target": p["target_name"], "ok": p["ok"]}
                                        for p in res["publish"]]
    if res.get("dry_run"):
        summary["dry_run"] = True
    _emit(summary)
    return 0


def cmd_list(args) -> int:
    server.bootstrap(verbose=False)
    sql, params = "SELECT * FROM certs WHERE 1=1", []
    if args.status:
        sql += " AND status=?"
        params.append(args.status)
    if args.q:
        sql += " AND (cn LIKE ? OR serial_hex LIKE ? OR subject LIKE ?)"
        params += [f"%{args.q}%"] * 3
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(args.limit)
    for row in db.q(sql, params):
        d = ca.cert_to_dict(row)
        print(f"{d['id']:>4}  {d['status']:<8} {d['cn'][:28]:<28} "
              f"{d['serial_hex'][:20]:<20} {d['not_after'][:10]}  {d['profile'] or '-'}")
    return 0


def cmd_issue(args) -> int:
    server.bootstrap(verbose=False)
    ca_row = ca.active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA")
    rs = rules.get(args.ruleset)
    result = ca.issue_certificate(
        ca_row=ca_row, ruleset=rs, cn=args.cn, vpn_identity=args.identity,
        vpn_identity_type=args.identity_type, validity_days=args.days,
        sans=[{"type": "dns", "value": d} for d in (args.san_dns or [])]
        + [{"type": "ip", "value": i} for i in (args.san_ip or [])]
        + ([{"type": "email", "value": args.san_email}] if args.san_email else []),
        owner=args.owner, tags=[t for t in (args.tags or "").split(",") if t],
        notes=args.notes, source="cli")
    cert = result["cert"]
    out_dir = Path(args.out).expanduser() if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in (cert["cn"] or "cert"))
        (out_dir / f"{slug}.crt.pem").write_text(result["secret"]["cert_pem"])
        if result["secret"].get("key_pem"):
            p = out_dir / f"{slug}.key.pem"
            p.write_text(result["secret"]["key_pem"])
            p.chmod(0o600)
        (out_dir / f"{slug}-chain.pem").write_text(result["secret"].get("chain_pem") or "")
        print(f"已写入 {out_dir}")
    _emit({"id": cert["id"], "cn": cert["cn"], "serial": cert["serial_hex"],
           "not_after": cert["not_after"], "sans": cert["sans"], "eku": cert["eku"],
           "ruleset": result["ruleset"]["slug"]})
    return 0


def cmd_revoke(args) -> int:
    server.bootstrap(verbose=False)
    cert_id = args.id
    if cert_id is None and args.cn:
        rows = db.q("SELECT id, serial_hex FROM certs WHERE cn=? AND status!='revoked'",
                    (args.cn,))
        if not rows:
            raise CertError(f"找不到 CN={args.cn} 的未吊销证书")
        if len(rows) > 1 and not args.force:
            raise CertError(f"CN={args.cn} 匹配到 {len(rows)} 张证书，请用 --serial 指定，"
                            f"或加 --force 全部吊销")
        if len(rows) > 1:
            out = []
            for r in rows:
                res = ca.revoke(int(r["id"]), reason=args.reason, notes=args.notes, actor="cli")
                out.append({"id": r["id"], "serial": r["serial_hex"],
                            "status": res["cert"]["status"]})
            ca.refresh_crl_and_publish(actor="cli", source="cli-revoke")
            _emit({"revoked": out})
            return 0
        cert_id = rows[0]["id"]
    if cert_id is None:
        row = db.q1("SELECT id FROM certs WHERE UPPER(serial_hex)=?",
                    ((args.serial or "").replace(":", "").upper(),))
        if row is None:
            raise CertError(f"找不到序列号为 {args.serial} 的证书")
        cert_id = row["id"]
    res = ca.revoke(int(cert_id), reason=args.reason, notes=args.notes, actor="cli")
    out = {"cert": res["cert"]["cn"], "status": res["cert"]["status"],
           "crl_entries": (res.get("crl") or {}).get("entries")}
    if db.get_setting("auto_publish", "1") == "1":
        out["publish"] = publish.publish(trigger="cli",
                                        reload=db.get_setting("auto_reload", "1") == "1",
                                        actor="cli")["results"]
    _emit(out)
    return 0


def cmd_sync_plan(args) -> int:
    """输出 root 兜底同步单元应拷贝的文件映射（每行 src<TAB>dst）。

    **只输出设置里指定的那一个 CRL**（以及需要且启用时的 CA 证书）——
    绝不把暂存目录里的所有文件都拷进 strongSwan（那里出现过同 CA 的多份 CRL，
    charon 只保留编号最大的那份，"用哪一份"不确定 → 吊销失效）。
    """
    server.bootstrap(verbose=False)
    cfg = publish.swanctl_settings()
    staging = Path(getattr(args, "staging", None) or (config.DATA_DIR / "publish"))
    targets = [t for t in publish.list_targets() if t["enabled"] and t["kind"] == "dir_file"]
    out: list[tuple[Path, Path]] = []

    def _staging_target(content: str, fmt: str | None = None):
        for t in targets:
            if (t.get("content") or "crl") == content and \
                    os.path.normpath(str(t["path"])) == os.path.normpath(str(staging)) and \
                    (fmt is None or str(t["format"]).lower() == fmt):
                return t
        return None

    want_fmt = str(cfg.get("crl_format") or "der").lower()
    crl_t = _staging_target("crl", want_fmt)
    if crl_t:
        name = (cfg.get("crl_filename") or "").strip() or crl_t["filename"]
        out.append((staging / crl_t["filename"], Path(cfg["crl_dir"]) / name))
    elif _staging_target("crl"):
        print(f"# 暂存目录没有启用 {want_fmt.upper()} 格式的 CRL 目标，"
              "跳过（请启用相应目标或使用直写目标）", flush=True)
    else:
        # 没有显式暂存目标时，按设置里的文件名推断（暂存文件名 = strongSwan 文件名）
        name = (cfg.get("crl_filename") or "").strip()
        if name and (staging / name).is_file():
            out.append((staging / name, Path(cfg["crl_dir"]) / name))
    if cfg.get("publish_ca_cert"):
        ca_t = _staging_target("ca_cert")
        if ca_t:
            name = (cfg.get("ca_cert_filename") or "").strip() or ca_t["filename"]
            out.append((staging / ca_t["filename"], Path(cfg["ca_dir"]) / name))
    for src, dst in out:
        if src.is_file():
            print(f"{src}\t{dst}")
    return 0


def cmd_targets(args) -> int:
    """列出/清理发布目标。--prune-unused 停用"目标目录不存在"的目标。"""
    server.bootstrap(verbose=False)
    items = publish.list_targets()
    rows = []
    for t in items:
        d = Path(os.path.expandvars(os.path.expanduser(str(t["path"]))))
        rows.append({"id": t["id"], "enabled": bool(t["enabled"]), "name": t["name"],
                     "kind": t["kind"], "content": t.get("content") or "crl",
                     "path": str(d), "filename": t["filename"], "dir_exists": d.is_dir(),
                     "reload_cmd": t.get("reload_cmd") or ""})
    pruned = []
    if getattr(args, "keep_single", False):
        # 同一目录同一内容只保留一个启用目标（优先保留设置里指定的那个）
        cfg_now = publish.swanctl_settings()
        def _norm(d):
            return os.path.normpath(os.path.expandvars(os.path.expanduser(str(d))))
        prefer = {("crl", _norm(cfg_now["crl_dir"])): str(cfg_now.get("crl_filename") or ""),
                  ("ca_cert", _norm(cfg_now["ca_dir"])): str(cfg_now.get("ca_cert_filename") or "")}
        keep: dict = {}
        for r in rows:
            if not r["enabled"] or r["kind"] != "dir_file":
                continue
            directory = _norm(r["path"])
            staging = _norm(publish.STAGING_DIR)
            key = ((r["content"], directory, r["filename"])
                   if directory == staging else (r["content"], directory))
            if key not in keep:
                keep[key] = r
                continue
            want = prefer.get((r["content"], directory), "")
            cur = keep[key]
            if want and r["filename"] == want and cur["filename"] != want:
                lose, keep[key] = cur, r
            else:
                lose = r
            publish.update_target(lose["id"], {"enabled": 0})
            lose["enabled"] = False
            pruned.append(lose)
    if getattr(args, "disable", None):
        for tid in args.disable:
            publish.update_target(int(tid), {"enabled": 0})
            pruned.append({"id": int(tid), "path": "(按 id 停用)"})
    if getattr(args, "allow_shadow", None):
        for tid in args.allow_shadow:
            publish.update_target(int(tid), {"shadow_ok": 1})
            print(f"已允许目标 #{tid} 与同目录其它目标并存（shadow_ok=1）")
    if getattr(args, "delete", None):
        for tid in args.delete:
            publish.delete_target(int(tid))
            print(f"已删除目标 #{tid}")
    if getattr(args, "prune_unused", False):
        for r in rows:
            if r["enabled"] and r["kind"] == "dir_file" and not r["dir_exists"]:
                publish.update_target(r["id"], {"enabled": 0})
                pruned.append(r)
                r["enabled"] = False
    if getattr(args, "json", False):
        print(json.dumps({"targets": rows, "pruned": pruned}, ensure_ascii=False, indent=2))
        return 0
    print(f"发布目标（{len(rows)} 个，启用 {sum(1 for r in rows if r['enabled'])} 个）:")
    for r in rows:
        print(f"  #{r['id']:<3} [{'启用' if r['enabled'] else '停用'}] "
              f"{r['content']:<8} {r['path']}/{r['filename']}"
              + ("" if r["dir_exists"] else "   ← 目录不存在（发布时会跳过）"))
        if r["reload_cmd"]:
            print(f"        重载: {r['reload_cmd']}")
    if pruned:
        print(f"\n已停用 {len(pruned)} 个目录不存在的目标：")
        for r in pruned:
            print(f"  #{r['id']} {r['path']}/{r['filename']}")
    elif getattr(args, "prune_unused", False):
        print("\n没有需要停用的目标。")
    print("\n提示：strongSwan 目录里同一 CA 只应有一份 CRL；"
          "多余目标会让 charon 的 CRL 选择不确定（见 cli doctor 的 CRL 文件唯一性检查）。")
    return 0


def cmd_crl_number(args) -> int:
    """查看/设置 CRL 编号下限（接管现场 CA 时用于"跳号"，避免被旧 CRL 遮蔽）。"""
    server.bootstrap(verbose=False)
    row = db.q1("SELECT number FROM crls ORDER BY id DESC LIMIT 1")
    cur = int(row["number"]) if (row and str(row["number"]).isdigit()) else 0
    floor = int(db.get_setting("crl_number_floor", "0") or 0)
    if getattr(args, "set", None) is not None:
        want = int(args.set)
        if want < 1:
            print("编号下限必须 ≥ 1"); return 2
        db.set_setting("crl_number_floor", str(want))
        print(f"已设置 CRL 编号下限 = {want}（下次生成 CRL 的编号将 ≥ {want}）")
        if want <= cur:
            print(f"  ⚠ 注意：当前库里最新编号是 #{cur}，下限设成 {want} 不会生效（还需 > 最大编号）")
        print("  提示：strongSwan 只保留**编号更大**的 CRL，接管现场 CA 时请把下限设为"
              "现场最大编号 + 1，然后 gencrl 并重载。")
        return 0
    info = strongswan.inspect_crl_files()
    print(f"库中最新的 CRL 编号: #{cur}")
    print(f"编号下限（crl_number_floor）: {floor}")
    print(f"下次生成的编号: #{max(cur + 1, floor)}")
    if info.get("exists") and info.get("ours"):
        nums = "、".join(f"{i['file']}(#{i['number']})" for i in info["ours"])
        print(f"{info['dir']} 里本 CA 的 CRL: {nums}")
        if len(info["ours"]) > 1:
            top = max(info["ours"], key=lambda i: i["number"] if isinstance(i["number"], int) else -1)
            print(f"  ⚠ 有多份；charon 只会用编号最大的那份：{top['file']}(#{top['number']})"
                  f" —— 若那不是我们发布的目标，吊销会被遮蔽")
    if getattr(args, "json", False):
        print(json.dumps({"latest": cur, "floor": floor, "next": max(cur + 1, floor),
                          "files": info}, ensure_ascii=False, indent=2))
    return 0


def cmd_import_crl(args) -> int:
    """导入外部 CRL：把其中的序列号在本库标记为已吊销（用于接管现场已有 CRL）。"""
    server.bootstrap(verbose=False)
    data = Path(args.file).expanduser().read_bytes()
    info = ca.import_crl(data, actor="cli")
    _emit(info)
    return 0


def cmd_unrevoke(args) -> int:
    """恢复吊销：更新本库 → 重新生成 CRL → 发布到 strongSwan → 重载。

    恢复与吊销一样必须"立即生效"：CRL 里去掉该序列号并让 charon 加载新 CRL，
    否则客户端仍然会因为旧 CRL 被拒（现场要求："证书恢复后也要更新 strongSwan"）。
    """
    server.bootstrap(verbose=False)
    cert_id = args.id
    if cert_id is None and args.serial:
        row = db.q1("SELECT id FROM certs WHERE UPPER(serial_hex)=?",
                    (str(args.serial).replace(":", "").upper(),))
        if row is None:
            raise CertError(f"找不到序列号为 {args.serial} 的证书")
        cert_id = row["id"]
    if cert_id is None and args.cn:
        rows = db.q("SELECT * FROM certs WHERE cn=? ORDER BY id DESC", (args.cn,))
        if not rows:
            raise CertError(f"找不到 CN={args.cn} 的证书")
        if len(rows) > 1 and not args.force:
            raise CertError(f"CN={args.cn} 匹配到 {len(rows)} 张证书，请用 --id/--serial 指定，"
                            f"或加 --force 全部恢复")
        out_multi = []
        for r in rows:
            if r["status"] != "revoked":
                out_multi.append({"id": r["id"], "serial": r["serial_hex"], "skipped": True,
                                  "why": "当前不是吊销状态"})
                continue
            res = ca.unrevoke(int(r["id"]), actor="cli")
            out_multi.append({"id": r["id"], "serial": r["serial_hex"],
                              "status": res["cert"]["status"]})
        pub = ca.refresh_crl_and_publish(actor="cli", source="cli-unrevoke")
        _emit({"unrevoked": out_multi,
               "crl": (pub.get("crl") or {}).get("number") if isinstance(pub.get("crl"), dict)
               else None,
               "publish": pub.get("publish")})
        return 0
    if cert_id is None:
        print("请用 --id / --serial / --cn 指定要恢复的证书"); return 2
    res = ca.unrevoke(int(cert_id), actor="cli")
    out = {"cert": res["cert"]["cn"], "status": res["cert"]["status"],
           "crl": (res.get("crl") or {}).get("entries")}
    if args.no_publish:
        _emit(out); return 0
    pub = ca.refresh_crl_and_publish(actor="cli", source="cli-unrevoke")
    out["crl_number"] = (pub.get("crl") or {}).get("number") if isinstance(pub.get("crl"), dict) \
        else None
    out["publish"] = pub.get("publish")
    _emit(out)
    return 0


def cmd_gencrl(args) -> int:
    server.bootstrap(verbose=False)
    crl = ca.generate_crl(validity_days=args.days, actor="cli")
    res = publish.publish(trigger="cli", reload=not args.no_reload, actor="cli")
    _emit({"crl": crl, "publish": res["results"]})
    return 0


def cmd_crl_info(args) -> int:
    """验证一份 CRL 文件：结构 + 签名 + 与数据库/发布目标的一致性。

    为什么需要它：光"文件存在"不能说明任何问题——要确认它确实是本 CA 签发的、
    内容没被改过、且与库里的吊销记录和网站上发布的内容一致。
    退出码：全部通过 0；有任何一项不通过 1（可直接用于监控脚本）。
    """
    server.bootstrap(verbose=False)
    problems: list[str] = []
    report: dict = {"file": None, "checks": []}
    as_json = bool(getattr(args, "json", False))
    _lines: list[str] = []

    def say(*parts) -> None:
        """人读输出；--json 时只缓冲不打印，保证 stdout 是纯 JSON（便于 jq / 监控）。"""
        line = " ".join(str(x) for x in parts)
        _lines.append(line)
        if not as_json:
            print(line)

    def note(item: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"item": item, "ok": bool(ok), "detail": detail})

    ca_row = ca.active_ca_row()
    if ca_row is None:
        say("尚未导入 CA，无法验证 CRL。")
        return 2
    # 取当前 CA 证书：固定路径 → 库里记录 → 数据目录里按证书类型搜索（导入的 CA 都放在 ca/ 下）
    cert_bytes = None
    cands: list[Path] = []
    for name in ("CA_CERT_FILE", "CA_CERT", "CA_PEM"):
        v = getattr(config, name, None)
        if v:
            cands.append(Path(v))
    if ca_row.get("cert_path"):
        cands.append(Path(ca_row["cert_path"]))
    if ca_row.get("chain_path"):
        cands.append(Path(ca_row["chain_path"]))
    try:
        cands.extend(sorted(config.CA_DIR.glob("*.pem")) + sorted(config.CA_DIR.glob("*.crt")))
    except OSError:
        pass
    for cand in cands:
        try:
            if cand.is_file() and cand.stat().st_size > 0:
                cert_bytes = cand.read_bytes()
                break
        except OSError:
            continue
    if not cert_bytes:
        say("找不到当前 CA 的证书文件，无法验证 CRL 签名。"
              "请先导入 CA（cli import-ca）或用 cli doctor 检查。")
        return 2
    ca_cert = x509util.load_cert(cert_bytes)

    # 选文件：--file > 最新发布目标里存在的 CRL > 数据库里最近一条 CRL 的路径
    path: Path | None = Path(args.file).expanduser() if getattr(args, "file", None) else None
    if path is None:
        for t in publish.list_targets():
            if t["enabled"] and t["kind"] == "dir_file" and \
                    (t.get("content") or "crl") == "crl":
                cand = Path(os.path.expandvars(os.path.expanduser(str(t["path"])))) / \
                    str(t["filename"])
                if cand.is_file():
                    path = cand
                    break
    if path is None:
        row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
        if row:
            for key in ("der_path", "path"):
                if row[key] and Path(row[key]).is_file():
                    path = Path(row[key])
                    break
    raw = b""
    if path is None or not path.is_file():
        if getattr(args, "cert", None):
            # 只做"证书诊断"时不强求 CRL 文件（还没发布/没配路径也能给出判定）
            say("（提示：未找到 CRL 文件，仅做证书与数据库比对；可用 --file 指定 CRL）")
            problems.append("未找到 CRL 文件（跳过签名/一致性检查）")
            info = {"issuer": None, "number": None, "entries": [], "count": 0,
                    "this_update": None, "next_update": None, "signature_algorithm": None}
            report["crl"] = info
            ca_cert = None
            crl = None
        else:
            say("找不到可验证的 CRL 文件。用 --file 指定，例如：\n"
                "  crl-info --file /etc/swanctl/x509crl/crl.der")
            return 2
    else:
        raw = path.read_bytes()
        report["file"] = str(path)
        report["size"] = len(raw)
        report["sha256"] = hashlib.sha256(raw).hexdigest()
        try:
            crl = x509util.load_crl(raw)
        except Exception as exc:  # noqa: BLE001
            say(f"文件无法解析为 CRL：{path}\n  {type(exc).__name__}: {exc}")
            return 1
        info = x509util.crl_info(crl)
        report["crl"] = info

    fmt = "PEM" if raw.lstrip().startswith(b"-----BEGIN") else "DER"
    say(f"文件: {path}")
    say(f"  格式 {fmt} · {len(raw)} 字节 · SHA-256 {report['sha256']}")
    say(f"  签发者 {info['issuer']}")
    say(f"  CRL 编号 {info['number']} · 条目 {info['count']}")
    say(f"  本次更新 {info['this_update']}")
    say(f"  下次更新 {info['next_update']}")
    for e in info["entries"]:
        say(f"    · 序列号 {e['serial_hex']}  吊销于 {e['revoked_at']}"
              f"{'  原因 ' + e['reason'] if e['reason'] else ''}")

    # ① 签名验证
    if crl is None:
        say("\n[1/4] 签名验证: 跳过（没有 CRL 文件）")
        note("签名由当前 CA 签发且未被篡改", False, "无 CRL 文件")
    else:
        sig_ok, sig_msg = x509util.crl_signature_ok(ca_cert, crl)
        say(f"\n[1/4] 签名验证: {'✓' if sig_ok else '✗'} {sig_msg}")
        if not sig_ok:
            problems.append(sig_msg)
        note("签名由当前 CA 签发且未被篡改", sig_ok, sig_msg)

    # ② 与数据库核对
    row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if row is None:
        say("[2/4] 与数据库核对: 库里还没有 CRL 记录（可能是外部导入的文件）")
        note("与数据库核对", True, "库里无记录，跳过")
    else:
        db_entries = db.q("SELECT serial_hex, revoked_at, revocation_reason FROM certs "
                          "WHERE status='revoked' ORDER BY id")
        db_serials = {int(str(r["serial_hex"]), 16) for r in db_entries}
        crl_serials = {int(e["serial"]) for e in info["entries"]}
        same_num = str(info["number"]) == str(row["number"])
        same_cnt = info["count"] == int(row["entries"] or 0)
        same_sha = (row["sha256"] or "") in ("", report["sha256"])
        missing = db_serials - crl_serials      # 库里吊销了但 CRL 里没有 → 吊销未生效！
        extra = crl_serials - db_serials        # CRL 里有但库里没有
        say(f"[2/4] 与数据库核对: 编号{'一致' if same_num else '不一致'}"
              f"（文件 {info['number']} / 库 {row['number']}）"
              f" · 条目{'一致' if same_cnt else '不一致'}"
              f"（文件 {info['count']} / 库 {row['entries']}）")
        if not same_num:
            problems.append(f"CRL 编号与库不一致（文件 {info['number']} / 库 {row['number']}）")
        if not same_cnt:
            problems.append(f"条目数与库不一致（文件 {info['count']} / 库 {row['entries']}）")
        note("CRL 编号与库一致", same_num, f"{info['number']} vs {row['number']}")
        note("条目数与库一致", same_cnt, f"{info['count']} vs {row['entries']}")
        if missing:
            problems.append("库中已吊销但本 CRL 缺失的序列号: " +
                            ", ".join(format(x, "X") for x in sorted(missing)[:5]))
            say(f"      ✗ 库中已吊销但 CRL 缺失 {len(missing)} 个序列号 —— 吊销未生效！")
            say("        " + ", ".join(format(x, "X") for x in sorted(missing)[:5]))
        else:
            say("      ✓ 库中已吊销的证书全部在本 CRL 中")
        note("库中已吊销项全部包含在本 CRL 中", not missing,
             f"缺失 {len(missing)}" if missing else "")
        if extra:
            say(f"      ! CRL 中有 {len(extra)} 个序列号在库里找不到（可能是外部导入的 CRL）")
        note("CRL 中无库里不存在的序列号", not extra, f"多出 {len(extra)}" if extra else "")

    # ③ 与各发布目标核对：磁盘上的内容是否就是"当前应发布的"内容
    targets = [t for t in publish.list_targets()
               if t["enabled"] and t["kind"] == "dir_file" and (t.get("content") or "crl") == "crl"]
    say(f"[3/4] 发布目标核对（{len(targets)} 个启用的 CRL 目标）:")
    for t in targets:
        d = Path(os.path.expandvars(os.path.expanduser(str(t["path"]))))
        f = d / str(t["filename"])
        if not d.is_dir():
            say(f"      · {t['name']}: 目录不存在（本机不使用该布局）→ 跳过")
            note(f"目标 {t['name']} 目录存在", True, "不存在，跳过")
            continue
        if not f.is_file():
            say(f"      ✗ {t['name']}: 文件不存在 {f}")
            problems.append(f"目标 {t['name']}: 文件不存在 {f}")
            note(f"目标 {t['name']} 文件存在", False, str(f))
            continue
        try:
            want = publish.payload_bytes(t)
        except Exception as exc:  # noqa: BLE001
            say(f"      · {t['name']}: 无法计算应发布内容（{exc}）→ 跳过")
            continue
        got = f.read_bytes()
        if got == want:
            say(f"      ✓ {t['name']}: {f} 与当前应发布内容一致")
            note(f"目标 {t['name']} 内容一致", True, str(f))
        else:
            want_sha, got_sha = (hashlib.sha256(want).hexdigest(),
                                 hashlib.sha256(got).hexdigest())
            say(f"      ✗ {t['name']}: 与当前应发布内容不一致")
            say(f"        磁盘 {got_sha}")
            say(f"        应为 {want_sha}")
            problems.append(f"目标 {t['name']} 内容与应发布内容不一致（磁盘 {got_sha[:12]}…）")
            note(f"目标 {t['name']} 内容一致", False, f"{got_sha[:12]} != {want_sha[:12]}")

    # ④ 有效期
    nxt_raw = getattr(crl, "next_update_utc", None) or crl.next_update
    now = x509util.now()
    if nxt_raw is not None:
        left_days = (nxt_raw - now).total_seconds() / 86400
        ok = left_days > 0
        say(f"[4/4] 有效期: {'✓' if ok else '✗'} 下次更新还有 {left_days:.1f} 天")
        if not ok:
            problems.append(f"CRL 已过期（nextUpdate={info['next_update']}）")
        note("CRL 未过期", ok, f"剩余 {left_days:.1f} 天")

    if getattr(args, "serial", None):
        hexs = str(args.serial).replace(":", "").replace(" ", "").strip()
        try:
            want_serial = int(hexs, 16)
        except ValueError:
            say(f"\n--serial 不是合法的十六进制序列号: {args.serial}")
            return 2
        hit = next((e for e in info["entries"] if int(e["serial"]) == want_serial), None)
        if hit:
            say(f"\n序列号 {hexs.upper()} → 已吊销（{hit['revoked_at']}"
                  f"{'，原因 ' + hit['reason'] if hit['reason'] else ''}）")
        else:
            say(f"\n序列号 {hexs.upper()} → **不在**这份 CRL 中（即未吊销）")
        report["serial_query"] = {"serial": hexs.upper(), "revoked": bool(hit), "entry": hit}

    if getattr(args, "cert", None):
        # 拿"客户端实际在用的那张证书"来判定：CRL 里有没有它的序列号、库里吊销的又是哪一张
        try:
            cert = x509util.load_cert(Path(args.cert).expanduser().read_bytes())
        except Exception as exc:  # noqa: BLE001
            print(f"\n--cert 无法解析：{type(exc).__name__}: {exc}")
            return 2
        cser = int(cert.serial_number)
        cinfo = {"subject": x509util.name_to_str(cert.subject),
                 "serial_hex": format(cser, "X"),
                 "fingerprint": x509util.fingerprint(cert),
                 "issuer": x509util.name_to_str(cert.issuer)}
        in_crl = any(int(e["serial"]) == cser for e in info["entries"])
        db_row = db.q1("SELECT * FROM certs WHERE UPPER(serial_hex)=?", (cinfo["serial_hex"],))
        print("\n【客户端证书】")
        print("  subject " + cinfo["subject"])
        print("  serial  " + cinfo["serial_hex"])
        print("  issuer  " + cinfo["issuer"])
        print("  指纹    " + cinfo["fingerprint"])
        print("  在这份 CRL 中：" + ("是（已吊销）" if in_crl else "否（未吊销）"))
        if db_row is not None:
            extra = (" revoked_at=" + str(db_row["revoked_at"])) if db_row["revoked_at"] else ""
            print("  在本库中：id=%s cn=%s status=%s%s"
                  % (db_row["id"], db_row["cn"], db_row["status"], extra))
        else:
            print("  在本库中：**没有这张证书**（不是本 CA 签发，或未导入）")
        same = db.q("SELECT id, serial_hex, status, revoked_at FROM certs WHERE cn=? "
                    "ORDER BY id DESC LIMIT 10", (db_row["cn"],)) if db_row is not None else []
        verdict: list[str] = []
        if in_crl:
            verdict.append("这张证书确实在 CRL 里 → 我们的 CRL 是对的。若 strongSwan 仍放行，"
                           "说明 charon 还在用旧 CRL：先 sudo swanctl --flush-certs，"
                           "仍不行再 sudo systemctl restart strongswan")
        elif db_row is None:
            verdict.append("这张证书不在本库：不是本 CA 签发的（本系统无法吊销它），"
                           "或它的 CA 还没导入本系统")
        elif db_row["status"] == "valid":
            verdict.append("这张证书在库里是 valid：你吊销的是另一个序列号"
                           "（同 CN 重新签发过多张时最常见）。请吊销 id=%s（serial %s）"
                           % (db_row["id"], cinfo["serial_hex"]))
        else:
            verdict.append("库里已吊销但 CRL 里没有它 → 重新生成并发布："
                           "cli gencrl && cli publish（然后 flush-certs 或 restart）")
        report["cert"] = dict(cinfo, in_crl=in_crl,
                              db=({"id": db_row["id"], "status": db_row["status"],
                                   "cn": db_row["cn"]} if db_row is not None else None),
                              verdict=verdict)
        print("\n【判定】")
        for v in verdict:
            print("  · " + v)
        if same:
            print("\n【同 CN 的其它证书（核对你吊销的是不是这一张）】")
            for r_ in same:
                print("  id=%-4s serial=%s status=%s%s"
                      % (r_["id"], r_["serial_hex"], r_["status"],
                         (" revoked_at=" + str(r_["revoked_at"])) if r_["revoked_at"] else ""))

    if as_json:
        # --json 时 stdout 必须是**纯 JSON**（便于 jq / 监控脚本直接消费）
        report["problems"] = problems
        report["ok"] = not problems
        print(json.dumps(report, ensure_ascii=False, indent=2))
    summary = ("✅ 全部检查通过：这份 CRL 可信、与数据库一致、且就是当前应发布的内容。"
               if not problems else
               "❌ 存在 " + str(len(problems)) + " 个问题：\n  - " + "\n  - ".join(problems))
    if not as_json:
        print("\n" + summary)
    return 0 if not problems else 1


def cmd_unlock(args) -> int:
    """清除登录失败锁定（跨进程通过标记文件生效，服务下次处理登录时消费）。"""
    server.bootstrap(verbose=False)
    security.request_guard_reset()
    print("已请求清除登录失败锁定。")
    print("  服务会在下次收到登录请求时清空计数（无需重启）。")
    print("  也可以用： sudo systemctl restart ca-admin  （内存计数随进程重启清空）")
    return 0


def cmd_asset_hash(args) -> int:
    """打印前端资源哈希/指纹；可用 --check-url 核对线上实际返回的字节。

    典型用法（**在你自己的机器上跑**，本地副本来自可信渠道）：
        ca asset-hash --check-url http://your-server:9443
    期望值来自本地可信副本，实际值来自线上；一致才说明没被中间人篡改。
    """
    root = Path(args.root).expanduser() if getattr(args, "root", None) else None
    info = assetguard.report(root=root, check_url=getattr(args, "check_url", None),
                             cookie=getattr(args, "cookie", None))
    if args.json:
        _emit(info)
        return 0 if (info.get("compare") is None or info["compare"]["ok"]) else 1
    print(assetguard.as_text(info))
    return 0 if (info.get("compare") is None or info["compare"]["ok"]) else 1


def cmd_preflight(args) -> int:
    """服务器部署前自检：一条命令列出“能不能装、还缺什么、接下来敲什么”。"""
    import platform
    import shutil as _sh
    import socket as _sock

    rows: list[dict] = []

    def item(level: str, name: str, detail: str, fix: str = "") -> None:
        rows.append({"level": level, "item": name, "detail": detail, "fix": fix})

    # ---- Python 与依赖 ----
    major, minor = sys.version_info[:2]
    ver_ok = (major, minor) >= (3, 10)
    item("ok" if ver_ok else "error", "Python 版本", platform.python_version(),
         "" if ver_ok else "本项目要求 Python ≥ 3.10（联合类型注解）")
    if ver_ok:
        try:
            from cryptography import __version__ as _cv  # noqa: F401
            import nacl  # noqa: F401
            item("ok", "依赖 cryptography / pynacl", "已安装")
        except Exception as exc:  # noqa: BLE001
            item("error", "依赖 cryptography / pynacl", "导入失败：" + str(exc),
                 "在项目目录执行： .venv/bin/python -m pip install cryptography pynacl")
    try:
        import compileall
        okc = compileall.compile_dir(str(config.BASE_DIR / "backend"), quiet=2, force=True)
        item("ok" if okc else "error", "后端代码可编译",
             "无语法错误" if okc else "存在语法错误")
    except Exception as exc:  # noqa: BLE001
        item("warn", "后端代码可编译", "未检查：" + str(exc))

    # ---- 运行身份与数据目录 ----
    is_root = os.geteuid() == 0
    item("ok" if is_root else "warn", "运行身份",
         "uid=" + str(os.geteuid()) + ("（root）" if is_root else "（非 root）"),
         "" if is_root else "以 root 运行才能直写 /etc/swanctl 并执行 swanctl；"
                            "否则请启用 ca-strongswan-sync 同步单元")
    data_dir = config.DATA_DIR
    if data_dir.is_dir():
        try:
            probe = data_dir / ".preflight-write-test"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
            item("ok", "数据目录可写", str(data_dir))
        except Exception as exc:  # noqa: BLE001
            item("error", "数据目录可写", str(data_dir) + " 不可写：" + str(exc),
                 "确认目录存在且属主/权限正确")
    else:
        # 自检不创建任何东西：只看“能不能建”
        parent = data_dir if data_dir.exists() else data_dir.parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        item("ok" if os.access(parent, os.W_OK) else "error", "数据目录（尚不存在）",
             str(data_dir) + " 安装时会创建",
             "" if os.access(parent, os.W_OK) else str(parent) + " 不可写，无法创建数据目录")
    db_file = data_dir / "ca.db"
    if db_file.exists():
        try:
            certs = db.scalar("SELECT COUNT(*) FROM certs") or 0
            cas = db.scalar("SELECT COUNT(*) FROM cas") or 0
            item("info", "已有数据（升级场景）",
                 "CA " + str(cas) + " 个、证书 " + str(certs) + " 张",
                 "升级前建议先备份： cli backup")
        except Exception as exc:  # noqa: BLE001
            item("warn", "已有数据（升级场景）", "读取失败：" + str(exc))
    bdir = data_dir / "backups"
    backups = sorted(bdir.glob("ca-backup-*.tar.gz")) if bdir.is_dir() else []
    item("info", "现有备份",
         str(len(backups)) + " 份" if backups else "无（升级/改动前请先备份）")

    # ---- 端口 ----
    host, port = config.HOST, config.PORT
    bind_host = "0.0.0.0" if host in ("", "0.0.0.0") else host
    sock = _sock.socket()
    try:
        sock.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        sock.bind((bind_host, port))
        item("ok", "监听端口可用", host + ":" + str(port) + " 可绑定")
    except Exception as exc:  # noqa: BLE001
        item("warn", "监听端口可用", host + ":" + str(port) + " 绑定失败：" + str(exc),
             "端口被占用（可能是已在运行的服务）；确认后改端口或 systemctl restart")
    finally:
        sock.close()

    # ---- strongSwan 相关 ----
    swanctl_dir = config.SWANCTL_DIR
    exists = swanctl_dir.exists()
    item("ok" if exists else "warn", "strongSwan 目录",
         str(swanctl_dir) + (" 存在" if exists else " 不存在"),
         "" if exists else "本机不装 strongSwan 可忽略；装好后系统会自动识别并发 CRL")
    if exists:
        for d in (config.SWANCTL_CRL_DIR, config.SWANCTL_CA_DIR):
            d2 = d if d.exists() else d.parent
            item("ok" if os.access(d2, os.W_OK) else "warn", "目录可写 " + str(d), str(d2))
    has_swanctl = bool(_sh.which("swanctl"))
    has_ipsec = bool(_sh.which("ipsec"))
    item("ok" if (has_swanctl or has_ipsec or not exists) else "warn", "swanctl / ipsec 命令",
         "swanctl=" + ("有" if has_swanctl else "无") + " ipsec=" + ("有" if has_ipsec else "无"),
         "" if (has_swanctl or has_ipsec or not exists) else
         "找到了 strongSwan 目录但没有命令，请确认 strongSwan 安装完整")

    # ---- 工具链与磁盘 ----
    # tar/systemctl 缺失不阻断应用运行（备份用 Python tarfile，服务可前台跑），
    # 只作为"部署系统单元/打包"的提醒，因此记 warn 而不是 error。
    for tool, note in (("tar", "仅打包发布时需要；备份走 Python tarfile"),
                       ("curl", ""), ("systemctl", "缺失则无法安装 systemd 服务，可改用前台运行")):
        found = bool(_sh.which(tool))
        item("ok" if found else "warn", "命令 " + tool,
             "存在" if found else "不存在" + (f"（{note}）" if note else ""))
    try:
        total, used, free = _sh.disk_usage(str(data_dir))
        item("ok" if free > 200 * 1024 * 1024 else "warn", "磁盘剩余空间",
             str(free // (1024 * 1024)) + " MB 可用 / 共 " + str(total // (1024 * 1024)) + " MB")
    except Exception:  # noqa: BLE001
        pass

    # ---- 输出 ----
    errors = [r for r in rows if r["level"] == "error"]
    warns = [r for r in rows if r["level"] == "warn"]
    if args.json:
        _emit({"results": rows, "error": len(errors), "warn": len(warns),
               "ready": not errors})
        return 1 if errors else 0
    icons = {"ok": "\033[32m✓\033[0m", "warn": "\033[33m!\033[0m",
             "error": "\033[31m✗\033[0m", "info": "\033[36mi\033[0m", "setup": "?"}
    print("\n\033[1m部署前自检\033[0m  项目目录 " + str(config.BASE_DIR) + "\n")
    for r in rows:
        print("  " + icons.get(r["level"], "?") + " " + r["item"].ljust(26) + " " + r["detail"])
    verdict = "可以做部署" if not errors else "先解决上面的 error"
    print("\n  error " + str(len(errors)) + " 项、warn " + str(len(warns)) + " 项 → " + verdict)
    print("\n\033[1m接下来：\033[0m")
    print("  首次安装： sudo ./deploy/install.sh --systemd")
    print("  升级：     sudo ./deploy/upgrade.sh --code /tmp/ca-dev-<新版本>")
    print("  导入 CA：  sudo .venv/bin/python -m backend.cli import-ca "
          "--cert ~/ca.cert.pem --key ~/ca.key.pem")
    print("  装完自检： sudo .venv/bin/python -m backend.cli doctor")
    print("  只读验收： sudo .venv/bin/python tests/verify_deploy.py "
          "http://127.0.0.1:" + str(port) + " --pw-file " + str(data_dir)
          + "/initial_admin_password.txt")
    return 1 if errors else 0


def cmd_reload_cmd(args) -> int:
    """查看/统一所有发布目标的重载命令；--print 只输出命令本身（给脚本用）。"""
    if getattr(args, "print_only", False):
        server.bootstrap(verbose=False)
        print(args.set or db.get_setting("crl_reload_cmd") or config.DEFAULT_RELOAD_CMD)
        return 0
    if getattr(args, "preset", None):
        chosen = config.RELOAD_PRESETS.get(str(args.preset))
        if not chosen:
            print("可用预设：" + "、".join(sorted(config.RELOAD_PRESETS)))
            return 2
        args.set = chosen
        print(f"使用预设 {args.preset}：{chosen}")
    server.bootstrap(verbose=False)
    # 注意：不能用 args.cmd —— 那是 argparse 存的**子命令名**（"reload-cmd"），
    # 早期版本因此把目标的重载命令写成了字面量 "reload-cmd"（strongSwan 再也重载不了）。
    result = publish.apply_reload_cmd(getattr(args, "set", None) or None)
    _emit(result)
    return 0


def cmd_publish(args) -> int:
    server.bootstrap(verbose=False)
    _emit(publish.publish(trigger="cli", reload=not args.no_reload, actor="cli"))
    return 0


def cmd_check(args) -> int:
    server.bootstrap(verbose=False)
    report = consistency.check()
    _emit({"summary": report["summary"], "issues": report["issues"]})
    if args.repair:
        fixed = consistency.repair(actor="cli")
        _emit({"repaired": fixed["repaired"],
               "remaining": fixed["remaining"]["summary"]})
    return 1 if report["summary"]["error"] else 0


def cmd_export(args) -> int:
    server.bootstrap(verbose=False)
    if args.format == "json":
        text = json.dumps({"items": inventory.export_rows()}, ensure_ascii=False, indent=2)
    else:
        text = inventory.export_csv()
    if args.out:
        Path(args.out).expanduser().write_text(text, encoding="utf-8")
        print(f"已导出 {args.out}（{len(text)} 字节）")
    else:
        print(text)
    return 0


def cmd_bundle(args) -> int:
    server.bootstrap(verbose=False)
    blob, filename = strongswan.build_bundle(
        args.id, password=args.password or None, gateway=args.gateway,
        role=args.role, eap_identity=args.identity)
    out = Path(args.out).expanduser() if args.out else Path(filename)
    out.write_bytes(blob)
    out.chmod(0o600)
    print(f"已生成 strongSwan 部署包: {out}（{len(blob)} 字节）")
    return 0


def cmd_passwd(args) -> int:
    server.bootstrap(verbose=False)
    old = getpass.getpass("当前口令: ")
    new = getpass.getpass("新口令: ")
    again = getpass.getpass("再输一次: ")
    if new != again:
        raise CertError("两次输入不一致")
    security.change_password(old, new, actor=args.user)
    print("口令已修改；初始口令文件已删除（如存在）。")
    return 0


def cmd_backup(args) -> int:
    server.bootstrap(verbose=False)
    if args.restore:
        _emit(backup.restore(args.restore, actor="cli"))
    else:
        info = backup.create(name=args.name, actor="cli")
        info.pop("manifest", None)
        _emit(info)
    return 0


def cmd_automation(args) -> int:
    server.bootstrap(verbose=False)
    if args.list:
        for t in automation.list_tasks():
            print(f"{t['id']:>3}  {'开' if t['enabled'] else '关'}  {t['trigger']:<14} "
                  f"{t['kind']:<8} {t['name']}")
        return 0
    if args.run:
        task = automation.get_task(args.run)
        if task is None:
            raise CertError(f"任务不存在: {args.run}")
        res = automation.run_task(task, trigger="manual", actor="cli", force=True)
        _emit({"ok": res.ok, "message": res.message, "output": res.output})
        return 0 if res.ok else 1
    if args.run_due:
        _emit(automation.run_due(actor="cli"))
        return 0
    raise CertError("请指定 --list / --run ID / --run-due")


def cmd_csr_import(args) -> int:
    server.bootstrap(verbose=False)
    from . import csrs as csrs_mod
    res = csrs_mod.import_directory(args.path, dry_run=args.dry_run, owner=args.owner,
                                    tags=[t for t in (args.tags or "").split(",") if t],
                                    actor="cli") if Path(args.path).expanduser().is_dir() \
        else csrs_mod.import_csrs([(args.path, Path(args.path).expanduser().read_bytes())],
                                  dry_run=args.dry_run, owner=args.owner,
                                  tags=[t for t in (args.tags or "").split(",") if t],
                                  actor="cli")
    _emit({"scanned": res.get("scanned_files"), "dry_run": res.get("dry_run"),
           "preview": res.get("preview"), "imported": res.get("imported"),
           "skipped": res.get("skipped"), "errors": res.get("errors")})
    return 0


def cmd_csr_list(args) -> int:
    server.bootstrap(verbose=False)
    from . import csrs as csrs_mod
    res = csrs_mod.list_csrs(q=args.q, status=args.status, page=1, page_size=args.limit)
    for item in res["items"]:
        print(f"{item['id']:>4}  {item['status']:<9} {(item['cn'] or '-')[:26]:<26} "
              f"{item['key_type'] or '-':<5}{item['key_size'] or '':<5} "
              f"{'签发#' + str(item['cert_id']) if item['cert_id'] else ''}")
    print(f"（共 {res['total']} 条；待签发 {csrs_mod.stats()['pending']}）")
    return 0


def cmd_csr_issue(args) -> int:
    server.bootstrap(verbose=False)
    from . import csrs as csrs_mod
    result = csrs_mod.issue_from_csr(
        args.id, profile=args.ruleset, validity_days=args.days, force=args.force, actor="cli")
    cert = result["cert"]
    if args.out:
        from pathlib import Path as _P
        d = _P(args.out).expanduser(); d.mkdir(parents=True, exist_ok=True)
        slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in (cert["cn"] or "cert"))
        (d / f"{slug}.crt.pem").write_text(result["secret"]["cert_pem"])
        (d / f"{slug}-chain.pem").write_text(result["secret"].get("chain_pem") or "")
        print(f"已写入 {d}")
    _emit({"csr_id": result["csr_id"], "cert_id": cert["id"], "cn": cert["cn"],
           "serial": cert["serial_hex"], "not_after": cert["not_after"],
           "sans": cert["sans"], "ruleset": result["ruleset"]["slug"]})
    return 0


def cmd_doctor(args) -> int:
    """部署前/部署后自检：一条命令看清这台机器能不能跑、还缺什么。"""
    import os as _os
    import shutil
    import socket
    import stat as _stat
    import sys as _sys

    results: list[tuple[str, str, str, str]] = []   # (level, 项目, 说明, 建议)

    def add(level: str, name: str, detail: str, fix: str = "") -> None:
        results.append((level, name, detail, fix))

    # ---- 运行环境 ----
    venv = _sys.prefix != getattr(_sys, "base_prefix", _sys.prefix) or bool(
        _os.environ.get("VIRTUAL_ENV"))
    add("ok" if venv else "warn", "虚拟环境",
        f"Python {_sys.version.split()[0]}（{'venv' if venv else '系统解释器'}）",
        "" if venv else "建议使用 ./deploy/install.sh 创建的 .venv")
    try:
        import cryptography
        import nacl
        add("ok", "依赖", f"cryptography {cryptography.__version__} / pynacl {nacl.__version__}")
    except Exception as exc:  # noqa: BLE001
        add("error", "依赖", f"缺少依赖：{exc}", "运行 ./deploy/install.sh 或 pip install cryptography pynacl")

    server.bootstrap(verbose=False)

    # ---- 数据目录与敏感文件 ----
    mode = _stat.S_IMODE(config.DATA_DIR.stat().st_mode)
    add("ok" if not mode & 0o077 else "error", "数据目录权限",
        f"{config.DATA_DIR} {oct(mode)}",
        "" if not mode & 0o077 else "chmod 700（以 root 运行时还应 chown root:root）")
    owner = config.DATA_DIR.stat().st_uid
    if _os.geteuid() == 0:
        add("ok" if owner == 0 else "warn", "数据目录属主",
            f"uid={owner}（当前以 root 运行）",
            "" if owner == 0 else "chown -R root:root 数据目录，避免其它用户可删改")
    for f in (config.CHANNEL_KEY_FILE, config.SECRET_FILE, config.INITIAL_PW_FILE):
        if f.exists():
            m = _stat.S_IMODE(f.stat().st_mode)
            add("ok" if not m & 0o077 else "error", f"敏感文件 {f.name}",
                oct(m), "" if not m & 0o077 else f"chmod 600 {f}")

    # ---- 运行身份与 strongSwan ----
    add("ok" if config.RUN_AS_ROOT else "warn", "运行身份",
        f"uid={_os.geteuid()}（{'root' if config.RUN_AS_ROOT else '非 root'}）",
        "" if config.RUN_AS_ROOT else "以 root 运行才能直写 /etc/swanctl 并执行 swanctl；"
                                      "否则请启用 ca-strongswan-sync 单元")
    swanctl_dir = config.SWANCTL_DIR
    installed = swanctl_dir.is_dir()
    add("ok" if installed else "warn", "strongSwan",
        f"{swanctl_dir} {'存在' if installed else '不存在'}；"
        f"swanctl={'有' if shutil.which('swanctl') else '无'} "
        f"ipsec={'有' if shutil.which('ipsec') else '无'}",
        "" if installed else "若这台机器不装 strongSwan，可忽略；装好后系统会自动识别并发 CRL")
    if installed:
        for d in (config.SWANCTL_CRL_DIR, config.SWANCTL_CA_DIR):
            d2 = d if d.exists() else d.parent
            add("ok" if _os.access(d2, _os.W_OK) else "warn", f"目录可写 {d}",
                str(d2), "" if _os.access(d2, _os.W_OK) else "需要 root 权限")

    # ---- CA / CRL / 数据 ----
    ca_row = ca.active_ca_row()
    fresh_install = ca_row is None
    if fresh_install:
        # 全新实例：只给一条“待完成步骤”，不要因为它连带报出 CRL/一致性三项 error
        add("setup", "尚未导入 CA（全新实例的正常状态）", "导入后本项自动消失",
            "界面「CA 管理 → 导入」或 cli import-ca --cert ~/ca.cert.pem --key ~/ca.key.pem")
    else:
        add("ok", "CA", f"{ca_row['subject']}（有效期至 {ca_row['not_after'][:10]}）")
        add("ok" if ca_row["has_key"] else "error", "CA 私钥",
            "已就绪" if ca_row["has_key"] else "未导入 → 无法签发/生成 CRL",
            "" if ca_row["has_key"] else "cli import-ca --cert <cert> --key <key> [--password ...]")
    st = publish.status()
    due = st.get("due_in_hours")
    due_text = f"{due} 小时" if due is not None else "尚未生成"
    if fresh_install:
        add("info", "CRL 健康度", "等待导入 CA 后评估（导入 CA 会自动生成第一份 CRL）")
    else:
        add("ok" if st["health"] == "ok" else ("warn" if st["health"] == "warning" else "error"),
            "CRL 健康度", f"{st['health']}（目标 {st['enabled_targets']} 个，距到期 {due_text}）",
            "" if st["health"] == "ok" else "；".join(st.get("problems") or [])[:160])
    if shutil.which("swanctl"):
        add("ok", "CRL 重载命令", "swanctl --flush-certs && swanctl --load-creds")
    elif shutil.which("ipsec"):
        add("ok", "CRL 重载命令", "ipsec rereadcrls")
    elif installed:
        add("warn", "CRL 重载命令", "找到了 /etc/swanctl 但没找到 swanctl/ipsec 命令",
            "确认 strongSwan 安装完整，或在发布目标里自定义 reload 命令")
    else:
        add("ok", "CRL 重载命令", "本机未装 strongSwan，无需重载")

    # ---- strongSwan 是否已加载最新 CRL（charon 只在启动/reload 时读盘）----
    try:
        row = db.q1("SELECT number, created_at FROM crls ORDER BY id DESC LIMIT 1")
        if row is None:
            add("info", "CRL 加载状态", "尚未生成 CRL")
        else:
            last = publish.last_reload_at()
            last_t = x509util.parse_iso(last) if last else None
            crl_t = x509util.parse_iso(row["created_at"])
            loaded = bool(last_t and crl_t and last_t >= crl_t)
            how = ("charon 只在**启动或 reload** 时读取 CRL 文件，不会监视文件变化；"
                   "已建立的 IKE_SA 也不会因吊销自动断开（吊销在认证时校验）")
            if loaded:
                add("ok", "CRL 加载状态",
                    f"最新 CRL #{row['number']} 已随发布触发重载（上次重载 {last}）")
            else:
                add("warn", "CRL 加载状态",
                    f"最新 CRL #{row['number']}（{row['created_at']}）晚于上次重载"
                    f"（{last or '从未'}），strongSwan 可能仍在用旧 CRL", 
                    "执行： sudo .venv/bin/python -m backend.cli publish --reload；"
                    "核对重载命令包含 swanctl --flush-certs")
            add("info", "CRL 加载机制", how, 
                "检查重载效果及连接配置中的 reauth_time；重启预设会中断在线连接")
    except Exception as exc:  # noqa: BLE001
        add("warn", "CRL 加载状态", f"未检查：{exc}")

    # ---- CRL 文件是否唯一：目录里多份同 CA 的 CRL 会互相遮蔽（charon 只用编号最大的）----
    try:
        from . import strongswan as _ss
        ins = _ss.inspect_crl_files()
        if not ins["exists"]:
            add("info", "CRL 文件唯一性", f"目录不存在：{ins['dir']}（本机可能未装 strongSwan）")
        elif len(ins["ours"]) > 1:
            nums = "、".join(f"{i['file']}(#{i['number']})" for i in ins["ours"])
            top = max(ins["ours"], key=lambda i: i["number"] if isinstance(i["number"], int) else -1)
            tgt = next((t for t in publish.list_targets()
                        if t["enabled"] and t["kind"] == "dir_file"
                        and (t.get("content") or "crl") == "crl"), None)
            tgt_file = str(tgt["filename"]) if tgt else ""
            shadow = (tgt_file and top["file"] != tgt_file)
            add("error", "CRL 文件唯一性",
                f"{ins['dir']} 里有 {len(ins['ours'])} 份本 CA 的 CRL：{nums}。"
                f"charon **只保留编号最大的那一份**（这里会是 {top['file']}(#{top['number']})）"
                + (f"，而系统发布的是 {tgt_file} → **你的吊销会被这个旧文件遮蔽，永远不生效**"
                   if shadow else "；多余的旧文件随时可能在某个编号上超过我们，导致吊销失效"),
                "只保留一份（系统发布的那个文件名）：把多余的发布目标停用/删除，"
                "并把多余文件移走备份；再执行已配置的清缓存/重载命令"
                + ("；若现场编号比我们大，可先用 cli crl-number --set <现场最大+1> 跳号" if shadow else ""))
        elif len(ins["ours"]) == 1:
            i = ins["ours"][0]
            add("ok", "CRL 文件唯一性",
                f"{ins['dir']} 里本 CA 的 CRL 只有 1 份：{i['file']}（#{i['number']}，"
                f"{i['count']} 条），无遮蔽风险")
        else:
            add("warn", "CRL 文件唯一性",
                f"{ins['dir']} 里没找到本 CA 的 CRL（可能还没发布过）")
        if ins["others"]:
            add("info", "CRL 目录其它文件",
                "、".join(f"{i['file']}({i['issuer']})" for i in ins["others"][:3])
                + "（别的 CA 的 CRL，不影响本 CA）")
        # 同名但不同指纹的 CA：会让 charon 的 CRL 选择变得不确定 → 吊销可能被遮蔽
        ca_ins = _ss.inspect_ca_certs()
        if ca_ins["duplicate_subjects"]:
            for d in ca_ins["duplicate_subjects"]:
                add("error", "同名 CA 重复",
                    f"{ca_ins['dir']} 里有 {len(d['files'])} 张 **subject 相同但指纹不同** 的 CA "
                    f"证书（{d['subject']}）：{'、'.join(d['files'])}。"
                    f"charon 按签发者名字索引 CRL 且只留编号最大的那份，"
                    f"会导致其中一张 CA 的吊销被另一张遮蔽（重连照样通过）",
                    "只保留本系统的那张 CA 证书，其余移走备份；"
                    "并确保客户端证书由本系统的 CA 签发")
        elif ca_ins["exists"] and ca_ins["certs"]:
            add("ok", "CA 证书唯一性",
                f"{ca_ins['dir']} 里 {len(ca_ins['certs'])} 张 CA 证书，subject 无重复")
    except Exception as exc:  # noqa: BLE001
        add("warn", "CRL 文件唯一性", f"未检查：{exc}")

    # ---- 传输安全：明文 HTTP + 非回环绑定（明文 cookie = bearer 凭据）----
    try:
        if not config.TLS_ENABLED and not security.is_loopback_ip(config.HOST):
            add("error", "传输安全",
                f"当前监听 {config.HOST}:{config.PORT}（非回环）且未启用 TLS。"
                f"明文 HTTP 上不会下发会话 cookie（避免被嗅探后接管管理权限），"
                f"跨页面会话不可用；管理接口也暴露在网络中",
                "推荐：只监听回环 + ssh -L 9443:127.0.0.1:9443（install.sh --loopback）；"
                "或启用 TLS： CA_TLS=on")
        elif config.TLS_ENABLED:
            add("ok", "传输安全", "已启用 TLS（会话 cookie 带 Secure）")
        else:
            add("ok", "传输安全", f"明文 HTTP 但仅监听回环（{config.HOST}）——"
                                  f"配合 SSH 隧道属于受支持的安全部署")
    except Exception as exc:  # noqa: BLE001
        add("warn", "传输安全", f"未检查：{exc}")

    # ---- 重载命令是否"真的生效"（现场实测：reload 可能只换文件不换判定）----
    try:
        cur_cmd = (db.get_setting("crl_reload_cmd") or config.DEFAULT_RELOAD_CMD or "").strip()
        strong = "swanctl --flush-certs" in cur_cmd
        if not cur_cmd:
            add("error", "重载命令", "未设置（吊销/恢复后 strongSwan 不会更新）",
                "sudo .venv/bin/python -m backend.cli reload-cmd --preset restart")
        elif strong:
            add("ok", "重载命令", f"已包含 swanctl --flush-certs：{cur_cmd}")
        else:
            add("warn", "重载命令",
                f"当前为：{cur_cmd}。实测（strongSwan 5.9.x）仅 reload 时 charon 会继续用"
                f"缓存里的证书状态判定，表现为**吊销/恢复不生效**（要重启才生效）",
                "改用默认预设： cli reload-cmd --preset restart；"
                "不想重启可用 --preset flush"
                "（swanctl --flush-certs --type x509_crl && swanctl --load-creds，需实测）")
    except Exception as exc:  # noqa: BLE001
        add("warn", "重载命令", f"未检查：{exc}")

    # ---- 发布目标可写性：避免"打开页面一看一片红" ----
    try:
        bad = []
        for t in publish.list_targets():
            if not t["enabled"] or t["kind"] != "dir_file":
                continue
            d = Path(os.path.expandvars(os.path.expanduser(str(t["path"]))))
            if not d.is_dir():
                bad.append((t["name"], str(d), "目标目录不存在（本机不使用该布局）"))
            else:
                # 真写一个探针文件：root 身份下 os.access 不可靠，
                # 而 ProtectSystem=strict 这种沙箱只读是"写时才报 EROFS"。
                probe = d / f".ca-write-probe-{os.getpid()}"
                try:
                    probe.write_text("probe", encoding="utf-8")
                    probe.unlink()
                except OSError as exc:
                    bad.append((t["name"], str(d),
                                f"目录不可写（{getattr(exc, 'strerror', '') or exc}）"))
                finally:
                    try:
                        probe.unlink()
                    except OSError:
                        pass
        if not bad:
            add("ok", "CRL 发布目标",
                f"{sum(1 for t in publish.list_targets() if t['enabled'])} 个启用目标全部可写")
        else:
            fix = "在「CRL 自动发布」页停用/删除不适用的目标；若确实需要写该目录，把它加入服务的 ReadWritePaths（如 ReadWritePaths=-/etc/ipsec.d）"
            for name, path, why in bad[:3]:
                if "不存在" in why:
                    add("warn", f"发布目标 · {name}", f"{path}：{why}（发布时会自动跳过，不影响其它目标）", fix)
                else:
                    add("error", f"发布目标 · {name}", f"{path}：{why}", fix)
    except Exception as exc:  # noqa: BLE001
        add("warn", "CRL 发布目标", f"未检查：{exc}")

    # ---- 前端 CSP 兼容性：真实浏览器执行 CSP，内联脚本会被直接拦掉 ----
    try:
        fe = config.BASE_DIR / "frontend"
        inline_hits = []
        for name in ("index.html", "login.html"):
            text = (fe / name).read_text(encoding="utf-8")
            if re.search(r"<script(?![^>]*\bsrc=)", text):
                inline_hits.append(name)
        csp = security.security_headers(False, api=False)["Content-Security-Policy"]
        script_src = [x.strip() for x in csp.split(";") if x.strip().startswith("script-src")]
        loose = "unsafe-inline" in " ".join(script_src)
        if inline_hits:
            add("error", "前端 CSP 兼容",
                "、".join(inline_hits) + " 含内联 <script>，会被 CSP 的 script-src 'self' 拦掉，"
                "页面将无法工作（登录页会停在“正在建立加密信道…”）",
                "把内联脚本抽成外部 .js 文件加载")
        elif loose:
            add("warn", "前端 CSP 兼容", "script-src 含 unsafe-inline（已放开内联脚本执行）")
        else:
            add("ok", "前端 CSP 兼容", "无内联脚本；CSP 保持 script-src 'self'")
    except Exception as exc:  # noqa: BLE001
        add("warn", "前端 CSP 兼容", f"未检查：{exc}")

    try:
        fp = assetguard.fingerprint()
        add("ok", "前端资源指纹", f"{fp}（用 cli asset-hash --check-url 可核对线上未被篡改）")
    except Exception as exc:  # noqa: BLE001
        add("warn", "前端资源指纹", f"无法计算：{exc}")

    counts = {
        "规则集": db.scalar("SELECT COUNT(*) FROM rulesets"),
        "证书": db.scalar("SELECT COUNT(*) FROM certs"),
        "已吊销": db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked'"),
        "CSR 待签发": db.scalar("SELECT COUNT(*) FROM csrs WHERE status='pending'"),
        "发布目标(启用)": db.scalar("SELECT COUNT(*) FROM publish_targets WHERE enabled=1"),
        "自动化任务(启用)": db.scalar("SELECT COUNT(*) FROM automation_tasks WHERE enabled=1"),
    }
    add("ok", "数据概览", "；".join(f"{k} {v}" for k, v in counts.items()))

    # ---- 一致性体检 ----
    report = consistency.check()
    errs = [i for i in report["issues"] if i["level"] == "error"]
    warnn = [i for i in report["issues"] if i["level"] == "warning"]
    if fresh_install:
        # 没有 CA 时一致性体检必然只剩 no_ca 一项，不必重复报错
        add("info", "一致性体检", "等待导入 CA 后评估")
    else:
        add("ok" if not errs else "error", "一致性体检",
            f"错误 {len(errs)}、警告 {len(warnn)}",
            "" if not errs else "；".join(f"{i['code']}: {i['message']}" for i in errs[:3]))
        if errs:
            add("info", "可自动修复", "cli check --repair 或界面「一致性体检 → 一键修复」")

    # ---- 端口 ----
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((config.HOST if config.HOST not in ("0.0.0.0", "::") else "127.0.0.1",
                    config.PORT))
        probe.close()
        add("ok", "监听端口", f"{config.HOST}:{config.PORT} 可绑定")
    except OSError as exc:
        add("warn", "监听端口", f"{config.HOST}:{config.PORT} 不可绑定：{exc}",
            "若服务已在本机运行则属正常；否则换端口（CA_PORT）")
    add("ok", "加密信道指纹", secure_channel.identity.fingerprint,
        "首次在浏览器打开界面时请核对一致")

    if args.json:
        _emit({"results": [{"level": l, "item": n, "detail": d, "fix": f}
                           for l, n, d, f in results],
               "ok": not any(l == "error" for l, _n, _d, _f in results)})
    else:
        icon = {"ok": "\033[32m✓\033[0m", "warn": "\033[33m!\033[0m",
                "error": "\033[31m✗\033[0m", "info": "\033[36mi\033[0m"}
        print("\n\033[1mCA 管理系统 · 部署自检\033[0m\n")
        for level, name, detail, _fix in results:
            print(f"  {icon.get(level, '?')} {name:<16} {detail}")
        todo = [(n, f) for l, n, _d, f in results if l in ("error", "warn") and f]
        print()
        if todo:
            print("\033[1m待办：\033[0m")
            for n, f in todo:
                print(f"  · {n}: {f}")
        else:
            print("\033[32m一切就绪。\033[0m")
    return 1 if any(l == "error" for l, _n, _d, _f in results) else 0


def cmd_rulesets(args) -> int:
    server.bootstrap(verbose=False)
    if args.show:
        _emit(rules.get(args.show))
    else:
        for rs in rules.list_all():
            spec = rs["spec"]
            print(f"{rs['id']:>3}  {rs['slug']:<28} {rs['platform']:<10} "
                  f"{spec['validity']['days']:>5}天  EKU={','.join(spec['extensions']['eku']) or '-'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ca", description="CA 证书管理系统命令行工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="初始化（数据目录/规则集/管理员）").set_defaults(func=cmd_init)
    sub.add_parser("fingerprint", help="打印加密信道指纹").set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("import-ca", help="导入 CA 证书/私钥")
    p.add_argument("--cert", required=True)
    p.add_argument("--key")
    p.add_argument("--chain")
    p.add_argument("--password", help="私钥口令（如果私钥是加密的）")
    p.set_defaults(func=cmd_import_ca)

    p = sub.add_parser("import", help="批量导入证书/私钥/PKCS#12/ZIP")
    p.add_argument("--path", required=True, help="目录或文件路径")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--revoked", action="store_true", help="导入时直接标记为已吊销")
    p.add_argument("--reason", default="unspecified")
    p.add_argument("--owner")
    p.add_argument("--tags")
    p.add_argument("--no-recursive", action="store_true")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("list", help="列出证书")
    p.add_argument("--status")
    p.add_argument("--q")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("issue", help="签发证书")
    p.add_argument("--cn")
    p.add_argument("--identity", help="VPN/IKEv2 身份（自动写入 SAN）")
    p.add_argument("--identity-type", default="auto", choices=["auto", "dns", "email", "ip", "upn"])
    p.add_argument("--ruleset", help="规则集 slug（默认取系统默认规则集）")
    p.add_argument("--days", type=int)
    p.add_argument("--san-dns", action="append")
    p.add_argument("--san-ip", action="append")
    p.add_argument("--san-email")
    p.add_argument("--owner")
    p.add_argument("--tags")
    p.add_argument("--notes")
    p.add_argument("--out", help="把证书/私钥输出到该目录")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("revoke", help="吊销证书并发布 CRL")
    p.add_argument("--id", type=int)
    p.add_argument("--serial")
    p.add_argument("--cn", help="按 CN 定位证书（可配合 --force 批量）")
    p.add_argument("--force", action="store_true", help="CN 匹配到多张时全部吊销")
    p.add_argument("--reason", default="unspecified")
    p.add_argument("--notes")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("unrevoke", help="恢复吊销并立即更新 strongSwan（重新生成/发布 CRL + 重载）")
    p.add_argument("--id", type=int)
    p.add_argument("--serial")
    p.add_argument("--cn", help="按 CN 定位（可配合 --force 批量恢复）")
    p.add_argument("--force", action="store_true", help="CN 匹配到多张时全部恢复")
    p.add_argument("--no-publish", action="store_true", help="只改本库，不发布/重载")
    p.set_defaults(func=cmd_unrevoke)

    p = sub.add_parser("gencrl", help="重新生成并发布 CRL")
    p.add_argument("--days", type=int)
    p.add_argument("--no-reload", action="store_true")
    p.set_defaults(func=cmd_gencrl)

    p = sub.add_parser("publish", help="把 CRL/CA 发布到所有目标")
    p.add_argument("--no-reload", action="store_true")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("sync-plan", help="（内部）root 同步单元该拷贝哪些文件：src<TAB>dst")
    p.add_argument("--staging", help="暂存目录（默认 data/publish）")
    p.set_defaults(func=cmd_sync_plan)

    p = sub.add_parser("targets", help="列出发布目标；--prune-unused 停用目录不存在的目标")
    p.add_argument("--prune-unused", action="store_true",
                   help="停用目录不存在的启用目标（清理历史遗留）")
    p.add_argument("--keep-single", action="store_true",
                   help="同一目录同一内容只保留一个启用目标（防 CRL 互相遮蔽，推荐）")
    p.add_argument("--disable", type=int, nargs="+", metavar="ID", help="按 id 停用目标")
    p.add_argument("--delete", type=int, nargs="+", metavar="ID", help="按 id 删除目标")
    p.add_argument("--allow-shadow", type=int, nargs="+", metavar="ID",
                   help="允许该目标与同目录其它目标并存（高级用法，默认禁止）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("crl-number", help="查看/设置 CRL 编号下限（接管现场 CA 时避免被旧 CRL 遮蔽）")
    p.add_argument("--set", type=int, help="设置编号下限（建议＝现场最大编号+1）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_crl_number)

    p = sub.add_parser("import-crl", help="导入外部 CRL（把其中的序列号标记为已吊销）")
    p.add_argument("--file", required=True, help="CRL 文件（PEM 或 DER）")
    p.set_defaults(func=cmd_import_crl)

    p = sub.add_parser("crl-info", help="验证 CRL 文件：结构 + 签名 + 与库/发布目标一致性")
    p.add_argument("--file", help="要验证的 CRL 文件（默认取启用的发布目标里的 CRL）")
    p.add_argument("--serial", help="额外查询某个序列号是否已吊销（十六进制）")
    p.add_argument("--cert", help="拿客户端实际在用的证书文件做判定（直接解释为什么还能连）")
    p.add_argument("--json", action="store_true", help="输出 JSON（含 checks 明细与 problems）")
    p.set_defaults(func=cmd_crl_info)

    p = sub.add_parser("unlock", help="清除登录失败锁定（被锁在外时用）")
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("asset-hash", help="前端资源指纹；可核对线上字节是否被篡改")
    p.add_argument("--json", action="store_true", help="机器可读输出")
    p.add_argument("--root", help="前端目录（默认项目 frontend/）")
    p.add_argument("--check-url", help="同时核对运行中的服务实际返回的字节，例如 http://your-server:9443")
    p.add_argument("--cookie", help="会话 cookie（核对登录后的 SPA 外壳时用，如 ca_session=...）")
    p.set_defaults(func=cmd_asset_hash)

    p = sub.add_parser("preflight", help="部署前自检（Python/依赖/权限/端口/strongSwan/工具链）")
    p.add_argument("--json", action="store_true", help="机器可读输出")
    p.set_defaults(func=cmd_preflight)

    p = sub.add_parser("reload-cmd", help="查看/统一发布目标的重载命令")
    p.add_argument("--set", help="设为指定命令")
    p.add_argument("--preset", help="用预设：restart(默认,最可靠) / flush(较轻) / reload(最轻)",
                   choices=("restart", "flush", "reload"))
    p.add_argument("--print", dest="print_only", action="store_true",
                   help="只输出当前重载命令（给同步脚本用）")
    p.set_defaults(func=cmd_reload_cmd)

    p = sub.add_parser("check", help="一致性体检")
    p.add_argument("--repair", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("export", help="导出证书清单")
    p.add_argument("--format", default="csv", choices=["csv", "json"])
    p.add_argument("--out")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("bundle", help="生成 strongSwan 一键部署包")
    p.add_argument("--id", type=int, required=True)
    p.add_argument("--role", choices=["client", "gateway"])
    p.add_argument("--gateway")
    p.add_argument("--identity")
    p.add_argument("--password", help="同时生成 PKCS#12（口令）")
    p.add_argument("--out")
    p.set_defaults(func=cmd_bundle)

    p = sub.add_parser("passwd", help="修改管理员口令")
    p.add_argument("--user", default="admin")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("backup", help="创建/恢复备份")
    p.add_argument("--name")
    p.add_argument("--restore", help="要恢复的备份文件名")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("automation", help="自动化任务")
    p.add_argument("--list", action="store_true")
    p.add_argument("--run", help="按 ID 立即运行")
    p.add_argument("--run-due", action="store_true", help="执行所有到期的定时/CRL 任务")
    p.set_defaults(func=cmd_automation)

    p = sub.add_parser("doctor", help="部署自检（环境/权限/CA/CRL/strongSwan/端口/一致性）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("csr-import", help="批量导入 CSR 到证书请求池")
    p.add_argument("--path", required=True, help="CSR 文件或目录（支持 zip）")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--owner")
    p.add_argument("--tags")
    p.set_defaults(func=cmd_csr_import)

    p = sub.add_parser("csr-list", help="列出证书请求池")
    p.add_argument("--status", choices=["pending", "issued", "rejected"])
    p.add_argument("--q")
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=cmd_csr_list)

    p = sub.add_parser("csr-issue", help="用池中的 CSR 签发证书")
    p.add_argument("--id", type=int, required=True)
    p.add_argument("--ruleset", help="规则集 slug")
    p.add_argument("--days", type=int)
    p.add_argument("--force", action="store_true", help="允许重复签发/签发被拒绝的请求")
    p.add_argument("--out", help="导出证书目录")
    p.set_defaults(func=cmd_csr_issue)

    p = sub.add_parser("rulesets", help="查看规则集")
    p.add_argument("--show", help="按 slug 或 ID 查看完整规则")
    p.set_defaults(func=cmd_rulesets)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CertError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
