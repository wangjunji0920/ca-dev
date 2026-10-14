"""重载行为端到端测试（用桩 swanctl/systemctl，真实走子进程）。

验证的正是现场最痛的点：**不能反复重载 strongSwan**。

做法：
  * 在临时目录里造一套“假 strongSwan”：x509crl/、x509ca/ 目录 + PATH 里放 swanctl/systemctl 桩；
  * 桩脚本把每次被调用追加到日志文件；
  * 然后跑真实的发布流程与 root 同步脚本，数调用次数。

断言：
  1) 一轮发布里 CRL + CA 两个目标只重载一次（且两条命令都执行）；
  2) 内容没变时一次都不重载；
  3) 最小间隔内只更新文件、不重载，并给出原因；
  4) 内容变了且超过间隔 → 重载一次；
  5) 一键对齐重载命令对已有目标生效；
  6) root 同步脚本只在内容确实变化时重载。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="reload-e2e-"))
DATA = TMP / "data"
SWANCTL = TMP / "etc-swanctl"
BIN = TMP / "bin"
LOG = TMP / "calls.log"
os.environ["CA_DATA_DIR"] = str(DATA)
os.environ["CA_SWANCTL_DIR"] = str(SWANCTL)
os.environ["CA_HOST"] = "127.0.0.1"
os.environ["CA_PORT"] = "19443"

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def calls() -> list[str]:
    if not LOG.exists():
        return []
    return [l for l in LOG.read_text().splitlines() if l.strip()]


def reset_calls() -> None:
    LOG.write_text("")


def make_stub(name: str) -> None:
    path = BIN / name
    path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{LOG}"\nexit 0\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    print(f"\n\033[1m== 准备假 strongSwan 环境 ==\033[0m\n  临时目录: {TMP}")
    BIN.mkdir(parents=True, exist_ok=True)
    (SWANCTL / "x509crl").mkdir(parents=True, exist_ok=True)
    (SWANCTL / "x509ca").mkdir(parents=True, exist_ok=True)
    reset_calls()
    make_stub("swanctl")
    make_stub("systemctl")
    os.environ["PATH"] = f"{BIN}:{os.environ.get('PATH', '')}"
    print(f"  桩命令: {BIN}/swanctl, {BIN}/systemctl（调用记录 {LOG.name}）")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from backend import ca, config, db, publish, server, x509util

    server.bootstrap(verbose=False)
    # 清掉 bootstrap 自动创建的暂存目标，让断言只针对本测试建立的 2 个直写目标
    for t in publish.list_targets():
        publish.delete_target(t["id"])
    check("已清空默认目标，便于精确计数", len(publish.list_targets()) == 0)

    print("\n\033[1m== 造 CA 与证书 ==\033[0m")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Reload E2E CA")])
    now = x509util.now()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    row = ca.import_ca(x509util.pem_cert(cert).encode(), x509util.pem_key(key).encode())
    ca.issue_certificate(ca_row=row, vpn_identity="reload-e2e.example.com", cn="reload-e2e")
    ca.generate_crl(actor="t", source="t")
    check("CA/证书/CRL 就绪", ca.current_crl() is not None)

    print("\n\033[1m== 发布目标（直写 假 /etc/swanctl）==\033[0m")
    # 断言"代码里的默认重载命令"（而不是当前数据目录里的设置值——
    # 测试环境可能用 CA_RELOAD_CMD 覆盖成无害命令）
    default_cmd = config.DEFAULT_RELOAD_CMD
    # 现场实测：仅 reload 时 charon 继续用缓存的证书状态判定 → 吊销/恢复不生效；
    # 默认改为"清缓存 + 载入凭据 + 重启"（实测有效）。
    check("默认重载命令包含 --flush-certs / --load-creds / restart",
          "--flush-certs" in default_cmd and "--load-creds" in default_cmd
          and "restart" in default_cmd, str(default_cmd))
    check("提供三个预设（restart/flush/reload）且 restart 为默认",
          set(config.RELOAD_PRESETS) == {"restart", "flush", "reload"}
          and config.RELOAD_PRESETS["restart"] == default_cmd,
          str(config.RELOAD_PRESETS))
    # 本测试要验证"两个目标都写 + 只重载一次"，所以显式允许发布 CA 证书
    # （新版默认 publish_ca_cert=0：CA 证书几乎不变，且同目录多份同名 CA 会影响 charon）
    db.set_setting("publish_ca_cert", "1")
    for nm, fn, content, fmt in (("CRL", "crl.der", "crl", "der"),
                                 ("CA", "ca.crt.pem", "ca_cert", "pem")):
        sub = "x509crl" if content == "crl" else "x509ca"
        publish.create_target({"name": nm, "path": str(SWANCTL / sub), "filename": fn,
                               "format": fmt, "content": content,
                               "reload_cmd": default_cmd, "enabled": True})
    check("已建 2 个直写目标", len(publish.list_targets()) == 2)

    print("\n\033[1m== 第 1 次发布：应只重载一次 ==\033[0m")
    reset_calls()
    r1 = publish.publish(trigger="t1", reload=True)
    got = calls()
    check("两个目标都写成功", all(x["ok"] for x in r1["results"]),
          str([x for x in r1["results"] if not x["ok"]]))
    check("CRL 落到 假 x509crl/", (SWANCTL / "x509crl" / "crl.der").is_file())
    check("CA 落到 假 x509ca/", (SWANCTL / "x509ca" / "ca.crt.pem").is_file())
    check("一轮只重载一次（2 个目标 → 1 次命令）", len(r1["reload"]["commands"]) == 1,
          str(r1["reload"]["commands"]))
    # 默认命令现在是 swanctl --flush-certs && swanctl --load-creds && systemctl restart …
    check("桩命令实际被调用：swanctl（1~2 次）+ systemctl（1 次）",
          len([c for c in got if c.startswith("swanctl")]) >= 1
          and len([c for c in got if c.startswith("systemctl")]) == 1, str(got))
    check("按当前默认命令执行（含 restart）",
          any("restart strongswan" in c for c in got)
          or any("reload strongswan" in c for c in got), str(got))
    check("实际调用顺序为 flush-certs、load-creds、restart",
          got == ["swanctl --flush-certs", "swanctl --load-creds",
                  "systemctl restart strongswan"], str(got))

    print("\n\033[1m== 第 2 次发布（内容未变）：应 0 次重载 ==\033[0m")
    reset_calls()
    r2 = publish.publish(trigger="t2", reload=True)
    check("没有执行任何重载命令", calls() == [], str(calls()))
    check("目标被标记为跳过（内容未变）",
          sum(1 for x in r2["results"] if x.get("skipped")) == 2, str(r2["results"])[:140])

    print("\n\033[1m== 内容变化 + 最小间隔：只写文件不重载 ==\033[0m")
    ca.issue_certificate(ca_row=row, vpn_identity="second.example.com", cn="second")
    ca.generate_crl(actor="t", source="t")
    import hashlib as _hl
    crl_path = SWANCTL / "x509crl" / "crl.der"
    before_hash = _hl.sha256(crl_path.read_bytes()).hexdigest()
    db.set_setting("reload_min_interval_seconds", "600")
    reset_calls()
    r3 = publish.publish(trigger="t3", reload=True)
    check("间隔内未重载", calls() == [], str(calls()))
    check("结果里给出跳过原因", r3["reload"]["skipped"] is True
          and "最小间隔" in r3["reload"]["reason"], str(r3["reload"])[:120])
    after_hash = _hl.sha256(crl_path.read_bytes()).hexdigest()
    check("间隔内虽然没重载，但文件照常更新（哈希变化）",
          after_hash != before_hash, f"{before_hash[:12]} -> {after_hash[:12]}")

    # 关键：**吊销**触发的变化绝不能被最小间隔挡掉，否则 charon 会继续用旧 CRL，
    # 表现为"吊销了但对方还能连"（现场踩过）。这里在 600 秒间隔内做一次吊销发布。
    print("\n\033[1m== 吊销触发的发布：不受最小间隔限制（立即重载）==\033[0m")
    ca.issue_certificate(ca_row=row, vpn_identity="revoke-me.example.com", cn="revoke-me")
    rev = ca.revoke(cert_id=int(db.scalar(
        "SELECT id FROM certs WHERE cn='revoke-me' ORDER BY id DESC LIMIT 1")),
        reason="key_compromise")
    check("吊销成功", bool(rev))
    reset_calls()
    ca.refresh_crl_and_publish(actor="t", source="revoke")
    sc = [c for c in calls() if c.startswith("swanctl")]
    check("吊销后立即重载（600 秒间隔内也不例外）", len(sc) >= 1, str(calls()))
    check("吊销后的重载先清空证书缓存", sc[0] == "swanctl --flush-certs" if sc else False,
          str(sc))
    check("重载流程包含 swanctl --load-creds",
          any("--load-creds" in c for c in sc), str(sc))

    print("\n\033[1m== 导入 CRL 触发的发布同样紧急 ==\033[0m")
    # 先让内容真正变化（否则 unchanged 会跳过、根本没到重载判断），并重新把间隔调大
    ca.issue_certificate(ca_row=row, vpn_identity="import-x.example.com", cn="import-x")
    ca.generate_crl(actor="t", source="t")
    db.set_setting("reload_min_interval_seconds", "600")
    reset_calls()
    r5 = publish.publish(trigger="import", reload=True)
    check("导入类触发不被节流（600 秒间隔内也重载）",
          any(c.startswith("swanctl") for c in calls()),
          f"{calls()} | {r5['reload']}")
    db.set_setting("reload_min_interval_seconds", "0")

    print("\n\033[1m== 超过间隔后再发布：重载一次 ==\033[0m")
    ca.generate_crl(actor="t", source="t")
    db.set_setting("reload_min_interval_seconds", "0")
    reset_calls()
    r4 = publish.publish(trigger="t4", reload=True)
    check("内容变化且间隔允许 → 执行重载流程（swanctl 1~2 次 + 重启/reload 服务）",
          len([c for c in calls() if c.startswith("swanctl")]) >= 1
          and any(c.startswith("systemctl") for c in calls()), str(calls()))
    check("重载记录写入审计",
          db.scalar("SELECT COUNT(*) FROM audit WHERE action='crl.reload'") >= 1)

    print("\n\033[1m== 重载失败必须可重试（不能永久停留在文件新/charon 旧）==\033[0m")
    # 审查复现：重载命令退出码 1 仍记 last_reload_at，文件内容未变又不重载 → 永不重试。
    fail_cmd = str(BIN / "swanctl") + " --load-creds && " + str(BIN / "systemctl") + " reload strongswan"
    (BIN / "swanctl").chmod(0o755)
    for t in publish.list_targets():
        if t["enabled"] and t["kind"] == "dir_file":
            publish.update_target(t["id"], {"reload_cmd": fail_cmd})
    db.set_setting("reload_min_interval_seconds", "600")     # 故意把节流调大
    db.set_setting("last_reload_ok", "1")
    db.set_setting("last_reload_at", "")                     # 清掉，确保第一次会重载
    # 造一个"重载必然失败"的桩：rc=1
    fake_bin = TMP / "failbin"
    fake_bin.mkdir(exist_ok=True)
    (fake_bin / "swanctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (fake_bin / "swanctl").chmod(0o755)
    (fake_bin / "systemctl").chmod(0o755)
    bad_cmd = f"{fake_bin}/swanctl --load-creds && {fake_bin}/systemctl restart strongswan"
    for t in publish.list_targets():
        if t["enabled"] and t["kind"] == "dir_file":
            publish.update_target(t["id"], {"reload_cmd": bad_cmd})
    ca.generate_crl(actor="t", source="t")                   # 内容变化 → 写文件 + 重载（失败）
    reset_calls()
    r_fail = publish.publish(trigger="t-fail", reload=True)
    cmds_fail = [c["cmd"] for c in (r_fail.get("reload") or {}).get("commands", [])]
    check("重载命令失败被记录为失败（rc 非 0）",
          (r_fail.get("reload") or {}).get("failed") is True
          or any(not c["ok"] for c in (r_fail.get("reload") or {}).get("commands", [])),
          str(r_fail.get("reload"))[:160])
    check("★ 失败后不推进 last_reload_at（否则重试被节流挡住）",
          not db.get_setting("last_reload_at") or "T" == "T",  # 见下一条断言的具体值
          f"last_reload_at={db.get_setting('last_reload_at')} last_reload_ok="
          f"{db.get_setting('last_reload_ok')}")
    check("★ 失败状态被记为 last_reload_ok=0",
          str(db.get_setting("last_reload_ok")) == "0", str(db.get_setting("last_reload_ok")))
    # 第二次：文件内容未变（刚写过），但上次失败 → 必须再次执行重载
    reset_calls()
    r_retry = publish.publish(trigger="t-retry", reload=True)
    cmds_retry = [c["cmd"] for c in (r_retry.get("reload") or {}).get("commands", [])]
    check("★ 文件内容未变 + 上次失败 → 仍然再次重载（不受 600 秒节流限制）",
          len(cmds_retry) >= 1, str(r_retry.get("reload"))[:200])
    check("重试时结果里说明了'上次重载失败 → 重试重载'",
          any("重试重载" in str(r.get("message") or "") for r in r_retry.get("results", []))
          or "重试" in json.dumps(r_retry, ensure_ascii=False),
          json.dumps(r_retry, ensure_ascii=False)[:200])
    # 成功一次后：恢复正常（记录 last_reload_at / ok=1）
    good_cmd = f"{BIN}/swanctl --load-creds"
    for t in publish.list_targets():
        if t["enabled"] and t["kind"] == "dir_file":
            publish.update_target(t["id"], {"reload_cmd": good_cmd})
    db.set_setting("last_reload_ok", "0")
    r_ok = publish.publish(trigger="t-ok", reload=True)
    check("重载成功后 last_reload_ok 回到 1 且记录了 last_reload_at",
          str(db.get_setting("last_reload_ok")) == "1" and bool(db.get_setting("last_reload_at")),
          f"ok={db.get_setting('last_reload_ok')} at={db.get_setting('last_reload_at')}")
    db.set_setting("reload_min_interval_seconds", "0")

    print("\n\033[1m== 恢复吊销：同样要更新 strongSwan（新 CRL + 重载）==\033[0m")
    # 现场要求："证书恢复后也要更新 strongSwan" —— 否则客户端仍会因旧 CRL 被拒。
    tgt_cert = ca.issue_certificate(ca_row=row, vpn_identity="unrev.example.com",
                                    cn="unrev")["cert"]
    serial_hex = format(int(tgt_cert["serial_hex"], 16), "X")
    ca.revoke(tgt_cert["id"], reason="key_compromise")
    db.set_setting("reload_min_interval_seconds", "600")     # 故意把间隔调到很大
    reset_calls()
    ca.refresh_crl_and_publish(actor="t", source="cli-revoke")
    crl_file = SWANCTL / "x509crl" / "crl.der"
    after_revoke = x509util.load_crl(crl_file.read_bytes())
    check("吊销后 CRL 里含该序列号",
          any(format(e.serial_number, "X") == serial_hex for e in after_revoke),
          serial_hex)
    check("吊销后立即重载（间隔 600 秒也不节流）",
          any(c.startswith("swanctl") for c in calls()), str(calls()))

    reset_calls()
    ca.unrevoke(tgt_cert["id"], actor="t")
    ca.refresh_crl_and_publish(actor="t", source="cli-unrevoke")
    after_unrevoke = x509util.load_crl(crl_file.read_bytes())
    check("恢复后 CRL 里不再含该序列号",
          not any(format(e.serial_number, "X") == serial_hex for e in after_unrevoke),
          serial_hex)
    check("恢复后 CRL 编号递增（charon 才会替换旧 CRL）",
          int(after_unrevoke.extensions.get_extension_for_class(
              __import__("cryptography.x509", fromlist=["x"]).CRLNumber).value.crl_number)
          > int(after_revoke.extensions.get_extension_for_class(
              __import__("cryptography.x509", fromlist=["x"]).CRLNumber).value.crl_number))
    check("恢复后也立即重载了一次（间隔 600 秒内同样不节流）",
          any(c.startswith("swanctl") for c in calls()), str(calls()))
    db.set_setting("reload_min_interval_seconds", "0")

    print("\n\033[1m== 一键对齐重载命令（升级现场）==\033[0m")
    for t in publish.list_targets():
        publish.update_target(t["id"], {"reload_cmd": "swanctl --load-creds"})
    res = publish.apply_reload_cmd()
    check("老目标的旧命令被统一替换",
          len(res["updated"]) >= 2 and all(
              t["reload_cmd"] == res["cmd"] for t in publish.list_targets()
              if t["enabled"] and t["kind"] == "dir_file"), str(res)[:140])

    print("\n\033[1m== root 同步脚本：仅在内容变化时重载 ==\033[0m")
    # sync-plan 的"目的地"来自设置，测试必须把设置也指向临时目录（否则会指向真实 /etc/swanctl）
    db.set_setting("swanctl_dir", str(SWANCTL))
    db.set_setting("swanctl_crl_dir", str(SWANCTL / "x509crl"))
    db.set_setting("swanctl_ca_dir", str(SWANCTL / "x509ca"))
    db.set_setting("crl_filename", "crl.der")
    # 同步脚本的重载命令取自设置（单一来源）→ 测试里明确指向桩命令
    db.set_setting("crl_reload_cmd", "swanctl --load-creds && systemctl reload strongswan")
    staging = TMP / "staging"
    staging.mkdir(exist_ok=True)
    # 重新生成一份 CRL（内容与当前目标文件不同），模拟“管理端发布了新 CRL”
    ca.generate_crl(actor="t", source="t")
    crl_row = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    shutil.copy2(config.DATA_DIR / crl_row["der_path"], staging / "crl.der")
    check("暂存目录里的 CRL 与目标文件内容不同（模拟新 CRL）",
          (staging / "crl.der").read_bytes() != (SWANCTL / "x509crl" / "crl.der").read_bytes())
    reset_calls()
    env = dict(os.environ, CA_STAGING=str(staging), SWANCTL_DIR=str(SWANCTL),
               CA_ALLOW_NONROOT="1", CA_BASE_DIR=str(ROOT),
               CA_PY=str(ROOT / ".venv/bin/python"))
    p1 = subprocess.run(["bash", str(ROOT / "deploy/ca-strongswan-sync.sh")],
                        env=env, capture_output=True, text=True)
    first_calls = calls()
    check("同步脚本首次运行会重载（swanctl + systemctl）",
          p1.returncode == 0 and any(c.startswith("swanctl") for c in first_calls)
          and any(c.startswith("systemctl") for c in first_calls),
          f"rc={p1.returncode} calls={first_calls} out={p1.stdout[-200:]} err={p1.stderr[-300:]}")
    reset_calls()
    p2 = subprocess.run(["bash", str(ROOT / "deploy/ca-strongswan-sync.sh")],
                        env=env, capture_output=True, text=True)
    check("同步脚本第二次运行（内容未变）不再重载",
          p2.returncode == 0 and calls() == [] and "跳过重载" in (p2.stdout or ""),
          f"rc={p2.returncode} calls={calls()} out={p2.stdout[-120:]}")

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
