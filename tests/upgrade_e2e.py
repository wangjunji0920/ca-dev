"""升级流程验收：在沙箱里演练"旧版本 → 新版本"，确认数据不丢。

服务器上升级就一条命令： sudo ./deploy/upgrade.sh --code /tmp/ca-dev-<新版本>
这里把它完整跑一遍，但：
  * 用 SYSTEMD_DIR / SBIN_DIR 指向临时目录（**不写 /etc/systemd/system**）；
  * CA_ALLOW_NONROOT=1 且自动跳过 systemctl（**不动任何系统服务**）；
  * 从一个"外地" cwd 执行（覆盖"从别处执行 sudo /opt/ca-dev/deploy/upgrade.sh"的场景）。

断言：
  1) --dry-run 不修改任何文件；
  2) 真升级会先备份（名字含 pre-upgrade）；
  3) 代码被新版本覆盖（新文件出现、旧文件消失）；
  4) **数据保留**：CA 私钥与证书数量不变；
  5) 升级**保留**自定义重载命令，--force-reload-cmd 才对齐为默认；
  6) 单元渲染到 SYSTEMD_DIR 且没有残留占位符；
  7) 定时器默认策略＝关闭；--dry-run --with-timer 时＝保留；
  8) 升级后 doctor 无 error。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="upgrade-e2e-"))
OLD = TMP / "old"
NEW = TMP / "new"
SYS_DIR = TMP / "etc-systemd"
SBIN_DIR = TMP / "sbin"
DATA = OLD / "data"

PASS: list[str] = []
FAIL: list[str] = []
COPY_DIRS = ("backend", "frontend", "deploy", "tests")
COPY_FILES = ("run.sh", "README.md")


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def copy_project(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for d in COPY_DIRS:
        shutil.copytree(ROOT / d, dest / d,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for f in COPY_FILES:
        if (ROOT / f).is_file():
            shutil.copy2(ROOT / f, dest / f)
    (dest / ".venv").symlink_to(ROOT / ".venv")


def tree_hash(root: Path, skip_data: bool = True) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(root)
        if skip_data and rel.parts and rel.parts[0] == "data":
            continue
        if "__pycache__" in rel.parts:
            continue
        h.update(str(rel).encode())
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def run(cmd: list[str], cwd: Path, env: dict, timeout: int = 600):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def db_query(env: dict, sql: str) -> str:
    return run([str(PY), "-c",
                "import sys; sys.path.insert(0, '.')\n"
                "from backend import db\n"
                f"print({sql!r} and db.scalar({sql!r}))"],
               cwd=OLD, env=env).stdout.strip()


def main() -> int:
    print("\n\033[1m== 准备：旧版本 + 新版本 ==\033[0m")
    copy_project(OLD)
    copy_project(NEW)
    # 新版本独有的文件，用来证明"代码确实被覆盖了"
    (NEW / "backend" / "UPGRADE_MARKER.txt").write_text("new-version\n", encoding="utf-8")
    (OLD / "backend" / "LEGACY_ONLY.txt").write_text("old\n", encoding="utf-8")
    check("沙箱就绪（旧/新两份代码 + 独立 venv 软链）",
          (OLD / "backend/server.py").is_file() and (NEW / "backend/server.py").is_file())

    env = dict(os.environ, CA_DATA_DIR=str(DATA), CA_ALLOW_NONROOT="1",
               SYSTEMD_DIR=str(SYS_DIR), SBIN_DIR=str(SBIN_DIR),
               PIP_NO_INDEX="1", PYTHONPATH=str(OLD))

    # ---- 旧版本：播种数据 + 把重载命令设成"旧命令" ----
    seed = subprocess.run([str(PY), "tests/drill_seed.py"], cwd=OLD, env=env,
                          capture_output=True, text=True)
    check("旧版本已播种数据（CA + 3 张证书 + CRL）", "seeded 3 certs" in (seed.stdout + seed.stderr),
          (seed.stderr or seed.stdout)[-200:])
    # 模拟实际运行中的部署：生成 CRL 后已发布到启用目标。
    published = run([str(PY), "-m", "backend.cli", "publish", "--no-reload"], OLD, env)
    check("旧版本 CRL 已发布到暂存目录", published.returncode == 0,
          (published.stderr or published.stdout)[-200:])
    old_cmd_code = (
        "import sys; sys.path.insert(0, '.')\n"
        "from backend import publish\n"
        "for t in publish.list_targets():\n"
        "    if t['enabled']:\n"
        "        publish.update_target(t['id'], {'reload_cmd': 'swanctl --load-creds'})\n"
        "print('ok')")
    subprocess.run([str(PY), "-c", old_cmd_code], cwd=OLD, env=env, check=True,
                   capture_output=True, text=True)
    before_certs = db_query(env, "SELECT COUNT(*) FROM certs")
    before_cas = db_query(env, "SELECT COUNT(*) FROM cas")
    check("旧版本数据就绪", before_certs == "3" and before_cas == "1",
          f"certs={before_certs} cas={before_cas}")

    # ---- 1) dry-run 不改动任何东西 ----
    print("\n\033[1m== 1. --dry-run 应零改动 ==\033[0m")
    hash_before = tree_hash(OLD)
    dr = run(["bash", str(OLD / "deploy/upgrade.sh"), "--dry-run", "--code", str(NEW)],
             cwd="/", env=env)
    check("--dry-run 从外地 cwd 执行成功", dr.returncode == 0,
          (dr.stderr or dr.stdout)[-200:])
    check("--dry-run 打印了完整计划（备份/代码/单元/重载命令/定时器）",
          all(k in dr.stdout for k in ("pre-upgrade", "ca-admin.service",
                                       "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan",
                                       "定时器")), dr.stdout[-200:])
    check("--dry-run 未修改项目任何文件", tree_hash(OLD) == hash_before)
    check("--dry-run 未创建单元文件", not list(SYS_DIR.glob("*")) if SYS_DIR.exists() else True)
    dr2 = run(["bash", str(OLD / "deploy/upgrade.sh"), "--dry-run", "--with-timer"],
              cwd="/", env=env)
    check("--dry-run --with-timer 计划里是“保留定时器”", "保留 30 分钟兜底定时器" in dr2.stdout,
          dr2.stdout[-160:])

    # ---- 2) 真升级（从外地 cwd 执行）----
    print("\n\033[1m== 2. 真升级（从 / 执行 upgrade.sh --code 新版本）==\033[0m")
    up = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart"],
             cwd="/", env=env)
    check("升级脚本执行成功", up.returncode == 0, (up.stderr or up.stdout)[-300:])
    initial_unit = (SYS_DIR / "ca-admin.service").read_text(encoding="utf-8") \
        if (SYS_DIR / "ca-admin.service").is_file() else ""
    check("没有原有服务单元时默认只监听回环",
          "Environment=CA_HOST=127.0.0.1" in initial_unit)
    out = up.stdout + up.stderr

    backups = sorted((DATA / "backups").glob("*pre-upgrade*"))
    check("升级前已自动备份", bool(backups), str([p.name for p in (DATA / "backups").glob("*")][:4]))
    check("代码被新版本覆盖（新文件出现）", (OLD / "backend/UPGRADE_MARKER.txt").is_file())
    check("旧文件被替换（旧版本独有文件消失）", not (OLD / "backend/LEGACY_ONLY.txt").exists())

    after_certs = db_query(env, "SELECT COUNT(*) FROM certs")
    after_cas = db_query(env, "SELECT COUNT(*) FROM cas")
    check("数据保留：证书数量不变", after_certs == before_certs, f"{before_certs} -> {after_certs}")
    check("数据保留：CA 数量不变", after_cas == before_cas, f"{before_cas} -> {after_cas}")
    ca_key = subprocess.run([str(PY), "-c",
                             "import sys; sys.path.insert(0,'.')\n"
                             "from backend import ca\n"
                             "row = ca.active_ca_row()\n"
                             "print(bool(row and row['has_key']))"],
                            cwd=OLD, env=env, capture_output=True, text=True).stdout.strip()
    check("数据保留：CA 私钥仍在（可继续签发）", ca_key == "True", ca_key)

    def target_cmds() -> str:
        return subprocess.run([str(PY), "-c",
                               "import sys; sys.path.insert(0,'.')\n"
                               "from backend import publish\n"
                               "print(sorted({t['reload_cmd'] for t in publish.list_targets()"
                               " if t['enabled']}))"],
                              cwd=OLD, env=env, capture_output=True, text=True).stdout.strip()

    # 关键：升级**不得覆盖用户自定义的重载命令**（现场单元名可能不是 strongswan）
    custom = "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan-starter"
    subprocess.run([str(PY), "-m", "backend.cli", "reload-cmd", "--set", custom],
                   cwd=OLD, env=env, capture_output=True, text=True)
    up2 = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart"],
              cwd="/", env=env)
    check("再升级一次成功", up2.returncode == 0, (up2.stderr or up2.stdout)[-200:])
    cmds = target_cmds()
    check("升级保留自定义重载命令（不覆盖现场设置）",
          "strongswan-starter" in cmds, cmds)
    check("升级输出里说明了保留而非覆盖",
          "保留现有重载命令" in (up2.stdout + up2.stderr), (up2.stdout + up2.stderr)[-200:])
    # ② --loopback 必须真的渲染成 127.0.0.1（曾经两条 s|__HOST__| 让 override 失效）
    up_lb = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart",
                 "--loopback"], cwd="/", env=env)
    svc_lb = (SYS_DIR / "ca-admin.service").read_text(encoding="utf-8") \
        if (SYS_DIR / "ca-admin.service").is_file() else ""
    rendered = [ln for ln in svc_lb.splitlines() if ln.startswith("Environment=CA_HOST=")]
    check("★ --loopback 升级后单元里是 CA_HOST=127.0.0.1",
          up_lb.returncode == 0 and rendered == ["Environment=CA_HOST=127.0.0.1"],
          f"rc={up_lb.returncode} {rendered}")
    check("★ 渲染后不再出现 0.0.0.0（管理端口不会意外暴露）",
          "CA_HOST=0.0.0.0" not in svc_lb, svc_lb[:120])
    # 不给 override 时应保留已有回环监听，不能意外重置为 0.0.0.0。
    run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart"],
        cwd="/", env=env)
    svc_def = (SYS_DIR / "ca-admin.service").read_text(encoding="utf-8")
    check("不带 --loopback 时保留现有 127.0.0.1 监听",
          "Environment=CA_HOST=127.0.0.1" in svc_def,
          [ln for ln in svc_def.splitlines() if "CA_HOST" in ln][:1])
    # 恢复成回环，避免影响后续断言
    run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart",
         "--loopback"], cwd="/", env=env)

    # ⑨ 备份失败必须停止升级（不能代码变了却没有回滚点）
    marker_before = (OLD / "backend/UPGRADE_MARKER.txt").read_bytes() \
        if (OLD / "backend/UPGRADE_MARKER.txt").is_file() else b""
    (DATA / "backups").rename(DATA / "backups.bak") if (DATA / "backups").is_dir() else None
    (DATA / "backups").write_text("not a dir", encoding="utf-8")   # 让备份必然失败
    up_nb = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart"],
                cwd="/", env=env)
    check("★ 备份失败时升级被拒绝（非 0 退出）", up_nb.returncode != 0,
          (up_nb.stdout + up_nb.stderr)[-200:])
    check("★ 备份失败时给出明确原因与绕过方式",
          "备份失败" in (up_nb.stdout + up_nb.stderr)
          and "--skip-backup" in (up_nb.stdout + up_nb.stderr),
          (up_nb.stdout + up_nb.stderr)[-200:])
    if (DATA / "backups").is_dir():
        shutil.rmtree(DATA / "backups")
    else:
        (DATA / "backups").unlink()
    if (DATA / "backups.bak").is_dir():
        (DATA / "backups.bak").rename(DATA / "backups")
    up_skip = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart",
                   "--skip-backup"], cwd="/", env=env)
    check("显式 --skip-backup 才允许跳过备份", up_skip.returncode == 0
          and "跳过" in (up_skip.stdout + up_skip.stderr), (up_skip.stdout + up_skip.stderr)[-160:])
    check("代码更新后没有残留 .old-*/.new-* 临时目录",
          not list(OLD.glob(".old-*")) and not list(OLD.glob(".new-*")),
          str([p.name for p in OLD.glob(".*-*")][:4]))

    # ⑤ 换入失败必须完整回滚（含正在切换的那个目录）
    up_rb = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart"],
                cwd="/", env=dict(env, CA_UPGRADE_FAIL_SWAP="frontend"))
    out_rb = up_rb.stdout + up_rb.stderr
    check("★ 注入换入失败时升级被拒绝", up_rb.returncode != 0, out_rb[-200:])
    check("★ 被中断的目录已完整还原（backend/deploy/tests 都在）",
          all((OLD / d).is_dir() for d in ("backend", "deploy", "tests")),
          str(sorted(p.name for p in OLD.iterdir()))[:200])
    check("★ 没有残留 .old-frontend / .new-frontend",
          not (OLD / ".old-frontend").exists() and not (OLD / ".new-frontend").exists(),
          str([p.name for p in OLD.glob(".*")][:6]))
    check("中途失败也说明了已回滚代码目录", "已回滚代码目录" in out_rb, out_rb[-160:])
    up_after = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW),
                    "--no-restart", "--skip-backup"], cwd="/", env=env)
    check("回滚后仍能正常升级（自愈）", up_after.returncode == 0,
          (up_after.stdout + up_after.stderr)[-200:])

    # 需要对齐时用 --force-reload-cmd 显式强制
    up3 = run(["bash", str(OLD / "deploy/upgrade.sh"), "--code", str(NEW), "--no-restart",
               "--force-reload-cmd"], cwd="/", env=env)
    check("--force-reload-cmd 可显式对齐为默认命令",
          up3.returncode == 0
          and target_cmds().strip("[]'\" ") == "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan",
          target_cmds())

    units = sorted(p.name for p in SYS_DIR.glob("*")) if SYS_DIR.exists() else []
    check("单元已渲染到目标目录", "ca-admin.service" in units and len(units) >= 4, str(units))
    svc = (SYS_DIR / "ca-admin.service").read_text(encoding="utf-8") if (
        SYS_DIR / "ca-admin.service").is_file() else ""
    check("渲染后的单元无残留占位符且 User=root",
          "__" not in svc.replace("___", "") and "User=root" in svc
          and "__BASE_DIR__" not in svc, svc[:80])
    syncsh = (SBIN_DIR / "ca-strongswan-sync.sh")
    _sync_txt = syncsh.read_text(encoding="utf-8") if syncsh.is_file() else ""
    check("同步脚本已安装且重载命令取自 settings（cli reload-cmd --print）",
          syncsh.is_file() and "reload-cmd --print" in _sync_txt)
    check("同步脚本兜底命令含 flush-certs + restart（实测 reload 不够）",
          "--flush-certs" in _sync_txt and "restart strongswan" in _sync_txt)
    check("定时器默认策略＝关闭（演练模式打印为跳过 disable）",
          "disable --now ca-strongswan-sync.timer" in out, out[-200:])
    # 演练必须只打印"跳过"，绝不真正执行 systemctl。
    # 注意：不能只按子串 "systemctl" 判定——doctor 的**修复建议文本**里也会出现
    # "sudo systemctl reload strongswan"（那不是执行）。这里改为看两类**执行证据**：
    #   ① 演练自己的执行标记 "[演练：执行 ...]"；② 全局 systemd 桩的调用日志。
    exec_markers = [ln for ln in out.splitlines() if "[演练：执行" in ln]
    check("演练期间没有真正执行 systemctl（无执行标记）", not exec_markers, str(exec_markers[:3]))
    guard_log = ROOT / ".tmp/systemd-calls.log"
    # 只读查询（swanctl --list-*）是允许的。
    # 绝不允许的是：任何 systemctl 调用，以及会改动 strongSwan 状态的命令
    # （--flush-certs / --load-creds / reload …）。
    import re as _re2
    readonly = _re2.compile(r"^swanctl (--list-sas|--list-crls|--list-certs|--list-pools|"
                            r"--list-conns|--list-authorities|--version|--stats|--help)( |$)")
    entries: list[str] = []
    if guard_log.is_file():
        entries = [ln.strip() for ln in
                   guard_log.read_text(encoding="utf-8", errors="replace").splitlines()
                   if ln.strip()]
    offenders = [e for e in entries if ("systemctl" in e) or not readonly.match(e)]
    check("演练期间没有 systemctl 调用，也没有改动 strongSwan 的命令", not offenders,
          str(offenders[:3]))
    check("只读 swanctl 查询即使发生也无害（被桩拦截）",
          all(readonly.match(e) for e in entries if e not in offenders), str(entries[:3]))
    # 真执行时演练会走 "[演练：执行"，跳过时打印 "[演练：跳过"
    skip_lines = [ln for ln in out.splitlines() if "[演练：跳过" in ln]
    check("演练确实以'打印跳过'的方式处理 systemctl", bool(skip_lines), out[-200:])

    # 演练按 --loopback 安装 → doctor 也按回环地址评估（否则会命中"明文+非回环"安全项）
    doc = run([str(PY), "-m", "backend.cli", "doctor", "--json"], cwd=OLD,
              env=dict(env, CA_HOST="127.0.0.1"))
    import json as _json
    dres = _json.loads(doc.stdout).get("results", [])
    check("升级后 doctor 无 error",
          not [r for r in dres if r.get("level") == "error"],
          str([r.get("item") for r in dres if r.get("level") == "error"]))

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
