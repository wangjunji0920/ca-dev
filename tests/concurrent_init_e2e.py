"""并发初始化健壮性：多个进程同时对**全新**数据库 bootstrap。

真实场景：服务首次启动正在 bootstrap，管理员同一时刻跑 `cli doctor` / `cli init`。
曾出现过两个问题（均已修）：
  1) `PRAGMA journal_mode=WAL` 切换需要短暂独占锁，并发时会立刻抛 "database is locked"
     （busy_timeout 设得太晚）→ 现在先设 busy_timeout 并显式重试；
  2) 内置规则集/管理员/自动化预设的插入不是幂等的 → UNIQUE 冲突或同名重复
     → 现在用 INSERT OR IGNORE + 幂等收尾。

断言：5 个进程全部退出码 0；规则集恰好 13 个；示例预设无重复；用户恰好 1 个；库处于 WAL。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")

PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="concurrent-init-"))
DATA = TMP / "data"
N = 5

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def main() -> int:
    print(f"\n\033[1m== {N} 个进程同时对全新库 bootstrap ==\033[0m")
    DATA.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CA_DATA_DIR=str(DATA))
    code = ("import sys; sys.path.insert(0, '.')\n"
            "from backend import server\n"
            "server.bootstrap(verbose=False)\n"
            "print('ok')\n")
    procs = [subprocess.Popen([PY, "-c", code], cwd=ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(N)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=300)
        results.append((p.returncode, out, err))
    failed = [(rc, (err or out)[-140:]) for rc, out, err in results if rc != 0]
    check(f"{N} 个进程全部初始化成功（无 database is locked / UNIQUE 冲突）",
          not failed, str(failed[:1]))

    q = subprocess.run([PY, "-c",
                        "import sys; sys.path.insert(0, '.')\n"
                        "from backend import db\n"
                        "print(db.scalar('SELECT COUNT(*) FROM rulesets'),\n"
                        "      db.scalar(\"SELECT COUNT(*) FROM automation_tasks \"\n"
                        "                \"WHERE name LIKE '示例：%'\"),\n"
                        "      db.scalar('SELECT COUNT(*) FROM users'),\n"
                        "      db.connect().execute('PRAGMA journal_mode').fetchone()[0])\n"],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    parts = q.stdout.split()
    check("内核库状态可读", len(parts) == 4, q.stdout + q.stderr[-120:])
    if len(parts) == 4:
        rulesets, presets, users, mode = parts
        check("内置规则集恰好 13 个（并发未产生重复）", rulesets == "13", rulesets)
        check("示例预设无重复（幂等收尾生效）", presets == "4", presets)
        check("管理员账号恰好 1 个", users == "1", users)
        check("数据库处于 WAL 模式", mode.lower() == "wal", mode)

    # 并发初始化后服务仍能正常起来并使用
    port = 0
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv_env = dict(env, CA_HOST="127.0.0.1", CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=srv_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import time
        import urllib.request
        up = False
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        check("并发初始化后的数据目录能正常起服务", up)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n  通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("  失败明细: " + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        code_ = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code_)
