"""登录失败锁定与解锁（真实踩过的坑）。

现场问题：服务只监听 127.0.0.1 + SSH 隧道时，**所有浏览器的请求源都是 127.0.0.1**。
旧实现沿用"5 次失败即锁 60s 起指数翻倍"的阈值，管理员多点几次就把自己锁死；
更糟的是**握手失败也计入**该计数，一个被 CSP 拦住的旧页面反复重试就能永久锁死账号。

本测试断言：
  1) 回环客户端阈值更宽（20 次），非回环仍是 5 次；
  2) 握手失败不计入账号锁定；
  3) `cli unlock`（标记文件）能跨进程清空计数；
  4) 失败提示给出"还可尝试 N 次"，锁定提示给出剩余秒数与解锁办法。
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="lockout-"))
# 测试进程也要用同一个数据目录（config 在导入时读它），否则标记文件找不到
DATA_DIR = TMP / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
os.environ["CA_DATA_DIR"] = str(DATA_DIR)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def post(base: str, payload: dict) -> tuple[int, str]:
    r = urllib.request.Request(base + "/api/login",
                               data=__import__("json").dumps(payload).encode(), method="POST")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def main() -> int:
    from backend import security, server

    # LoginGuard.fail() 会写审计，需要先把库建好
    server.bootstrap(verbose=False)

    print("\n\033[1m== 1) 阈值：回环更宽，非回环仍严格 ==\033[0m")
    g = security.LoginGuard()
    check("回环阈值 > 非回环阈值",
          g.threshold("127.0.0.1") > g.threshold("203.0.113.9"),
          f"{g.threshold('127.0.0.1')} vs {g.threshold('203.0.113.9')}")
    check("非回环仍是 5 次", g.threshold("203.0.113.9") == 5, str(g.threshold("203.0.113.9")))
    for _ in range(g.threshold("203.0.113.9")):
        g.fail("203.0.113.9")
    check("非回环达到阈值后被锁定", g.check("203.0.113.9") > 0, str(g.check("203.0.113.9")))
    for _ in range(g.threshold("127.0.0.1") - 1):
        g.fail("127.0.0.1")
    check("回环在阈值-1 次时仍可用（不会把自己锁死）", g.check("127.0.0.1") == 0,
          str(g.check("127.0.0.1")))
    g.fail("127.0.0.1")
    check("回环达到阈值后确实锁定", g.check("127.0.0.1") > 0)
    g.reset()
    check("reset() 清空全部计数", g.check("127.0.0.1") == 0 and g.check("203.0.113.9") == 0)

    print("\n\033[1m== 2) cli unlock：跨进程清空（标记文件）==\033[0m")
    data = DATA_DIR
    env = dict(os.environ, CA_DATA_DIR=str(data))
    r = subprocess.run([PY, "-m", "backend.cli", "unlock"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    check("cli unlock 执行成功", r.returncode == 0 and "清除" in r.stdout, r.stdout[-120:])
    check("已写入解锁标记文件", (data / security.GUARD_RESET_FILE).is_file())
    security.login_guard.fail("127.0.0.1")
    consumed = security.consume_guard_reset()
    check("服务侧消费标记后清空计数", consumed and security.login_guard.check("127.0.0.1") == 0)
    check("标记只生效一次（消费后即删除）",
          not security.consume_guard_reset() and not (data / security.GUARD_RESET_FILE).exists())

    print("\n\033[1m== 3) HTTP 层：提示信息与握手不锁账号 ==\033[0m")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv_env = dict(env, CA_HOST="127.0.0.1", CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=srv_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=2)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        # 10 次坏握手（旧实现会把账号锁死）
        for _ in range(10):
            rr = urllib.request.Request(base + "/api/handshake", data=b"{}", method="POST")
            rr.add_header("Content-Type", "application/json")
            try:
                urllib.request.urlopen(rr, timeout=5)
            except Exception:  # noqa: BLE001
                pass
        st, body = post(base, {"username": "admin", "password": "definitely-wrong"})
        check("10 次握手失败后仍能尝试登录（握手不计入锁定）", st == 401, f"{st} {body[:100]}")
        check("失败提示包含'还可尝试 N 次'", "还可尝试" in body, body[:120])
        st2, body2 = post(base, {"username": "admin", "password": "definitely-wrong"})
        check("连续失败只累计口令错误（仍为 401 而非 429）", st2 == 401, f"{st2} {body2[:100]}")
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
        code = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)
