"""前端资源完整性核对（带外验证）测试。

背景：系统按现场要求跑在纯 HTTP 上，加密由 `frontend/crypto.js` 在应用层实现，
而**这段代码本身也通过同一个 HTTP 通道下发**——主动中间人可以换掉它。
纯客户端手段无法自证清白，唯一可靠的办法是**带外核对**：
在"本地副本可信、网络不可信"的位置，用本地副本的哈希去比对线上实际返回的字节。

本测试验证这套机制真的能用、且真的能发现篡改：
  1) 本地哈希与磁盘文件一致；指纹稳定，改一个字节就变；
  2) 对着真实服务跑 `cli asset-hash --check-url` → 判定一致（未登录时被认证门禁
     替换成登录页的 index.html 会被正确识别为正常，不误报）；
  3) 对着"被篡改的服务"跑 → 必须报出不一致，并指出是哪个文件；
  4) `--json` 可机器解析。
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import io
import os
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")

PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="assetguard-"))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    from backend import assetguard, config

    fe = config.BASE_DIR / "frontend"

    print("\n\033[1m== 1) 本地哈希与指纹 ==\033[0m")
    hashes = assetguard.file_hashes(fe)
    ok_all = all(hashes[rel] == sha(fe / rel) for rel in assetguard.ASSETS if (fe / rel).is_file())
    check("每个资源哈希与磁盘文件一致", ok_all and len(hashes) == len(assetguard.ASSETS),
          str(hashes)[:160])
    fp1 = assetguard.fingerprint(hashes)
    check("指纹格式为 4 段短码", len(fp1.split("-")) == 4 and len(fp1.replace("-", "")) == 16, fp1)
    check("指纹稳定（同输入同输出）", assetguard.fingerprint(assetguard.file_hashes(fe)) == fp1)

    tampered_dir = TMP / "frontend-tampered"
    shutil.copytree(fe, tampered_dir)
    (tampered_dir / "app.js").write_bytes((tampered_dir / "app.js").read_bytes()
                                          + b"\n// injected by MITM\n")
    t_hashes = assetguard.file_hashes(tampered_dir)
    check("改动一个字节 → 指纹改变", assetguard.fingerprint(t_hashes) != fp1,
          f"{fp1} -> {assetguard.fingerprint(t_hashes)}")
    cmp_t = assetguard.compare(hashes, t_hashes)
    check("compare 能精确指出被改的文件",
          (not cmp_t["ok"]) and any(d["file"] == "app.js" for d in cmp_t["diffs"]),
          str(cmp_t["diffs"])[:160])

    print("\n\033[1m== 2) 对真实服务核对（应判定一致）==\033[0m")
    data = TMP / "data"
    data.mkdir(parents=True, exist_ok=True)
    port = free_port()
    env = dict(os.environ, CA_DATA_DIR=str(data), CA_HOST="127.0.0.1",
               CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        up = False
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        check("临时服务已启动", up)
        base = f"http://127.0.0.1:{port}"
        r = subprocess.run([PY, "-m", "backend.cli", "asset-hash", "--check-url", base],
                           cwd=ROOT, env=env, capture_output=True, text=True)
        check("对真实服务核对 → 一致（退出码 0）", r.returncode == 0, r.stdout[-200:])
        check("输出明确说明'未被篡改'", "未被篡改" in r.stdout, r.stdout[-160:])
        check("未登录时 index.html 的门禁替换被正确识别（不误报）",
              "认证门禁" in r.stdout, r.stdout[-200:])
        rj = subprocess.run([PY, "-m", "backend.cli", "asset-hash", "--json"],
                            cwd=ROOT, env=env, capture_output=True, text=True)
        info = json.loads(rj.stdout)
        check("--json 可机器解析且含指纹", info.get("fingerprint") == fp1, str(info)[:120])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n\033[1m== 3) 对'被篡改的服务'核对（必须报不一致）==\033[0m")
    served = TMP / "served"
    shutil.copytree(fe, served)
    (served / "crypto.js").write_bytes(
        (served / "crypto.js").read_bytes() + b"\n/* MITM: exfiltrate password */\n")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(served))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    evil_base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        info = assetguard.report(check_url=evil_base)
        c = info["compare"]
        check("被篡改的服务 → 判定不一致", c["ok"] is False, str(c)[:160])
        check("明确指出是 crypto.js 被改",
              [d["file"] for d in c["diffs"]] == ["crypto.js"], str(c["diffs"])[:160])
        check("指纹不同（可用于快速比对）",
              c["expected_fingerprint"] != c["actual_fingerprint"],
              f"{c['expected_fingerprint']} vs {c['actual_fingerprint']}")
        r = subprocess.run([PY, "-m", "backend.cli", "asset-hash", "--check-url", evil_base],
                           cwd=ROOT, env=env, capture_output=True, text=True)
        check("CLI 对被篡改的服务返回非 0 退出码", r.returncode != 0, f"rc={r.returncode}")
        check("CLI 提示可能被中间人篡改", "中间人" in r.stdout, r.stdout[-160:])
    finally:
        httpd.shutdown()

    print("\n\033[1m== 4) doctor 里带外可见的指纹 ==\033[0m")
    r = subprocess.run([PY, "-m", "backend.cli", "doctor", "--json"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    dres = json.loads(r.stdout).get("results", [])
    fp_line = [x for x in dres if x.get("item") == "前端资源指纹"]
    check("doctor 输出包含前端资源指纹（journalctl 里也能看到）",
          bool(fp_line) and fp1 in fp_line[0]["detail"], str(fp_line)[:160])

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
