"""CSP 兼容性验收：**真实浏览器会执行 CSP，jsdom 不会** —— 这类问题必须静态拦住。

真实故障：登录页的登录逻辑写在内联 <script> 里，而响应头是
`script-src 'self'`（无 unsafe-inline、无 nonce）。真实浏览器会直接拒绝执行内联脚本，
于是页面永远停在"正在建立加密信道…"、点登录没反应。jsdom 不执行 CSP，
所以前端 DOM 测试全绿也发现不了。

断言：
  1) 交付的 HTML 里没有内联 <script>（每个 <script> 都必须有 src）；
  2) 没有内联事件处理器（onclick= 之类，同样会被 CSP 拦）；
  3) 引用的本地脚本/样式都存在（避免 404 导致页面半死）；
  4) 服务响应头里的 CSP 不允许内联脚本（不允许 script-src 带 unsafe-inline）；
  5) 服务实际返回的 HTML 与磁盘一致、且带 CSP 头；
  6) doctor 能发现"前端存在内联脚本"（防止将来回归）。
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="csp-"))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def main() -> int:
    from backend import security

    print("\n\033[1m== 1) 交付的 HTML 不得含内联脚本 ==\033[0m")
    for name in ("index.html", "login.html"):
        html = (ROOT / "frontend" / name).read_text(encoding="utf-8")
        inline = [m.group(0) for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>", html)]
        check(f"{name}：没有内联 <script>（否则会被 CSP 拦掉）", not inline, str(inline[:2]))
        handlers = re.findall(r"\son[a-z]+\s*=\s*[\"']", html)
        check(f"{name}：没有内联事件处理器（onclick= 等）", not handlers, str(handlers[:3]))
        # 引用的本地资源必须存在
        missing = []
        for m in re.finditer(r'(?:src|href)="([^"#?]+)"', html):
            ref = m.group(1)
            if ref.startswith(("http://", "https://", "data:", "mailto:", "//")):
                continue
            if not (ROOT / "frontend" / ref).is_file():
                missing.append(ref)
        check(f"{name}：引用的本地资源都存在（避免 404 半死页面）", not missing, str(missing))

    print("\n\033[1m== 2) 响应头里的 CSP 不允许内联脚本 ==\033[0m")
    csp = security.security_headers(False, api=False)["Content-Security-Policy"]
    script_src = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
    check("CSP 含 script-src 'self'", bool(script_src) and "'self'" in script_src[0], csp)
    check("CSP 的 script-src 不含 unsafe-inline（否则等于放开内联执行）",
          "unsafe-inline" not in " ".join(script_src), str(script_src))
    check("CSP 含 object-src 'none' 与 base-uri 'none'",
          "object-src 'none'" in csp and "base-uri 'none'" in csp)

    print("\n\033[1m== 3) 服务实际返回的页面 ==\033[0m")
    data = TMP / "data"
    data.mkdir(parents=True, exist_ok=True)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
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
        for page, expect in (("/login.html", "login.html"), ("/", "login.html")):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{page}", timeout=5) as r:
                body = r.read().decode("utf-8", "replace")
                hdr = r.headers.get("Content-Security-Policy") or ""
            check(f"{page} 返回 HTML 且带 CSP 头", "<html" in body and "script-src" in hdr)
            inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", body)
            check(f"{page} 实际返回的 HTML 无内联脚本", not inline, str(inline[:2]))
        # 外部脚本必须可取到
        for asset in ("login.js", "theme-boot.js", "crypto.js", "app.js",
                      "vendor/tweetnacl.min.js"):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/{asset}", timeout=5) as r:
                check(f"外部脚本 {asset} 可访问且非空", r.status == 200 and len(r.read()) > 50)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n\033[1m== 4) doctor 能发现内联脚本（防回归）==\033[0m")
    r = subprocess.run([PY, "-m", "backend.cli", "doctor", "--json"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    import json as _json
    try:
        items = _json.loads(r.stdout).get("results", [])
    except Exception:  # noqa: BLE001
        items = []
    csp_item = [x for x in items if "CSP" in str(x.get("item", "")) or "内联" in str(x.get("item", ""))]
    check("doctor 输出包含 CSP/内联脚本检查项", bool(csp_item), str(items)[:200])
    check("当前交付状态下该项为 ok（无内联脚本）",
          bool(csp_item) and csp_item[0].get("level") == "ok",
          str(csp_item[:1]))

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
