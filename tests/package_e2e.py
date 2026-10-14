"""交付包端到端验收：解包 → 初始化 → 起服务 → 部署验收。

验证的是"**交付物本身**能部署"：
  1) 交付包里**不含**任何数据/私钥/口令/虚拟环境/缓存（CA 产品尤其重要）；
  2) 全新解包后 `deploy/install.sh` 能完成初始化（建库、内置规则集、管理员口令）；
  3) 从解包目录能起服务，静态前端文件齐全；
  4) 跑交付包**自带**的 tests/verify_deploy.py，先空库验收、再播种 CA 后全绿；
  5) `cli doctor` 无 error。

全程只用 127.0.0.1 与临时目录，不碰 /etc/swanctl、不碰系统单元。
"""
from __future__ import annotations

import os
import hashlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="pkg-e2e-"))
EXTRACT = TMP / "unpacked"
DATA = EXTRACT / "data"

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


def http_get(url: str, timeout: float = 5.0) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:  # noqa: BLE001
        return 0, b""


def main() -> int:
    # ---------------------------------------------------------------- 打包
    print("\n\033[1m== 1. 生成并检查交付包 ==\033[0m")
    # 产物写到临时目录：测试不应污染交付目录 dist/（否则会堆出一堆包，混淆"该上传哪一个"）
    pkg_dir = TMP / "pkg"
    out = subprocess.run([str(ROOT / "deploy/package.sh")], cwd=ROOT,
                         env=dict(os.environ, CA_PKG_DIR=str(pkg_dir)),
                         capture_output=True, text=True)
    pkgs = sorted(pkg_dir.glob("ca-dev-*.tar.gz"), key=lambda p: p.stat().st_mtime)
    if not check("打包成功", out.returncode == 0 and bool(pkgs), (out.stderr or out.stdout)[-200:]):
        return 1
    pkg = pkgs[-1]
    print(f"  交付包: {pkg.name}（{pkg.stat().st_size // 1024} KB）")

    with tarfile.open(pkg) as tf:
        members = [m.name for m in tf.getmembers()]
        manifest = tf.extractfile('./SHA256SUMS').read().decode().splitlines()
        valid = all(hashlib.sha256(tf.extractfile('./' + line.split('  ', 1)[1]).read()).hexdigest()
                    == line.split('  ', 1)[0] for line in manifest)
        check("tar.gz 内全部源码与 SHA256SUMS 一致", valid
              and len(manifest) == len([m for m in tf.getmembers() if m.isfile()]) - 1)
    zip_path = pkg_dir / 'ca-dev-github-public.zip'
    zip_result = subprocess.run(['bash', str(ROOT / 'deploy/package.sh'), '--out', str(zip_path)],
                                cwd=ROOT, capture_output=True, text=True)
    check("ZIP 发布包命令成功", zip_result.returncode == 0, zip_result.stderr[-300:])
    if zip_result.returncode == 0:
        with zipfile.ZipFile(zip_path) as zf:
            prefix = 'ca-dev-github-public/'
            lines = zf.read(prefix + 'SHA256SUMS').decode().splitlines()
            check("ZIP 与 tar.gz 的源码及文件清单完全一致", lines == manifest and all(
                hashlib.sha256(zf.read(prefix + line.split('  ', 1)[1])).hexdigest()
                == line.split('  ', 1)[0] for line in lines))
            check("ZIP 保留安装入口的可执行权限",
                  ((zf.getinfo(prefix + 'deploy/install.sh').external_attr >> 16) & 0o111) == 0o111)
    forbidden = [m for m in members if re.search(
        r"(^|/)(data|\.venv|\.tmp|__pycache__|node_modules)/"
        r"|initial_admin_password|\.key(\.pem)?$|\.p12$|\.db$|\.sqlite", m)]
    check("交付包不含数据目录/私钥/口令/venv/缓存", not forbidden,
          str(forbidden[:5]))
    check("交付包含前端与后端必需文件", all(any(m.endswith(x) for m in members) for x in
          ("frontend/index.html", "frontend/app.js", "frontend/crypto.js",
           "frontend/vendor/tweetnacl.min.js", "backend/server.py",
           "deploy/install.sh", "deploy/upgrade.sh", "tests/verify_deploy.py")))

    # ---------------------------------------------------------------- 解包
    print("\n\033[1m== 2. 全新解包并初始化 ==\033[0m")
    EXTRACT.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "xzf", str(pkg), "-C", str(EXTRACT)], check=True)
    # 交付包不带 .venv（正确）：这里软链本地已装好的 venv，模拟服务器上装好依赖的状态
    (EXTRACT / ".venv").symlink_to(ROOT / ".venv")
    port = free_port()
    # CA_HOST=127.0.0.1：全新实例按"回环部署"评估 doctor（明文+非回环会被判 error）
    env = dict(os.environ, PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               CA_DATA_DIR=str(DATA), CA_HOST="127.0.0.1", CA_PORT=str(port))
    inst = subprocess.run(["bash", str(EXTRACT / "deploy/install.sh"),
                           "--host", "127.0.0.1", "--port", str(port)],
                          cwd=EXTRACT, env=env, capture_output=True, text=True, timeout=300)
    check("install.sh 初始化成功（无 systemd 模式）", inst.returncode == 0,
          (inst.stderr or inst.stdout)[-300:])
    check("数据目录已建立库与初始口令文件",
          (DATA / "ca.db").is_file() and (DATA / "initial_admin_password.txt").is_file())
    check("内置规则集已就位（strongswan 默认规则集）",
          "strongswan-vpn-client" in subprocess.run(
              [str(PY), "-m", "backend.cli", "rulesets"], cwd=EXTRACT, env=env,
              capture_output=True, text=True).stdout)
    doc = subprocess.run([str(PY), "-m", "backend.cli", "doctor", "--json"],
                         cwd=EXTRACT, env=env, capture_output=True, text=True)
    import json as _json
    try:
        dres = _json.loads(doc.stdout).get("results", [])
    except Exception:  # noqa: BLE001
        dres = []
    derr = [r for r in dres if r.get("level") == "error"]
    setup = [r for r in dres if r.get("level") == "setup"]
    # 全新实例不应报任何 error，只需一条“待导入 CA”的步骤提示
    check("解包后 doctor 无 error，且给出导入 CA 的待办",
          bool(dres) and not derr and len(setup) == 1,
          "errors=" + str([r.get("item") for r in derr]) + " setup=" + str(len(setup)))

    # ---------------------------------------------------------------- 起服务
    print("\n\033[1m== 3. 从解包目录起服务 ==\033[0m")
    srv_env = dict(env, CA_HOST="127.0.0.1", CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc = subprocess.Popen([str(EXTRACT / ".venv/bin/python"), "-m", "backend.server"],
                            cwd=EXTRACT, env=srv_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    up = False
    for _ in range(60):
        code, body = http_get(base + "/api/health")
        if code == 200:
            up = True
            break
        time.sleep(0.3)
    try:
        check("服务可启动并响应 /api/health", up)
        # Verify the deploy readiness gate against the actual extracted HTTP server.
        # Only the systemctl status query is simulated; no host services are touched.
        fake_bin = TMP / "ready-bin"
        fake_bin.mkdir()
        fake_ctl = fake_bin / "systemctl"
        fake_ctl.write_text("#!/bin/sh\nprintf 'ActiveState=active\\nSubState=running\\nMainPID="
                            + str(proc.pid) + "\\nNRestarts=0\\nExecMainStatus=0\\n'\n")
        fake_ctl.chmod(0o755)
        ready = subprocess.run([str(PY), str(EXTRACT / "deploy/service_tools.py"),
                                "ready", "--host", "127.0.0.1", "--port", str(port),
                                "--timeout", "5"], capture_output=True, text=True,
                               env=dict(env, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"]))
        check("部署就绪检查识别真实后端健康响应", ready.returncode == 0,
              (ready.stdout + ready.stderr)[-300:])
        code, body = http_get(base + "/index.html")
        # 未登录时首页应当只给登录页（认证门禁），而不是把应用骨架吐出来
        check("未登录访问首页被要求登录（认证门禁生效）",
              code == 200 and b'id="loginForm"' in body and b'data-view="certs"' not in body,
              f"HTTP {code}")
        shell = (EXTRACT / "frontend/index.html").read_text(encoding="utf-8")
        check("交付的应用骨架完整（13+ 视图 / 引用了 app.js 与 crypto.js）",
              shell.count("data-view=") >= 13 and "app.js" in shell and "crypto.js" in shell,
              f"data-view={shell.count('data-view=')}")
        for asset in ("app.js", "crypto.js", "style.css", "vendor/tweetnacl.min.js"):
            c, b = http_get(base + "/" + asset)
            check(f"静态资源 {asset} 可访问", c == 200 and len(b) > 100, f"HTTP {c}")
        c, b = http_get(base + "/crl/current.crl")
        check("公开 CRL 端点存在（空库时返回 404/未生成而非 500）", c in (200, 404),
              f"HTTP {c}")

        # ------------------------------------------------------------ 验收
        print("\n\033[1m== 4. 跑交付包自带的部署验收 ==\033[0m")
        v = subprocess.run([str(PY), str(EXTRACT / "tests/verify_deploy.py"), base,
                            "--pw-file", str(DATA / "initial_admin_password.txt"), "--allow-empty"],
                           cwd=EXTRACT, env=env, capture_output=True, text=True, timeout=300)
        empty_ok = len(re.findall(r"✓", v.stdout))
        check("空库验收基本通过（仅允许 no_ca 一项提示）",
              v.returncode == 0 and empty_ok >= 28, v.stdout[-300:])

        seed = subprocess.run([str(EXTRACT / ".venv/bin/python"),
                               str(EXTRACT / "tests/drill_seed.py")],
                              cwd=EXTRACT, env=env, capture_output=True, text=True)
        check("用交付包自带脚本播种 CA 成功", "seeded" in (seed.stdout + seed.stderr),
              (seed.stderr or "")[-200:])
        v2 = subprocess.run([str(PY), str(EXTRACT / "tests/verify_deploy.py"), base,
                             "--pw-file", str(DATA / "initial_admin_password.txt")],
                            cwd=EXTRACT, env=env, capture_output=True, text=True, timeout=300)
        ok2 = len(re.findall(r"✓", v2.stdout))
        bad2 = re.findall(r"✗[^\n]*", v2.stdout)
        check("有 CA 时验收全绿", v2.returncode == 0 and not bad2 and ok2 >= 30, str(bad2[:3]))

        # A published CRL mismatch must make deployment acceptance fail, not just warn.
        crl = next((DATA / "publish").glob("*.crl"))
        original = crl.read_bytes()
        try:
            crl.write_bytes(b"corrupt-published-crl")
            failed = subprocess.run([str(PY), str(EXTRACT / "tests/verify_deploy.py"), base,
                                     "--pw-file", str(DATA / "initial_admin_password.txt")],
                                    cwd=EXTRACT, env=env, capture_output=True, text=True,
                                    timeout=60)
            check("CRL 内容损坏时部署验收返回失败", failed.returncode != 0
                  and "crl_target_mismatch" in failed.stdout, failed.stdout[-400:])
        finally:
            crl.write_bytes(original)
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
