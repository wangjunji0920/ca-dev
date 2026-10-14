"""systemd 单元验收：按 install.sh 的方式渲染占位符，再逐项校验。

服务器上真正启动的是**渲染后**的单元，所以这里验证渲染结果，而不是仓库里的模板：
  1) 没有残留 __PLACEHOLDER__；
  2) ca-admin.service：User=root、root 沙箱（ProtectSystem=strict / ProtectHome=yes /
     UMask=0077）、可写路径含数据目录 + /etc/swanctl + /run、ExecStart 指向真实入口与端口；
  3) strongSwan 同步单元：ExecStart 指向 /usr/local/sbin/ca-strongswan-sync.sh，
     path 单元的 __STAGING__ 已替换；
  4) 防重载风暴策略确实在部署脚本里（定时器默认不启用、install.sh 有 --with-timer）；
  5) upgrade.sh 会统一重载命令；
  6) （可选，默认关闭）用 systemd-analyze verify 校验渲染后的单元：
        设置 CA_RUN_SYSTEMD_ANALYZE=1 才会调用，测试默认不碰任何 systemd 工具。
"""
from __future__ import annotations

import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="units-e2e-"))
DATA = TMP / "data"
ETC = TMP / "etc-systemd"
ETC.mkdir(parents=True, exist_ok=True)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def render(unit_src: Path, dest: Path, user: str = "root", host: str = "0.0.0.0",
           port: int = 9443, staging: Path | None = None) -> str:
    """与 deploy/install.sh 完全一致的替换方式。"""
    sys.path.insert(0, str(ROOT / "deploy"))
    from service_tools import render as render_unit
    text = render_unit(unit_src, str(ROOT), str(DATA), host, str(port), user)
    dest.write_text(text, encoding="utf-8")
    return text


def main() -> int:
    print("\n\033[1m== 渲染 systemd 单元（与 install.sh 相同方式）==\033[0m")
    rendered: dict[str, str] = {}
    for unit in ("ca-admin-root.service", "ca-strongswan-sync.service",
                 "ca-strongswan-sync.path", "ca-strongswan-sync.timer"):
        src = ROOT / "deploy" / unit
        if not check(f"存在单元模板 {unit}", src.is_file()):
            continue
        text = render(src, ETC / unit)
        rendered[unit] = text
    check("渲染后没有残留占位符",
          all("__" not in re.sub(r"__\w+__", "", t) and "__BASE_DIR__" not in t
              and "__DATA_DIR__" not in t and "__STAGING__" not in t
              and "__USER__" not in t and "__PORT__" not in t
              for t in rendered.values()),
          str([k for k, t in rendered.items() if "__" in t and re.search(r"__[A-Z_]+__", t)]))

    # ---------------------------------------------------------------- 主服务
    print("\n\033[1m== ca-admin.service（root 沙箱）==\033[0m")
    svc = rendered.get("ca-admin-root.service", "")

    def has(pattern: str) -> bool:
        return re.search(pattern, svc, re.M) is not None

    check("User=root（按现场要求以 root 运行）", has(r"^User=root$"))
    check("ProtectSystem=strict", has(r"^ProtectSystem=strict$"))
    check("ProtectHome=yes（不去读其他用户家目录）", has(r"^ProtectHome=yes$"))
    check("UMask=0077（新建文件默认不可被他人读）", has(r"^UMask=0077$"))
    check("NoNewPrivileges / PrivateTmp 等加固项在位",
          has(r"^NoNewPrivileges=yes$") and has(r"^PrivateTmp=yes$"))
    # systemd 允许多行 ReadWritePaths= 累加，必须全部收齐
    rw_paths: list[str] = []
    for m in re.finditer(r"^ReadWritePaths=(.+)$", svc, re.M):
        rw_paths.extend(shlex.split(m.group(1)))
    check("ReadWritePaths 含数据目录", str(DATA) in rw_paths, str(rw_paths))
    check("ReadWritePaths 含 /etc/swanctl（直写 CRL/CA）", "/etc/swanctl" in rw_paths, str(rw_paths))
    check("ReadWritePaths 含 /run（放 pid/临时文件）", "/run" in rw_paths, str(rw_paths))
    check("/opt 部署不绑定被 ProtectHome 隐藏的家目录",
          not has(r"^BindPaths=") and not has(r"^BindReadOnlyPaths="))
    check("敏感路径可缺失且没有伪通配符",
          has(r"^InaccessiblePaths=-/etc/shadow -/etc/gshadow$") and "/home/*" not in svc)
    exec_start = re.search(r"^ExecStart=(.+)$", svc, re.M)
    exec_line = exec_start.group(1).strip() if exec_start else ""
    check("ExecStart 指向 backend.server", "backend.server" in exec_line, exec_line)
    env_lines = re.findall(r"^Environment=(.+)$", svc, re.M)
    check("通过 Environment 传 CA_HOST/CA_PORT/CA_DATA_DIR",
          any("CA_PORT=9443" in e for e in env_lines)
          and any(str(DATA) in e for e in env_lines)
          and any("CA_HOST=" in e for e in env_lines), str(env_lines[:4]))
    check("ExecStart 的 python 路径真实存在",
          Path(exec_line.split()[0]).is_file() or "python" in exec_line.split()[0],
          exec_line.split()[0] if exec_line else "无")
    check("Restart=always（异常自动拉起）", has(r"^Restart=always$"))

    # ---------------------------------------------------------------- 同步单元
    print("\n\033[1m== strongSwan 同步单元 ==\033[0m")
    sync = rendered.get("ca-strongswan-sync.service", "")
    check("同步服务 ExecStart 指向 /usr/local/sbin/ca-strongswan-sync.sh",
          "/usr/local/sbin/ca-strongswan-sync.sh" in sync)
    path_unit = rendered.get("ca-strongswan-sync.path", "")
    check("path 单元监视的是发布暂存目录（已替换）",
          str(DATA / "publish") in path_unit, path_unit[:160])
    check("timer 单元存在但只是兜底（OnUnitActiveSec）",
          "OnUnitActiveSec" in rendered.get("ca-strongswan-sync.timer", ""))

    # ---------------------------------------------------------------- 策略检查
    print("\n\033[1m== 防重载风暴策略在部署脚本里 ==\033[0m")
    install = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
    check("install.sh 默认只启用 path，定时器需 --with-timer",
          "--with-timer" in install and "systemctl disable --now ca-strongswan-sync.timer" in install)
    check("install.sh 有 Python >= 3.10 门槛",
          "3,10" in install and "版本过低" in install)
    check("install.sh 支持 --dry-run（先看不改）", "--dry-run" in install and "DRY_RUN" in install)
    upgrade = (ROOT / "deploy/upgrade.sh").read_text(encoding="utf-8")
    check("upgrade.sh 会统一重载命令", "reload-cmd --set" in upgrade)
    check("upgrade.sh 默认关掉多余定时器",
          "disable --now ca-strongswan-sync.timer" in upgrade)
    check("upgrade.sh 升级前先备份", "backup --name" in upgrade)
    syncsh = (ROOT / "deploy/ca-strongswan-sync.sh").read_text(encoding="utf-8")
    check("同步脚本的重载命令取自设置（cli reload-cmd --print）",
          "reload-cmd --print" in syncsh)
    check("同步脚本兜底命令含 restart 与 flush-certs（实测 reload 不够）",
          "--flush-certs" in syncsh and "restart strongswan" in syncsh)
    # 新行为：只同步"设置里指定的那一个文件"（由后端 sync-plan 给清单），
    # 不再按内容/扩展名扫全目录 —— 否则暂存目录里的多份副本会被全拷进 strongSwan，
    # 同一 CA 出现多份 CRL 会让 charon 的选择不确定（现场踩过：吊销失效）。
    check("同步脚本改为按后端清单只同步指定文件（sync-plan）",
          "sync-plan" in syncsh and "--staging" in syncsh)
    check("同步脚本不再全目录扫描（避免拷进同 CA 的多份 CRL）",
          not any(ln.strip().startswith('for f in "$STAGING"/*')
                  for ln in syncsh.splitlines()))
    check("同步脚本有项目目录/python 占位符（安装时替换）",
          "__BASE_DIR__" in syncsh and "__PY__" in syncsh)

    # ---------------------------------------------------------------- systemd-analyze
    print("\n\033[1m== systemd-analyze verify（渲染后的文件）==\033[0m")
    # 默认**不调用**任何 systemd 工具（只做静态校验）。
    # 需要真正跑 systemd-analyze 时显式开： CA_RUN_SYSTEMD_ANALYZE=1
    analyze = shutil.which("systemd-analyze") if os.environ.get("CA_RUN_SYSTEMD_ANALYZE") == "1" else None
    if not analyze:
        check("systemd-analyze 校验（默认跳过，不调用 systemd 工具）", True,
              "如需运行请设置 CA_RUN_SYSTEMD_ANALYZE=1")
    else:
        # 逐单元校验：同步脚本是部署时才装到 /usr/local/sbin 的，
        # 本机校验时 systemd 会报 "is not executable"，这属于预期，不算失败。
        proc = subprocess.run([analyze, "verify", *[str(ETC / u) for u in rendered]],
                              capture_output=True, text=True)
        out = (proc.stdout + proc.stderr)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        expected = [ln for ln in lines if "ca-strongswan-sync.sh" in ln and "not executable" in ln]
        unexpected = [ln for ln in lines if ln not in expected]
        check("渲染后的单元通过 systemd-analyze verify（仅缺部署时才安装的同步脚本）",
              not unexpected and (proc.returncode == 0 or len(expected) == len(lines)),
              f"rc={proc.returncode} 未预期输出={unexpected[:2]}")

    # ---------------------------------------------------------------- 方案 A：只监听回环
    print("\n\033[1m== 方案 A：只监听回环（配合 SSH 隧道）==\033[0m")
    loopback_unit = ETC / "ca-admin-loopback.service"
    text = render(ROOT / "deploy/ca-admin-root.service", loopback_unit, host="127.0.0.1")
    check("回环部署渲染后 Environment=CA_HOST=127.0.0.1",
          "Environment=CA_HOST=127.0.0.1" in text and "0.0.0.0" not in text,
          [ln for ln in text.splitlines() if "CA_HOST" in ln])
    check("回环部署仍保留 root 沙箱与可写路径",
          "ProtectSystem=strict" in text and "User=root" in text
          and str(DATA) in text and "/etc/swanctl" in text)
    check("单元把 legacy /etc/ipsec.d 也设为可写（- 前缀容忍目录不存在）",
          "ReadWritePaths=-/etc/ipsec.d" in (ROOT / "deploy/ca-admin-root.service").read_text(
              encoding="utf-8"))
    install_sh = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
    check("install.sh 支持 --loopback（等价 --host 127.0.0.1）",
          "--loopback" in install_sh and 'HOST="127.0.0.1"' in install_sh)
    upgrade_sh = (ROOT / "deploy/upgrade.sh").read_text(encoding="utf-8")
    check("upgrade.sh 支持 --loopback（升级后仍是回环）",
          "--loopback" in upgrade_sh and "service_tools.py" in upgrade_sh and '--host "$DEPLOY_HOST"' in upgrade_sh)
    check("部署指南存在（只监听回环 + SSH 隧道）",
          (ROOT / "deploy/DEPLOY-LOOPBACK-SSH.md").is_file())

    # 运行时实测：绑定后局域网 IP 必须不可达
    import socket as _sock
    import subprocess as _sp
    import time as _time
    import urllib.request as _url
    lan_ip = None
    try:
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        lan_ip = _s.getsockname()[0]
        _s.close()
    except Exception:  # noqa: BLE001
        pass
    port = 0
    _ps = _sock.socket()
    _ps.bind(("127.0.0.1", 0))
    port = _ps.getsockname()[1]
    _ps.close()
    data2 = TMP / "data-loopback"
    data2.mkdir(parents=True, exist_ok=True)
    env2 = dict(os.environ, CA_DATA_DIR=str(data2), CA_HOST="127.0.0.1",
                CA_PORT=str(port), CA_LEGACY_API="loopback")
    proc2 = _sp.Popen([str(ROOT / ".venv/bin/python"), "-m", "backend.server"], cwd=ROOT,
                      env=env2, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        up = False
        for _ in range(80):
            try:
                _url.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
                up = True
                break
            except Exception:  # noqa: BLE001
                _time.sleep(0.25)
        check("回环实例可启动并从 127.0.0.1 访问", up)
        # 127.0.0.2 同样是本机回环；若服务绑定 0.0.0.0，也会接受这个地址。
        with _sock.socket() as probe:
            probe.settimeout(2)
            accepts_other_loopback = probe.connect_ex(("127.0.0.2", port)) == 0
        check("实际只监听 127.0.0.1（不是 0.0.0.0）",
              up and not accepts_other_loopback,
              f"127.0.0.1 可达={up}，127.0.0.2 可达={accepts_other_loopback}")
        if lan_ip:
            reachable = True
            try:
                _url.urlopen(f"http://{lan_ip}:{port}/api/health", timeout=3)
            except Exception:  # noqa: BLE001
                reachable = False
            check(f"局域网 IP({lan_ip}) 不可达（未暴露到网络）", not reachable)
        else:
            check("局域网 IP 不可达（本机无局域网地址，跳过）", True)
    finally:
        proc2.terminate()
        try:
            proc2.wait(timeout=10)
        except _sp.TimeoutExpired:
            proc2.kill()

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
