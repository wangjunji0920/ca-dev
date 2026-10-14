#!/usr/bin/env python3
"""Deployment helpers using only the Python standard library.

Render each systemd directive according to its own parser, and require both a stable
systemd process and the application's HTTP health response before success.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.request


def validate(base: str, data: str, host: str, port: str, user: str) -> None:
    for value in (base, data, host, port, user):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("参数不得含换行或控制字符")
    for value in (base, data):
        if not Path(value).is_absolute() or ":" in value:
            raise ValueError("项目/数据目录须为绝对路径且不能含冒号")
    b, d = Path(base).resolve(), Path(data).resolve()
    if b == d or b.is_relative_to(d):
        raise ValueError("数据目录不能是项目目录本身或其父目录")
    ipaddress.ip_address(host)  # explicit listen address; no shell/systemd tokens
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("端口须为 1–65535")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*[$]?", user):
        raise ValueError("无效的服务用户名")


def unit_value(value: str, *, executable: bool = False) -> str:
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return value.replace("$", "$$") if executable else value


def render(src: Path, base: str, data: str, host: str, port: str, user: str) -> str:
    validate(base, data, host, port, user)
    values = {
        "BASE_DIR": base, "DATA_DIR": data, "HOST": host, "PORT": port,
        "USER": user, "STAGING": str(Path(data) / "publish"),
        "PY": str(Path(base) / ".venv/bin/python"),
    }
    lines = []
    for line in src.read_text(encoding="utf-8").splitlines():
        for key, value in values.items():
            if src.suffix == ".sh":
                replacement = shlex.quote(value)
            elif line.startswith(("WorkingDirectory=", "PathChanged=")):
                # These are single path values, NOT shell/list words. systemd does
                # not remove surrounding quotes or decode backslash escapes here.
                # Only percent specifiers are expanded by these directive parsers.
                if value.endswith((" ", "\\")):
                    raise ValueError("systemd 单路径字段不支持以空格或反斜杠结尾的目录")
                replacement = value.replace("%", "%%")
            else:
                replacement = unit_value(value, executable=line.startswith("ExecStart="))
            line = line.replace("__" + key + "__", replacement)
        lines.append(line)
    text = "\n".join(lines) + "\n"
    if re.search(r"__[A-Z_]+__", text):
        raise ValueError(f"模板有未替换的占位符: {src.name}")
    return text


def wait_ready(host: str, port: str, *, timeout: float = 30,
               stable_seconds: float = 2, systemctl: str = "systemctl") -> bool:
    address = "127.0.0.1" if host == "0.0.0.0" else ("::1" if host == "::" else host)
    authority = f"[{address}]" if ":" in address else address
    url = f"http://{authority}:{port}/api/health"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    first_ok = None
    identity = None
    last = "未就绪"
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                [systemctl, "show", "ca-admin.service", "--no-pager",
                 "--property=ActiveState,SubState,MainPID,NRestarts,ExecMainStatus"],
                capture_output=True, text=True, timeout=3, check=True)
            state = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            last = f"ActiveState={state.get('ActiveState')} SubState={state.get('SubState')} status={state.get('ExecMainStatus')}"
            if state.get("ActiveState") == "failed" or state.get("SubState") == "auto-restart":
                raise RuntimeError(last)
            if (state.get("ActiveState"), state.get("SubState")) != ("active", "running"):
                first_ok = None
                time.sleep(0.25)
                continue
            pid = int(state.get("MainPID", "0"))
            if pid <= 0:
                raise ValueError("没有有效的服务主进程")
            current = (pid, state.get("NRestarts"))
            with opener.open(url, timeout=2) as response:
                body = json.load(response)
                if response.status != 200 or not isinstance(body, dict) or body.get("status") != "ok":
                    raise ValueError("HTTP 健康检查未通过")
            if first_ok is None or current != identity:
                first_ok, identity = time.monotonic(), current
            if time.monotonic() - first_ok >= stable_seconds:
                print(f"服务就绪：PID {pid}，{url} 正常，进程持续稳定")
                return True
        except RuntimeError as exc:
            print(f"服务启动失败：{exc}", file=sys.stderr)
            return False
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            first_ok = None
            last = str(exc)
        time.sleep(0.25)
    print(f"服务未在 {timeout:g} 秒内就绪：{last}", file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("validate", "render", "ready"))
    parser.add_argument("--base", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--data")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="9443")
    parser.add_argument("--user", default="root")
    parser.add_argument("--template", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    data = args.data or str(Path(args.base) / "data")
    try:
        validate(args.base, data, args.host, args.port, args.user)
        if args.action == "render":
            if not args.template or not args.output:
                parser.error("render 需要 --template 和 --output")
            text = render(args.template, args.base, data, args.host, args.port, args.user)
            # Atomic replacement: a failed render must not truncate the installed unit.
            tmp = args.output.with_name(args.output.name + f".tmp-{os.getpid()}")
            try:
                tmp.write_text(text, encoding="utf-8")
                tmp.chmod(0o755 if args.template.suffix == ".sh" else 0o644)
                tmp.replace(args.output)
            finally:
                tmp.unlink(missing_ok=True)
        elif args.action == "ready":
            return 0 if wait_ready(args.host, args.port, timeout=args.timeout) else 1
    except (ValueError, OSError) as exc:
        print(f"部署检查失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
