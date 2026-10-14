"""部署验收检查：对**正在运行的服务**做一遍端到端体检（不启动新服务、不改数据）。

用法：
    .venv/bin/python tests/verify_deploy.py                       # 默认 http://127.0.0.1:9443
    .venv/bin/python tests/verify_deploy.py http://10.0.0.5:9443 --password 'xxx'

检查内容：
  1) HTTP 层：登录页/静态资源/安全响应头/未登录拦截/公开 CRL 端点
  2) 加密信道：握手、指纹、登录、重放/篡改防护
  3) 业务只读接口：概览、证书清单、规则集、自动化、发布状态、strongSwan 状态、审计、一致性
  4) 敏感路径：明文 REST 是否按策略对外关闭
全部为只读操作，可以随时在生产环境跑。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nacl import public, secret, utils  # noqa: E402

PASSED, FAILED = [], []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASSED if cond else FAILED).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def http(base: str, method: str, path: str, payload=None, timeout=20):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ctype else raw), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        return exc.code, body, dict(exc.headers)


class Channel:
    def __init__(self, base: str):
        self.base, self.out = base, 0

    def connect(self):
        st, info, _ = http(self.base, "GET", "/api/handshake")
        assert st == 200, f"handshake 失败: {st}"
        self.fp = info["fingerprint"]
        spub = public.PublicKey(base64.b64decode(info["server_pub"]))
        sk = public.PrivateKey.generate()
        box = public.Box(sk, spub)
        shared = box.shared_key()
        self.k_c2s = hashlib.sha512(shared + b"CA-CHANNEL-c2s-v1").digest()[:32]
        self.k_s2c = hashlib.sha512(shared + b"CA-CHANNEL-s2c-v1").digest()[:32]
        hello = json.dumps({"v": 1, "ts": int(time.time()), "ua": "verify-deploy"}).encode()
        st, reply, _ = http(self.base, "POST", "/api/handshake", {
            "client_pub": base64.b64encode(bytes(sk.public_key)).decode(),
            "box": base64.b64encode(bytes(box.encrypt(hello, utils.random(24)))).decode()})
        assert st == 200, f"握手失败: {st} {reply}"
        self.ch = reply["ch"]
        inner = json.loads(secret.SecretBox(self.k_s2c).decrypt(
            base64.b64decode(reply["n"]) + base64.b64decode(reply["c"])))
        assert inner["fingerprint"] == self.fp, "响应内指纹与握手信息不一致"
        return info

    def envelope(self, inner: dict):
        self.out += 1
        nonce = self.out.to_bytes(8, "big") + utils.random(16)
        ct = secret.SecretBox(self.k_c2s).encrypt(
            json.dumps(inner, ensure_ascii=False).encode(), nonce)
        return {"ch": self.ch, "n": base64.b64encode(nonce).decode(),
                "c": base64.b64encode(ct.ciphertext).decode()}

    def rpc(self, method: str, path: str, body=None, query=None, raise_on_error=True):
        st, payload, _ = http(self.base, "POST", "/api/rpc",
                              self.envelope({"m": method, "p": path, "q": query or {},
                                             "b": body}))
        if st != 200:
            if raise_on_error:
                raise RuntimeError(f"HTTP {st}: {payload}")
            return st, payload
        out = json.loads(secret.SecretBox(self.k_s2c).decrypt(
            base64.b64decode(payload["n"]) + base64.b64decode(payload["c"])))
        if out["s"] >= 400 and raise_on_error:
            raise RuntimeError((out.get("b") or {}).get("error", "unknown"))
        return out

    def data(self, method: str, path: str, body=None, query=None):
        out = self.rpc(method, path, body, query)
        return out.get("b")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", nargs="?", default="http://127.0.0.1:9443")
    ap.add_argument("--password", help="管理员口令；不填则尝试读取口令文件")
    ap.add_argument("--pw-file", help="口令文件路径（默认项目 data/initial_admin_password.txt）")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--allow-empty", action="store_true",
                    help="仅首次安装验收：允许尚未导入 CA；不代表业务发布就绪")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    password = args.password
    if not password:
        pw_file = (Path(args.pw_file) if args.pw_file
                   else Path(__file__).resolve().parent.parent / "data"
                   / "initial_admin_password.txt")
        if pw_file.exists():
            m = re.search(r"初始口令:\s*(\S+)", pw_file.read_text())
            password = m.group(1) if m else None
    if not password:
        print("需要口令：请用 --password 或 --pw-file 指定", file=sys.stderr)
        return 2

    print(f"\n\033[1m验收目标: {base}\033[0m")
    print("\n\033[1m== HTTP 层 ==\033[0m")
    st, _, hdrs = http(base, "GET", "/login.html")
    check("登录页可访问", st == 200)
    check("CSP 已下发", "Content-Security-Policy" in hdrs)
    check("防点击劫持", hdrs.get("X-Frame-Options") == "DENY")
    check("nosniff", hdrs.get("X-Content-Type-Options") == "nosniff")
    for path in ("/crypto.js", "/vendor/tweetnacl.min.js", "/app.js", "/style.css"):
        st, body, _ = http(base, "GET", path)
        check(f"静态资源 {path}", st == 200 and isinstance(body, bytes) and len(body) > 100)
    st, body, _ = http(base, "GET", "/api/overview")
    check("未登录接口被拦截", st == 401, f"HTTP {st}")
    st, body, _ = http(base, "GET", "/crl/current.crl")
    check("公开 CRL 端点可用（无 CRL 时为 404）", st in (200, 404), f"HTTP {st} {body}")
    st, _, _ = http(base, "GET", "/../etc/passwd")
    check("路径穿越被拒", st in (403, 404, 400), f"HTTP {st}")

    print("\n\033[1m== 加密信道 ==\033[0m")
    ch = Channel(base)
    info = ch.connect()
    check("握手成功并取到指纹", len(ch.fp) == 39, ch.fp)
    check("KDF 声明为 sha512", info["kdf"]["hash"] == "sha512")
    st, payload, _ = http(base, "POST", "/api/rpc", {"ch": "not-a-channel", "n": "AA", "c": "AA"})
    check("伪造信道被拒并提示重新握手",
          st == 401 and isinstance(payload, dict) and payload.get("rehandshake") is True)
    out = ch.rpc("GET", "/api/me", raise_on_error=False)
    check("未登录时 RPC 返回 401", out["s"] == 401, str(out)[:80])
    me = ch.data("POST", "/api/login", {"username": args.user, "password": password})
    check("登录成功", me.get("username") == args.user and me.get("channel") is True, str(me)[:80])
    check("登录后身份有效", ch.data("GET", "/api/me")["username"] == args.user)
    env = ch.envelope({"m": "GET", "p": "/api/health", "q": {}, "b": None})
    http(base, "POST", "/api/rpc", env)
    st2, payload2, _ = http(base, "POST", "/api/rpc", env)
    check("重放同一信封被拒", st2 == 401 and payload2.get("error") == "channel_broken",
          f"{st2} {payload2}")

    print("\n\033[1m== 业务接口（只读） ==\033[0m")
    ch2 = Channel(base)
    ch2.connect()
    ch2.data("POST", "/api/login", {"username": args.user, "password": password})
    ov = ch2.data("GET", "/api/overview")
    check("概览可读", "total" in ov and "ca" in ov)
    if args.allow_empty and not ov["ca"]:
        check("首次安装允许空库（显式 --allow-empty）", True)
    else:
        check("能识别现有 CA", bool(ov["ca"]), str(ov["ca"])[:80] if ov["ca"] else "未导入 CA")
    if ov["ca"]:
        check("CA 私钥状态可见（未导入时应明确为 false）",
              isinstance(ov["ca"].get("has_key"), bool), f"has_key={ov['ca'].get('has_key')}")
    certs = ch2.data("GET", "/api/certs", query={"page_size": ["50"]})
    check("证书清单可读", "items" in certs and "facets" in certs,
          f"{certs.get('total')} 张")
    rulesets = ch2.data("GET", "/api/rulesets")
    check("规则集可读且含 strongSwan 默认集",
          any(r["slug"].startswith("strongswan") for r in rulesets["items"])
          and bool(rulesets["default_ruleset"]), f"{len(rulesets['items'])} 个")
    templates = ch2.data("GET", "/api/templates")
    check("/api/templates 向后兼容", any(t["id"].startswith("strongswan")
                                    for t in templates["items"]))
    tasks = ch2.data("GET", "/api/automation/tasks")
    check("自动化任务可读", "items" in tasks, f"{len(tasks['items'])} 个")
    meta = ch2.data("GET", "/api/automation/meta")
    check("自动化支持多种触发器/动作",
          len(meta["triggers"]) >= 7 and len(meta["kinds"]) == 3)
    ps = ch2.data("GET", "/api/publish/status")
    check("CRL 发布状态可读", "health" in ps and "strongswan" in ps,
          f"health={ps['health']} 目标={ps['enabled_targets']}")
    check("状态体现运行身份", "running_as_root" in ps, f"root={ps.get('running_as_root')}")
    ss = ch2.data("GET", "/api/strongswan/status")
    check("strongSwan 状态可读", "strongswan" in ss and "crl_url" in ss)
    snip = ch2.data("GET", "/api/strongswan/snippet", query={"role": ["client"]})
    check("可生成 swanctl 配置片段", "connections {" in snip["snippet"])
    csrs = ch2.data("GET", "/api/csrs", query={"page_size": ["10"]})
    check("CSR 证书请求池可读", "items" in csrs and "stats" in csrs,
          f"待签发 {(csrs.get('stats') or {}).get('pending', 0)}")
    audit = ch2.data("GET", "/api/audit", query={"page_size": ["10"]})
    check("审计日志可读", "items" in audit and audit["total"] >= 0)
    rep = ch2.data("POST", "/api/consistency/check")
    check("一致性体检可执行", "summary" in rep, str(rep["summary"]))
    # 首次未导入 CA 是明确的初始化待办；其他 error 必须令验收失败。
    errors = [i.get("code") for i in rep.get("issues", []) if i.get("level") == "error"]
    unexpected = [code for code in errors if code != "no_ca"]
    check("一致性体检无实际错误（空库仅允许 no_ca）", not unexpected, str(unexpected))
    if "no_ca" in errors:
        print("    待配置：尚未导入 CA；此结果不表示已完成 CRL/VPN 业务验收")

    print(f"\n  通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("  失败明细: " + "、".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
