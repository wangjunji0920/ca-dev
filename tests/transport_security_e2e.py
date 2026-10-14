"""传输安全验收（外部审查 ①）：

审查复现：明文 HTTP 上登录会下发会话 cookie；拿到该 cookie 即可自建加密信道、
读 CSRF 令牌并修改系统设置。根因是 cookie 是 **bearer 凭据**，而明文链路可被嗅探。

本测试锁定修复后的行为：
  1) **非回环 + 明文**登录：响应里**不得**出现 Set-Cookie（不下发明文 bearer 凭据）；
  2) **回环**（本机 / SSH 隧道）登录：正常下发 cookie（受支持的安全部署）；
  3) 会话与首次登录的 IP/UA 绑定：cookie 被搬到别的来源即失效；
  4) `doctor` 对"非回环 + 未启用 TLS"报 error，对"仅回环明文"判 ok；
  5) 非回环 + 明文时，管理页面本身也拿不到会话（跨页面会话不可用 → 暴露面收敛）。
"""
from __future__ import annotations

import base64
import hashlib
import json
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

from nacl import public, secret, utils  # noqa: E402

PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="transport-"))
DATA = TMP / "data"
DATA.mkdir(parents=True, exist_ok=True)
# 测试进程也必须用同一个数据目录（否则读到的口令来自其它目录）
os.environ["CA_DATA_DIR"] = str(DATA)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def http(base: str, method: str, path: str, payload=None, headers: dict | None = None,
         timeout: int = 20):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode() if payload is not None else None,
        headers=h, method=method)
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
    """最小加密信道客户端；支持附加 HTTP 头（用 X-Forwarded-For 伪造来源 IP）。"""

    def __init__(self, base: str, headers: dict | None = None):
        self.base, self.headers, self.out = base, headers or {}, 0

    def connect(self):
        st, info, _ = http(self.base, "GET", "/api/handshake", headers=self.headers)
        assert st == 200, f"handshake 失败: {st}"
        spub = public.PublicKey(base64.b64decode(info["server_pub"]))
        sk = public.PrivateKey.generate()
        box = public.Box(sk, spub)
        shared = box.shared_key()
        self.k_c2s = hashlib.sha512(shared + b"CA-CHANNEL-c2s-v1").digest()[:32]
        self.k_s2c = hashlib.sha512(shared + b"CA-CHANNEL-s2c-v1").digest()[:32]
        hello = json.dumps({"v": 1, "ts": int(time.time()), "ua": "transport-test"}).encode()
        st, reply, _ = http(self.base, "POST", "/api/handshake", {
            "client_pub": base64.b64encode(bytes(sk.public_key)).decode(),
            "box": base64.b64encode(bytes(box.encrypt(hello, utils.random(24)))).decode()},
            headers=self.headers)
        assert st == 200, f"握手失败: {st} {reply}"
        self.ch = reply["ch"]
        return info

    def envelope(self, inner: dict):
        self.out += 1
        nonce = self.out.to_bytes(8, "big") + utils.random(16)
        ct = secret.SecretBox(self.k_c2s).encrypt(
            json.dumps(inner, ensure_ascii=False).encode(), nonce)
        return {"ch": self.ch, "n": base64.b64encode(nonce).decode(),
                "c": base64.b64encode(ct.ciphertext).decode()}

    def rpc_raw(self, method: str, path: str, body=None):
        return http(self.base, "POST", "/api/rpc",
                    self.envelope({"m": method, "p": path, "q": {}, "b": body}),
                    headers=self.headers)

    def rpc(self, method: str, path: str, body=None):
        st, payload, _ = self.rpc_raw(method, path, body)
        assert st == 200, f"HTTP {st}: {payload}"
        return json.loads(secret.SecretBox(self.k_s2c).decrypt(
            base64.b64decode(payload["n"]) + base64.b64decode(payload["c"])))


def main() -> int:
    from backend import config, db, security, server

    server.bootstrap(verbose=False)
    pw = re.search(r"初始口令:\s*(\S+)",
                   config.INITIAL_PW_FILE.read_text(encoding="utf-8")).group(1)
    port = 0
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ, CA_DATA_DIR=str(DATA), CA_HOST="127.0.0.1", CA_PORT=str(port),
               CA_LEGACY_API="loopback", CA_TRUST_PROXY="1")   # 允许用 XFF 模拟来源
    proc = subprocess.Popen([PY, "-m", "backend.server"], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        up = False
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=2)
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        check("临时服务已启动", up)

        print("\n\033[1m== 1) 非回环 + 明文：不得下发会话 cookie ==\033[0m")
        remote = Channel(base, headers={"X-Forwarded-For": "203.0.113.9"})
        remote.connect()
        st, payload, hdrs = remote.rpc_raw("POST", "/api/login",
                                           {"username": "admin", "password": pw})
        set_cookie = {k.lower(): v for k, v in hdrs.items()}.get("set-cookie", "")
        check("非回环来源登录成功（信道身份仍绑定）", st == 200, f"HTTP {st}: {payload}")
        body = json.loads(secret.SecretBox(remote.k_s2c).decrypt(
            base64.b64decode(payload["n"]) + base64.b64decode(payload["c"])))
        check("登录返回 channel=true 与 csrf（信道内可用）",
              body.get("s") == 200 and (body.get("b") or {}).get("csrf"), str(body)[:120])
        check("★ 响应头里没有 Set-Cookie（不下发明文 bearer 凭据）", not set_cookie,
              set_cookie[:120])

        print("\n\033[1m== 2) 回环（SSH 隧道）登录：正常下发 cookie ==\033[0m")
        local = Channel(base)
        local.connect()
        st2, payload2, hdrs2 = local.rpc_raw("POST", "/api/login",
                                             {"username": "admin", "password": pw})
        sc2 = {k.lower(): v for k, v in hdrs2.items()}.get("set-cookie", "")
        check("回环来源登录成功", st2 == 200, f"HTTP {st2}")
        check("回环来源下发了会话 cookie（受支持部署）", "ca_session=" in sc2, sc2[:120])
        check("明文下 cookie 仍带 HttpOnly + SameSite=Strict",
              "HttpOnly" in sc2 and "SameSite=Strict" in sc2, sc2[:120])

        print("\n\033[1m== 3) 会话与来源 IP/UA 绑定 ==\033[0m")
        sess = security.sessions.create("admin", "127.0.0.1", "transport-test")
        check("同来源可取到会话", security.sessions.get(sess.sid, ip="127.0.0.1",
                                                        user_agent="transport-test") is not None)
        check("★ cookie 被搬到其它来源 → 立即失效",
              security.sessions.get(sess.sid, ip="203.0.113.9") is None)
        check("UA 明显不符也会失效",
              security.sessions.get(sess.sid, ip="127.0.0.1", user_agent="Mozilla/9") is None)
        security.sessions.destroy(sess.sid)

        print("\n\033[1m== 4) 改密后旧信道立即失效 ==\033[0m")
        c1 = Channel(base)
        c1.connect()
        c1.rpc("POST", "/api/login", {"username": "admin", "password": pw})
        check("改密前：该信道已认证（/api/me 可用）",
              c1.rpc("GET", "/api/me").get("b", {}).get("username") == "admin",
              str(c1.rpc("GET", "/api/me"))[:120])
        security.change_password(pw, "NewPass-12345", actor="admin")
        me2 = c1.rpc("GET", "/api/me")
        check("★ 改密后旧信道立即变为未认证",
              me2.get("s") == 401 or not (me2.get("b") or {}).get("username"),
              str(me2)[:140])
        # 还原口令，避免影响后续断言
        security.change_password("NewPass-12345", pw, actor="admin")

        print("\n\033[1m== 5) doctor 的传输安全判定 ==\033[0m")
        r = subprocess.run([PY, "-m", "backend.cli", "doctor", "--json"], cwd=ROOT,
                           env=dict(env, CA_HOST="127.0.0.1"), capture_output=True, text=True)
        items = {i["item"]: i for i in json.loads(r.stdout).get("results", [])}
        check("仅回环明文 → 判 ok（受支持部署）",
              items.get("传输安全", {}).get("level") == "ok", str(items.get("传输安全"))[:140])
        r2 = subprocess.run([PY, "-m", "backend.cli", "doctor", "--json"], cwd=ROOT,
                            env=dict(env, CA_HOST="0.0.0.0"), capture_output=True, text=True)
        items2 = {i["item"]: i for i in json.loads(r2.stdout).get("results", [])}
        check("★ 非回环 + 无 TLS → 判 error 并给出改法",
              items2.get("传输安全", {}).get("level") == "error"
              and "回环" in (items2.get("传输安全", {}).get("fix") or ""),
              str(items2.get("传输安全"))[:180])
        print("\n\033[1m== 6) 只有已核实的代理来源才允许 X-Forwarded-For ==\033[0m")
        # 审查复现：开启 CA_TRUST_PROXY=1 时，直连客户端用 XFF: 127.0.0.1 即可伪装本机，
        # 从而绕过"明文仅回环"限制并拿到会话 cookie。
        class FakeHandler:
            def __init__(self, ip: str, xff: str | None = None):
                self.client_address = (ip, 51234)
                self.headers = {"X-Forwarded-For": xff} if xff else {}

        check("★ 非回环直连 + XFF=127.0.0.1 → 仍按真实来源（不获得本机特权）",
              security.client_ip(FakeHandler("203.0.113.9", "127.0.0.1"), True) == "203.0.113.9",
              security.client_ip(FakeHandler("203.0.113.9", "127.0.0.1"), True))
        check("回环对端 + XFF → 采信 XFF（本机反代 / SSH 隧道场景）",
              security.client_ip(FakeHandler("127.0.0.1", "203.0.113.9"), True) == "203.0.113.9",
              security.client_ip(FakeHandler("127.0.0.1", "203.0.113.9"), True))
        check("关闭代理信任时完全忽略 XFF",
              security.client_ip(FakeHandler("203.0.113.9", "127.0.0.1"), False) == "203.0.113.9")
        os.environ["CA_TRUSTED_PROXIES"] = "198.51.100.9"
        try:
            check("显式列入 CA_TRUSTED_PROXIES 的来源才采信 XFF",
                  security.client_ip(FakeHandler("198.51.100.9", "203.0.113.9"), True)
                  == "203.0.113.9")
            check("未列入的来源即使 CA_TRUST_PROXY=1 也不采信",
                  security.client_ip(FakeHandler("203.0.113.9", "127.0.0.1"), True)
                  == "203.0.113.9")
        finally:
            os.environ.pop("CA_TRUSTED_PROXIES", None)

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
