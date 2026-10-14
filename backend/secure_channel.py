"""HTTP 之上的自建应用层加密信道（不依赖 HTTPS）。

为什么这样做
------------
需求是“不要 HTTPS，要在 HTTP 里自己加密”：因为服务端没有可被浏览器完全信任的证书。
本模块用 NaCl 原语在**明文 HTTP 之上**建立一个端到端加密信道：

1. 服务端有长期 X25519 密钥对，公钥与**指纹**公开（``GET /api/handshake``），
   指纹同时打印在服务端启动日志里，管理员可带外核对（首次信任 TOFU + 指纹固定）。
2. 浏览器生成临时 X25519 密钥对，用 ``crypto_box_beforenm`` 得到共享密钥
   （X25519 + HSalsa20），然后派生出两个方向的对称密钥：
   ``k_c2s = SHA512(shared || "CA-CHANNEL-c2s-v1")[:32]``、
   ``k_s2c = SHA512(shared || "CA-CHANNEL-s2c-v1")[:32]``。
   （两个方向用不同密钥，因此计数器互不干扰，不会出现 nonce 复用。）
3. 所有请求/响应正文用 ``secretbox``（XSalsa20-Poly1305）加解密，AEAD 保证机密性与完整性；
   每条消息的 nonce = ``计数器(8B, 大端) || 随机(16B)``，服务端强制计数器严格递增 → 防重放。
4. 登录在密文内部完成，成功后把用户名绑定到该信道。可信传输（TLS 或回环/SSH）
   还会发会话 cookie 供跨页面使用；非回环明文访问不发 cookie。
5. 服务端用自己的长期私钥解开客户端首包并返回正确密文，等于隐含地完成了密钥确认
   （被动攻击者无法冒充服务端；主动中间人只能靠首次连接时的指纹核对来发现）。

与 HTTPS 相比的诚实结论
----------------------
* 防被动窃听：**好于**明文 HTTP，达到 HTTPS 的机密性水平。
* 防主动中间人：HTTP 下发的网页/JavaScript 可被篡改，指纹检查代码本身也会被替换。
  指纹固定只能检测没有改动前端代码时的密钥替换，不能代替 SSH 或可信 TLS。
* 不提供：前向保密之外的流量分析防护、客户端身份（浏览器端本来就是匿名管理员）。

公开例外（故意不加密）
----------------------
``/crl/*`` 的 CRL 下载是本系统对外提供服务的接口，strongSwan 对端要靠它自动拉取 CRL；
CRL 本身是公开信息（不含私钥、不含口令），因此保持明文可访问。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from nacl import public, secret
from nacl.exceptions import CryptoError

from . import api, audit, config, db, security, x509util
from .api import ApiError, FilePart, Request, Resp

PROTOCOL_VERSION = 1
KDF_C2S = b"CA-CHANNEL-c2s-v1"
KDF_S2C = b"CA-CHANNEL-s2c-v1"
CHANNEL_TTL_IDLE = int(os.environ.get("CA_CHANNEL_IDLE", "1800"))     # 空闲 30 分钟
CHANNEL_TTL_MAX = int(os.environ.get("CA_CHANNEL_MAX_AGE", "43200"))  # 最长 12 小时
MAX_CHANNELS = int(os.environ.get("CA_CHANNEL_MAX", "256"))
MAX_CHANNELS_PER_IP = int(os.environ.get("CA_CHANNEL_MAX_PER_IP", "16"))
HANDSHAKE_SKEW = 180          # 客户端时间戳允许的偏移（秒）
HANDSHAKE_RATE = 60           # 每个 IP 每分钟最多握手次数


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ChannelError("base64 解码失败") from exc


class ChannelError(Exception):
    """信道层错误（握手失败、解密失败、重放等）。"""


def derive(shared: bytes, label: bytes) -> bytes:
    return hashlib.sha512(shared + label).digest()[:32]


def fingerprint_of(pubkey: bytes) -> str:
    digest = hashlib.sha256(pubkey).hexdigest().upper()[:32]
    return "-".join(digest[i:i + 4] for i in range(0, len(digest), 4))


# ---------------------------------------------------------------- 服务端身份
class ServerIdentity:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._key: public.PrivateKey | None = None

    def load(self) -> public.PrivateKey:
        with self._lock:
            if self._key is not None:
                return self._key
            config.ensure_dirs()
            path = config.CHANNEL_KEY_FILE
            if path.exists():
                try:
                    raw = b64d(path.read_text().strip())
                    if len(raw) == 32:
                        self._key = public.PrivateKey(raw)
                        self._check_fingerprint_change()
                        return self._key
                except (ChannelError, ValueError, OSError):
                    pass
            key = public.PrivateKey.generate()
            config.atomic_write_text(path, b64e(bytes(key)), private=True)
            db.set_setting("channel_fingerprint", self.fingerprint)
            audit.log("channel.server_key_created", target_type="channel",
                      target_label=self.fingerprint, actor="system",
                      detail={"fingerprint": self.fingerprint})
            self._key = key
            return key

    def _check_fingerprint_change(self) -> None:
        stored = db.get_setting("channel_fingerprint")
        if stored and stored != self.fingerprint:
            audit.log("channel.server_key_changed", target_type="channel",
                      target_label=self.fingerprint, actor="system",
                      detail={"old": stored, "new": self.fingerprint,
                              "warning": "服务端信道密钥发生变化，已固定的客户端会收到告警"})
        db.set_setting("channel_fingerprint", self.fingerprint)

    @property
    def pubkey(self) -> bytes:
        return bytes(self.load().public_key)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.pubkey)

    def rotate(self, actor: str = "admin") -> str:
        """轮换服务端信道密钥（客户端下次连接需要重新核对指纹）。"""
        with self._lock:
            key = public.PrivateKey.generate()
            config.atomic_write_text(config.CHANNEL_KEY_FILE, b64e(bytes(key)), private=True)
            old = self.fingerprint
            self._key = key
            db.set_setting("channel_fingerprint", self.fingerprint)
            channels.clear()
            audit.log("channel.server_key_rotated", target_type="channel",
                      target_label=self.fingerprint, actor=actor,
                      detail={"old": old, "new": self.fingerprint})
            return self.fingerprint


identity = ServerIdentity()


# ---------------------------------------------------------------- 信道
REPLAY_CACHE_MAX = 64


@dataclass
class Channel:
    ch: str
    key_c2s: bytes
    key_s2c: bytes
    ip: str
    created: float
    last_seen: float
    user_agent: str = ""
    username: str | None = None
    csrf: str = ""
    in_counter: int = 0
    out_counter: int = 0
    # 请求去重：{rid: 内部响应}。客户端重试（信道重建/响应丢失）时不再重复执行，
    # 这对签发/吊销这类**非幂等**操作很关键——否则一次点击可能签出两张证书。
    replay: dict = field(default_factory=dict)
    # 信道内登录成功时，除了把身份绑定到信道，还要下发一个会话 cookie：
    # 否则 location.replace('index.html') 打开新页面 = 新信道 = 未登录，
    # 浏览器里表现为"点了登录没反应"（真实踩过）。
    pending_set_cookie: str = ""
    # 登录时的**凭据纪元号**：改密（含其它进程）后纪元 +1，旧信道立即失效
    login_epoch: int = 0

    def session(self) -> security.Session | None:
        if not self.username:
            return None
        # 改密后（哪怕是 CLI 在另一个进程里改的）旧信道必须立即失效
        if not security.channel_still_valid(self.login_epoch):
            self.username = None
            return None
        return security.Session(sid=self.ch, username=self.username, csrf=self.csrf,
                                created=self.created, last_seen=self.last_seen, ip=self.ip,
                                user_agent=self.user_agent)


class ChannelStore:
    def __init__(self) -> None:
        self._items: dict[str, Channel] = {}
        self._lock = threading.RLock()
        self._handshake_hits: dict[str, list[float]] = {}

    # -- 握手限速（防内存耗尽） --------------------------------------
    def handshake_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._handshake_hits.get(ip, []) if now - t < 60]
            if len(hits) >= HANDSHAKE_RATE:
                self._handshake_hits[ip] = hits
                return False
            hits.append(now)
            self._handshake_hits[ip] = hits
            return True

    def create(self, client_pub: bytes, ip: str, user_agent: str = "") -> Channel:
        box = public.Box(identity.load(), public.PublicKey(client_pub))
        shared = box.shared_key()
        now = time.time()
        ch = Channel(ch=secrets.token_urlsafe(24), key_c2s=derive(shared, KDF_C2S),
                     key_s2c=derive(shared, KDF_S2C), ip=ip, created=now, last_seen=now,
                     user_agent=(user_agent or "")[:200], csrf=secrets.token_urlsafe(24))
        with self._lock:
            self._prune_locked()
            per_ip = [c for c in self._items.values() if c.ip == ip]
            if len(per_ip) >= MAX_CHANNELS_PER_IP:      # 顶掉该 IP 最旧的信道
                oldest = min(per_ip, key=lambda c: c.last_seen)
                self._items.pop(oldest.ch, None)
            while len(self._items) >= MAX_CHANNELS:
                oldest = min(self._items.values(), key=lambda c: c.last_seen)
                self._items.pop(oldest.ch, None)
            self._items[ch.ch] = ch
        return ch

    def get(self, ch: str | None) -> Channel | None:
        if not ch:
            return None
        with self._lock:
            channel = self._items.get(ch)
            if channel is None:
                return None
            now = time.time()
            if (now - channel.last_seen > CHANNEL_TTL_IDLE
                    or now - channel.created > CHANNEL_TTL_MAX):
                self._items.pop(ch, None)
                return None
            channel.last_seen = now
            return channel

    def drop(self, ch: str) -> None:
        with self._lock:
            self._items.pop(ch, None)

    def all(self) -> list[Channel]:
        """当前所有有效信道（用于按用户批量丢弃，例如改密后强制重新登录）。"""
        with self._lock:
            self._prune_locked()
            return list(self._items.values())

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def count(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._items)

    def _prune_locked(self) -> None:
        now = time.time()
        for ch in [k for k, v in self._items.items()
                   if now - v.last_seen > CHANNEL_TTL_IDLE
                   or now - v.created > CHANNEL_TTL_MAX]:
            self._items.pop(ch, None)

    def stats(self) -> dict:
        with self._lock:
            self._prune_locked()
            return {"channels": len(self._items),
                    "authenticated": sum(1 for c in self._items.values() if c.username),
                    "ips": len({c.ip for c in self._items.values()})}


channels = ChannelStore()


# ---------------------------------------------------------------- 信封加解密
def _nonce(counter: int) -> bytes:
    return counter.to_bytes(8, "big") + os.urandom(16)


def seal(channel: Channel, obj: Any) -> dict:
    channel.out_counter += 1
    nonce = _nonce(channel.out_counter)
    box = secret.SecretBox(channel.key_s2c)
    ct = box.encrypt(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"), nonce)
    return {"n": b64e(nonce), "c": b64e(ct.ciphertext)}


def unseal(channel: Channel, envelope: dict) -> Any:
    if not isinstance(envelope, dict) or "n" not in envelope or "c" not in envelope:
        raise ChannelError("加密信封格式不正确")
    nonce = b64d(envelope["n"])
    if len(nonce) != 24:
        raise ChannelError("nonce 长度不正确")
    counter = int.from_bytes(nonce[:8], "big")
    if counter <= channel.in_counter:
        raise ChannelError("检测到重放或乱序消息（计数器未递增），已拒绝")
    box = secret.SecretBox(channel.key_c2s)
    try:
        raw = box.decrypt(nonce + b64d(envelope["c"]))
    except CryptoError as exc:
        raise ChannelError("解密失败（密钥不匹配或数据被篡改）") from exc
    channel.in_counter = counter
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------- 握手
def handshake_info() -> dict:
    return {
        "v": PROTOCOL_VERSION,
        "server_pub": b64e(identity.pubkey),
        "fingerprint": identity.fingerprint,
        "kdf": {"c2s": KDF_C2S.decode(), "s2c": KDF_S2C.decode(), "hash": "sha512"},
        "idle_ttl": CHANNEL_TTL_IDLE,
        "max_age": CHANNEL_TTL_MAX,
        "note": "首次连接请把此指纹与服务端启动日志中的指纹核对一致",
    }


def handshake(payload: dict, ip: str, user_agent: str = "") -> dict:
    """客户端首包：用服务端长期公钥加密的 {client_pub, box}。"""
    if not channels.handshake_allowed(ip):
        raise ChannelError("握手过于频繁，请稍后再试")
    if not isinstance(payload, dict):
        raise ChannelError("请求格式不正确")
    try:
        client_pub = b64d(payload.get("client_pub") or "")
    except ChannelError:
        raise
    if len(client_pub) != 32:
        raise ChannelError("客户端公钥长度不正确")
    box_b64 = payload.get("box") or ""
    try:
        client_box = public.Box(identity.load(), public.PublicKey(client_pub))
        inner = json.loads(client_box.decrypt(b64d(box_b64)).decode("utf-8"))
    except (CryptoError, ChannelError, ValueError) as exc:
        raise ChannelError("握手包无法解密，请刷新页面重试") from exc
    if inner.get("v") != PROTOCOL_VERSION:
        raise ChannelError(f"协议版本不匹配（客户端 {inner.get('v')}，"
                           f"服务端 {PROTOCOL_VERSION}）")
    ts = inner.get("ts")
    if not isinstance(ts, (int, float)) or abs(time.time() - ts) > HANDSHAKE_SKEW:
        raise ChannelError("客户端时间戳超出允许范围（请检查系统时间）")

    channel = channels.create(client_pub, ip, user_agent)
    reply = seal(channel, {"v": PROTOCOL_VERSION, "ch": channel.ch,
                           "server_pub": b64e(identity.pubkey),
                           "fingerprint": identity.fingerprint,
                           "idle_ttl": CHANNEL_TTL_IDLE})
    return {"ch": channel.ch, **reply}


# ---------------------------------------------------------------- RPC
_PATH_RE = re.compile(r"^/api/[A-Za-z0-9._/-]+$")
FORBIDDEN_IN_RPC = {"^/api/handshake$", "^/api/rpc$"}


def _build_files(raw: Any) -> dict[str, list[FilePart]]:
    out: dict[str, list[FilePart]] = {}
    if not isinstance(raw, dict):
        return out
    for field_name, items in raw.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or "data" not in item:
                continue
            try:
                content = b64d(item["data"])
            except ChannelError:
                continue
            out.setdefault(str(field_name), []).append(FilePart(
                filename=str(item.get("name") or "unnamed"),
                content=content, content_type=str(item.get("ct") or "application/octet-stream")))
    return out


def _envelope_response(resp: Resp) -> dict:
    """把内部 Resp 转成可放入加密信封的结构（文件以 base64 承载）。"""
    if resp.file is not None:
        return {"s": resp.status, "b": None,
                "f": {"name": resp.filename or resp.file.name,
                      "ct": resp.content_type,
                      "data": b64e(resp.file.read_bytes())}}
    if resp.body is not None:
        return {"s": resp.status, "b": None,
                "f": {"name": resp.filename or "download.bin", "ct": resp.content_type,
                      "data": b64e(resp.body)}}
    return {"s": resp.status, "b": resp.json, "h": resp.headers, "f": None}


def rpc(envelope: dict, ip: str, host: str = "", user_agent: str = "",
        cookie_session=None) -> tuple[int, dict, dict]:
    """处理一次加密 RPC 调用。返回 (HTTP 状态码, 响应体, 附加响应头)。

    ``cookie_session``：同一浏览器在**其它页面**建立的会话（来自 cookie）。
    信道未绑定用户时用它授权，这样登录页登录后跳转到 index.html（新信道）仍然有效。
    """
    ch = envelope.get("ch") if isinstance(envelope, dict) else None
    channel = channels.get(ch)
    if channel is None:
        # 信道不存在/过期：这里无法加密（没有密钥），返回明文提示让前端重新握手。
        # 错误信息不含任何敏感内容。
        return 401, {"error": "channel_expired", "rehandshake": True,
                     "message": "加密信道已过期，正在重新建立安全连接"}, {}
    try:
        inner = unseal(channel, envelope)
    except ChannelError as exc:
        channels.drop(channel.ch)
        return 401, {"error": "channel_broken", "rehandshake": True,
                     "message": str(exc)}, {}

    rid = str(inner.get("rid") or "")
    if os.environ.get("CA_DEBUG_RPC") == "1":
        import sys as _sys
        _sys.stderr.write(f"[rpc] ch={channel.ch[:6]} rid={rid or '-'} "
                          f"{inner.get('m')} {inner.get('p')}\n")
        _sys.stderr.flush()
    if rid and rid in channel.replay:
        # 同一逻辑请求的重试：直接回放上次的结果，绝不重复执行
        return 200, _wrap(channel, channel.replay[rid]), _take_headers(channel)

    method = str(inner.get("m") or "GET").upper()
    path = str(inner.get("p") or "")
    if not _PATH_RE.match(path) or any(re.match(p, path) for p in FORBIDDEN_IN_RPC):
        return 200, _wrap(channel, {"s": 400, "b": {"error": f"非法的 RPC 路径: {path}"}}), {}

    query = inner.get("q") if isinstance(inner.get("q"), dict) else {}
    body = inner.get("b")
    # 身份来源：优先"信道自身已绑定"，否则用同一浏览器的 cookie 会话
    cookie_auth = channel.username is None and cookie_session is not None
    session = channel.session() or cookie_session
    if cookie_auth and method in ("POST", "PUT", "PATCH", "DELETE"):
        # 用 cookie 授权时要求信封内带 CSRF 令牌（纵深防御；cookie 本身是 SameSite=Strict）
        token = str(inner.get("csrf") or "")
        if not token or token != getattr(cookie_session, "csrf", None):
            return 200, _wrap(channel, {"s": 403, "b": {
                "error": "CSRF 令牌缺失或不正确，请刷新页面后重试"}}), {}
    req = Request(method=method, path=path, query=query or {}, form={},
                  files=_build_files(inner.get("files")), payload=body,
                  session=session, ip=ip, host=host, rpc=True,
                  on_login=lambda username: _bind_login(channel, username, ip, user_agent),
                  on_logout=lambda: _bind_logout(channel))
    try:
        resp = api.route_api(req)
    except ApiError as exc:
        resp = Resp(status=exc.status, json={"error": exc.message})
    except Exception as exc:  # noqa: BLE001 - 加密信道内也要返回结构化错误
        resp = Resp(status=500, json={"error": f"服务器内部错误: {type(exc).__name__}: {exc}"})
    headers = _take_headers(channel)
    if path == "/api/logout" and cookie_session is not None and resp.status < 400:
        # cookie 会话也要真正登出（否则信道解绑了、cookie 还活着）
        try:
            security.sessions.destroy(cookie_session.sid, reason="logout")
        except Exception:  # noqa: BLE001
            pass
        headers["Set-Cookie"] = security.cookie(config.SESSION_COOKIE, "", max_age=0,
                                               secure=config.TLS_ENABLED)
    envelope = _envelope_response(resp)
    if rid:
        # 只缓存非文件响应（文件响应较大），并限制条数
        if envelope.get("f") is None:
            channel.replay[rid] = envelope
            while len(channel.replay) > REPLAY_CACHE_MAX:
                channel.replay.pop(next(iter(channel.replay)))
    return 200, _wrap(channel, envelope), headers


def _take_headers(channel: Channel) -> dict:
    out: dict = {}
    if channel.pending_set_cookie:
        out["Set-Cookie"] = channel.pending_set_cookie
        channel.pending_set_cookie = ""
    return out


def _wrap(channel: Channel, payload: dict) -> dict:
    return seal(channel, payload)


def drop_user_channels(username: str, reason: str = "password_change") -> int:
    """丢弃某个用户名的**全部**已认证信道（改密/登出全设备时用）。返回丢弃条数。"""
    dropped = 0
    for ch in list(channels.all()):
        if ch.username == username:
            channels.drop(ch.ch)
            dropped += 1
    if dropped:
        audit.log("channel.revoked", target_type="channel", target_label=username,
                  actor=username, detail={"count": dropped, "reason": reason})
    return dropped


def trusted_for_cookie(ip: str) -> bool:
    """是否允许在这个来源上下发明文会话 cookie。

    cookie 是 **bearer 凭据**：在明文 HTTP 上只要被嗅探到就能被用于接管管理权限
    （审查复现：拿 cookie → 自建信道 → 读 CSRF → 改设置）。因此只允许两种"可信传输"：
      * 已启用 TLS（cookie 还会带 Secure）；
      * 客户端来自回环（本机 / SSH 隧道 —— 隧道流量在服务端看就是 127.0.0.1）。
    其它情况（非回环 + 明文）**不下发 cookie**：这种部署方式本身就不受支持，
    必须改用 --loopback + SSH 隧道，或 CA_TLS=on。
    """
    if config.TLS_ENABLED:
        return True
    return security.is_loopback_ip(ip)


def _bind_login(channel: Channel, username: str, ip: str = "",
                user_agent: str = "") -> str:
    """信道内登录成功：绑定信道身份；仅可信传输才下发会话 cookie（跨页面有效）。"""
    channel.username = username
    channel.login_epoch = security.credential_epoch()   # 改密后纪元 +1 → 旧信道失效
    if not channel.csrf:
        channel.csrf = secrets.token_urlsafe(24)
    src_ip = ip or channel.ip
    if trusted_for_cookie(src_ip):
        try:
            sess = security.sessions.create(username, src_ip, user_agent or "")
            # 让信道与会话共用一个 CSRF 令牌，前端只需要记一个值
            sess.csrf = channel.csrf
            channel.pending_set_cookie = security.cookie(
                config.SESSION_COOKIE, sess.sid, max_age=config.SESSION_TTL,
                secure=config.TLS_ENABLED)
        except Exception:  # noqa: BLE001 - 会话创建失败不应导致登录失败（信道仍可用）
            pass
    else:
        # 明文 + 非回环：绝不下发明文 bearer cookie（会破坏整套加密信道的意义）
        _log_once_untrusted(src_ip)
    audit.log("auth.login", target_type="user", target_label=username, actor=username,
              detail={"ip": src_ip, "channel": True, "cookie": trusted_for_cookie(src_ip),
                      "user_agent": (user_agent or "")[:120]})
    return channel.csrf


_UNTRUSTED_LOGGED = False


def _log_once_untrusted(ip: str) -> None:
    """明文 + 非回环时告警一次（写日志，便于现场发现部署方式不对）。"""
    global _UNTRUSTED_LOGGED
    if _UNTRUSTED_LOGGED:
        return
    _UNTRUSTED_LOGGED = True
    try:
        import sys as _sys
        _sys.stderr.write(
            f"[{x509util.to_iso(x509util.now())}] [安全] 明文 HTTP + 非回环来源({ip}) "
            f"登录成功，但**不下发会话 cookie**（明文 cookie 可被嗅探后用于接管管理权限）。"
            f"请改用 --loopback + SSH 隧道，或设置 CA_TLS=on。\n")
        _sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass


def _bind_logout(channel: Channel) -> None:
    username = channel.username
    channel.username = None
    channel.csrf = secrets.token_urlsafe(24)
    if username:
        audit.log("auth.logout", target_type="user", target_label=username, actor=username,
                  detail={"ip": channel.ip, "channel": True})


# ---------------------------------------------------------------- 明文 REST 门禁
def legacy_allowed(ip: str) -> bool:
    mode = config.LEGACY_API
    if mode in ("off", "0", "false", "no"):
        return False
    if mode == "on":
        return True
    return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def enforce_legacy(ip: str) -> None:
    if legacy_allowed(ip):
        return
    raise ApiError(
        403,
        "本站的明文 REST 接口已关闭，请通过界面访问（界面使用应用层加密信道传输，"
        "口令与私钥不会以明文出现在网络上）。运维如需本机调试，请在服务器上用 "
        "http://127.0.0.1:%d 访问，或设置 CA_LEGACY_API=on。" % config.PORT)
