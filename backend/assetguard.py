"""前端资源完整性：算指纹、以及"拿本地可信副本去核对线上实际拿到的字节"。

为什么需要它
------------
本系统按现场要求在**纯 HTTP** 上跑，加密是应用层自建的（`frontend/crypto.js`）。
但"加密代码本身"也是通过同一个 HTTP 通道发给浏览器的，所以**主动中间人**可以把
`crypto.js` 换成自己的版本，从而偷口令/伪造操作。纯客户端手段无法自证清白
（自证的那段代码本身也可能是被换过的）。

因此这里提供**带外核对（out-of-band）**能力：

  1) 在服务器上（经 SSH，可信）打印每个前端文件的 SHA-256 与一个短的"资源指纹"；
  2) 在**你自己的机器**上，用你从**可信渠道**（scp/tarball）拿到的同一份代码，
     去核对服务器实际返回的字节：
        ca asset-hash --check-url http://your-server:9443
     期望值来自本地可信副本，实际值来自线上的字节；两者一致才说明没有被篡改。
     注意：**必须在你自己的机器上跑**（或在任何"本地副本可信、但网络不可信"的位置），
     在服务器本机跑 `--check-url` 只能验证回环，不能验证你那条网络路径。
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

from . import config

# 浏览器会加载的全部前端资源（任何一项被改都算篡改）
ASSETS = ("index.html", "login.html", "app.js", "crypto.js", "login.js",
          "theme-boot.js", "style.css", "vendor/tweetnacl.min.js", "favicon.svg")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hashes(root: Path | None = None) -> dict[str, str]:
    """计算前端资源哈希（默认对交付目录里的文件）。缺失的文件记为 "missing"。"""
    base = Path(root) if root is not None else (config.BASE_DIR / "frontend")
    out: dict[str, str] = {}
    for rel in ASSETS:
        path = base / rel
        try:
            out[rel] = _sha256(path.read_bytes())
        except OSError:
            out[rel] = "missing"
    return out


def fingerprint(hashes: dict[str, str] | None = None) -> str:
    """把全部资源哈希压成一个便于核对的短指纹，形如 A1B2-C3D4-E5F6-7890。"""
    hashes = hashes if hashes is not None else file_hashes()
    joined = "\n".join(f"{k}:{v}" for k, v in sorted(hashes.items()))
    digest = _sha256(joined.encode()).upper()
    short = digest[:16]
    return "-".join(short[i:i + 4] for i in range(0, 16, 4))


GATED = "gated:login"   # 未登录时 /index.html 被认证门禁替换为登录页（正常行为）


def fetch_hashes(base_url: str, timeout: float = 10.0, cookie: str | None = None,
                 expect: dict[str, str] | None = None) -> dict[str, str]:
    """从运行中的服务取回各前端资源的**实际字节**并就地算哈希。

    未登录访问 /index.html（或 /）时，服务会返回**登录页**——这是设计如此
    （认证门禁），不是篡改。这里把它识别为 GATED 并单独说明；
    带上会话 cookie 再跑一次即可核对真正的 SPA 外壳。
    """
    base = base_url.rstrip("/")
    out: dict[str, str] = {}
    for rel in ASSETS:
        url = f"{base}/{rel}"
        headers = {"Cache-Control": "no-cache"}
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                digest = _sha256(body)
                if rel == "index.html" and not cookie and expect is not None:
                    # 门禁把外壳换成了登录页：识别出来，不当作篡改
                    if digest == expect.get("login.html"):
                        digest = GATED
                out[rel] = digest
        except urllib.error.HTTPError as exc:
            out[rel] = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            out[rel] = f"error: {type(exc).__name__}"
    return out


def compare(expected: dict[str, str], actual: dict[str, str]) -> dict:
    """逐项比较；返回可以直接展示/JSON 化的结果。"""
    diffs, notes = [], []
    for rel in ASSETS:
        exp, act = expected.get(rel, "missing"), actual.get(rel, "missing")
        if exp == act:
            continue
        if act == GATED:
            notes.append(f"{rel}: 未登录时被认证门禁替换为登录页（正常）；"
                         f"如需核对外壳请带会话 cookie 重跑")
            continue
        diffs.append({"file": rel, "expected": exp, "actual": act})
    return {
        "ok": not diffs,
        "expected_fingerprint": fingerprint(expected),
        # 指纹只对有实际哈希的项计算（门禁项不参与）
        "actual_fingerprint": fingerprint({k: v for k, v in actual.items() if v != GATED}),
        "checked": list(ASSETS),
        "notes": notes,
        "diffs": diffs,
    }


def report(root: Path | None = None, check_url: str | None = None,
           cookie: str | None = None) -> dict:
    """给 CLI/doctor 用的汇总：本地(或指定目录)哈希 + 可选与线上字节对比。"""
    local = file_hashes(root)
    out: dict = {"root": str(root) if root else str(config.BASE_DIR / "frontend"),
                 "files": local, "fingerprint": fingerprint(local)}
    if check_url:
        actual = fetch_hashes(check_url, cookie=cookie, expect=local)
        out["check_url"] = check_url
        out["remote"] = actual
        out["remote_fingerprint"] = fingerprint(actual)
        out["compare"] = compare(local, actual)
    return out


def as_text(info: dict) -> str:
    lines = [f"前端资源目录: {info['root']}", "", "文件                                         SHA-256"]
    for rel, digest in info["files"].items():
        lines.append(f"  {rel:<42} {digest}")
    lines += ["", f"资源指纹（与登录页/服务器日志核对）: {info['fingerprint']}"]
    cmp_ = info.get("compare")
    for note in (cmp_ or {}).get("notes", []) if cmp_ else []:
        lines.append(f"  · {note}")
    if cmp_ is not None:
        lines += ["", f"线上核对: {info.get('check_url')}",
                  f"  线上资源指纹: {info.get('remote_fingerprint')}"]
        if cmp_["ok"]:
            lines.append("  ✅ 一致：服务器返回的前端字节与本地可信副本完全相同（未被篡改）")
        else:
            lines.append("  ❌ 不一致：可能存在中间人篡改 / 版本不同 / 服务器侧文件被改")
            for d in cmp_["diffs"]:
                lines.append(f"     · {d['file']}\n         期望 {d['expected']}\n         实际 {d['actual']}")
    return "\n".join(lines)


def json_text(info: dict) -> str:
    return json.dumps(info, ensure_ascii=False, indent=2)
