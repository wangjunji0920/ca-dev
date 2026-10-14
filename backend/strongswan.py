"""strongSwan 集成：本系统的服务对象。

本系统的证书就是给 strongSwan（IKEv2，证书认证 / EAP-TLS）用的，因此这里把
strongSwan 侧的“正确做法”固化下来，避免手工拼配置出错：

1. **身份标识（IKEv2 id）必须出现在 SAN 里**。strongSwan 用对端证书的 SAN 匹配
   ``local.id`` / ``remote.id``，只看 CN 是不够的。本模块把用户填写的 VPN 身份
   自动映射成正确的 SAN 类型：
      * FQDN  ``vpn1.example.com``  -> dNSName
      * 邮箱  ``user@example.com``  -> rfc822Name（并附加 MS UPN otherName，兼容 Windows）
      * IP    ``10.9.9.9``         -> iPAddress
2. **EKU**：客户端 clientAuth（+ ipsecIKE），网关 serverAuth（+ ipsecIKE）。
3. **CRL 分发点**：证书里写入 CDP，对端可通过 HTTP 自动拉取 CRL（本系统提供公开端点）。
4. **文件落位**：按 strongSwan 约定生成拷贝脚本
   （x509/ 证书、private/ 私钥、x509ca/ CA、x509crl/ CRL），并调用
   ``swanctl --load-creds`` / ``swanctl --load-conns``。
5. **一键部署包**：把证书、私钥、CA、CRL、swanctl.conf 片段、安装脚本、说明打包成 ZIP。
"""
from __future__ import annotations

import io
import ipaddress
import os
import zipfile
from pathlib import Path

from . import ca, config, db, publish, x509util
from .x509util import CertError

DEFAULT_GATEWAY = "vpn.example.com"
CLIENT_ROLES = ("client", "gateway")


# ---------------------------------------------------------------- 身份 → SAN
def identity_sans(identity: str, kind: str = "auto") -> list[dict[str, str]]:
    """把 IKEv2 身份标识转换成 SAN 条目（strongSwan 靠 SAN 匹配 id）。"""
    identity = (identity or "").strip()
    if not identity:
        return []
    kind = (kind or "auto").lower()
    if kind == "auto":
        try:
            ipaddress.ip_address(identity)
            kind = "ip"
        except ValueError:
            kind = "email" if "@" in identity else "dns"
    if kind not in ("dns", "email", "ip", "upn", "uri"):
        raise CertError(f"不支持的 VPN 身份类型: {kind}")
    out = [{"type": kind, "value": identity}]
    if kind == "email":
        # 同时写入 MS UPN，兼容 Windows 客户端与部分网关配置
        out.append({"type": "upn", "value": identity})
    return out


def merge_sans(existing: list[dict], extra: list[dict]) -> list[dict]:
    seen = {(s.get("type"), s.get("value")) for s in existing or []}
    out = list(existing or [])
    for item in extra or []:
        key = (item.get("type"), item.get("value"))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


# ---------------------------------------------------------------- 配置片段
SNIPPET_CLIENT = """# strongSwan 客户端配置（swanctl）
# 放到 /etc/swanctl/conf.d/{slug}.conf，然后执行：
#   sudo swanctl --load-creds && sudo swanctl --load-conns
connections {{
    {slug} {{
        version = 2
        local_addrs = %any
        remote_addrs = {gateway}
        proposals = aes256-sha256-prfsha256-modp2048

        local {{
            auth = eap-tls
            id = {identity}
            certs = {cert_file}
            # EAP-TLS 用证书认证，这里填证书里的身份（需与 SAN 一致）
            eap_id = {identity}
        }}
        remote {{
            auth = pubkey
            id = {gateway}
            cacerts = {ca_file}
        }}

        children {{
            {slug}-net {{
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256gcm16-prfsha256-ecp256
                start_action = trap
                dpd_action = restart
            }}
        }}
        dpd_delay = 30s
        rekey_time = 4h
    }}
}}
"""

SNIPPET_GATEWAY = """# strongSwan 网关（服务端）配置片段（swanctl）
# 放到 /etc/swanctl/conf.d/{slug}.conf，然后执行：
#   sudo swanctl --load-creds && sudo swanctl --load-conns
connections {{
    {slug} {{
        version = 2
        local_addrs = %any
        proposals = aes256-sha256-prfsha256-modp2048

        local {{
            auth = pubkey
            id = {identity}
            certs = {cert_file}
        }}
        remote {{
            auth = eap-tls
            cacerts = {ca_file}
        }}

        pools {{
            {slug}_pool {{
                addrs = 10.10.0.0/24
                dns = 1.1.1.1
            }}
        }}

        children {{
            {slug}-net {{
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                esp_proposals = aes256gcm16-prfsha256-ecp256
            }}
        }}
        dpd_delay = 30s
        rekey_time = 4h
    }}
}}
"""

GATEWAY_NOTES = """# 网关侧还需要（/etc/strongswan.d/charon/ 或 strongswan.conf）确认吊销检查已启用：
#
#   charon {
#       plugins {
#           revocation {
#               # 默认同时使用 CRL 与 OCSP；只为 CRL 时可关掉 ocsp：
#               # ocsp = no
#           }
#       }
#   }
#
# CA 证书放 /etc/swanctl/x509ca/，CRL 放 /etc/swanctl/x509crl/，
# 对端证书放 /etc/swanctl/x509/，私钥放 /etc/swanctl/private/（权限 0600）。
# 本系统的「CRL 自动发布」会把 CA 与 CRL 自动同步进这两个目录并在吊销后自动
# 执行 swanctl --load-creds，所以网关不需要人工维护 CRL 文件。
"""


# ---------------------------------------------------------------- 状态
def status() -> dict:
    detected = publish.detect_strongswan()
    st = publish.status()
    ca_row = ca.active_ca_row()
    vpn_certs = db.q(
        "SELECT * FROM certs WHERE status='valid' AND (profile LIKE 'strongswan%' "
        "OR profile='vpn_client' OR eku_json LIKE '%ipsecIKE%' OR eku_json LIKE '%clientAuth%') "
        "ORDER BY id DESC LIMIT 200")
    crl_url = (db.get_setting("crl_url") or "").strip()
    return {
        "strongswan": detected,
        "crl_health": st["health"],
        "crl_due_in_hours": st["due_in_hours"],
        "auto_publish": st["auto_publish"],
        "publish_targets": st["enabled_targets"],
        "ca": ca.ca_to_dict(ca_row) if ca_row else None,
        "crl_url": crl_url,
        "public_crl_path": f"/crl/ca-{ca_row['id']}.crl" if ca_row else "/crl/current.crl",
        "vpn_cert_count": len(vpn_certs),
        "vpn_certs": [ca.cert_to_dict(r) for r in vpn_certs[:20]],
        "profiles": [t for t in __import__("backend.rules", fromlist=["x"]).template_view()
                     if str(t.get("purpose") or "").startswith("vpn")],
    }


# ---------------------------------------------------------------- 安装脚本
INSTALL_SCRIPT = """#!/usr/bin/env bash
# 由 CA 管理系统自动生成：把证书/私钥/CA/CRL 安装到 strongSwan 并生效。
# 用法： sudo ./install-strongswan.sh
set -euo pipefail

# ---- strongSwan 目录布局（swanctl 默认配置） ----
SWANCTL_DIR="${{SWANCTL_DIR:-/etc/swanctl}}"
X509_DIR="$SWANCTL_DIR/x509"
PRIV_DIR="$SWANCTL_DIR/private"
CA_DIR="$SWANCTL_DIR/x509ca"
CRL_DIR="$SWANCTL_DIR/x509crl"
CONF_DIR="$SWANCTL_DIR/conf.d"

if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行： sudo $0" >&2
  exit 1
fi

install -d -m 0755 "$X509_DIR" "$CA_DIR" "$CRL_DIR" "$CONF_DIR"
install -d -m 0700 "$PRIV_DIR"

# 证书（公钥）
{cert_install}
# 私钥（仅 root 可读）
{key_install}
# CA 证书与 CRL
{ca_install}
# 连接配置
install -m 0644 "{slug}.conf" "$CONF_DIR/{slug}.conf"

echo "==> 重新加载 strongSwan 凭据与连接"
if command -v swanctl >/dev/null 2>&1; then
  swanctl --load-creds
  swanctl --load-conns
  swanctl --list-certs 2>/dev/null | head -20 || true
  swanctl --list-certs 2>/dev/null | head -20 || true
elif command -v ipsec >/dev/null 2>&1; then
  ipsec rereadcerts
  ipsec rereadcrls
  ipsec reload
else
  echo "未找到 swanctl / ipsec，请手动重载 strongSwan" >&2
fi
# 按现场要求：同时 reload strongSwan 服务（失败不阻断）
systemctl reload strongswan 2>/dev/null || true

echo "==> 完成。可用 'swanctl --list-sas' 查看隧道状态。"
"""


def _install_line(src: str, dst_dir: str, mode: str, name: str | None = None) -> str:
    return f'install -m {mode} "{src}" "{dst_dir}/{(name or src)}"'


def _resolve_gateway(role: str, row: dict | None, explicit: str | None) -> str:
    """确定配置片段里的对端网关地址。

    * 客户端：用「设置 → VPN 网关地址」，没配就用占位符
      （绝不能拿客户端自己的 SAN 当网关地址，那是它自己）；
    * 网关：它自己，取证书里的 DNS SAN。
    """
    if explicit and explicit.strip():
        return explicit.strip()
    setting = (db.get_setting("vpn_gateway") or "").strip()
    if setting:
        return setting
    if role == "gateway" and row is not None:
        dns = next((s["value"] for s in db.json_load(row["sans_json"], [])
                    if s.get("type") == "dns"), "")
        if dns:
            return dns
    return DEFAULT_GATEWAY


def _resolve_identity(row: dict | None, explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    if row is None:
        return "vpn-client"
    sans = db.json_load(row["sans_json"], [])
    return next((s["value"] for s in sans if s.get("type") in ("dns", "email", "ip")),
                row["cn"] or "vpn-client")


def build_bundle(cert_id: int, *, password: str | None = None, gateway: str | None = None,
                 role: str | None = None, eap_identity: str | None = None) -> tuple[bytes, str]:
    """生成 strongSwan 一键部署包（ZIP）。返回 (字节, 文件名)。"""
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    if row is None:
        raise CertError("证书不存在")
    ca_row = ca.get_ca(row["ca_id"]) if row["ca_id"] else ca.active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA")

    cert = x509util.load_cert(ca._path(row["cert_path"]).read_bytes())
    cn = row["cn"] or "cert"
    slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in cn)[:40] or "vpn"
    ca_name = (ca_row["cn"] or "ca")
    ca_slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in ca_name)[:40] or "ca"

    role = (role or ("gateway" if row["profile"] == "strongswan_gateway" else "client")).lower()
    if role not in CLIENT_ROLES:
        raise CertError("role 只能是 client 或 gateway")

    identity = _resolve_identity(row, eap_identity)
    gateway = _resolve_gateway(role, row, gateway)

    cert_file = f"{slug}.crt.pem"
    key_file = f"{slug}.key.pem"
    ca_file = f"{ca_slug}.crt.pem"
    crl_files = [f"{ca_slug}.crl.pem", f"{ca_slug}.crl"]

    cert_pem = x509util.pem_cert(cert)
    ca_pem = ca._path(ca_row["cert_path"]).read_text()
    key_pem = None
    if row["key_path"] and ca._path(row["key_path"]).exists():
        key_pem = ca._path(row["key_path"]).read_text()

    crl_pem = crl_der = None
    crl = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if crl is not None:
        p = config.DATA_DIR / crl["path"]
        d = config.DATA_DIR / crl["der_path"]
        crl_pem = p.read_text() if p.exists() else None
        crl_der = d.read_bytes() if d.exists() else None

    template = SNIPPET_GATEWAY if role == "gateway" else SNIPPET_CLIENT
    snippet = template.format(slug=slug, gateway=gateway, identity=identity,
                              cert_file=cert_file, ca_file=ca_file)
    if role == "gateway":
        snippet += "\n" + GATEWAY_NOTES

    script = INSTALL_SCRIPT.format(
        slug=slug,
        cert_install=_install_line(cert_file, "$X509_DIR", "0644"),
        key_install=(_install_line(key_file, "$PRIV_DIR", "0600") if key_pem
                     else 'echo "（本次部署包不含私钥，私钥请从签发时的下载保存）"'),
        ca_install="\n".join([
            _install_line(ca_file, "$CA_DIR", "0644"),
            *([f'if [ -f "{f}" ]; then install -m 0644 "{f}" "$CRL_DIR/{f}"; fi'
               for f in crl_files] if crl_pem else
              ['echo "（尚未生成 CRL，请在管理界面生成并发布）"']),
        ]),
    )

    readme = _bundle_readme(row, ca_row, role, gateway, identity, cert_file, key_file, ca_file,
                            crl_pem is not None, crl_pem is not None and row["key_path"])

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{cert_file}", cert_pem)
        if key_pem:
            zf.writestr(f"{key_file}", key_pem)
        zf.writestr(f"{ca_file}", ca_pem)
        if crl_pem:
            zf.writestr(f"{ca_slug}.crl.pem", crl_pem)
        if crl_der:
            zf.writestr(f"{ca_slug}.crl", crl_der)
        zf.writestr(f"{slug}.conf", snippet)
        zf.writestr("install-strongswan.sh", script)
        zf.writestr("README.txt", readme)
        if password and key_pem:
            key = x509util.load_key(key_pem.encode())
            blob = x509util.make_pkcs12(key, cert, [x509util.load_cert(ca_pem.encode())],
                                       password)
            zf.writestr(f"{slug}.p12", blob)
    return buf.getvalue(), f"strongswan-{slug}-{role}.zip"


def _bundle_readme(row: dict, ca_row: dict, role: str, gateway: str, identity: str,
                   cert_file: str, key_file: str, ca_file: str, has_crl: bool,
                   has_key: bool) -> str:
    crl_url = (db.get_setting("crl_url") or "").strip() or "(未设置，请在「设置」里填写 CRL 分发点 URL)"
    lines = [
        "strongSwan 证书部署包",
        "=" * 60,
        f"证书主题   : {row['subject']}",
        f"序列号     : {row['serial_hex']}",
        f"有效期至   : {row['not_after']}",
        f"用途       : {'VPN 网关（服务端）' if role == 'gateway' else 'VPN 客户端'}",
        f"对端/网关  : {gateway}",
        f"IKEv2 身份 : {identity}（必须与证书 SAN 一致，strongSwan 用 SAN 匹配 id）",
        f"CA 主题    : {ca_row['subject']}",
        f"CRL 已在包内: {'是' if has_crl else '否（请先生成 CRL）'}",
        f"包含私钥   : {'是' if has_key else '否（本系统未保存该证书的私钥）'}",
        "",
        "文件说明",
        "-" * 60,
        f"{cert_file}      证书（放到 /etc/swanctl/x509/）",
        f"{key_file}       私钥（放到 /etc/swanctl/private/，权限 0600）",
        f"{ca_file}       CA 证书（放到 /etc/swanctl/x509ca/）",
        "*.crl / *.crl.pem   吊销列表（放到 /etc/swanctl/x509crl/）",
        "*.conf              strongSwan 连接配置片段（放到 /etc/swanctl/conf.d/）",
        "install-strongswan.sh  一键安装脚本（root 执行）",
        "",
        "部署步骤",
        "-" * 60,
        "1) 把本包解压到目标主机任意目录（例如 /tmp/vpn/）",
        "2) 执行： sudo ./install-strongswan.sh",
        "3) 查看状态： sudo swanctl --list-certs  /  sudo swanctl --list-sas",
        "",
        "CRL 自动化",
        "-" * 60,
        f"CRL 分发点(CDP): {crl_url}",
        "管理系统的「CRL 自动发布」会在 CRL 到期前自动续签，并把 CRL 与 CA 证书同步到",
        "strongSwan 目录后执行 swanctl --load-creds，因此网关无需人工维护 CRL。",
        "若目标主机不在本机，可在发布目标里用 command 类型配合 scp/rsync 推送。",
    ]
    if not has_key:
        lines += ["", "注意：本证书是导入的历史证书，系统未保存私钥；如需私钥请从原签发处获取。"]
    return "\n".join(lines) + "\n"


def snippet_for(cert_id: int | None = None, *, role: str | None = None,
                gateway: str | None = None, identity: str | None = None) -> dict:
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,)) if cert_id else None
    ca_row = (ca.get_ca(row["ca_id"]) if row and row["ca_id"] else ca.active_ca_row())
    cn = (row["cn"] if row else (ca_row["cn"] if ca_row else "vpn-client")) or "vpn-client"
    slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in cn)[:40] or "vpn"
    ca_name = ((ca_row["cn"] if ca_row else "ca") or "ca")
    ca_slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in ca_name)[:40] or "ca"
    role = (role or "client").lower()
    identity = _resolve_identity(row, identity)
    gateway = _resolve_gateway(role, row, gateway)
    template = SNIPPET_GATEWAY if role == "gateway" else SNIPPET_CLIENT
    text = template.format(slug=slug, gateway=gateway, identity=identity,
                           cert_file=f"{slug}.crt.pem", ca_file=f"{ca_slug}.crt.pem")
    if role == "gateway":
        text += "\n" + GATEWAY_NOTES
    return {"snippet": text, "slug": slug, "cert_file": f"{slug}.crt.pem",
            "ca_file": f"{ca_slug}.crt.pem", "role": role, "identity": identity,
            "gateway": gateway}


# ---------------------------------------------------------------- 外部同步脚本
SYNC_SCRIPT = """#!/usr/bin/env bash
# 由 CA 管理系统生成：把管理系统的“发布暂存目录”同步给 strongSwan 并重载。
# 适用于管理服务以普通用户运行、没有权限直接写 /etc/swanctl 的场景。
# 用法（root）：  sudo /usr/local/sbin/ca-strongswan-sync.sh
#
# 关键行为：**内容没有变化就不重载**，避免反复 reload strongSwan。
set -euo pipefail
STAGING="{staging}"
SWANCTL_DIR="${{SWANCTL_DIR:-/etc/swanctl}}"

if [ "$(id -u)" != "0" ] && [ "${{CA_ALLOW_NONROOT:-0}}" != "1" ]; then
  echo "请用 root 运行" >&2; exit 1
fi
install -d -m 0755 "$SWANCTL_DIR/x509ca" "$SWANCTL_DIR/x509crl"

# 按内容/扩展名判定是 CRL 还是 CA 证书：
# 支持 crl.der、<ca>.crl、<ca>.crl.pem、<ca>.crt.pem 等任意命名
classify() {{
  f="$1"; base="$(basename "$f")"
  if head -c 64 "$f" 2>/dev/null | grep -q "BEGIN X509 CRL"; then echo x509crl; return; fi
  if head -c 64 "$f" 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then echo x509ca; return; fi
  case "$base" in
    *.crl|*.crl.pem|*.der) echo x509crl ;;
    *.crt|*.crt.pem|*.pem)  echo x509ca ;;
    *) echo "" ;;
  esac
}}

reload_needed=0
copied=0
for f in "$STAGING"/*; do
  [ -f "$f" ] || continue
  sub="$(classify "$f")"
  [ -n "$sub" ] || continue
  base="$(basename "$f")"
  target="$SWANCTL_DIR/$sub/$base"
  if [ ! -f "$target" ] || ! cmp -s "$f" "$target"; then reload_needed=1; fi
  install -m 0644 "$f" "$target"
  copied=$((copied + 1))
done

if [ "$copied" = "0" ]; then
  echo "暂存目录里没有 CRL/CA 文件：$STAGING" >&2
  exit 0
fi
if [ "$reload_needed" = "0" ]; then
  echo "CRL/CA 内容未变化，跳过重载（$(date -Is)）"
  exit 0
fi

if command -v swanctl >/dev/null 2>&1; then
  swanctl --flush-certs
  swanctl --load-creds
fi
# 按现场约定重启 strongSwan 服务，确保吊销判定采用新 CRL
systemctl restart strongswan
echo "已同步 CRL/CA 至 $SWANCTL_DIR 并重载 strongSwan: $(date -Is)"
"""


def sync_script() -> str:
    ca_row = ca.active_ca_row()
    ca_slug = "example-ca"
    if ca_row:
        ca_slug = "".join(ch if ch.isalnum() or ch in "-_" else "-"
                          for ch in (ca_row["cn"] or "ca"))[:40] or "ca"
    return SYNC_SCRIPT.format(staging=publish.STAGING_DIR, ca_slug=ca_slug)


def inspect_crl_files(dir_path: str | None = None) -> dict:
    """扫描 strongSwan 的 CRL 目录，找出**本 CA 的每一份 CRL** 及其编号。

    为什么必须查这个：charon 会把目录里出现过的所有 CRL 都加载，但**同一签发者只保留
    编号最大的那一份**（日志里的 "crl #09 is newer - existing crl #08 replaced"）。
    所以目录里只要残留一份编号更大的旧 CRL，我们新发布的吊销就**永远不会生效**，
    表现为"吊销了、也 reload 了，但对方重连依然能过"（现场踩过：目录里有 3 份 CRL）。
    """
    cfg = publish.swanctl_settings()
    directory = Path(os.path.expandvars(os.path.expanduser(
        dir_path or cfg["crl_dir"] or "/etc/swanctl/x509crl")))
    out: dict = {"dir": str(directory), "exists": directory.is_dir(), "ours": [],
                 "others": [], "errors": [], "our_subject": None}
    row = ca.active_ca_row()
    if row:
        out["our_subject"] = row["subject"]
    if not out["exists"]:
        return out
    try:
        files = sorted(p for p in directory.iterdir() if p.is_file() and not p.name.startswith("."))
    except OSError as exc:
        out["errors"].append(f"{directory}: {exc}")
        return out
    for p in files:
        try:
            blob = p.read_bytes()
            crl = x509util.load_crl(blob)
        except Exception:  # noqa: BLE001 - 不是 CRL（可能是证书/其它文件）就跳过
            continue
        info = x509util.crl_info(crl)
        item = {"file": p.name, "path": str(p), "issuer": info["issuer"],
                "number": info["number"], "count": info["count"],
                "next_update": info["next_update"], "sha256": x509util.sha256_hex(blob)}
        if out["our_subject"] and info["issuer"] == out["our_subject"]:
            out["ours"].append(item)
        else:
            out["others"].append(item)
    out["ours"].sort(key=lambda i: (i["number"] if isinstance(i["number"], int) else -1))
    out["max_number"] = max((i["number"] for i in out["ours"]
                            if isinstance(i["number"], int)), default=None)
    return out


def inspect_ca_certs(dir_path: str | None = None) -> dict:
    """扫描 strongSwan 的 x509ca 目录：是否有**多张 subject 相同但指纹不同**的 CA 证书。

    这是"吊销不生效"的隐形元凶：charon 按**签发者名字**索引 CRL，只保留编号最大的那份。
    如果存在两个同名 CA（各自签发了证书、各自发布同 subject 的 CRL），
    那么对其中一张 CA 的吊销就可能被另一张 CA 的 CRL 遮蔽 —— 客户端重连照样通过。
    """
    cfg = publish.swanctl_settings()
    directory = Path(os.path.expandvars(os.path.expanduser(
        dir_path or cfg["ca_dir"] or "/etc/swanctl/x509ca")))
    out: dict = {"dir": str(directory), "exists": directory.is_dir(),
                 "certs": [], "duplicate_subjects": [], "errors": []}
    if not out["exists"]:
        return out
    try:
        files = sorted(p for p in directory.iterdir() if p.is_file() and not p.name.startswith("."))
    except OSError as exc:
        out["errors"].append(f"{directory}: {exc}")
        return out
    by_subject: dict[str, list[dict]] = {}
    for p in files:
        try:
            cert = x509util.load_cert(p.read_bytes())
        except Exception:  # noqa: BLE001 - 非证书文件跳过
            continue
        item = {"file": p.name, "subject": x509util.name_to_str(cert.subject),
                "fingerprint": x509util.fingerprint(cert),
                "not_after": x509util.to_iso(getattr(cert, "not_valid_after_utc", None)
                                             or cert.not_valid_after)}
        out["certs"].append(item)
        by_subject.setdefault(item["subject"], []).append(item)
    for subject, items in by_subject.items():
        fps = {i["fingerprint"] for i in items}
        if len(fps) > 1:
            out["duplicate_subjects"].append({"subject": subject,
                                              "files": [i["file"] for i in items],
                                              "fingerprints": sorted(fps)})
    return out
