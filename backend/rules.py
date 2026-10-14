"""规则集（Rule Set）：把“证书怎么签”全部变成**可编辑的数据**，而不是写死在代码里。

设计原则
--------
1. **零硬编码**：密钥算法、位数、摘要算法、有效期、KeyUsage/EKU、SAN 策略、CDP、
   自定义扩展、序列号策略、导出格式……全部来自规则集的 ``spec`` JSON。
   代码里只有“默认值”和“校验”，运行时不依赖任何 OpenSSL 配置文件或命令行。
2. **默认面向 strongSwan**：内置规则集里排在最前的是 strongSwan（IKEv2 / EAP-TLS）
   客户端与网关；它们的 SAN 策略、EKU、CRL 分发点都是按 strongSwan 的匹配规则设置的。
3. **考虑 Windows / Linux 差异**：``platform`` 字段区分平台，
   ``export`` 段决定导出什么（PEM 分离文件 / PKCS#12 / 两者），
   Windows 侧还会自动补 MS UPN 的 otherName SAN 并提示 certutil 导入方式，
   Linux/strongSwan 侧提示文件落位（x509、private 0600、x509ca、x509crl）与 swanctl 重载。
4. **可扩展**：规则集是通用容器，字段是开放 JSON；
   以后要给别的系统（邮件、代码签名、802.1X、签名网关……）加用途，
   只是再建一个规则集，不需要改代码。
5. **全部可改**：管理员可以对任意内置规则集直接编辑、复制、停用、删除；
   也可以限定哪些字段允许在签发时临时覆盖（``strict`` + ``overridable``）。

规则集结构（``spec``）
---------------------
``subject``     主题字段要求：必须哪些字段、CN 长度、CN 是否取自身份
``san``         身份/SAN 策略：是否必须、允许类型、从身份自动生成、邮箱补 UPN、CN 复制进 SAN
``key``         密钥与摘要：类型/位数/允许范围/摘要算法
``validity``    有效期：天数与上下限、notBefore 回溯分钟
``extensions``  KeyUsage / EKU / BasicConstraints / SKI / AKI / CDP / AIA / 自定义 OID
``serial``      序列号：随机位数或顺序
``revocation``  吊销策略：默认原因、是否允许吊销、是否自动发布 CRL
``export``      导出与平台差异：打包格式、私钥文件权限、平台安装提示
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from . import db, x509util
from .x509util import CertError

PLATFORMS = ("strongswan", "linux", "windows", "macos", "any")
BUNDLES = ("pem", "p12", "both")
DIGESTS = ("sha256", "sha384", "sha512", "sha1", "sha224")
SAN_TYPES = ("dns", "ip", "email", "upn", "uri", "othername")

# ------------------------------------------------------------------ 默认值
DEFAULT_SPEC: dict[str, Any] = {
    "subject": {
        "require_cn": True,
        "required_fields": ["CN"],
        "cn_from_identity": True,
        "max_cn_length": 64,
        "max_field_length": 128,
        "allow_empty_organization": True,
    },
    "san": {
        "required": False,
        "allowed_types": list(SAN_TYPES),
        "auto_from_identity": False,
        "add_upn_for_email": False,
        "copy_cn_if_fqdn": False,
        "max_entries": 20,
        "default_type": "dns",
    },
    "key": {
        "type": "rsa",
        "size": 2048,
        "allowed_types": ["rsa", "ec"],
        "min_rsa_size": 2048,
        "allowed_ec_sizes": [256, 384, 521],
        "digest": "sha256",
    },
    "validity": {
        "days": 365,
        "min_days": 1,
        "max_days": 3650,
        "not_before_skew_minutes": 5,
    },
    "extensions": {
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "eku": [],
        "basic_constraints_ca": False,
        "path_length": None,
        "subject_key_identifier": True,
        "authority_key_identifier": True,
        "crl_distribution_point": False,
        "crl_url": "",
        "ocsp_url": "",
        "custom": [],
    },
    "serial": {"mode": "random", "bits": 159},
    "revocation": {"allow_revoke": True, "default_reason": "unspecified",
                   "auto_publish_crl": True},
    "export": {
        "bundle": "pem",
        "key_file_mode": "0600",
        "require_p12_password": False,
        "windows_import_hint": "",
        "linux_install_hint": "",
        "extra_notes": "",
    },
    "strict": False,
    "overridable": [],
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def normalize(spec: dict | None) -> dict:
    return deep_merge(DEFAULT_SPEC, spec or {})


# ------------------------------------------------------------------ 内置规则集
def _base(**kw) -> dict:
    return kw


PLATFORM_HINTS = {
    "strongswan": {
        "linux_install_hint": "证书放 /etc/swanctl/x509/，私钥放 /etc/swanctl/private/（0600），"
                              "CA 放 /etc/swanctl/x509ca/，CRL 放 /etc/swanctl/x509crl/，"
                              "然后 swanctl --load-creds && swanctl --load-conns",
        "extra_notes": "strongSwan 用证书 SAN 匹配 IKEv2 身份（id），请确保 local.id/eap_id "
                       "与 SAN 完全一致；CRL 由本系统自动发布。",
    },
    "windows": {
        "windows_import_hint": "双击 .p12 导入「个人」存储，或在管理员命令行执行：\n"
                               "  certutil -importPFX -p <口令> <证书>.p12\n"
                               "智能卡/域登录场景需 UPN（otherName）SAN 且 EKU 含 clientAuth。",
        "extra_notes": "Windows 不读取本机文件形式的 CRL，吊销检查依赖证书里的 CDP/OCSP 地址，"
                       "因此务必设置 CRL 分发点 URL。",
    },
    "linux": {
        "linux_install_hint": "证书与私钥按服务要求放置，私钥权限 0600；"
                              "吊销检查需在客户端配置 CRL 文件或 CDP 地址。",
    },
    "macos": {"extra_notes": "导入钥匙串： security import <证书>.p12 -k login.keychain"},
    "any": {},
}


SEEDS: list[dict[str, Any]] = [
    {
        "slug": "strongswan-vpn-client",
        "name": "strongSwan VPN 客户端（IKEv2 / EAP-TLS）",
        "description": "strongSwan 客户端默认规则集：clientAuth + ipsecIKE，"
                       "身份写入 SAN（FQDN/邮箱/IP），含 CRL 分发点，825 天。",
        "platform": "strongswan", "purpose": "vpn-client", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "add_upn_for_email": True,
                 "copy_cn_if_fqdn": True, "allowed_types": ["dns", "email", "ip", "upn", "uri"],
                 "default_type": "dns", "max_entries": 20},
            key={"type": "rsa", "size": 2048, "allowed_types": ["rsa", "ec"],
                 "min_rsa_size": 2048, "allowed_ec_sizes": [256, 384], "digest": "sha256"},
            validity={"days": 825, "min_days": 1, "max_days": 3650,
                      "not_before_skew_minutes": 5},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth", "ipsecIKE"],
                        "crl_distribution_point": True,
                        "subject_key_identifier": True, "authority_key_identifier": True},
            export={"bundle": "both", "key_file_mode": "0600",
                    **PLATFORM_HINTS["strongswan"]},
            overridable=["validity.days", "key.type", "key.size", "san", "extensions.eku"],
        ),
    },
    {
        "slug": "strongswan-vpn-gateway",
        "name": "strongSwan VPN 网关（服务端）",
        "description": "strongSwan 服务端默认规则集：serverAuth + ipsecIKE，"
                       "SAN 必须填网关域名/公网 IP，含 CRL 分发点，825 天。",
        "platform": "strongswan", "purpose": "vpn-gateway", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "add_upn_for_email": False,
                 "copy_cn_if_fqdn": True, "allowed_types": ["dns", "ip", "uri"],
                 "default_type": "dns"},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 825, "max_days": 3650},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["serverAuth", "ipsecIKE"],
                        "crl_distribution_point": True},
            export={"bundle": "both", "key_file_mode": "0600",
                    **PLATFORM_HINTS["strongswan"]},
        ),
    },
    {
        "slug": "strongswan-vpn-client-ec",
        "name": "strongSwan VPN 客户端（EC P-256）",
        "description": "同 strongSwan 客户端，但使用 EC P-256 密钥，握手更快、报文更小。",
        "platform": "strongswan", "purpose": "vpn-client", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "add_upn_for_email": True,
                 "copy_cn_if_fqdn": True, "default_type": "dns"},
            key={"type": "ec", "size": 256, "allowed_types": ["ec"],
                 "allowed_ec_sizes": [256, 384, 521], "digest": "sha256"},
            validity={"days": 825},
            extensions={"key_usage": ["digitalSignature"], "eku": ["clientAuth", "ipsecIKE"],
                        "crl_distribution_point": True},
            export={"bundle": "both", "key_file_mode": "0600",
                    **PLATFORM_HINTS["strongswan"]},
        ),
    },
    {
        "slug": "windows-smartcard-upn",
        "name": "Windows 智能卡登录（UPN）",
        "description": "Windows 域登录/智能卡：CN 为显示名，身份用 UPN(otherName)，"
                       "EKU 含 clientAuth + msSmartcardLogin，导出 PKCS#12。",
        "platform": "windows", "purpose": "smartcard", "builtin": 1,
        "spec": _base(
            subject={"require_cn": True, "cn_from_identity": False, "max_cn_length": 64},
            san={"required": True, "allowed_types": ["upn", "dns", "email"],
                 "auto_from_identity": True, "add_upn_for_email": True,
                 "default_type": "upn"},
            key={"type": "rsa", "size": 2048, "min_rsa_size": 2048, "digest": "sha256"},
            validity={"days": 365, "max_days": 1095},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth", "msSmartcardLogin"],
                        "crl_distribution_point": True},
            export={"bundle": "p12", "require_p12_password": True, "key_file_mode": "0600",
                    **PLATFORM_HINTS["windows"]},
        ),
    },
    {
        "slug": "windows-user-vpn",
        "name": "Windows VPN 客户端（IKEv2）",
        "description": "Windows 内置 IKEv2 客户端：EKU clientAuth + ipsecIKE，"
                       "同时写 UPN 与 FQDN SAN，导出 PKCS#12 便于双击导入。",
        "platform": "windows", "purpose": "vpn-client", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "add_upn_for_email": True,
                 "copy_cn_if_fqdn": True, "allowed_types": ["upn", "dns", "email", "ip"]},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 825},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth", "ipsecIKE"],
                        "crl_distribution_point": True},
            export={"bundle": "both", "require_p12_password": True,
                    **PLATFORM_HINTS["windows"]},
        ),
    },
    {
        "slug": "linux-vpn-client",
        "name": "Linux / 通用 VPN 客户端",
        "description": "Linux 客户端（strongSwan/OpenVPN 等）：PEM 分离文件、私钥 0600、"
                       "SAN 填 FQDN，含 CRL 分发点。",
        "platform": "linux", "purpose": "vpn-client", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "copy_cn_if_fqdn": True,
                 "default_type": "dns"},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 825},
            extensions={"key_usage": ["digitalSignature"], "eku": ["clientAuth", "ipsecIKE"],
                        "crl_distribution_point": True},
            export={"bundle": "pem", "key_file_mode": "0600",
                    **PLATFORM_HINTS["linux"]},
        ),
    },
    {
        "slug": "server_tls",
        "name": "TLS 服务端证书（通用）",
        "description": "HTTPS/服务端身份认证，serverAuth，1 年，允许任意 SAN。",
        "platform": "any", "purpose": "tls-server", "builtin": 1,
        "spec": _base(
            san={"required": True, "allowed_types": ["dns", "ip", "uri"],
                 "copy_cn_if_fqdn": True},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 365},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["serverAuth"], "crl_distribution_point": True},
            export={"bundle": "pem", "key_file_mode": "0600"},
        ),
    },
    {
        "slug": "client_tls",
        "name": "TLS 客户端证书（通用 mTLS）",
        "description": "mTLS 客户端认证，clientAuth，1 年。",
        "platform": "any", "purpose": "tls-client", "builtin": 1,
        "spec": _base(
            san={"required": False, "allowed_types": list(SAN_TYPES)},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 365},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth"], "crl_distribution_point": True},
            export={"bundle": "pem", "key_file_mode": "0600"},
        ),
    },
    {
        "slug": "vpn_client",
        "name": "VPN / IPSec 客户端（兼容旧配置）",
        "description": "clientAuth + ipsecIKE，5 年；旧部署沿用，新部署建议切到 strongSwan 规则集。",
        "platform": "any", "purpose": "vpn-client", "builtin": 1,
        "spec": _base(
            san={"required": True, "auto_from_identity": True, "add_upn_for_email": True,
                 "copy_cn_if_fqdn": True, "default_type": "dns"},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 1825, "max_days": 3650},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth", "ipsecIKE"],
                        "crl_distribution_point": True},
            export={"bundle": "both", "key_file_mode": "0600"},
        ),
    },
    {
        "slug": "smartcard_upn",
        "name": "智能卡登录（UPN，兼容旧配置）",
        "description": "Windows 智能卡登录，含 UPN 与 msSmartcardLogin。",
        "platform": "windows", "purpose": "smartcard", "builtin": 1,
        "spec": _base(
            san={"required": True, "allowed_types": ["upn", "email"],
                 "auto_from_identity": True, "add_upn_for_email": True,
                 "default_type": "upn"},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 1825},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment"],
                        "eku": ["clientAuth", "msSmartcardLogin"],
                        "crl_distribution_point": True},
            export={"bundle": "p12", "require_p12_password": True, **PLATFORM_HINTS["windows"]},
        ),
    },
    {
        "slug": "code_signing",
        "name": "代码签名证书",
        "description": "签名软件包与脚本，codeSigning，3 年。",
        "platform": "any", "purpose": "code-signing", "builtin": 1,
        "spec": _base(
            san={"required": False},
            key={"type": "rsa", "size": 3072, "digest": "sha256"},
            validity={"days": 1095, "max_days": 1095},
            extensions={"key_usage": ["digitalSignature"], "eku": ["codeSigning"],
                        "crl_distribution_point": True},
            export={"bundle": "pem", "key_file_mode": "0600"},
        ),
    },
    {
        "slug": "email_smime",
        "name": "S/MIME 邮件证书",
        "description": "邮件加密与签名，emailProtection，SAN 用邮箱地址。",
        "platform": "any", "purpose": "smime", "builtin": 1,
        "spec": _base(
            san={"required": True, "allowed_types": ["email"], "auto_from_identity": True,
                 "default_type": "email"},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 1095},
            extensions={"key_usage": ["digitalSignature", "keyEncipherment",
                                      "dataEncipherment"],
                        "eku": ["emailProtection"], "crl_distribution_point": True},
            export={"bundle": "both", "key_file_mode": "0600"},
        ),
    },
    {
        "slug": "custom",
        "name": "自定义（不套用任何规则）",
        "description": "所有字段都手填，适合一次性/试验用途。",
        "platform": "any", "purpose": "custom", "builtin": 1,
        "spec": _base(
            san={"required": False, "allowed_types": list(SAN_TYPES)},
            key={"type": "rsa", "size": 2048, "digest": "sha256"},
            validity={"days": 365},
            extensions={"key_usage": ["digitalSignature"], "eku": []},
            export={"bundle": "pem", "key_file_mode": "0600"},
        ),
    },
]


# ------------------------------------------------------------------ 校验
def validate(spec: dict) -> dict:
    """校验规则集本身是否合法；返回规范化后的 spec。"""
    spec = normalize(spec)
    problems: list[str] = []

    key = spec["key"]
    if key.get("type") not in ("rsa", "ec", "ed25519"):
        problems.append(f"密钥类型只支持 rsa / ec / ed25519，收到 {key.get('type')}")
    if key.get("type") == "rsa":
        try:
            size = int(key.get("size") or 0)
            if not (1024 <= size <= 16384):
                problems.append("RSA 位数需在 1024~16384 之间")
            if size < int(key.get("min_rsa_size") or 2048):
                problems.append(f"RSA 位数低于该规则集要求的最小值 {key.get('min_rsa_size')}")
        except (TypeError, ValueError):
            problems.append("RSA 位数必须是整数")
    if key.get("type") == "ec":
        try:
            if int(key.get("size") or 0) not in [int(s) for s in key.get("allowed_ec_sizes") or []]:
                problems.append(f"EC 位数必须在 {key.get('allowed_ec_sizes')} 中")
        except (TypeError, ValueError):
            problems.append("EC 位数必须是整数")
    if key.get("digest") not in DIGESTS:
        problems.append(f"摘要算法必须是 {', '.join(DIGESTS)} 之一")

    val = spec["validity"]
    try:
        days = int(val.get("days") or 0)
        if not (int(val.get("min_days") or 1) <= days <= int(val.get("max_days") or 36500)):
            problems.append(f"有效期 {days} 天超出规则集范围 "
                            f"{val.get('min_days')}~{val.get('max_days')}")
    except (TypeError, ValueError):
        problems.append("有效期天数必须是整数")

    ext = spec["extensions"]
    valid_ku = {f for _a, f, _l in x509util.KEY_USAGE_FIELDS}
    bad_ku = [k for k in (ext.get("key_usage") or []) if k not in valid_ku]
    if bad_ku:
        problems.append(f"未知的 KeyUsage: {', '.join(bad_ku)}")
    bad_eku = [e for e in (ext.get("eku") or [])
               if e not in x509util.EKU_MAP and e.count(".") < 2]
    if bad_eku:
        problems.append(f"未知的 EKU: {', '.join(bad_eku)}（也可直接写 OID，如 1.3.6.1.5.5.7.3.17）")
    if ext.get("basic_constraints_ca"):
        problems.append("规则集用于签发终端实体证书，basic_constraints_ca 必须为 false"
                        "（如需签发子 CA，请直接导入 CA 证书）")
    for item in ext.get("custom") or []:
        if not item.get("oid") or not re.match(r"^\d+(\.\d+)+$", str(item["oid"])):
            problems.append(f"自定义扩展的 OID 非法: {item.get('oid')}")
        if (item.get("type") or "utf8") not in ("utf8", "hex", "der-base64", "int"):
            problems.append(f"自定义扩展 {item.get('oid')} 的编码类型不支持")
    for label, url in (("CRL 分发点", ext.get("crl_url")), ("OCSP 地址", ext.get("ocsp_url"))):
        if url and not str(url).startswith(("http://", "https://")):
            problems.append(f"{label} URL 必须以 http:// 或 https:// 开头")

    san = spec["san"]
    bad_san = [t for t in (san.get("allowed_types") or []) if t not in SAN_TYPES]
    if bad_san:
        problems.append(f"未知的 SAN 类型: {', '.join(bad_san)}")
    if san.get("default_type") not in SAN_TYPES:
        problems.append("SAN 默认类型非法")
    if int(san.get("max_entries") or 0) < 1:
        problems.append("SAN 最大条目数至少为 1")

    sub = spec["subject"]
    for field in sub.get("required_fields") or []:
        if field.upper() not in ("CN", "O", "OU", "C", "ST", "L", "EMAILADDRESS"):
            problems.append(f"主题必填字段不支持: {field}")
    if int(sub.get("max_cn_length") or 0) < 1:
        problems.append("CN 最大长度至少为 1")

    if spec["export"].get("bundle") not in BUNDLES:
        problems.append(f"导出格式必须是 {'/'.join(BUNDLES)} 之一")
    if spec["serial"].get("mode") not in ("random", "sequential"):
        problems.append("序列号模式只能是 random 或 sequential")
    try:
        bits = int(spec["serial"].get("bits") or 0)
        if not (64 <= bits <= 256):
            problems.append("随机序列号位数需在 64~256 之间")
    except (TypeError, ValueError):
        problems.append("随机序列号位数必须是整数")
    if spec["extensions"].get("path_length") not in (None, "",) and \
            not str(spec["extensions"]["path_length"]).isdigit():
        problems.append("path_length 必须是整数或留空")

    if problems:
        raise CertError("规则集不合法：" + "；".join(problems))
    return spec


def build_custom_extensions(spec: dict) -> list[tuple[x509.ExtensionType, bool]]:
    """把自定义 OID 扩展转成 cryptography 的扩展对象。"""
    out: list[tuple[x509.ExtensionType, bool]] = []
    for item in normalize(spec)["extensions"].get("custom") or []:
        oid = ObjectIdentifier(str(item["oid"]))
        kind = (item.get("type") or "utf8").lower()
        raw_value = str(item.get("value") or "")
        if kind == "utf8":
            der = x509util.der_utf8(raw_value)
        elif kind == "hex":
            der = bytes.fromhex(raw_value.replace(" ", "").replace(":", ""))
        elif kind == "der-base64":
            import base64
            der = base64.b64decode(raw_value)
        elif kind == "int":
            value = int(raw_value)
            raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            der = b"\x02" + (bytes([len(raw)]) if len(raw) < 128
                             else bytes([0x81, len(raw)])) + raw
        else:  # pragma: no cover - validate() 已拦截
            raise CertError(f"不支持的自定义扩展编码: {kind}")
        out.append((x509.UnrecognizedExtension(oid, der), bool(item.get("critical"))))
    return out


# ------------------------------------------------------------------ SAN 策略
def apply_san_policy(spec: dict, *, cn: str | None, sans: list[dict] | None,
                     identity: str | None = None,
                     identity_type: str = "auto") -> list[dict]:
    """按规则集策略补全/校验 SAN。返回最终 SAN 列表。"""
    spec = normalize(spec)
    policy = spec["san"]
    out = [dict(s) for s in (sans or []) if s.get("value")]

    if policy.get("auto_from_identity") and identity:
        for item in _identity_sans(identity, identity_type):
            if item["type"] in policy["allowed_types"] or item["type"] == "upn":
                if not any(o["type"] == item["type"] and o["value"] == item["value"] for o in out):
                    out.append(item)
    if policy.get("add_upn_for_email"):
        for item in list(out):
            if item["type"] == "email" and "@" in item["value"]:
                if not any(o["type"] == "upn" and o["value"] == item["value"] for o in out):
                    out.append({"type": "upn", "value": item["value"]})
    if policy.get("copy_cn_if_fqdn") and cn and "." in cn and " " not in cn:
        if not any(o["value"] == cn for o in out):
            out.append({"type": "dns", "value": cn})

    # 类型白名单
    allowed = set(policy.get("allowed_types") or SAN_TYPES)
    rejected = [o for o in out if o["type"] not in allowed]
    if rejected:
        raise CertError("规则集不允许这些 SAN 类型：" +
                        "、".join(sorted({o["type"] for o in rejected})) +
                        f"（允许：{', '.join(sorted(allowed))}）")
    if len(out) > int(policy.get("max_entries") or 999):
        raise CertError(f"SAN 条目过多（最多 {policy.get('max_entries')} 条）")
    if policy.get("required") and not out:
        raise CertError("该规则集要求证书必须包含 SAN（身份标识），"
                        "请填写 VPN 身份或至少一条 SAN")
    return out


def _identity_sans(identity: str, identity_type: str = "auto") -> list[dict]:
    from . import strongswan
    return strongswan.identity_sans(identity, identity_type)


# ------------------------------------------------------------------ CRUD
def _row_to_dict(row: dict) -> dict:
    spec = db.json_load(row.get("spec_json"), {})
    return {
        "id": row["id"], "slug": row["slug"], "name": row["name"],
        "description": row.get("description") or "", "platform": row.get("platform") or "any",
        "purpose": row.get("purpose") or "", "enabled": bool(row["enabled"]),
        "builtin": bool(row["builtin"]), "spec": normalize(spec),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


def seed_builtin() -> None:
    """首次运行写入内置规则集；已存在的不覆盖（管理员改过的内容必须保留）。"""
    existing = {r["slug"] for r in db.q("SELECT slug FROM rulesets")}
    ts = x509util.to_iso(x509util.now())
    with db.tx() as conn:
        for seed in SEEDS:
            if seed["slug"] in existing:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO rulesets(slug,name,description,platform,purpose,enabled,builtin,"
                "spec_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (seed["slug"], seed["name"], seed["description"], seed["platform"],
                 seed.get("purpose") or "", 1, seed.get("builtin", 1),
                 json.dumps(validate(seed["spec"]), ensure_ascii=False), ts, ts))


def list_all(include_disabled: bool = True) -> list[dict]:
    sql = "SELECT * FROM rulesets"
    if not include_disabled:
        sql += " WHERE enabled=1"
    rows = db.q(sql + " ORDER BY builtin DESC, id")
    order = {s["slug"]: i for i, s in enumerate(SEEDS)}
    items = [_row_to_dict(r) for r in rows]
    items.sort(key=lambda r: (order.get(r["slug"], 999), r["id"]))
    return items


def get(id_or_slug: int | str | None) -> dict | None:
    if id_or_slug in (None, "", "default"):
        configured = db.get_setting("default_ruleset")
        if configured:
            row = db.q1("SELECT * FROM rulesets WHERE slug=? AND enabled=1", (configured,))
            if row is not None:
                return _row_to_dict(row)
        items = list_all(include_disabled=False)
        return items[0] if items else None
    row = None
    if isinstance(id_or_slug, int) or str(id_or_slug).isdigit():
        row = db.q1("SELECT * FROM rulesets WHERE id=?", (int(id_or_slug),))
    if row is None:
        row = db.q1("SELECT * FROM rulesets WHERE slug=?", (str(id_or_slug),))
    return _row_to_dict(row) if row else None


def create(data: dict) -> dict:
    slug = (data.get("slug") or "").strip() or _slugify(data.get("name") or "")
    if not slug:
        raise CertError("请填写规则集名称")
    if db.q1("SELECT id FROM rulesets WHERE slug=?", (slug,)):
        raise CertError(f"规则集标识已存在: {slug}")
    spec = validate(data.get("spec") or data.get("rules") or {})
    platform = (data.get("platform") or "any").lower()
    if platform not in PLATFORMS:
        raise CertError(f"平台只能是 {'/'.join(PLATFORMS)}")
    ts = x509util.to_iso(x509util.now())
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO rulesets(slug,name,description,platform,purpose,enabled,builtin,"
            "spec_json,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?)",
            (slug, data.get("name") or slug, data.get("description") or "", platform,
             data.get("purpose") or "", 1 if data.get("enabled", True) else 0,
             json.dumps(spec, ensure_ascii=False), ts, ts))
        rid = cur.lastrowid
        from . import audit
        audit.log("ruleset.create", target_type="ruleset", target_id=rid, target_label=slug,
                  detail={"platform": platform}, conn=conn)
    return get(rid)


def update(rid: int, data: dict) -> dict:
    row = db.q1("SELECT * FROM rulesets WHERE id=?", (rid,))
    if row is None:
        raise CertError("规则集不存在")
    fields, args, detail = [], [], {}
    if data.get("name"):
        fields.append("name=?")
        args.append(str(data["name"]))
        detail["name"] = data["name"]
    if "description" in data:
        fields.append("description=?")
        args.append(str(data.get("description") or ""))
    if data.get("platform"):
        if str(data["platform"]).lower() not in PLATFORMS:
            raise CertError(f"平台只能是 {'/'.join(PLATFORMS)}")
        fields.append("platform=?")
        args.append(str(data["platform"]).lower())
    if "purpose" in data:
        fields.append("purpose=?")
        args.append(str(data.get("purpose") or ""))
    if "enabled" in data:
        fields.append("enabled=?")
        args.append(1 if data["enabled"] else 0)
        detail["enabled"] = bool(data["enabled"])
    if "spec" in data or "rules" in data:
        spec = validate(data.get("spec") or data.get("rules"))
        fields.append("spec_json=?")
        args.append(json.dumps(spec, ensure_ascii=False))
        detail["spec_changed"] = True
    if not fields:
        raise CertError("没有提供任何要修改的内容")
    fields.append("updated_at=?")
    args += [x509util.to_iso(x509util.now()), rid]
    from . import audit
    with db.tx() as conn:
        conn.execute(f"UPDATE rulesets SET {', '.join(fields)} WHERE id=?", args)
        audit.log("ruleset.update", target_type="ruleset", target_id=rid,
                  target_label=row["slug"], detail=detail, conn=conn)
    return get(rid)


def duplicate(rid: int, new_name: str | None = None) -> dict:
    src = get(rid)
    if src is None:
        raise CertError("规则集不存在")
    base = _slugify(new_name or (src["name"] + " 副本"))
    slug, i = base, 2
    while db.q1("SELECT id FROM rulesets WHERE slug=?", (slug,)):
        slug, i = f"{base}-{i}", i + 1
    return create({"slug": slug, "name": new_name or (src["name"] + " 副本"),
                   "description": src["description"], "platform": src["platform"],
                   "purpose": src["purpose"], "spec": src["spec"]})


def delete(rid: int) -> None:
    row = db.q1("SELECT * FROM rulesets WHERE id=?", (rid,))
    if row is None:
        raise CertError("规则集不存在")
    used = db.scalar("SELECT COUNT(*) FROM certs WHERE profile=?", (row["slug"],))
    if used:
        raise CertError(f"已有 {used} 张证书使用该规则集，不能删除；可以停用（enabled=false）")
    from . import audit
    with db.tx() as conn:
        conn.execute("DELETE FROM rulesets WHERE id=?", (rid,))
        audit.log("ruleset.delete", target_type="ruleset", target_id=rid,
                  target_label=row["slug"], conn=conn)


def _slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", text)
    return text.strip("-")[:48]


# ------------------------------------------------------------------ 生效参数
def effective(spec: dict, overrides: dict | None = None) -> tuple[dict, list[str], list[str]]:
    """把签发时的临时覆盖合并进规则集。

    ``strict=true`` 时，只允许覆盖 ``overridable`` 中列出的字段；
    宽松模式（默认）允许覆盖任意字段，但会如实报告覆盖了哪些字段。
    """
    spec = normalize(spec)
    overrides = {k: v for k, v in (overrides or {}).items() if v is not None}
    applied: list[str] = []
    rejected: list[str] = []
    allowed = [str(x) for x in (spec.get("overridable") or [])]
    strict = bool(spec.get("strict"))

    def setter(path: str, value):
        if strict and allowed and path not in allowed:
            rejected.append(path)
            return
        section, _, leaf = path.partition(".")
        if leaf:
            spec.setdefault(section, {})[leaf] = value
        else:
            spec[section] = value
        applied.append(path)

    for path in ("validity.days", "key.type", "key.size", "key.digest"):
        section, _, leaf = path.partition(".")
        if section in overrides and isinstance(overrides[section], dict) \
                and leaf in overrides[section]:
            setter(path, overrides[section][leaf])
    for path in ("sans", "san"):
        if path in overrides and isinstance(overrides[path], (list, dict)):
            setter("san.list" if isinstance(overrides[path], list) else "san.policy",
                   overrides[path])
    for path in ("key_usage", "eku", "custom_extensions", "crl_url", "crl_distribution_point"):
        if path in overrides and overrides[path] is not None:
            setter(f"extensions.{path}", overrides[path])
    for path in ("subject", "serial", "export", "extensions", "revocation", "san"):
        if path in overrides and isinstance(overrides[path], dict):
            for leaf, value in overrides[path].items():
                if value is not None:
                    setter(f"{path}.{leaf}", value)
    return validate(spec), applied, rejected


def platform_notes(ruleset: dict) -> dict:
    """平台差异提示（界面直接展示）。"""
    spec = normalize(ruleset.get("spec"))
    platform = (ruleset.get("platform") or "any").lower()
    hints = dict(PLATFORM_HINTS.get(platform, {}))
    if platform == "strongswan":
        hints["linux"] = PLATFORM_HINTS["strongswan"]["linux_install_hint"]
    for key in ("windows_import_hint", "linux_install_hint", "extra_notes"):
        custom = (spec.get("export") or {}).get(key)
        if custom:
            hints[key] = custom
    hints["platform"] = platform
    hints["bundle"] = spec["export"]["bundle"]
    hints["bundle_label"] = {"pem": "PEM 分离文件（证书/私钥/链）",
                             "p12": "PKCS#12（.p12/.pfx，适合 Windows 导入）",
                             "both": "PEM + PKCS#12 两种都给"}[spec["export"]["bundle"]]
    return hints


def template_view() -> list[dict]:
    """给旧版前端/接口用的扁平视图（保持 /api/templates 兼容）。"""
    out = []
    for rs in list_all(include_disabled=False):
        spec = rs["spec"]
        out.append({
            "id": rs["slug"], "ruleset_id": rs["id"], "name": rs["name"],
            "description": rs["description"], "builtin": rs["builtin"],
            "platform": rs["platform"], "purpose": rs["purpose"],
            "key_usage": spec["extensions"]["key_usage"],
            "eku": spec["extensions"]["eku"],
            "validity_days": spec["validity"]["days"],
            "key_type": spec["key"]["type"], "key_size": spec["key"]["size"],
            "digest": spec["key"]["digest"],
            "san_required": spec["san"]["required"],
            "bundle": spec["export"]["bundle"],
            "spec": spec,
        })
    return out
