"""X.509 解析 / 序列化 / 构造工具层。

只依赖 ``cryptography``，不调用外部 openssl 命令行，避免 shell 注入与输出解析脆弱。
所有对外的时间统一为带时区的 ISO8601 字符串（UTC）。
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
    ObjectIdentifier,
)

UTC = _dt.timezone.utc
UPN_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")  # Microsoft UPN
CERT_TEMPLATE_OID = ObjectIdentifier("1.3.6.1.4.1.311.21.7")


# ------------------------------------------------------------------ 时间
def to_iso(dt: _dt.datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0).isoformat()


def now() -> _dt.datetime:
    return _dt.datetime.now(UTC).replace(microsecond=0)


def parse_iso(text: str | None) -> _dt.datetime | None:
    if not text:
        return None
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def days_remaining(not_after: _dt.datetime) -> int:
    return (not_after.astimezone(UTC) - now()).days


# ------------------------------------------------------------------ 加载
class CertError(ValueError):
    """证书/密钥内容无法识别。"""


def _normalize(data) -> bytes:
    """准备待解析的字节。

    关键点：**只有 PEM/文本才去掉首尾空白**。
    DER 是二进制，``bytes.strip()`` 会把结尾恰好是 0x09/0x0a/0x0d/0x20 之类的字节吃掉，
    导致签名被破坏、解析随机失败（这个坑真实出现过：CRL 的 DER 最后一位是 0x0d）。
    """
    if isinstance(data, str):
        data = data.encode()
    if data.lstrip()[:16].startswith(b"-----BEGIN"):
        return data.strip()
    return data


def load_cert(data: bytes) -> x509.Certificate:
    data = _normalize(data)
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(data)
        except Exception:  # noqa: BLE001 - 依次尝试多种编码
            continue
    # 某些文件是多证书链，取第一个
    try:
        text = data.decode("utf-8", "ignore")
        if "-----BEGIN CERTIFICATE-----" in text:
            first = text.split("-----BEGIN CERTIFICATE-----")[1]
            pem = "-----BEGIN CERTIFICATE-----" + first.split("-----END CERTIFICATE-----")[0] + \
                  "-----END CERTIFICATE-----\n"
            return x509.load_pem_x509_certificate(pem.encode())
    except Exception:  # noqa: BLE001
        pass
    raise CertError("无法解析证书内容（支持 PEM / DER 编码的 X.509 证书）")


def load_certs(data: bytes) -> list[x509.Certificate]:
    """从一个文件里解析出所有证书（支持证书链 / 多证书拼接）。"""
    text = data.decode("utf-8", "ignore")
    out: list[x509.Certificate] = []
    if "-----BEGIN CERTIFICATE-----" in text:
        for chunk in text.split("-----BEGIN CERTIFICATE-----")[1:]:
            body = chunk.split("-----END CERTIFICATE-----")[0]
            try:
                out.append(x509.load_pem_x509_certificate(
                    ("-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----\n").encode()))
            except Exception:  # noqa: BLE001
                continue
    if not out:
        try:
            out.append(load_cert(data))
        except CertError:
            pass
    return out


def load_key(data: bytes, password: str | None = None):
    data = _normalize(data)
    pw = password.encode() if password else None
    for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        try:
            return loader(data, password=pw)
        except TypeError as exc:  # 加密私钥但未提供口令
            if "password" in str(exc).lower() or pw is None:
                raise CertError("私钥已加密，请提供正确的私钥口令") from exc
        except Exception:  # noqa: BLE001
            continue
    raise CertError("无法解析私钥内容（支持 PEM / DER 编码的 RSA / EC 私钥）")


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    data = _normalize(data)
    for loader in (x509.load_pem_x509_csr, x509.load_der_x509_csr):
        try:
            return loader(data)
        except Exception:  # noqa: BLE001
            continue
    raise CertError("无法解析 CSR 内容（支持 PEM / DER 编码的 PKCS#10 请求）")


def load_crl(data: bytes) -> x509.CertificateRevocationList:
    data = _normalize(data)
    for loader in (x509.load_pem_x509_crl, x509.load_der_x509_crl):
        try:
            return loader(data)
        except Exception:  # noqa: BLE001
            continue
    raise CertError("无法解析 CRL 内容（支持 PEM / DER 编码的证书吊销列表）")


# ------------------------------------------------------------------ 序列化
def pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pem_certs(certs: list[x509.Certificate]) -> str:
    return "".join(pem_cert(c) for c in certs)


def der_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def pem_key(key, password: str | None = None, signing_only: bool = False) -> str:
    enc = serialization.PrivateFormat.PKCS8
    if password:
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password.encode()))
    else:
        encryption = serialization.NoEncryption()
    if signing_only:
        try:
            return key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, encryption).decode()
        except Exception:  # noqa: BLE001
            pass
    return key.private_bytes(serialization.Encoding.PEM, enc, encryption).decode()


def pem_csr(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ------------------------------------------------------------------ 名称
def name_to_str(name: x509.Name) -> str:
    """RFC4514 风格的紧凑主题串，如 ``CN=test,OU=Dev,O=Example Organization,C=CN``。"""
    parts: list[str] = []
    order = [
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.LOCALITY_NAME, "L"),
        (NameOID.STATE_OR_PROVINCE_NAME, "ST"),
        (NameOID.COUNTRY_NAME, "C"),
        (NameOID.EMAIL_ADDRESS, "emailAddress"),
    ]
    seen: set[str] = set()
    for oid, label in order:
        for attr in name.get_attributes_for_oid(oid):
            parts.append(f"{label}={attr.value}")
            seen.add(oid.dotted_string)
    for attr in name:
        if attr.oid.dotted_string not in seen:
            parts.append(f"{attr.oid._name or attr.oid.dotted_string}={attr.value}")
    return ",".join(parts)


def get_name(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


# ------------------------------------------------------------------ 扩展
def san_list(cert_or_csr) -> list[dict[str, str]]:
    ext = _get_ext(cert_or_csr, x509.SubjectAlternativeName)
    if ext is None:
        return []
    out: list[dict[str, str]] = []
    for t, values in (("dns", ext.get_values_for_type(x509.DNSName)),
                      ("ip", [str(v) for v in ext.get_values_for_type(x509.IPAddress)]),
                      ("email", ext.get_values_for_type(x509.RFC822Name)),
                      ("uri", ext.get_values_for_type(x509.UniformResourceIdentifier))):
        out.extend({"type": t, "value": v} for v in values)
    for other in ext.get_values_for_type(x509.OtherName):
        # cryptography 46 用 .oid，50+ 改名 .type_id，两者都兼容
        type_id = getattr(other, "type_id", None) or getattr(other, "oid", None)
        kind = "upn" if type_id == UPN_OID else "othername"
        out.append({"type": kind, "value": _decode_other_name(other.value)})
    return out


def _decode_other_name(raw: bytes) -> str:
    """尽力解析 OtherName 的 DER 值（主要是 UTF8String 形式的 UPN）。

    注意 DER 结构是 ``0C <长度> <内容>``：tag 之后还要跳过长度字节，索引从 2 开始。
    """
    try:
        if raw and raw[0] == 0x0C:  # UTF8String
            if len(raw) < 2:
                return ""
            first, idx = raw[1], 2
            if first & 0x80:                     # 长格式长度
                n = first & 0x7F
                length = int.from_bytes(raw[idx:idx + n], "big")
                idx += n
            else:
                length = first
            return raw[idx:idx + length].decode("utf-8", "replace")
        return raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return raw.hex()


KEY_USAGE_FIELDS = [
    ("digital_signature", "digitalSignature", "数字签名"),
    ("content_commitment", "nonRepudiation", "不可否认"),
    ("key_encipherment", "keyEncipherment", "密钥加密"),
    ("data_encipherment", "dataEncipherment", "数据加密"),
    ("key_agreement", "keyAgreement", "密钥协商"),
    ("key_cert_sign", "keyCertSign", "签发证书"),
    ("crl_sign", "cRLSign", "签发 CRL"),
    ("encipher_only", "encipherOnly", "仅加密"),
    ("decipher_only", "decipherOnly", "仅解密"),
]

EKU_MAP: dict[str, tuple[ObjectIdentifier, str]] = {
    "serverAuth": (ExtendedKeyUsageOID.SERVER_AUTH, "TLS 服务端认证"),
    "clientAuth": (ExtendedKeyUsageOID.CLIENT_AUTH, "TLS 客户端认证"),
    "codeSigning": (ExtendedKeyUsageOID.CODE_SIGNING, "代码签名"),
    "emailProtection": (ExtendedKeyUsageOID.EMAIL_PROTECTION, "邮件保护"),
    "timeStamping": (ExtendedKeyUsageOID.TIME_STAMPING, "时间戳"),
    "ocspSigning": (ExtendedKeyUsageOID.OCSP_SIGNING, "OCSP 签名"),
    "ipsecIKE": (ObjectIdentifier("1.3.6.1.5.5.7.3.17"), "IPSec IKE"),
    "msSmartcardLogin": (ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"), "智能卡登录"),
    "msEFS": (ObjectIdentifier("1.3.6.1.4.1.311.10.3.4"), "EFS 加密文件系统"),
    "anyExtendedKeyUsage": (ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE, "任意用途"),
}
EKU_BY_OID = {oid.dotted_string: name for name, (oid, _) in EKU_MAP.items()}


def _get_ext(obj, ext_type):
    try:
        return obj.extensions.get_extension_for_class(ext_type).value
    except x509.ExtensionNotFound:
        return None
    except Exception:  # noqa: BLE001 - CSR 可能没有 extensions
        return None


def key_usage_list(cert) -> list[str]:
    ku = _get_ext(cert, x509.KeyUsage)
    if ku is None:
        return []
    out = []
    for attr, friendly, _ in KEY_USAGE_FIELDS:
        try:
            if getattr(ku, attr):
                out.append(friendly)
        except ValueError:
            continue
    return out


def eku_list(cert) -> list[str]:
    ext = _get_ext(cert, x509.ExtendedKeyUsage)
    if ext is None:
        return []
    return [EKU_BY_OID.get(o.dotted_string, o.dotted_string) for o in ext]


def key_type_size(key) -> tuple[str, int | None]:
    if isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PrivateKey | ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPrivateKey | dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, None


def signature_algorithm(cert) -> str | None:
    try:
        return cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001
        return None


def fingerprint(cert) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def fingerprint_bytes(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def serial_hex(cert) -> str:
    return format(cert.serial_number, "X")


def crl_number(crl: x509.CertificateRevocationList) -> str | None:
    try:
        ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
        return str(ext.value.crl_number)
    except x509.ExtensionNotFound:
        return None
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ 证书 → dict
def cert_to_dict(cert: x509.Certificate, *, status_hint: str | None = None) -> dict[str, Any]:
    subject = name_to_str(cert.subject)
    ktype, ksize = key_type_size(cert.public_key())
    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
        cert.not_valid_after.replace(tzinfo=UTC)
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else \
        cert.not_valid_before.replace(tzinfo=UTC)
    status = status_hint or ("expired" if na < now() else "valid")
    return {
        "subject": subject,
        "cn": get_name(cert.subject, NameOID.COMMON_NAME) or subject,
        "issuer": name_to_str(cert.issuer),
        "serial_hex": serial_hex(cert),
        "serial_dec": str(cert.serial_number),
        "fingerprint_sha256": fingerprint(cert),
        "not_before": to_iso(nb),
        "not_after": to_iso(na),
        "key_type": ktype,
        "key_size": ksize,
        "signature_algorithm": signature_algorithm(cert),
        "sans": san_list(cert),
        "key_usage": key_usage_list(cert),
        "eku": eku_list(cert),
        "status": status,
        "is_ca": bool((_get_ext(cert, x509.BasicConstraints) or
                       x509.BasicConstraints(ca=False, path_length=None)).ca),
    }


def csr_to_dict(csr: x509.CertificateSigningRequest) -> dict[str, Any]:
    ktype, ksize = key_type_size(csr.public_key())
    return {
        "subject": name_to_str(csr.subject),
        "cn": get_name(csr.subject, NameOID.COMMON_NAME),
        "sans": san_list(csr),
        "key_type": ktype,
        "key_size": ksize,
        "signature_valid": csr.is_signature_valid,
        "pem": pem_csr(csr),
    }


# ------------------------------------------------------------------ 构造
def generate_key(key_type: str = "rsa", key_size: int | str = 2048):
    key_type = (key_type or "rsa").lower()
    size = int(key_size or 2048)
    if key_type == "rsa":
        if size < 2048:
            raise CertError("RSA 密钥长度至少 2048 位")
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    if key_type in ("ec", "ecdsa"):
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}
        if size not in curves:
            raise CertError("EC 密钥长度需为 256 / 384 / 521")
        return ec.generate_private_key(curves[size])
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise CertError(f"不支持的密钥类型: {key_type}")


def hash_algorithm(name: str = "sha256"):
    name = (name or "sha256").lower().replace("-", "")
    mapping = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
               "sha1": hashes.SHA1, "sha224": hashes.SHA224}
    if name not in mapping:
        raise CertError(f"不支持的摘要算法: {name}")
    return mapping[name]()


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_utf8(text: str) -> bytes:
    raw = text.encode("utf-8")
    return b"\x0c" + _der_len(len(raw)) + raw


def build_san(entries: list[dict[str, str]]) -> x509.SubjectAlternativeName | None:
    """把前端传来的 SAN 列表转换为 X.509 扩展。"""
    general_names: list[x509.GeneralName] = []
    for e in entries or []:
        t = (e.get("type") or "").lower().strip()
        v = (e.get("value") or "").strip()
        if not v:
            continue
        if t == "dns":
            general_names.append(x509.DNSName(v))
        elif t == "ip":
            try:
                general_names.append(x509.IPAddress(ipaddress.ip_address(v)))
            except ValueError as exc:
                raise CertError(f"无效的 IP 地址: {v}") from exc
        elif t == "email":
            general_names.append(x509.RFC822Name(v))
        elif t == "uri":
            general_names.append(x509.UniformResourceIdentifier(v))
        elif t == "upn":
            general_names.append(x509.OtherName(UPN_OID, der_utf8(v)))
        elif t == "othername":
            # 形如 1.2.3.4:value，value 按 UTF8String 编码
            oid_s, _, val = v.partition(":")
            general_names.append(x509.OtherName(ObjectIdentifier(oid_s.strip()), der_utf8(val)))
        else:
            raise CertError(f"未知的 SAN 类型: {t}")
    if not general_names:
        return None
    return x509.SubjectAlternativeName(general_names)


def build_name(*, cn: str | None = None, o: str | None = None, ou: str | None = None,
               c: str | None = None, st: str | None = None, l: str | None = None,
               email: str | None = None) -> x509.Name:
    attrs: list[x509.NameAttribute] = []
    for value, oid in ((c, NameOID.COUNTRY_NAME), (st, NameOID.STATE_OR_PROVINCE_NAME),
                       (l, NameOID.LOCALITY_NAME), (o, NameOID.ORGANIZATION_NAME),
                       (ou, NameOID.ORGANIZATIONAL_UNIT_NAME), (cn, NameOID.COMMON_NAME),
                       (email, NameOID.EMAIL_ADDRESS)):
        if value:
            attrs.append(x509.NameAttribute(oid, str(value).strip()))
    if not attrs:
        raise CertError("证书主题不能为空，至少需要 CN")
    return x509.Name(attrs)


def ku_kwargs(names: list[str]) -> dict[str, bool]:
    wanted = {n.strip() for n in (names or []) if n and n.strip()}
    kwargs = {attr: (friendly in wanted) for attr, friendly, _ in KEY_USAGE_FIELDS}
    if not any(kwargs.values()):
        # 默认给一个通用组合，但必须保留全部 9 个字段（KeyUsage 要求全部传参）
        kwargs["digital_signature"] = True
        kwargs["key_encipherment"] = True
    if kwargs.get("encipher_only") or kwargs.get("decipher_only"):
        if not kwargs.get("key_agreement"):
            kwargs["key_agreement"] = True
    return kwargs


def eku_objects(names: list[str]) -> list[ObjectIdentifier] | None:
    out = []
    for n in names or []:
        n = n.strip()
        if not n:
            continue
        if n in EKU_MAP:
            out.append(EKU_MAP[n][0])
        elif n.count(".") >= 2:
            out.append(ObjectIdentifier(n))
    return out or None


# ------------------------------------------------------------------ PKCS#12
def make_pkcs12(key, cert: x509.Certificate, chain: list[x509.Certificate], password: str) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        (get_name(cert.subject, NameOID.COMMON_NAME) or "cert").encode(),
        key, cert, chain or None,
        serialization.BestAvailableEncryption(password.encode()),
    )


def read_pkcs12(data: bytes, password: str | None):
    return pkcs12.load_key_and_certificates(data, password.encode() if password else None)


# ------------------------------------------------------------------ 吊销原因
REASONS: dict[str, str] = {
    "unspecified": "未指定",
    "keyCompromise": "私钥泄露",
    "cACompromise": "CA 私钥泄露",
    "affiliationChanged": "隶属关系变更",
    "superseded": "已被取代",
    "cessationOfOperation": "停止使用",
    "certificateHold": "暂时挂起",
    "removeFromCRL": "从 CRL 移除",
    "privilegeWithdrawn": "权限被撤销",
    "aACompromise": "属性权威泄露",
}
_REASON_ENUM = {m.value.lower(): m for m in x509.ReasonFlags}


def reason_enum(name: str | None):
    if not name:
        return x509.ReasonFlags.unspecified
    return _REASON_ENUM.get(str(name).strip().lower(), x509.ReasonFlags.unspecified)


def reason_label(name: str | None) -> str:
    return REASONS.get(name or "", name or "未指定")


def validity_days_ahead(days: int) -> _dt.datetime:
    return now() + _dt.timedelta(days=int(days))


def crl_signature_ok(ca_cert, crl) -> tuple[bool, str]:
    """用 CA 证书公钥验证 CRL 签名。返回 (是否通过, 说明)。

    这一步才是"内容可信"的关键：仅解析能看出内容，但无法证明它确实是本 CA 签发的、
    也没被人改过。算法按公钥类型分派（RSA / ECDSA / Ed25519 / Ed448）。
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
    pub = ca_cert.public_key()
    algo = crl.signature_hash_algorithm
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), algo)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(algo))
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(crl.signature, crl.tbs_certlist_bytes)
        else:
            return False, f"不支持的 CA 公钥类型：{type(pub).__name__}"
    except InvalidSignature:
        return False, "签名验证失败：CRL 不是由该 CA 签发，或内容已被篡改"
    except Exception as exc:  # noqa: BLE001
        return False, f"签名验证异常：{type(exc).__name__}: {exc}"
    return True, "签名验证通过（确由该 CA 签发且内容未被改动）"


def crl_info(crl) -> dict:
    """把 CRL 解析成便于展示/核对的字典。"""
    from cryptography import x509 as _x509
    from cryptography.x509.oid import ExtensionOID
    try:
        number = crl.extensions.get_extension_for_class(_x509.CRLNumber).value.crl_number
    except Exception:  # noqa: BLE001
        number = None
    last = getattr(crl, "last_update_utc", None) or crl.last_update
    nxt = getattr(crl, "next_update_utc", None) or crl.next_update
    entries = []
    for e in crl:
        reason = None
        try:
            reason = e.extensions.get_extension_for_oid(
                ExtensionOID.CRL_REASON).value.reason.name
        except Exception:  # noqa: BLE001
            reason = None
        entries.append({"serial": e.serial_number,
                        "serial_hex": format(e.serial_number, "X"),
                        "revoked_at": to_iso(getattr(e, "revocation_date_utc", None)
                                             or e.revocation_date),
                        "reason": reason})
    return {"issuer": name_to_str(crl.issuer), "number": number,
            "this_update": to_iso(last), "next_update": to_iso(nxt),
            "entries": entries, "count": len(entries),
            "signature_algorithm": crl.signature_algorithm_oid._name,
            "is_delta": bool(getattr(crl, "is_delta", False))}


def sha256_hex(data: bytes) -> str:
    """字节的 SHA-256 十六进制（用于文件内容核对）。"""
    import hashlib as _h
    return _h.sha256(data).hexdigest()
