"""CA 引擎：导入 CA、签发证书、吊销/恢复、生成 CRL。

关键约定
--------
* **数据库是唯一事实来源**；``index.txt`` 与 CRL 文件都是从数据库派生出来的产物，
  派生过程放在 ``generate_crl`` / ``export_index_txt`` 里，任何时刻都可重新生成。
* 签发时先在同一事务内分配序列号，再把 PEM 文件原子落盘，最后写库并提交。
  任一环节失败即回滚并清理已写文件，避免出现“库里有、盘上无”的不一致。
* 私钥永不通过列表接口返回；只有签发当次的响应里带一次，之后需重新签发或从备份取回。
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading

# 序列化 CRL 生成：读取已吊销集合 → 取编号 → 写文件/入库 必须整体互斥。
# 否则并发吊销时，先读到旧快照的那次生成若更慢，会**后**写入，
# 导致最新的 CRL（以及落盘的 DER 文件）漏掉一张已吊销证书——
# strongSwan 会继续认为它有效。tests/crl_race_e2e.py 用故障注入复现过。
_CRL_LOCK = threading.RLock()
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from . import audit, config, db, x509util
from .x509util import CertError

# 证书模板已全部迁移到「规则集」（backend/rules.py，存数据库、可编辑）。


# ------------------------------------------------------------------ CA 读取
def active_ca_row() -> dict | None:
    row = db.q1("SELECT * FROM cas WHERE is_active=1 ORDER BY id DESC LIMIT 1")
    if row is None:
        row = db.q1("SELECT * FROM cas ORDER BY id DESC LIMIT 1")
    return row


def get_ca(ca_id: int) -> dict | None:
    return db.q1("SELECT * FROM cas WHERE id=?", (ca_id,))


def ca_to_dict(row: dict) -> dict[str, Any]:
    return {
        "id": row["id"],
        "subject": row["subject"],
        "cn": row["cn"],
        "serial_hex": row["serial_hex"],
        "fingerprint_sha256": row["fingerprint"],
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "key_type": row["key_type"],
        "key_size": row["key_size"],
        "signature_algorithm": row.get("signature_algorithm"),
        "has_key": bool(row["has_key"]),
        "is_active": bool(row["is_active"]),
        "source": row.get("source"),
        "created_at": row["created_at"],
        "days_remaining": x509util.days_remaining(
            x509util.parse_iso(row["not_after"]) or x509util.now()),
    }


def load_material(row: dict) -> tuple[x509.Certificate, Any | None, list[x509.Certificate]]:
    """读取 CA 的证书、私钥（可能为 None）与链。"""
    cert = x509util.load_cert(_path(row["cert_path"]).read_bytes())
    key = None
    if row.get("has_key") and row.get("key_path"):
        key = x509util.load_key(_path(row["key_path"]).read_bytes())
    chain: list[x509.Certificate] = []
    if row.get("chain_path"):
        try:
            chain = x509util.load_certs(_path(row["chain_path"]).read_bytes())
        except OSError:
            chain = []
    return cert, key, chain


def _path(rel: str) -> Path:
    """把数据库里的相对路径解析为数据目录下的绝对路径（绝对路径原样使用）。"""
    p = Path(rel)
    return p if p.is_absolute() else config.DATA_DIR / p


# ------------------------------------------------------------------ CA 导入
def import_ca(cert_data: bytes, key_data: bytes | None = None, chain_data: bytes | None = None,
              password: str | None = None, source: str = "upload",
              actor: str = "admin") -> dict:
    cert = x509util.load_cert(cert_data)

    # 若是 PKCS#12，允许把整个 p12 当 cert 传
    if key_data is None and cert_data[:1] == b"\x30":
        try:
            _k, _c, _extra = x509util.read_pkcs12(cert_data, password)
            if _c is not None:
                cert, key_data = _c, x509util.pem_key(_k).encode() if _k else None
        except Exception:  # noqa: BLE001
            pass

    info = x509util.cert_to_dict(cert, status_hint="valid")
    if not info["is_ca"]:
        raise CertError("该证书不是 CA 证书（BasicConstraints CA:FALSE），不能用作 CA")

    key_pem_text: str | None = None
    if key_data:
        try:
            key = x509util.load_key(key_data, password)
        except CertError:
            raise
        # 校验私钥与证书是否匹配
        if key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo) != cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo):
            raise CertError("私钥与 CA 证书不匹配，请检查是否传错文件")
        # 统一转成未加密 PKCS#8 存储（服务需要无人值守使用），权限 0600
        key_pem_text = x509util.pem_key(key)

    chain_pem: str | None = None
    if chain_data:
        chain = [c for c in x509util.load_certs(chain_data)
                 if x509util.fingerprint(c) != info["fingerprint_sha256"]]
        chain_pem = x509util.pem_certs(chain) or None

    fp_slug = info["fingerprint_sha256"].replace(":", "")[-16:].lower()
    cert_rel = f"ca/{fp_slug}-ca.crt"
    key_rel = f"ca/{fp_slug}-ca.key"
    chain_rel = f"ca/{fp_slug}-chain.crt" if chain_pem else None
    ts = x509util.to_iso(x509util.now())

    existing = db.q1("SELECT * FROM cas WHERE fingerprint=?", (info["fingerprint_sha256"],))
    if existing:
        # 已存在：只补私钥 / 链，不新建记录
        with db.tx() as conn:
            if key_pem_text:
                config.atomic_write_text(_path(key_rel), key_pem_text, private=True)
                conn.execute("UPDATE cas SET has_key=1, key_path=? WHERE id=?",
                             (key_rel, existing["id"]))
            if chain_pem:
                config.atomic_write_text(_path(chain_rel), chain_pem, private=False)
                conn.execute("UPDATE cas SET chain_path=? WHERE id=?", (chain_rel, existing["id"]))
            audit.log("ca.reimport", target_type="ca", target_id=existing["id"],
                      target_label=info["subject"], actor=actor,
                      detail={"has_key": bool(key_pem_text)}, conn=conn)
        return get_ca(existing["id"])

    config.atomic_write_text(_path(cert_rel), x509util.pem_cert(cert), private=False)
    if key_pem_text:
        config.atomic_write_text(_path(key_rel), key_pem_text, private=True)
    if chain_pem:
        config.atomic_write_text(_path(chain_rel), chain_pem, private=False)

    with db.tx() as conn:
        conn.execute("UPDATE cas SET is_active=0")
        cur = conn.execute(
            "INSERT INTO cas(subject,cn,serial_hex,fingerprint,not_before,not_after,key_type,"
            "key_size,signature_algorithm,has_key,is_active,cert_path,key_path,chain_path,source,"
            "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)",
            (info["subject"], info["cn"], info["serial_hex"], info["fingerprint_sha256"],
             info["not_before"], info["not_after"], info["key_type"], info["key_size"],
             info["signature_algorithm"], 1 if key_pem_text else 0, cert_rel,
             key_rel if key_pem_text else None, chain_rel, source, ts))
        ca_id = cur.lastrowid
        audit.log("ca.import", target_type="ca", target_id=ca_id, target_label=info["subject"],
                  actor=actor, detail={"has_key": bool(key_pem_text), "source": source}, conn=conn)
    return get_ca(ca_id)


def activate_ca(ca_id: int, actor: str = "admin") -> dict:
    row = get_ca(ca_id)
    if row is None:
        raise CertError("指定的 CA 不存在")
    with db.tx() as conn:
        conn.execute("UPDATE cas SET is_active=0")
        conn.execute("UPDATE cas SET is_active=1 WHERE id=?", (ca_id,))
        audit.log("ca.activate", target_type="ca", target_id=ca_id, target_label=row["subject"],
                  actor=actor, conn=conn)
    return get_ca(ca_id)


# ------------------------------------------------------------------ 序列号
def _new_serial(ca_id: int, mode: str = "random", bits: int = 159) -> int:
    if (mode or "random").lower() == "sequential":
        return db.next_serial(ca_id)
    bits = max(64, min(256, int(bits or 159)))
    return secrets.randbits(bits) | (1 << (bits - 1)) | 1


# ------------------------------------------------------------------ 签发
def issue_certificate(*, ca_row: dict, profile: str | None = None,
                      ruleset: dict | None = None,
                      cn: str | None = None, o: str | None = None, ou: str | None = None,
                      c: str | None = None, st: str | None = None, l: str | None = None,
                      email: str | None = None,
                      sans: list[dict] | None = None, validity_days: int | None = None,
                      key_type: str | None = None, key_size: int | str | None = None,
                      key_usage: list[str] | None = None, eku: list[str] | None = None,
                      serial_mode: str | None = None, csr_pem: str | None = None,
                      generate_key: bool = True, owner: str | None = None,
                      tags: list[str] | None = None, notes: str | None = None,
                      source: str = "issued", status_hint: str | None = None,
                      actor: str = "admin", vpn_identity: str | None = None,
                      vpn_identity_type: str = "auto",
                      overrides: dict | None = None) -> dict:
    """按规则集签发证书。

    所有密码学与扩展参数都来自规则集（``profile``/``ruleset`` 指定），
    显式传入的参数视为“本次签发的临时覆盖”。代码里不写死任何算法、位数或扩展。
    """
    from . import rules as rules_mod

    ca_cert, ca_key, _chain = load_material(ca_row)
    if ca_key is None:
        raise CertError("当前 CA 未导入私钥，无法签发证书。请在「CA 管理」中导入 CA 私钥。")

    rs = ruleset or rules_mod.get(profile)
    if rs is None:
        raise CertError(f"找不到规则集: {profile or '(默认)'}。请先在「规则集」页创建。")

    # ---- 把显式参数整理成覆盖项，交给规则集合并 ----
    ov: dict[str, Any] = dict(overrides or {})
    if validity_days is not None:
        ov.setdefault("validity", {})["days"] = int(validity_days)
    if key_type:
        ov.setdefault("key", {})["type"] = str(key_type).lower()
    if key_size:
        ov.setdefault("key", {})["size"] = int(key_size)
    if key_usage:
        ov.setdefault("extensions", {})["key_usage"] = list(key_usage)
    if eku is not None and eku != []:
        ov.setdefault("extensions", {})["eku"] = list(eku)
    if serial_mode:
        ov.setdefault("serial", {})["mode"] = str(serial_mode)
    if sans:
        ov["san"] = {"list": list(sans)}
    spec, applied, rejected = rules_mod.effective(rs["spec"], ov)
    if rejected:
        raise CertError("该规则集不允许覆盖以下字段：" + "、".join(sorted(set(rejected))))

    # ---- 有效期校验（上下限来自规则集） ----
    days = int(spec["validity"]["days"])
    lo, hi = int(spec["validity"]["min_days"]), int(spec["validity"]["max_days"])
    if not (lo <= days <= hi):
        raise CertError(f"有效期 {days} 天超出规则集「{rs['name']}」允许范围 {lo}~{hi} 天")

    # ---- 密钥 / CSR ----
    key = None
    csr = None
    resolved_sans = ov.get("san", {}).get("list") if isinstance(ov.get("san"), dict) else sans
    if csr_pem:
        csr = x509util.load_csr(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem)
        if not csr.is_signature_valid:
            raise CertError("CSR 的自签名校验失败，请确认 CSR 未损坏")
        subject = csr.subject
        public_key = csr.public_key()
        info_csr = x509util.csr_to_dict(csr)
        if not resolved_sans:            # 空列表与 None 一样，都表示“没给 SAN”
            resolved_sans = info_csr["sans"]
        if not cn:
            cn = info_csr["cn"]
        ctype, csize = info_csr["key_type"], info_csr["key_size"] or 0
        min_rsa = int(spec["key"].get("min_rsa_size") or 2048)
        if ctype == "RSA" and csize and csize < min_rsa:
            raise CertError(f"CSR 使用 {csize} 位 RSA 密钥，低于规则集要求的最小 {min_rsa} 位")
        digest_name = spec["key"]["digest"]
    else:
        if not cn and not vpn_identity:
            raise CertError("请填写证书 CN（通用名称）或 VPN 身份")
        if spec["subject"].get("cn_from_identity") and not cn and vpn_identity:
            cn = vpn_identity
        ktype = str(spec["key"]["type"]).lower()
        ksize = int(spec["key"]["size"])
        if generate_key:
            key = x509util.generate_key(ktype, ksize)
            public_key = key.public_key()
        else:
            raise CertError("未提供 CSR 时必须由系统生成密钥")
        subject = x509util.build_name(cn=cn, o=o, ou=ou, c=c, st=st, l=l, email=email)
        digest_name = spec["key"]["digest"]

    # ---- 主题规则 ----
    sub_policy = spec["subject"]
    if sub_policy.get("require_cn") and not x509util.get_name(subject, NameOID.COMMON_NAME):
        raise CertError("该规则集要求证书必须包含 CN")
    required = [str(f).upper() for f in (sub_policy.get("required_fields") or [])]
    for field in required:
        if field == "CN" and not x509util.get_name(subject, NameOID.COMMON_NAME):
            raise CertError("缺少必填主题字段 CN")
    cn_value = x509util.get_name(subject, NameOID.COMMON_NAME) or ""
    if len(cn_value) > int(sub_policy.get("max_cn_length") or 64):
        raise CertError(f"CN 长度超过规则集限制（最多 {sub_policy.get('max_cn_length')} 字符）")

    # ---- SAN 策略（strongSwan 靠 SAN 匹配 IKEv2 身份） ----
    identity = vpn_identity or (cn_value if spec["san"].get("auto_from_identity") else None)
    final_sans = rules_mod.apply_san_policy(spec, cn=cn_value, sans=resolved_sans,
                                            identity=identity,
                                            identity_type=vpn_identity_type)

    now = x509util.now()
    skew = int(spec["validity"].get("not_before_skew_minutes") or 0)
    not_before = now - x509util._dt.timedelta(minutes=skew) if skew else now
    not_after = now + x509util._dt.timedelta(days=days)

    # ---- 组装扩展（全部按规则集） ----
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(ca_cert.subject)
               .public_key(public_key)
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(
                   x509.BasicConstraints(ca=bool(spec["extensions"].get("basic_constraints_ca")),
                                         path_length=_path_length(spec)), critical=True)
               .add_extension(x509.KeyUsage(**x509util.ku_kwargs(spec["extensions"]["key_usage"])),
                              critical=True))
    if spec["extensions"].get("subject_key_identifier", True):
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    if spec["extensions"].get("authority_key_identifier", True):
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False)

    eku_objs = x509util.eku_objects(spec["extensions"].get("eku") or [])
    if eku_objs:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_objs), critical=False)

    san_ext = x509util.build_san(final_sans)
    if san_ext is not None:
        builder = builder.add_extension(san_ext, critical=False)

    if spec["extensions"].get("crl_distribution_point"):
        url = (spec["extensions"].get("crl_url") or db.get_setting("crl_url") or "").strip()
        if url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(url)], relative_name=None,
                    reasons=None, crl_issuer=None)]), critical=False)

    ocsp = (spec["extensions"].get("ocsp_url") or "").strip()
    if ocsp:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(ocsp))]), critical=False)

    for ext_obj, critical in rules_mod.build_custom_extensions(spec):
        builder = builder.add_extension(ext_obj, critical=critical)

    serial_cfg = spec["serial"]
    serial = _new_serial(ca_row["id"], serial_cfg.get("mode", "random"),
                         int(serial_cfg.get("bits") or 159))
    builder = builder.serial_number(serial)

    # 摘要算法来自规则集；只有 Ed25519/Ed448 必须传 None
    digest = _digest_for(ca_key, digest_name)
    cert = builder.sign(private_key=ca_key, algorithm=digest, rsa_padding=_rsa_padding(ca_key))

    result = _persist_cert(cert, key=key, ca_row=ca_row, subject_override=None,
                           profile=rs["slug"], owner=owner, tags=tags, notes=notes,
                           source=source, status_hint=status_hint, actor=actor,
                           return_secret=True)
    result["ruleset"] = {"id": rs["id"], "slug": rs["slug"], "name": rs["name"],
                         "platform": rs["platform"]}
    result["applied_overrides"] = applied
    result["effective"] = {
        "validity_days": days,
        "key": {"type": spec["key"]["type"], "size": spec["key"]["size"],
                "digest": spec["key"]["digest"]},
        "key_usage": spec["extensions"]["key_usage"],
        "eku": spec["extensions"]["eku"],
        "san_required": spec["san"].get("required"),
        "bundle": spec["export"].get("bundle"),
        "platform": rs["platform"],
    }
    # 触发自动化（签发后事件）；CRL 相关的自动化由发布目标/调度器负责，避免重复执行
    try:
        from . import automation
        automation.fire("cert.issued", {
            "cert_id": result["id"], "profile": rs["slug"],
            "summary": f"签发 {result['cert']['cn']}（{rs['name']}）"}, actor=actor)
    except Exception:  # noqa: BLE001 - 自动化异常不得影响签发
        pass
    return result


def _path_length(spec: dict):
    value = spec["extensions"].get("path_length")
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rsa_padding(key):
    from cryptography.hazmat.primitives.asymmetric import padding
    if isinstance(key, __import__("cryptography.hazmat.primitives.asymmetric.rsa",
                                  fromlist=["RSAPrivateKey"]).RSAPrivateKey):
        return padding.PKCS1v15()
    return None


def _digest_for(key, digest_name: str = "sha256"):
    """Ed25519 / Ed448 不能指定摘要算法（必须 None），其余用规则集指定的摘要。"""
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
    if isinstance(key, ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey):
        return None
    return x509util.hash_algorithm(digest_name)


def _persist_cert(cert: x509.Certificate, *, key, ca_row: dict | None, subject_override,
                  profile: str | None, owner: str | None, tags: list[str] | None,
                  notes: str | None, source: str, status_hint: str | None = None,
                  actor: str = "admin", return_secret: bool = False,
                  revoked_at: str | None = None, revocation_reason: str | None = None) -> dict:
    info = x509util.cert_to_dict(cert, status_hint=status_hint)
    fp = info["fingerprint_sha256"]
    slug = fp.replace(":", "")[-20:].lower()
    seq = info["serial_hex"]
    cert_rel = f"certs/{seq}-{slug}.crt"
    key_rel = f"certs/{seq}-{slug}.key" if key is not None else None
    ts = x509util.to_iso(x509util.now())

    written: list[str] = []
    try:
        config.atomic_write_text(_path(cert_rel), x509util.pem_cert(cert))
        written.append(cert_rel)
        if key is not None:
            config.atomic_write_text(_path(key_rel), x509util.pem_key(key), private=True)
            written.append(key_rel)

        with db.tx() as conn:
            cur = conn.execute(
                "INSERT INTO certs(serial_hex,serial_dec,subject,cn,issuer,fingerprint,status,"
                "not_before,not_after,revoked_at,revocation_reason,profile,key_type,key_size,"
                "signature_algorithm,sans_json,key_usage_json,eku_json,owner,tags_json,notes,"
                "cert_path,key_path,has_key,ca_id,source,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (info["serial_hex"], info["serial_dec"], info["subject"], info["cn"],
                 info["issuer"], fp, info["status"], info["not_before"], info["not_after"],
                 revoked_at, revocation_reason, profile, info["key_type"], info["key_size"],
                 info["signature_algorithm"], db.json.dumps(info["sans"], ensure_ascii=False),
                 db.json.dumps(info["key_usage"], ensure_ascii=False),
                 db.json.dumps(info["eku"], ensure_ascii=False),
                 owner, db.json.dumps(tags or [], ensure_ascii=False), notes,
                 cert_rel, key_rel, 1 if key is not None else 0,
                 ca_row["id"] if ca_row else None, source, ts, ts))
            cert_id = cur.lastrowid
            audit.log("cert.issue" if source == "issued" else "cert.import",
                      target_type="cert", target_id=cert_id, target_label=info["cn"] or subject_override,
                      actor=actor,
                      detail={"serial": info["serial_hex"], "profile": profile,
                              "not_after": info["not_after"], "source": source}, conn=conn)
    except BaseException:
        for rel in written:  # 回滚已落盘文件，保持“盘上有 ⇔ 库里有”
            try:
                _path(rel).unlink()
            except OSError:
                pass
        raise

    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    result: dict[str, Any] = {"cert": cert_to_dict(row), "id": cert_id}
    if return_secret:
        secret = {"cert_pem": x509util.pem_cert(cert)}
        if key is not None:
            secret["key_pem"] = x509util.pem_key(key)
        _, _, chain = load_material(ca_row) if ca_row else (None, None, [])
        ca_cert = load_material(ca_row)[0] if ca_row else None
        secret["chain_pem"] = (x509util.pem_cert(ca_cert) + x509util.pem_certs(chain)) if ca_cert else ""
        result["secret"] = secret
    return result


def store_certificate(cert: x509.Certificate, *, key=None, ca_row: dict | None = None,
                      profile: str | None = None, owner: str | None = None,
                      tags: list[str] | None = None, notes: str | None = None,
                      source: str = "imported", actor: str = "admin",
                      status_hint: str | None = None, revoked_at: str | None = None,
                      revocation_reason: str | None = None) -> dict:
    """把一张（外部导入的）证书落库落盘，供 inventory 复用同一套持久化逻辑。"""
    return _persist_cert(cert, key=key, ca_row=ca_row, subject_override=None, profile=profile,
                         owner=owner, tags=tags, notes=notes, source=source,
                         status_hint=status_hint, actor=actor, return_secret=False,
                         revoked_at=revoked_at, revocation_reason=revocation_reason)


# ------------------------------------------------------------------ dict 输出
def cert_to_dict(row: dict) -> dict[str, Any]:
    na = x509util.parse_iso(row["not_after"]) or x509util.now()
    status = row["status"]
    if status not in ("archived", "revoked") and na < x509util.now():
        status = "expired"
    return {
        "id": row["id"],
        "serial_hex": row["serial_hex"],
        "serial_dec": row["serial_dec"],
        "subject": row["subject"],
        "cn": row["cn"],
        "issuer": row["issuer"],
        "fingerprint_sha256": row["fingerprint"],
        "status": status,
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "revoked_at": row["revoked_at"],
        "revocation_reason": row["revocation_reason"],
        "revocation_notes": row.get("revocation_notes"),
        "profile": row["profile"],
        "key_type": row["key_type"],
        "key_size": row["key_size"],
        "signature_algorithm": row["signature_algorithm"],
        "sans": db.json_load(row["sans_json"], []),
        "key_usage": db.json_load(row["key_usage_json"], []),
        "eku": db.json_load(row["eku_json"], []),
        "owner": row["owner"],
        "tags": db.json_load(row["tags_json"], []),
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row.get("updated_at"),
        "has_key": bool(row["has_key"]),
        "ca_id": row["ca_id"],
        "replaces_id": row["replaces_id"],
        "replaced_by_id": row["replaced_by_id"],
        "source": row.get("source"),
        "days_remaining": x509util.days_remaining(na),
    }


def get_cert(cert_id: int) -> dict | None:
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    return cert_to_dict(row) if row else None


# ------------------------------------------------------------------ 吊销
def revoke(cert_id: int, reason: str = "unspecified", revocation_date: str | None = None,
           notes: str | None = None, actor: str = "admin") -> dict:
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    if row is None:
        raise CertError("证书不存在")
    if row["status"] == "revoked":
        raise CertError("该证书已经是吊销状态")
    when = revocation_date or x509util.to_iso(x509util.now())
    if x509util.parse_iso(when) is None:
        raise CertError("吊销时间格式不正确，应为 ISO8601")
    with db.tx() as conn:
        conn.execute("UPDATE certs SET status='revoked', revoked_at=?, revocation_reason=?, "
                     "revocation_notes=?, updated_at=? WHERE id=?",
                     (when, reason, notes, x509util.to_iso(x509util.now()), cert_id))
        audit.log("cert.revoke", target_type="cert", target_id=cert_id,
                  target_label=row["cn"] or row["subject"], actor=actor,
                  detail={"reason": reason, "reason_label": x509util.reason_label(reason),
                          "revoked_at": when, "serial": row["serial_hex"]}, conn=conn)
    out = {"cert": get_cert(cert_id), "crl": None}
    try:
        out["crl"] = generate_crl(actor=actor)
    except CertError as exc:
        out["crl_error"] = str(exc)
    try:
        from . import automation
        automation.fire("cert.revoked", {
            "cert_id": cert_id, "serial": row["serial_hex"], "reason": reason,
            "summary": f"吊销 {row['cn'] or row['subject']}（{x509util.reason_label(reason)}）"},
            actor=actor)
    except Exception:  # noqa: BLE001
        pass
    return out


def unrevoke(cert_id: int, actor: str = "admin") -> dict:
    row = db.q1("SELECT * FROM certs WHERE id=?", (cert_id,))
    if row is None:
        raise CertError("证书不存在")
    if row["status"] != "revoked":
        raise CertError("该证书当前不是吊销状态")
    with db.tx() as conn:
        conn.execute("UPDATE certs SET status='valid', revoked_at=NULL, revocation_reason=NULL, "
                     "revocation_notes=NULL, updated_at=? WHERE id=?",
                     (x509util.to_iso(x509util.now()), cert_id))
        audit.log("cert.unrevoke", target_type="cert", target_id=cert_id,
                  target_label=row["cn"] or row["subject"], actor=actor,
                  detail={"previous_reason": row["revocation_reason"],
                          "warning": "调用了非标准操作，已恢复吊销状态"}, conn=conn)
    out = {"cert": get_cert(cert_id), "crl": None}
    try:
        out["crl"] = generate_crl(actor=actor)
    except CertError as exc:
        out["crl_error"] = str(exc)
    try:
        from . import automation
        automation.fire("cert.unrevoked", {
            "cert_id": cert_id, "serial": row["serial_hex"],
            "summary": f"恢复吊销 {row['cn'] or row['subject']}"}, actor=actor)
    except Exception:  # noqa: BLE001
        pass
    return out


# ------------------------------------------------------------------ CRL
def _openssl_oneline(name: x509.Name) -> str:
    parts = []
    for attr in name:
        label = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
                 "2.5.4.7": "L", "2.5.4.8": "ST",
                 "1.2.840.113549.1.9.1": "emailAddress"}.get(attr.oid.dotted_string,
                                                             attr.oid.dotted_string)
        parts.append(f"/{label}={attr.value}")
    return "".join(parts)


def _asn1_time(dt) -> str:
    return dt.astimezone(x509util.UTC).strftime("%y%m%d%H%M%SZ")


def export_index_txt(ca_id: int, path=None) -> str:
    """从数据库派生 OpenSSL 风格的 index.txt，便于与外部工具互操作。

    subject 列直接从**证书文件**取（权威、且天然带正确转义），
    只有证书文件读不到时才退回库里存的字符串。
    注意：早期版本这里是"把库里存的 subject 字符串再解析回 Name"，
    一旦主题值里含逗号（如 O=公司, 分部）就会 ValueError，
    进而让**整个 CRL 生成失败**——已改为直接从证书取，不再做这种脆弱往返。
    """
    text = ""
    for row in db.q("SELECT * FROM certs WHERE ca_id=? ORDER BY id", (ca_id,)):
        revoked_fact = row["revoked_at"] is not None or row["status"] == "revoked"
        # 归档：仅当**没有吊销事实**时才跳过（已吊销的必须继续出现在 index.txt 里）
        if row["status"] == "archived" and not revoked_fact:
            continue
        na = x509util.parse_iso(row["not_after"])
        expired = na is not None and na < x509util.now()
        if revoked_fact:
            status, rev = "R", _asn1_time(x509util.parse_iso(row["revoked_at"]) or x509util.now())
        else:
            status, rev = ("E" if expired else "V"), ""
        subject_oneline = row["subject"]
        try:
            cert = x509util.load_cert(_path(row["cert_path"]).read_bytes())
            subject_oneline = _openssl_oneline(cert.subject)
        except Exception:  # noqa: BLE001 - 文件缺失/损坏时退回库内字符串，保证导出不中断
            pass
        text += "\t".join([status, _asn1_time(na or x509util.now()), rev,
                           row["serial_hex"].upper(), "unknown", subject_oneline]) + "\n"
    target = path or (_path(f"ca/index-{ca_id}.txt"))
    config.atomic_write_text(target, text or "")
    return text


def _next_crl_number(ca_id: int, conn=None) -> int:
    """下一个 CRL 编号。

    ``conn``：传入当前事务的连接，读号与随后的 INSERT 处在**同一事务**里，
    才能保证跨进程（服务 + CLI）不会取到同一个编号。
    """
    row = (conn.execute("SELECT number FROM crls WHERE ca_id=? ORDER BY id DESC LIMIT 1",
                        (ca_id,)).fetchone() if conn is not None
           else db.q1("SELECT number FROM crls WHERE ca_id=? ORDER BY id DESC LIMIT 1", (ca_id,)))
    nxt = int(row["number"]) + 1 if (row and str(row["number"]).isdigit()) else 1
    # 下限：接管现场 CA 时可能要"跳号"到现场已有编号之上，否则 strongSwan 会继续用旧 CRL
    try:
        floor = int(db.get_setting("crl_number_floor", "0") or 0)
    except ValueError:
        floor = 0
    return max(nxt, floor)


def generate_crl(**kwargs) -> dict:
    """生成并保存 CRL（对外入口，串行化）。见 _CRL_LOCK 的说明。"""
    with _CRL_LOCK:
        return _generate_crl_locked(**kwargs)


def _generate_crl_locked(*, ca_row: dict | None = None, validity_days: int | None = None,
                         next_update_days: int | None = None, digest: str = "sha256",
                         actor: str = "admin", source: str = "generated") -> dict:
    ca_row = ca_row or active_ca_row()
    if ca_row is None:
        raise CertError("尚未导入 CA，无法生成 CRL")
    ca_cert, ca_key, _ = load_material(ca_row)
    if ca_key is None:
        raise CertError("当前 CA 未导入私钥，无法签发 CRL。请在「CA 管理」中导入 CA 私钥。")

    days = int(validity_days or next_update_days or db.get_setting("crl_validity_days", "30"))
    this_update = x509util.now()
    next_update = this_update + x509util._dt.timedelta(days=max(1, days))

    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca_cert.subject)
               .last_update(this_update)
               .next_update(next_update)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   ca_cert.public_key()), critical=False))

    algo = _digest_for(ca_key, digest)
    # 本次生成涉及的文件（唯一名，见下）；失败时只删这些，绝不会碰到上一份有效 CRL
    tmp_files: list[Path] = []
    final_files: list[Path] = []

    # 取号 → 读吊销集合 → 签名 → 写文件 → 入库 **全部在同一个 BEGIN IMMEDIATE 事务里**：
    #   * 编号：事务外取号会让服务与 CLI 取到同一个编号（审查复现两进程都是 #2）；
    #   * 吊销集合：事务外读取会让"读到旧快照的那次生成"后插入，产生**最新 CRL 漏项**
    #     （审查复现 #2 有 1 条、随后写入的 #3 却 0 条）。
    try:
        with db.tx() as conn:
            number = _next_crl_number(ca_row["id"], conn=conn)
            # **每次生成使用独立文件名**：文件替换与数据库提交无法"跨文件原子"，
            # 固定文件名会出现"DB 指向 #4 而 PEM 已是 #5"这类错配（审查故障注入复现：
            # 第二次替换失败 → DB/DER=#4、PEM=#5；替换后审计失败 → DB=#4、DER=#5）。
            # 唯一名之后：失败只留下本次的孤儿文件（可清理），DB 行永远指向完整的一对文件。
            token = f"{ca_row['id']}-{number}-{secrets.token_hex(3)}"
            pem_rel = f"crl/ca-{token}.crl.pem"
            der_rel = f"crl/ca-{token}.crl.der"
            tmp_pem = _path(pem_rel).with_name(f".{Path(pem_rel).name}.tmp")
            tmp_der = _path(der_rel).with_name(f".{Path(der_rel).name}.tmp")
            # **吊销事实驱动**：只要吊销过就必须进 CRL，与是否归档/隐藏无关。
            revoked = conn.execute(
                "SELECT * FROM certs WHERE ca_id=? "
                "AND (revoked_at IS NOT NULL OR status='revoked') ORDER BY id",
                (ca_row["id"],)).fetchall()
            for row in revoked:
                when = x509util.parse_iso(row["revoked_at"]) or this_update
                ext = [x509.CRLReason(x509util.reason_enum(row["revocation_reason"]))]
                entry = (x509.RevokedCertificateBuilder()
                         .serial_number(int(row["serial_hex"], 16))
                         .revocation_date(when)
                         .add_extension(ext[0], critical=False)
                         .build())
                builder = builder.add_revoked_certificate(entry)
            builder = builder.add_extension(x509.CRLNumber(number), critical=False)
            crl = builder.sign(private_key=ca_key, algorithm=algo,
                               rsa_padding=_rsa_padding(ca_key))
            crl_pem = crl.public_bytes(serialization.Encoding.PEM)
            crl_der = crl.public_bytes(serialization.Encoding.DER)
            ts = x509util.to_iso(x509util.now())
            sha = hashlib.sha256(crl_der).hexdigest()
            # ① 两份文件先完整写到临时文件
            config.atomic_write(tmp_pem, crl_pem)
            tmp_files.append(tmp_pem)
            config.atomic_write(tmp_der, crl_der)
            tmp_files.append(tmp_der)
            # ② 原子改名到本次的唯一文件名（此时两份文件都已完整落盘）
            os.replace(tmp_pem, _path(pem_rel))
            final_files.append(_path(pem_rel))
            os.replace(tmp_der, _path(der_rel))
            final_files.append(_path(der_rel))
            # ③ 两个文件都就位后，才写入指向它们的数据库记录（同事务提交）
            cur = conn.execute(
                "INSERT INTO crls(number,this_update,next_update,entries,sha256,ca_id,path,"
                "der_path,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (str(number), x509util.to_iso(this_update), x509util.to_iso(next_update),
                 len(revoked), sha, ca_row["id"], pem_rel, der_rel, ts))
            crl_id = cur.lastrowid
            audit.log("crl.generate", target_type="crl", target_id=crl_id,
                      target_label=f"CRL #{number}", actor=actor,
                      detail={"entries": len(revoked), "next_update": x509util.to_iso(next_update),
                              "source": source}, conn=conn)
    except BaseException:
        # 仅事务提交之前可以回滚文件；提交后的数据库记录已经引用它们。
        for f in [*tmp_files, *final_files]:
            try:
                f.unlink()
            except OSError:
                pass
        raise

    # index.txt 是数据库的派生副本。导出失败不能撤销已提交的 CRL，
    # 也不能阻断后续发布；将失败报告给调用方，留待下一次重试。
    index_error = None
    try:
        export_index_txt(ca_row["id"])
    except Exception as exc:  # noqa: BLE001
        index_error = str(exc)
    # 只删旧文件，不动数据库行；清理失败不影响本次生成。
    try:
        _prune_old_crl_files(int(db.get_setting("crl_files_keep", "50") or 50))
    except Exception:  # noqa: BLE001
        pass

    result = {
        "id": crl_id, "number": str(number), "this_update": x509util.to_iso(this_update),
        "next_update": x509util.to_iso(next_update), "entries": len(revoked), "sha256": sha,
        "created_at": ts, "has_file": True, "ca_id": ca_row["id"],
    }
    if index_error is not None:
        result["index_error"] = index_error
    return result


def _prune_old_crl_files(keep: int = 50) -> int:
    """每个 CA 至少保留一份、至多保留最近 ``keep`` 份 CRL 文件。

    为什么需要：现在每次生成都用独立文件名（为了"文件与数据库一起一致"），
    文件会随生成次数累积；strongSwan 只关心最新一份，历史留在数据库即可。
    只删文件、不删记录，删不到就跳过（幂等）。
    """
    deleted = 0
    try:
        limit = max(1, int(keep))
        rows = db.q("SELECT ca_id, path, der_path FROM crls ORDER BY id DESC")
    except Exception:  # noqa: BLE001
        return 0
    counts: dict[int | None, int] = {}
    retained: set[str] = set()
    old = []
    for r in rows:
        ca_id = r["ca_id"]
        counts[ca_id] = counts.get(ca_id, 0) + 1
        if counts[ca_id] <= limit:
            retained.update(v for v in (r["path"], r["der_path"]) if v)
        else:
            old.append(r)
    for r in old:
        for key in ("path", "der_path"):
            v = r[key]
            if not v or v in retained:
                continue
            f = _path(v)
            try:
                if f.is_file():
                    f.unlink()
                    deleted += 1
            except OSError:
                pass
    return deleted


def current_crl() -> dict | None:
    ca_row = active_ca_row()
    row = db.q1("SELECT * FROM crls WHERE ca_id=? ORDER BY id DESC LIMIT 1",
                (ca_row["id"],)) if ca_row else db.q1(
        "SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    if row is None:
        return None
    return {"id": row["id"], "number": row["number"], "this_update": row["this_update"],
            "next_update": row["next_update"], "entries": row["entries"],
            "sha256": row["sha256"], "created_at": row["created_at"],
            "has_file": bool(row["path"] and row["der_path"]
                             and _path(row["path"]).is_file()
                             and _path(row["der_path"]).is_file()),
            "ca_id": row["ca_id"]}


def refresh_crl_and_publish(actor: str = "admin", source: str = "change") -> dict:
    """吊销状态发生变化后：重新生成 CRL，并按配置自动发布。

    统一放在这里，保证 REST 接口、批量导入、命令行三条路径行为完全一致。
    """
    out: dict = {}
    try:
        out["crl"] = generate_crl(actor=actor, source=source)
    except CertError as exc:
        out["crl_error"] = str(exc)
        return out
    if db.get_setting("auto_publish", "1") == "1":
        try:
            from . import publish as _publish
            # 吊销/导入导致的变化按"紧急"处理：不受最小重载间隔限制
            urgent = any(k in str(source).lower()
                         for k in ("revoke", "import", "expire", "cli"))
            out["publish"] = _publish.publish(
                trigger=source, reload=db.get_setting("auto_reload", "1") == "1",
                actor=actor, reload_urgent=urgent)["results"]
        except Exception as exc:  # noqa: BLE001
            out["publish_error"] = str(exc)
    return out


def import_crl(data: bytes, actor: str = "admin") -> dict:
    """导入外部 CRL，把其中的序列号在本库中标记为已吊销（数据一致性同步）。

    **必须先验证再采信**：仅按序列号匹配的话，任何用无关密钥/无关签发者伪造的 CRL
    都能把有效证书标成已吊销（审查复现）。所以：用当前 CA 证书验签 + 签发者必须匹配。
    """
    crl = x509util.load_crl(data)
    ca_row = active_ca_row()
    if ca_row is None:
        raise CertError("本库还没有 CA，无法验证 CRL 归属，拒绝导入")
    try:
        ca_cert = x509util.load_cert(_path(ca_row["cert_path"]).read_bytes())
    except Exception as exc:  # noqa: BLE001
        raise CertError(f"无法读取当前 CA 证书，拒绝导入 CRL：{exc}") from exc
    # ① 签发者必须就是本 CA（先用名称粗筛，避免用错误的证书去验签产生误导性错误）
    crl_issuer = x509util.name_to_str(crl.issuer)
    ca_subject = x509util.name_to_str(ca_cert.subject)
    if crl_issuer != ca_subject:
        raise CertError(f"CRL 签发者（{crl_issuer}）不是本 CA（{ca_subject}），拒绝导入")
    # ② 签名必须由本 CA 验证通过（这才是"内容确实由本 CA 签发且未被篡改"）
    sig_ok, sig_msg = x509util.crl_signature_ok(ca_cert, crl)
    if not sig_ok:
        raise CertError(f"CRL 签名验证失败（{sig_msg}），拒绝导入："
                        f"该文件不是本 CA 签发的 CRL，或已被篡改")
    entries = list(crl)
    updated, unknown = [], []
    with db.tx() as conn:
        for entry in entries:
            serial = format(entry.serial_number, "X")
            row = conn.execute("SELECT * FROM certs WHERE serial_hex=?", (serial,)).fetchone()
            if row is None:
                unknown.append({"serial": serial, "revoked_at": x509util.to_iso(
                    entry.revocation_date_utc if hasattr(entry, "revocation_date_utc")
                    else entry.revocation_date.replace(tzinfo=x509util.UTC))})
                continue
            if row["status"] == "revoked":
                continue
            reason = "unspecified"
            try:
                ext = entry.extensions.get_extension_for_class(x509.CRLReason)
                reason = ext.value.reason.value
            except Exception:  # noqa: BLE001
                pass
            when = entry.revocation_date_utc if hasattr(entry, "revocation_date_utc") else \
                entry.revocation_date.replace(tzinfo=x509util.UTC)
            conn.execute("UPDATE certs SET status='revoked', revoked_at=?, revocation_reason=?, "
                         "updated_at=? WHERE id=?",
                         (x509util.to_iso(when), reason,
                          x509util.to_iso(x509util.now()), row["id"]))
            updated.append({"id": row["id"], "serial": serial, "cn": row["cn"]})
        audit.log("crl.import", target_type="crl", target_label=f"{len(entries)} 条目", actor=actor,
                  detail={"matched": len(updated), "unknown": len(unknown)}, conn=conn)
    return {"updated": updated, "unknown": unknown, "entries": len(entries)}


# ------------------------------------------------------------------ 校验
def verify_cert(row: dict, ca_row: dict | None = None) -> dict:
    """验证证书是否由指定 CA 签发（签名 + 签发者匹配）。"""
    ca_row = ca_row or (get_ca(row["ca_id"]) if row.get("ca_id") else None) or active_ca_row()
    if ca_row is None:
        return {"ok": False, "reason": "没有可用的 CA"}
    try:
        cert = x509util.load_cert(_path(row["cert_path"]).read_bytes())
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"证书文件不可读: {exc}"}
    ca_cert, _, _ = load_material(ca_row)
    if cert.issuer != ca_cert.subject:
        return {"ok": False, "reason": "签发者与当前 CA 不一致"}
    try:
        cert.verify_directly_issued_by(ca_cert)
        return {"ok": True, "reason": "签名校验通过"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"签名校验失败: {exc}"}
