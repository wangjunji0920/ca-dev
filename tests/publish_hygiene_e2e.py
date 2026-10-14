"""发布目标"卫生"：默认只写一份 CRL，不产生多余文件。

现场问题：/etc/swanctl 里同时出现
  · 设置驱动的直写目标（crl.der，真正在用的那份）
  · 建议目标里的 PEM/legacy 变体（example-ca.crl.pem、example-ca.crt.pem）
同一 CA 多份 CRL/CA 证书 → charon 的 CRL 选择不确定（编号更大的旧 CRL 会遮蔽新 CRL，
表现为"吊销了但重连照样通过"）。本测试锁定新行为：

  1) 首次安装只在"设置指定的 strongSwan 目录"里创建一个 CRL 目标（默认 crl.der）；
  2) 不自动创建 .crl.pem / .crt / CA 证书 等建议变体；
  3) x509ca 默认不写任何文件（publish_ca_cert 默认关）；
  4) 发布一次后，strongSwan 目录里只有配置的那一个文件；
  5) 已有目标时 ensure_default_targets 不会重建被删掉的目标；
  6) cli targets 能列出目标，--prune-unused 能停用目录不存在的目标。
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CA_RELOAD_CMD", "true")

PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="pubhygiene-"))
DATA = TMP / "data"
DATA.mkdir(parents=True, exist_ok=True)
os.environ["CA_DATA_DIR"] = str(DATA)
SWAN = TMP / "swanctl"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def main() -> int:
    for d in ("x509crl", "x509ca"):
        (SWAN / d).mkdir(parents=True, exist_ok=True)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from backend import ca, config, consistency, db, publish, server, x509util

    config.RUN_AS_ROOT = True
    config.MANAGE_STRONGSWAN = True
    server.bootstrap(verbose=False)
    for k, v in (("swanctl_dir", str(SWAN)), ("swanctl_crl_dir", str(SWAN / "x509crl")),
                 ("swanctl_ca_dir", str(SWAN / "x509ca"))):
        db.set_setting(k, v)

    print("\n\033[1m== 1) 首次安装创建哪些目标 ==\033[0m")
    with db.tx() as c:
        c.execute("DELETE FROM publish_targets")
    publish.ensure_default_targets()
    targets = publish.list_targets()
    in_swan = [t for t in targets if str(t["path"]).startswith(str(SWAN))]
    check("strongSwan 目录里只自动创建一个目标", len(in_swan) == 1,
          str([(t["path"], t["filename"]) for t in in_swan]))
    check("该目标是启用状态", bool(in_swan) and in_swan[0]["enabled"] == 1)
    check("文件名是设置里的 crl.der", bool(in_swan) and in_swan[0]["filename"] == "crl.der",
          str(in_swan[0]["filename"]) if in_swan else "")
    check("没有自动创建 CA 证书目标（publish_ca_cert 默认关）",
          not any(t.get("content") == "ca_cert" and str(t["path"]).startswith(str(SWAN))
                  for t in targets),
          str([(t["path"], t["filename"]) for t in targets]))
    check("没有 .crl.pem 之类的建议变体落在 strongSwan 目录",
          not any(str(t["path"]).startswith(str(SWAN)) and t["filename"].endswith(".pem")
                  for t in targets),
          str([t["filename"] for t in in_swan]))

    print("\n\033[1m== 2) 发布一次后目录里只有配置的文件 ==\033[0m")
    kk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hygiene CA")])
    now = x509util.now()
    cc = (x509.CertificateBuilder().subject_name(nn).issuer_name(nn).public_key(kk.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now)
          .not_valid_after(now + dt.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(kk, hashes.SHA256()))
    row = ca.import_ca(x509util.pem_cert(cc).encode(), x509util.pem_key(kk).encode())
    cert = ca.issue_certificate(ca_row=row, vpn_identity="h.example.com", cn="h1")["cert"]
    ca.revoke(cert["id"], reason="key_compromise")
    ca.generate_crl(actor="t", source="t")
    publish.publish(trigger="t", reload=False)
    crl_files = sorted(f.name for f in (SWAN / "x509crl").iterdir())
    ca_files = sorted(f.name for f in (SWAN / "x509ca").iterdir())
    check("x509crl 里只有 crl.der", crl_files == ["crl.der"], str(crl_files))
    check("x509ca 里没有被写入任何文件", ca_files == [], str(ca_files))

    print("\n\033[1m== 2.5) 暂存 DER/PEM 并存与过期目标修复 ==\033[0m")
    staging_targets = [t for t in publish.list_targets()
                       if t["path"] == str(publish.STAGING_DIR)
                       and (t.get("content") or "crl") == "crl"]
    pem = next(t for t in staging_targets if t["format"] == "pem")
    der = next(t for t in staging_targets if t["format"] == "der")
    publish.update_target(pem["id"], {"enabled": 1})
    pem_file = publish.STAGING_DIR / pem["filename"]
    pem_file.write_bytes(b"stale CRL")
    before = consistency.check()
    check("体检能发现启用的 PEM 暂存目标内容陈旧",
          any(i["code"] == "crl_target_mismatch" and i["extra"]["target_id"] == pem["id"]
              for i in before["issues"]) and before["summary"]["error"] > 0)
    old_number = ca.current_crl()["number"]
    repaired = consistency.repair(["crl_target_mismatch"], actor="t")
    check("一键修复重发旧 PEM 且不生成新编号",
          pem_file.read_bytes() == publish.payload_bytes(pem)
          and ca.current_crl()["number"] == old_number
          and any(r["code"] == "crl_target_mismatch" and "result" in r
                  for r in repaired["repaired"]))
    check("DER/PEM 均为最新且体检不再报目标不同步",
          (publish.STAGING_DIR / der["filename"]).read_bytes() == publish.payload_bytes(der)
          and not [i for i in consistency.check()["issues"]
                   if i["code"] in ("crl_target_mismatch", "crl_target_missing")])
    db.set_setting("crl_format", "pem")
    env = dict(os.environ)
    plan = subprocess.run([PY, "-m", "backend.cli", "sync-plan", "--staging",
                           str(publish.STAGING_DIR)], cwd=ROOT, env=env,
                          capture_output=True, text=True)
    check("同步计划选择配置的 PEM 暂存文件",
          plan.returncode == 0 and str(pem_file) + "\t" in plan.stdout,
          plan.stdout[-200:])
    db.set_setting("crl_format", "der")

    print("\n\033[1m== 3) 删掉的目标不会被重建 ==\033[0m")
    for t in publish.list_targets():
        if str(t["path"]).startswith(str(SWAN)):
            publish.delete_target(t["id"])
    publish.ensure_default_targets()          # 升级/重启/发布时都会走到它
    check("已有其它目标时不再自动补建 strongSwan 目标",
          not [t for t in publish.list_targets() if str(t["path"]).startswith(str(SWAN))],
          str([t["filename"] for t in publish.list_targets()]))
    check("原有目标仍然保留（表非空即短路）", len(publish.list_targets()) >= 1)

    print("\n\033[1m== 3.5) 硬护栏：同目录第二份 CRL 会被跳过 ==\033[0m")
    # 模拟"数据库里残留历史目标"（文件名不同、但同一目录同一内容）
    good = publish.create_target({"name": "设置指定的 CRL", "kind": "dir_file",
                                  "path": str(SWAN / "x509crl"), "filename": "crl.der",
                                  "format": "der", "content": "crl", "enabled": True})
    legacy = publish.create_target({"name": "历史遗留 CRL(PEM)", "kind": "dir_file",
                                    "path": str(SWAN / "x509crl"),
                                    "filename": "example-ca.crl.pem",
                                    "format": "pem", "content": "crl", "enabled": True})
    ca_legacy = publish.create_target({"name": "历史遗留 CA 证书", "kind": "dir_file",
                                       "path": str(SWAN / "x509ca"),
                                       "filename": "example-ca.crt.pem",
                                       "format": "pem", "content": "ca_cert",
                                       "enabled": True})
    ca.issue_certificate(ca_row=row, vpn_identity="h2.example.com", cn="h2")
    ca.generate_crl(actor="t", source="t")
    pub2 = publish.publish(trigger="t", reload=False)
    by_id = {r["target_id"]: r for r in pub2["results"]}
    check("设置指定的目标照常写入", by_id[good["id"]]["ok"] and not by_id[good["id"]].get("skipped"))
    check("同目录的历史 CRL 目标被跳过（不再产生第二个文件）",
          by_id[legacy["id"]].get("skipped") and by_id[legacy["id"]].get("shadow_guard"),
          str(by_id[legacy["id"]])[:160])
    check("跳过原因说明是「避免选择不确定」并给出处置",
          "不确定" in by_id[legacy["id"]]["message"] and "keep-single" in by_id[legacy["id"]]["message"],
          by_id[legacy["id"]]["message"][:160])
    crl_files2 = sorted(f.name for f in (SWAN / "x509crl").iterdir())
    check("目录里始终只有 crl.der", crl_files2 == ["crl.der"], str(crl_files2))
    check("CA 证书目标被设置拦住（publish_ca_cert=0 → 目录里没有 .crt.pem）",
          sorted(f.name for f in (SWAN / "x509ca").iterdir()) == [],
          str(sorted(f.name for f in (SWAN / "x509ca").iterdir())))
    check("该目标给出可执行的说明（勾选 / 停用）",
          by_id[ca_legacy["id"]].get("skipped")
          and "publish_ca_cert" in by_id[ca_legacy["id"]]["message"],
          str(by_id.get(ca_legacy["id"]))[:160])

    print("\n\033[1m== 3.6) cli targets --keep-single 持久化清理 ==\033[0m")
    env = dict(os.environ)
    r = subprocess.run([PY, "-m", "backend.cli", "targets", "--keep-single"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    check("--keep-single 执行成功并停用了多余目标",
          r.returncode == 0 and "已停用" in r.stdout, r.stdout[-200:])
    still_on = [t for t in publish.list_targets()
                if t["enabled"] and str(t["path"]).startswith(str(SWAN))]
    check("同一目录只剩一个启用目标",
          len([t for t in still_on if (t.get("content") or "crl") == "crl"]) == 1,
          str([(t["filename"], t["content"]) for t in still_on]))
    check("--keep-single 保留暂存目录的 DER 和 PEM",
          all(publish.get_target(t["id"])["enabled"] for t in (der, pem)))
    publish.delete_target(ca_legacy["id"])

    print("\n\033[1m== 4) cli targets / --prune-unused ==\033[0m")
    publish.create_target({"name": "目录不存在的目标", "kind": "dir_file",
                           "path": str(TMP / "does-not-exist"), "filename": "x.crl",
                           "format": "der", "content": "crl", "enabled": True})
    env = dict(os.environ)
    r = subprocess.run([PY, "-m", "backend.cli", "targets"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    check("cli targets 列出目标（含路径与文件名）",
          r.returncode == 0 and "does-not-exist" in r.stdout, r.stdout[-200:])
    r = subprocess.run([PY, "-m", "backend.cli", "targets", "--prune-unused"], cwd=ROOT,
                       env=env, capture_output=True, text=True)
    check("--prune-unused 停用目录不存在的目标",
          r.returncode == 0 and "停用" in r.stdout, r.stdout[-200:])
    bad = [t for t in publish.list_targets() if t["filename"] == "x.crl"]
    check("该目标确实变为停用", bool(bad) and bad[0]["enabled"] == 0,
          str(bad)[:120])

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
