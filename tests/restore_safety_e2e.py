"""备份/恢复安全性验收：**失败的恢复绝不能毁数据**。

覆盖的失败形态：
  a) 截断/损坏的 tar.gz            b) 内容被篡改（哈希不符）
  c) 恶意归档带 ../ 路径穿越        d) 缺少 manifest.json
  e) ca.db 是垃圾内容（哈希自洽）   f) 故障注入：替换过程中途失败（回滚是否完整）

每种情况都断言：
  * 恢复必须**明确报错**（不能"假装成功"）；
  * 原有数据完好：证书数量不变、CA 私钥仍可读、一致性体检仍可运行；
  * 恶意归档没有在数据目录之外写出任何文件。
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="restore-"))
os.environ["CA_DATA_DIR"] = str(TMP / "data")
EXTRA = TMP / "archives"
EXTRA.mkdir(parents=True, exist_ok=True)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def snapshot(db_module) -> dict:
    return {
        "certs": db_module.scalar("SELECT COUNT(*) FROM certs"),
        "cas": db_module.scalar("SELECT COUNT(*) FROM cas"),
        "active": (db_module.q1("SELECT cn FROM cas WHERE is_active=1") or {}).get("cn"),
    }


def make_tar(path: Path, entries: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def main() -> int:
    from backend import backup, ca, config, consistency, db, server, x509util
    from backend.x509util import CertError

    print("\n\033[1m== 准备：造数据 + 正常备份 ==\033[0m")
    server.bootstrap(verbose=False)
    # 用 drill_seed 造 CA + 3 张证书 + CRL
    import subprocess
    subprocess.run([sys.executable, str(ROOT / "tests/drill_seed.py")],
                   cwd=ROOT, env=dict(os.environ), check=True, capture_output=True)
    db.init_db()
    before = snapshot(db)
    good = backup.create(name="good", actor="test")
    check("正常备份已生成", (config.BACKUP_DIR / good["name"]).is_file())
    check("备份前数据就绪", before == {"certs": 3, "cas": 1, "active": before["active"]},
          str(before))

    def assert_intact(tag: str) -> None:
        now = snapshot(db)
        check(f"{tag}：证书/CA 数量与备份前一致",
              now["certs"] == before["certs"] and now["cas"] == before["cas"],
              f"{before} -> {now}")
        key_ok = False
        try:
            _cert, key, _chain = ca.load_material(ca.active_ca_row())
            key_ok = key is not None
        except Exception:  # noqa: BLE001
            key_ok = False
        check(f"{tag}：CA 私钥仍可读（未被打断）", key_ok)
        rep = consistency.check()
        check(f"{tag}：一致性体检仍可运行", isinstance(rep.get("issues"), list))

    # ---------------- a) 截断的归档 ----------------
    print("\n\033[1m== a) 截断/损坏的 tar.gz ==\033[0m")
    truncated = EXTRA / "ca-backup-truncated.tar.gz"
    truncated.write_bytes((config.BACKUP_DIR / good["name"]).read_bytes()[:400])
    try:
        backup.restore(str(truncated), make_safety_backup=False)
        check("截断归档必须报错", False, "竟然恢复成功了")
    except Exception as exc:  # noqa: BLE001
        check("截断归档必须报错", True)
        check("报错信息可读（不是裸 IOError）",
              isinstance(exc, CertError) or "not a gzip" in str(exc) or "ReadError" in type(exc).__name__,
              f"{type(exc).__name__}: {exc}")
    assert_intact("a")

    # ---------------- b) 内容被篡改 ----------------
    print("\n\033[1m== b) 内容被篡改（哈希不符）==\033[0m")
    import gzip
    tampered = EXTRA / "ca-backup-tampered.tar.gz"
    with tarfile.open(config.BACKUP_DIR / good["name"], "r:gz") as tar:
        members = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
    # 改一个证书文件的内容，但保持 manifest 里的哈希不变
    for name in list(members):
        if name.startswith("ca-data/certs/") and name.endswith((".crt", ".key")):
            members[name] = members[name] + b"\n# tampered\n"
            break
    make_tar(tampered, members)
    try:
        backup.restore(str(tampered), make_safety_backup=False)
        check("被篡改的归档必须报错", False, "竟然恢复成功了")
    except CertError as exc:
        check("被篡改的归档必须报错", True)
        check("错误信息指出校验失败", "校验失败" in str(exc) or "不完整" in str(exc), str(exc)[:60])
    except Exception as exc:  # noqa: BLE001
        check("被篡改的归档必须报错", False, f"错误类型不对: {type(exc).__name__}: {exc}")
    assert_intact("b")

    # ---------------- c) 路径穿越 ----------------
    print("\n\033[1m== c) 恶意归档（../ 路径穿越）==\033[0m")
    outside = TMP / "pwned.txt"
    evil = EXTRA / "ca-backup-evil.tar.gz"
    make_tar(evil, {
        "manifest.json": json.dumps({"files": {}}).encode(),
        "ca.db": b"not a db",
        "../../pwned.txt": b"pwned",
    })
    try:
        backup.restore(str(evil), make_safety_backup=False)
        check("带 ../ 的归档必须被拒", False, "竟然接受了")
    except CertError as exc:
        check("带 ../ 的归档必须被拒", True)
        check("拒绝理由提到非法路径/链接", "非法" in str(exc), str(exc)[:60])
    except Exception as exc:  # noqa: BLE001
        check("带 ../ 的归档必须被拒", False, f"{type(exc).__name__}: {exc}")
    check("恶意归档没有在数据目录之外写出文件", not outside.exists(), str(outside))
    assert_intact("c")

    # ---------------- d) 缺少 manifest ----------------
    print("\n\033[1m== d) 缺少 manifest.json ==\033[0m")
    nomani = EXTRA / "ca-backup-nomani.tar.gz"
    make_tar(nomani, {"ca.db": (config.DATA_DIR / "ca.db").read_bytes()})
    try:
        backup.restore(str(nomani), make_safety_backup=False)
        check("缺 manifest 的归档必须被拒", False, "竟然接受了")
    except CertError as exc:
        check("缺 manifest 的归档必须被拒", "manifest" in str(exc), str(exc)[:60])
    except Exception as exc:  # noqa: BLE001
        check("缺 manifest 的归档必须被拒", False, f"{type(exc).__name__}: {exc}")
    assert_intact("d")

    # ---------------- e) ca.db 是垃圾（哈希自洽） ----------------
    print("\n\033[1m== e) ca.db 内容不是数据库 ==\033[0m")
    import hashlib
    junk = b"this is definitely not sqlite"
    junkarch = EXTRA / "ca-backup-junkdb.tar.gz"
    make_tar(junkarch, {
        "manifest.json": json.dumps(
            {"files": {"ca.db": hashlib.sha256(junk).hexdigest()}}).encode(),
        "ca.db": junk,
    })
    try:
        backup.restore(str(junkarch), make_safety_backup=False)
        check("非数据库内容必须被拒", False, "竟然接受了")
    except CertError as exc:
        check("非数据库内容必须被拒", "无法读取" in str(exc) or "数据库" in str(exc), str(exc)[:60])
    except Exception as exc:  # noqa: BLE001
        check("非数据库内容必须被拒", False, f"{type(exc).__name__}: {exc}")
    assert_intact("e")

    # ---------------- f) 故障注入：替换中途失败 ----------------
    print("\n\033[1m== f) 故障注入：替换过程中途失败（回滚完整性）==\033[0m")
    # 审查指出：原测试用的是"内容与现网完全相同"的备份，所以"数据库被备份里的旧值覆盖"
    # 这种情况根本看不出来。这里先把某个设置改成与备份**不同**的值，再注入失败。
    probe_key = "crl_validity_days"
    probe_original = db.get_setting(probe_key)
    db.set_setting(probe_key, "77")
    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 3:          # 前两次成功（含 ca.db 替换 + 第一个目录），第三次炸
            raise OSError("injected failure during swap")
        return real_replace(src, dst, *a, **kw)

    os.replace = flaky_replace
    try:
        backup.restore(str(config.BACKUP_DIR / good["name"]), make_safety_backup=False)
        check("注入失败时应抛错", False, "竟然成功了")
    except Exception as exc:  # noqa: BLE001
        check("注入失败时如实抛错", True, type(exc).__name__)
    finally:
        os.replace = real_replace
        db.init_db()
    after = snapshot(db)
    check("回滚后证书数量与失败前一致（不半途而废）",
          after["certs"] == before["certs"], f"{before} -> {after}")
    check("回滚后仍有且仅有一个激活 CA",
          after["active"] == before["active"], f"{before['active']} -> {after['active']}")
    # ★ 关键：数据库必须一起回滚，否则"恢复失败"却把设置退回了备份里的旧值
    after_probe = db.get_setting(probe_key)
    check("★ 恢复失败后设置未被备份里的旧值覆盖（数据库整体回滚）",
          after_probe == "77", f"{probe_key}: 期望 77，实际 {after_probe}")
    check("★ 恢复失败后没有残留 ca.db.old-restore",
          not list(config.DATA_DIR.glob("ca.db.old-restore*")),
          str([p.name for p in config.DATA_DIR.glob("ca.db.*")]))
    db.set_setting(probe_key, probe_original)
    assert_intact("f")

    # ---------------- g) 坏归档不得覆盖正常备份 ----------------
    print("\n\033[1m== g) 恢复失败后系统仍可用 ==\033[0m")
    ok_restore = backup.restore(good["name"], make_safety_backup=True)
    check("正常备份仍可正常恢复（自愈）", ok_restore.get("ok") is True, str(ok_restore)[:80])
    check("恢复时会自动做一次恢复前备份", bool(ok_restore.get("safety_backup")))
    check("成功恢复后没有残留 ca.db.old-restore",
          not list(config.DATA_DIR.glob("ca.db.old-restore*")),
          str([p.name for p in config.DATA_DIR.glob("ca.db.*")]))

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
