"""备份与恢复。

* 备份内容：SQLite 快照（用官方 backup API，保证热备份一致）+ CA 证书/私钥 + 已签发证书
  + CRL + 发布暂存 + 配置，统一打包成 tar.gz，并附 ``manifest.json``（含校验和）。
* 恢复：先自动做一次“恢复前备份”，再把归档解到临时目录校验，最后在全局锁内替换数据文件，
  避免运行中的连接指向已被替换的旧文件。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path

from . import audit, ca, config, db, x509util
from .x509util import CertError

INCLUDE_DIRS = ("ca", "certs", "crl", "publish")
ARCHIVE_PREFIX = "ca-data"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sqlite_snapshot(dest: Path) -> None:
    """用 SQLite 在线备份 API 生成一致性快照。"""
    with db.locked():
        src = db.connect()
        tmp = sqlite3.connect(dest)
        try:
            src.backup(tmp)
            tmp.commit()
        finally:
            tmp.close()


def create(name: str | None = None, actor: str = "admin") -> dict:
    config.ensure_dirs()
    stamp = x509util.now().strftime("%Y%m%d-%H%M%S")
    label = "".join(ch for ch in (name or "") if ch.isalnum() or ch in "-_")[:40]
    filename = f"ca-backup-{stamp}{'-' + label if label else ''}.tar.gz"
    dest = config.BACKUP_DIR / filename

    with tempfile.TemporaryDirectory(dir=config.TMP_DIR) as tmpdir:
        stage = Path(tmpdir)
        _sqlite_snapshot(stage / "ca.db")
        manifest = {
            "app": config.APP_NAME,
            "version": config.VERSION,
            "data_dir": str(config.DATA_DIR),
            "created_at": x509util.to_iso(x509util.now()),
            "created_by": actor,
            "counts": {
                "cas": db.scalar("SELECT COUNT(*) FROM cas"),
                "certs": db.scalar("SELECT COUNT(*) FROM certs"),
                "crls": db.scalar("SELECT COUNT(*) FROM crls"),
                "audit": db.scalar("SELECT COUNT(*) FROM audit"),
            },
            "active_ca": None,
            "files": {},
        }
        ca_row = ca.active_ca_row()
        if ca_row:
            manifest["active_ca"] = {"subject": ca_row["subject"],
                                     "fingerprint_sha256": ca_row["fingerprint"],
                                     "has_key": bool(ca_row["has_key"])}
        manifest["files"]["ca.db"] = _sha256(stage / "ca.db")

        for d in INCLUDE_DIRS:
            src_dir = config.DATA_DIR / d
            if not src_dir.exists():
                continue
            for p in src_dir.rglob("*"):
                if not p.is_file():
                    continue
                rel = Path(d) / p.relative_to(src_dir)
                target = stage / ARCHIVE_PREFIX / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, target)
                manifest["files"][str(Path(ARCHIVE_PREFIX) / rel)] = _sha256(target)

        (stage / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        tmp_out = dest.with_suffix(".tmp")
        with tarfile.open(tmp_out, "w:gz") as tar:
            for p in sorted(stage.rglob("*")):
                if p.is_file():
                    tar.add(p, arcname=str(p.relative_to(stage)))
        os.replace(tmp_out, dest)

    info = {"name": filename, "size": dest.stat().st_size,
            "created": x509util.to_iso(x509util.now()),
            "path": str(dest), "manifest": manifest}
    audit.log("backup.create", target_type="backup", target_label=filename, actor=actor,
              detail={"size": info["size"], "counts": manifest["counts"]})
    return info


def list_backups() -> list[dict]:
    config.ensure_dirs()
    out = []
    for p in sorted(config.BACKUP_DIR.glob("ca-backup-*.tar.gz"), reverse=True):
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size,
                    "created": x509util.to_iso(x509util._dt.datetime.fromtimestamp(
                        st.st_mtime, tz=x509util.UTC))})
    return out


def resolve_backup(name: str) -> Path:
    safe = Path(name).name
    path = config.BACKUP_DIR / safe
    if not path.exists() or not path.is_file():
        raise CertError(f"备份文件不存在: {safe}")
    if not path.name.startswith("ca-backup-") or path.suffix != ".gz":
        raise CertError("非法的备份文件名")
    return path


def restore(name_or_path: str, actor: str = "admin", make_safety_backup: bool = True) -> dict:
    path = resolve_backup(name_or_path) if not os.path.isabs(str(name_or_path)) \
        else Path(name_or_path)
    if not path.exists():
        raise CertError(f"备份文件不存在: {path}")

    safety = create(name="pre-restore", actor=actor) if make_safety_backup else None

    with tempfile.TemporaryDirectory(dir=config.TMP_DIR) as tmpdir:
        stage = Path(tmpdir)
        try:
            with tarfile.open(path, "r:gz") as tar:
                _safe_extract(tar, stage)
        except (tarfile.TarError, EOFError, OSError) as exc:
            # 截断/损坏/非 gzip 的上传文件必须变成可读错误，
            # 否则异常会冒到 API 层变成 500 + 堆栈（CLI 也会打印 traceback）。
            import zlib
            if isinstance(exc, zlib.error):
                reason = "解压失败"
            else:
                reason = str(exc) or type(exc).__name__
            raise CertError(f"备份文件已损坏或不是有效的归档（{reason}）") from exc
        manifest_file = stage / "manifest.json"
        if not manifest_file.exists():
            raise CertError("备份文件缺少 manifest.json，可能不是本系统生成的归档")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        db_snapshot = stage / "ca.db"
        if not db_snapshot.exists():
            raise CertError("备份文件缺少 ca.db")
        # 校验完整性
        for rel, expected in (manifest.get("files") or {}).items():
            if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts:
                raise CertError(f"备份清单包含非法路径: {rel}")
            f = (stage / rel).resolve()
            try:
                f.relative_to(stage.resolve())
            except ValueError as exc:
                raise CertError(f"备份清单包含非法路径: {rel}") from exc
            if not f.is_file():
                raise CertError(f"备份文件不完整，缺少 {rel}")
            if _sha256(f) != expected:
                raise CertError(f"备份文件校验失败（内容被篡改或损坏）: {rel}")

        # 校验快照可读
        test = sqlite3.connect(db_snapshot)
        try:
            test.execute("SELECT COUNT(*) FROM certs").fetchone()
        except sqlite3.Error as exc:
            raise CertError(f"备份中的数据库无法读取: {exc}") from exc
        finally:
            test.close()

        # 在另一台机器或不同数据目录恢复时，重定位原数据目录内的发布目标。
        # /etc/swanctl 等外部目标保持原路径；旧归档没有 data_dir 时保持兼容。
        previous_dir = manifest.get("data_dir")
        if isinstance(previous_dir, str) and previous_dir:
            old_base = Path(previous_dir).resolve()
            new_base = config.DATA_DIR.resolve()
            if old_base != new_base:
                with closing(sqlite3.connect(db_snapshot)) as snapshot:
                    with snapshot:
                        for target_id, target_path in snapshot.execute(
                                "SELECT id, path FROM publish_targets WHERE kind='dir_file'"):
                            if not target_path or not Path(target_path).is_absolute():
                                continue
                            try:
                                subpath = Path(target_path).resolve().relative_to(old_base)
                            except ValueError:
                                continue
                            snapshot.execute("UPDATE publish_targets SET path=? WHERE id=?",
                                             (str(new_base / subpath), target_id))

        with db.locked():
            db.close()
            # 回滚点：把当前材料目录改名保留，替换失败可还原
            rollback: list[tuple[Path, Path]] = []
            # 回滚点：现网数据库也要先改名保留 —— 审查发现：旧实现直接 os.replace 覆盖，
            # 之后材料替换若失败，异常处理只还原材料目录，**数据库仍是备份里的旧值**
            # （表现为"恢复失败，但设置被悄悄回退"）。
            db_old: Path | None = None
            try:
                config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                for suffix in ("-wal", "-shm"):
                    p = Path(str(config.DB_PATH) + suffix)
                    if p.exists():
                        p.unlink()
                if config.DB_PATH.exists():
                    db_old = config.DB_PATH.with_name(config.DB_PATH.name + ".old-restore")
                    if db_old.exists():
                        db_old.unlink()
                    os.replace(config.DB_PATH, db_old)
                os.replace(db_snapshot, config.DB_PATH)
                src_root = stage / ARCHIVE_PREFIX
                for d in INCLUDE_DIRS:
                    live = config.DATA_DIR / d
                    backup_dir = stage / f".old-{d}"
                    if live.exists():
                        os.replace(live, backup_dir)
                        rollback.append((live, backup_dir))
                    incoming = src_root / d
                    if incoming.exists():
                        os.replace(incoming, live)
                    else:
                        live.mkdir(parents=True, exist_ok=True)
            except BaseException:
                for live, backup_dir in rollback:
                    if live.exists():
                        shutil.rmtree(live, ignore_errors=True)
                    if backup_dir.exists():
                        os.replace(backup_dir, live)
                # 数据库一并回滚到恢复前的那份（否则设置/数据被备份里的旧值覆盖）
                try:
                    if config.DB_PATH.exists():
                        config.DB_PATH.unlink()
                    if db_old is not None and db_old.exists():
                        os.replace(db_old, config.DB_PATH)
                    for suffix in ("-wal", "-shm"):
                        p = Path(str(config.DB_PATH) + suffix)
                        if p.exists():
                            p.unlink()
                except OSError:
                    pass
                raise
            finally:
                db.init_db()  # 重新建立连接与表结构
                if db_old is not None and db_old.exists():
                    try:
                        db_old.unlink()      # 成功恢复：删除保留的旧库
                    except OSError:
                        pass
                try:
                    cleanup = sqlite3.connect(config.DB_PATH)
                    cleanup.execute("PRAGMA journal_mode=WAL")
                    cleanup.close()
                except sqlite3.Error:
                    pass

    counts = {"cas": db.scalar("SELECT COUNT(*) FROM cas"),
              "certs": db.scalar("SELECT COUNT(*) FROM certs")}
    audit.log("backup.restore", target_type="backup", target_label=path.name, actor=actor,
              detail={"counts": counts, "safety_backup": (safety or {}).get("name")})
    return {"ok": True, "restored": path.name, "counts": counts,
            "safety_backup": (safety or {}).get("name")}


MAX_EXTRACT_BYTES = int(os.environ.get("CA_MAX_RESTORE_BYTES", str(4 * 1024 * 1024 * 1024)))


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """防止路径穿越（../ 或绝对路径）、链接攻击，以及解压炸弹。"""
    base = dest.resolve()
    total = 0
    for member in tar.getmembers():
        total += max(0, int(member.size or 0))
        if total > MAX_EXTRACT_BYTES:
            raise CertError("备份归档解压后过大，已中止（可能是损坏或恶意归档）")
        if member.isfile() and int(member.size or 0) > MAX_EXTRACT_BYTES:
            raise CertError(f"备份归档中的文件过大: {member.name}")
    for member in tar.getmembers():
        if not (member.isfile() or member.isdir()):
            raise CertError(f"备份归档包含非法类型: {member.name}")
        if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
            raise CertError(f"备份归档包含非法路径: {member.name}")
        target = (dest / member.name).resolve()
        try:
            target.relative_to(base)
        except ValueError:
            raise CertError(f"备份归档包含非法路径: {member.name}")
    tar.extractall(dest)


def delete_backup(name: str, actor: str = "admin") -> dict:
    path = resolve_backup(name)
    path.unlink()
    audit.log("backup.delete", target_type="backup", target_label=path.name, actor=actor)
    return {"ok": True, "name": path.name}
