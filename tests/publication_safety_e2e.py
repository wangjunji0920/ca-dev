"""公开发布前的路径边界和默认监听回归测试（无需网络或真实 CA）。"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    from backend import backup, config, publish, server
    from backend.api import ApiError
    from backend.x509util import CertError

    checks: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="public-safety-") as temp:
        base = Path(temp)
        frontend = base / "frontend"
        frontend.mkdir()
        (frontend / "app.js").write_text("public script")
        sibling = base / "frontend-private"
        sibling.mkdir()
        (sibling / "secret.txt").write_text("dummy secret")
        (frontend / "link.txt").symlink_to(sibling / "secret.txt")
        old_frontend = config.FRONTEND_DIR
        config.FRONTEND_DIR = frontend
        try:
            handler = object.__new__(server.Handler)
            handler.headers = {}
            checks.append(("正常前端文件可读取",
                           handler._handle_static("/app.js", None).body == b"public script"))
            for path in ("/../frontend-private/secret.txt", "/link.txt"):
                try:
                    handler._handle_static(path, None)
                    rejected = False
                except ApiError as exc:
                    rejected = exc.status == 404
                checks.append((f"前端文件边界拒绝 {path}", rejected))
        finally:
            config.FRONTEND_DIR = old_frontend

        archive = base / "escape.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            item = tarfile.TarInfo("../stage-private/secret.txt")
            blob = b"dummy secret"
            item.size = len(blob)
            tar.addfile(item, io.BytesIO(blob))
        stage = base / "stage"
        stage.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            try:
                backup._safe_extract(tar, stage)
                rejected = False
            except CertError:
                rejected = True
        checks.append(("恢复归档不能写入同名前缀的相邻目录",
                       rejected and not (base / "stage-private").exists()))

        old_data = config.DATA_DIR
        config.DATA_DIR = base / "data"
        try:
            checks.append(("数据目录边界拒绝同名前缀的相邻目录",
                           publish._within_data(base / "data" / "publish")
                           and not publish._within_data(base / "data-private")))
        finally:
            config.DATA_DIR = old_data

        env = dict(os.environ)
        env.pop("CA_HOST", None)
        proc = subprocess.run([sys.executable, "-c",
                               "from backend import config; print(config.HOST)"],
                              cwd=ROOT, env=env, capture_output=True, text=True)
        checks.append(("未指定监听地址时只监听回环",
                       proc.returncode == 0 and proc.stdout.strip() == "127.0.0.1"))

    for label, ok in checks:
        print(f"{'✓' if ok else '✗'} {label}")
    print(f"通过 {sum(ok for _, ok in checks)}/{len(checks)} 项")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
