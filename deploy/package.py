#!/usr/bin/env python3
"""Build a clean, versioned source archive without importing the backend."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TREES = ('backend', 'frontend', 'deploy', 'tests', '.github')
TOP_FILES = ('README.md', 'SECURITY.md', 'DELIVERY.md', 'run.sh', 'requirements.txt', '.gitignore')
EXCLUDE = {'.venv', 'data', '.tmp', 'dist', '.git', '__pycache__', 'node_modules'}
SUFFIXES = {'.py', '.sh', '.js', '.css', '.html', '.svg', '.md', '.txt', '.json',
            '.yml', '.yaml', '.service', '.path', '.timer'}
PRIVATE = {'.pem', '.key', '.p12', '.pfx', '.db', '.sqlite', '.sqlite3'}


def source_files() -> dict[str, bytes]:
    files = {}
    for tree in TREES:
        directory = ROOT / tree
        if directory.is_symlink():
            raise ValueError(f'打包目录不能是符号链接：{tree}')
        for current, dirs, names in os.walk(directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDE)
            for d in dirs:
                if (Path(current) / d).is_symlink():
                    raise ValueError(f'打包目录含符号链接：{Path(current) / d}')
            for name in sorted(names):
                p = Path(current) / name
                if p.suffix == '.pyc':
                    continue
                if p.is_symlink() or p.suffix in PRIVATE or 'initial_admin_password' in name:
                    raise ValueError(f'拒绝把数据、凭据或符号链接放进发布包：{p}')
                if p.suffix not in SUFFIXES:
                    raise ValueError(f'未列入源码类型的文件，请先确认：{p}')
                files[p.relative_to(ROOT).as_posix()] = p.read_bytes()
    for name in TOP_FILES:
        p = ROOT / name
        if p.is_symlink():
            raise ValueError(f'打包文件不能是符号链接：{p}')
        if p.is_file():
            files[name] = p.read_bytes()
    for required in ('backend/server.py', 'frontend/index.html', 'deploy/install.sh',
                     'deploy/service_tools.py', 'requirements.txt', 'run.sh'):
        if required not in files:
            raise ValueError(f'发布包缺少必要文件：{required}')
    return files


def build(out: Path) -> None:
    if not (out.name.endswith('.tar.gz') or out.suffix == '.zip'):
        raise ValueError('--out 必须以 .tar.gz 或 .zip 结尾')
    files = source_files()
    files['SHA256SUMS'] = ''.join(
        f'{hashlib.sha256(blob).hexdigest()}  {name}\n'
        for name, blob in sorted(files.items())).encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.ca-package-', dir=out.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        if out.suffix == '.zip':
            with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, blob in sorted(files.items()):
                    entry = zipfile.ZipInfo('ca-dev-github-public/' + name)
                    entry.create_system = 3
                    entry.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(entry, blob)
        else:
            with tarfile.open(tmp, 'w:gz') as archive:
                for name, blob in sorted(files.items()):
                    entry = tarfile.TarInfo('./' + name)
                    entry.size = len(blob)
                    entry.mode = 0o755 if name.endswith('.sh') else 0o644
                    entry.mtime = 0
                    archive.addfile(entry, io.BytesIO(blob))
        tmp.chmod(0o644)
        tmp.replace(out)
    finally:
        tmp.unlink(missing_ok=True)
    print(f'已生成：{out}\n文件数：{len(files)}\nSHA256：{hashlib.sha256(out.read_bytes()).hexdigest()}')


def main() -> int:
    version = re.search(r'^VERSION = "([0-9.]+)"$',
                        (ROOT / 'backend/config.py').read_text(), re.M).group(1)
    parser = argparse.ArgumentParser(description='生成干净的完整源码包（含 SHA256SUMS）')
    parser.add_argument('--out', type=Path, default=Path(os.environ.get('CA_PKG_DIR', ROOT / 'dist'))
                        / f'ca-dev-{version}-{dt.datetime.now(dt.timezone.utc):%Y%m%d-%H%M%S}.tar.gz')
    args = parser.parse_args()
    try:
        build(args.out.resolve())
    except (ValueError, OSError) as exc:
        parser.exit(1, f'打包失败：{exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
