#!/usr/bin/env bash
# 完整源码归档（tar.gz 或 zip），带文件校验清单；不包含运行数据。
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 "$BASE_DIR/deploy/package.py" "$@"
