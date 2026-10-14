#!/usr/bin/env bash
# 前台启动 CA 证书管理系统（开发/临时运行用）。
# 正式部署请用 deploy/install.sh --systemd 或 deploy/ca-admin-user.service。
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$BASE_DIR/.venv/bin/python"
[ -x "$PY" ] || { echo "缺少 .venv，请先执行 ./deploy/install.sh" >&2; exit 1; }

# 本地前台运行默认只监听回环，避免误把管理端口暴露到局域网；
# 正式部署默认也只监听回环；如需开放网络须显式配置受保护的传输。
export CA_HOST="${CA_HOST:-127.0.0.1}"
export CA_PORT="${CA_PORT:-9443}"
export CA_DATA_DIR="${CA_DATA_DIR:-$BASE_DIR/data}"
export CA_TLS="${CA_TLS:-off}"
export CA_LEGACY_API="${CA_LEGACY_API:-loopback}"

cd "$BASE_DIR"
echo "启动 CA 管理系统： http://$CA_HOST:$CA_PORT/  （数据目录 $CA_DATA_DIR）"
exec "$PY" -m backend.server
