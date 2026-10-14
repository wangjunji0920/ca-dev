#!/usr/bin/env bash
# ============================================================================
#  把 CA 管理系统「发布暂存目录」里的 CRL / CA 证书同步进 strongSwan 并重载。
#
#  为什么需要它：CA 服务以普通用户运行（不该用 root 跑 Web 服务），
#  没有权限写 /etc/swanctl；由本脚本（root）完成同步与 strongSwan 重载。
#
#  由 systemd 的 ca-strongswan-sync.path 在暂存目录变化时自动触发，
#  也可由 ca-strongswan-sync.timer 定期兜底，或手动执行：
#      sudo /usr/local/sbin/ca-strongswan-sync.sh
# ============================================================================
set -euo pipefail

STAGING=__STAGING__
STAGING="${CA_STAGING:-$STAGING}"
SWANCTL_DIR="${SWANCTL_DIR:-/etc/swanctl}"
# 由 install.sh / upgrade.sh 在安装时替换为实际路径（也可用环境变量覆盖，便于测试）
BASE_DIR=__BASE_DIR__
BASE_DIR="${CA_BASE_DIR:-$BASE_DIR}"
PY=__PY__
PY="${CA_PY:-$PY}"
export CA_DATA_DIR="${CA_DATA_DIR:-$(dirname "$STAGING")}"
[ -x "$PY" ] || PY="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"

# CA_ALLOW_NONROOT=1 仅用于自动化测试（在临时目录里跑，不碰真实 /etc/swanctl）
if [ "$(id -u)" != "0" ] && [ "${CA_ALLOW_NONROOT:-0}" != "1" ]; then
  echo "请用 root 运行： sudo $0" >&2
  exit 1
fi
if [ ! -d "$STAGING" ]; then
  echo "暂存目录不存在：$STAGING（先在管理界面发布一次 CRL）" >&2
  exit 1
fi

install -d -m 0755 "$SWANCTL_DIR/x509crl" "$SWANCTL_DIR/x509ca"

# 只拷贝"设置里指定的那一个文件"：由后端 sync-plan 给出映射（src<TAB>dst）。
# 以前这里是 `for f in "$STAGING"/*` 按内容分类全拷 —— 结果暂存目录里的
# example-ca.crl / .crl.pem / .crt.pem 三个副本被逐个拷进 strongSwan，
# 同一 CA 出现多份 CRL → charon 只保留编号最大的那份，"用哪一份"不确定 → 吊销失效。
reload_needed=0
copied=0
if [ ! -d "$BASE_DIR/backend" ] || [ ! -x "$PY" ]; then
  echo "找不到项目目录或 python（BASE_DIR=$BASE_DIR PY=$PY）。" >&2
  echo "为安全起见不做任何拷贝（旧版本扫全目录会把同 CA 的多份 CRL 拷进 strongSwan）。" >&2
  exit 0
fi
PLAN="$(cd "$BASE_DIR" && "$PY" -m backend.cli sync-plan --staging "$STAGING" 2>/dev/null | grep -v '^#' || true)"
if [ -z "$(printf '%s' "$PLAN" | tr -d '[:space:]')" ]; then
  echo "没有需要同步的文件（sync-plan 为空）：请检查发布目标与 CRL 设置" >&2
  exit 0
fi
reload_needed=0
copied=0
# here-string：在**当前 shell**里循环，计数器才有效（管道会进子 shell）
while IFS="$(printf '\t')" read -r src dst; do
  [ -n "$src" ] && [ -n "$dst" ] || continue
  [ -f "$src" ] || continue
  install -d -m 0755 "$(dirname "$dst")"
  if [ ! -f "$dst" ] || ! cmp -s "$src" "$dst"; then reload_needed=1; fi
  install -m 0644 "$src" "$dst"
  copied=$((copied + 1))
done <<< "$PLAN"

if [ "$copied" = "0" ]; then
  echo "暂存目录里没有 CRL/CA 文件：$STAGING" >&2
  exit 0
fi

if [ "$reload_needed" = "0" ]; then
  echo "CRL/CA 内容未变化，跳过重载（$(date -Is)）"
  exit 0
fi

# 重载命令以"设置里的 crl_reload_cmd"为唯一来源（默认含 restart，见 config.DEFAULT_RELOAD_CMD）
RELOAD_CMD="$(cd "$BASE_DIR" && "$PY" -m backend.cli reload-cmd --print 2>/dev/null || true)"
if [ -z "$RELOAD_CMD" ]; then
  RELOAD_CMD="swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan"
fi
if command -v swanctl >/dev/null 2>&1 || command -v systemctl >/dev/null 2>&1; then
  # 失败不阻断同步（文件已经就位）
  sh -c "$RELOAD_CMD" || echo "重载命令返回非 0（$RELOAD_CMD），文件已就位" >&2
elif command -v ipsec >/dev/null 2>&1; then
  ipsec rereadcrls || true
  ipsec rereadcacerts || true
else
  echo "未找到 swanctl / ipsec / systemctl，已同步文件但未重载 strongSwan" >&2
fi

echo "已同步 CRL/CA 至 $SWANCTL_DIR 并重载：$(date -Is)"
