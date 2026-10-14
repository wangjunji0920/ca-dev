#!/usr/bin/env bash
# ============================================================================
#  安全升级脚本（在服务器上以 root 运行）
#
#  它做这几件事，尽量不打扰你现有的数据与 strongSwan：
#    1) 先做一次完整备份（出事可回滚）
#    2) 可选：用新代码覆盖当前目录（--code /path/to/new-ca-dev）
#    3) 刷新 systemd 单元（服务 + strongSwan 同步单元）
#    4) 把已有发布目标的重载命令统一到设置值
#       默认： swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan
#    5) 默认**关掉** 30 分钟兜底定时器（避免无意义重载）；要保留就加 --with-timer
#    6) 重启服务并跑一次部署自检 doctor
#
#  用法：
#    sudo ./deploy/upgrade.sh                      # 只做升级后动作
#    sudo ./deploy/upgrade.sh --code /tmp/ca-dev-new
#    sudo ./deploy/upgrade.sh --with-timer         # 保留定时兜底
#    sudo ./deploy/upgrade.sh --no-restart         # 不重启服务（稍后手动重启）
# ============================================================================
set -Euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG_PWD="$PWD"
DATA_DIR="${CA_DATA_DIR:-$BASE_DIR/data}"
PY="$BASE_DIR/.venv/bin/python"
CODE_SRC=""
WITH_TIMER=0
DO_RESTART=1
RELOAD_CMD_DEFAULT="swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan"

while [ $# -gt 0 ]; do
  case "$1" in
    --code) CODE_SRC="$2"; shift ;;
    --with-timer) WITH_TIMER=1 ;;
    --loopback) CA_HOST_OVERRIDE="127.0.0.1" ;;   # 升级后仍只监听回环
    --force-reload-cmd) FORCE_RELOAD_CMD=1 ;;   # 强制把重载命令对齐成默认值（覆盖自定义）
    --skip-backup) SKIP_BACKUP=1 ;;             # 显式跳过升级前备份（默认必须备份成功）
    --no-restart) DO_RESTART=0 ;;
    --dry-run) DRY_RUN=1 ;;
    --data-dir) DATA_DIR="$2"; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

# --dry-run 不修改任何东西，普通用户也可以看；正式升级才要求 root
if [ "$(id -u)" != "0" ] && [ "${CA_ALLOW_NONROOT:-0}" != "1" ] \
   && [ "${DRY_RUN:-0}" != "1" ]; then
  die "请用 sudo 运行（需要写 /etc/systemd/system 与 /etc/swanctl）；只预览请加 --dry-run"
fi
[ -x "$PY" ] || die "找不到 $PY，请先执行 ./deploy/install.sh"

# 系统路径与 systemctl 可覆盖（便于在临时目录里做升级演练，不影响生产默认值）
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SBIN_DIR="${SBIN_DIR:-/usr/local/sbin}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
[ "$(id -u)" = "0" ] || SKIP_SYSTEMCTL=1
# 升级演练即便由 root 运行，也不能触碰真实 systemd。
[ "${CA_ALLOW_NONROOT:-0}" = "1" ] && SKIP_SYSTEMCTL=1
sctl() {
  if [ "${SKIP_SYSTEMCTL:-0}" = "1" ]; then
    warn "[演练：跳过 $SYSTEMCTL $*]"
    return 0
  fi
  "$SYSTEMCTL" "$@"
}

# --data-dir 相对路径按执行时所在目录解析
case "$DATA_DIR" in
  /*) : ;;
  *)  DATA_DIR="$ORIG_PWD/$DATA_DIR" ;;
esac

# 切到项目目录并设置 PYTHONPATH：脚本内部用 `python -m backend.cli`，
# 从别处执行（sudo /opt/ca-dev/deploy/upgrade.sh）时必须保证能导入本项目。
export CA_DATA_DIR="$DATA_DIR"
cd "$BASE_DIR"
export PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

# ---------------------------------------------------------------- 0. 演练
if [ "${DRY_RUN:-0}" = "1" ]; then
  say "[dry-run] 只做检查，不备份、不改代码、不动单元"
  "$PY" -m backend.cli preflight || true
  cat <<EOF

[dry-run] 正式升级会依次做：
  1) 备份到 $DATA_DIR/backups（名字含 pre-upgrade）
  2) 覆盖代码： ${CODE_SRC:-（未指定 --code，将跳过代码覆盖）}
  3) 刷新单元： $SYSTEMD_DIR/ca-admin.service、ca-strongswan-sync.{service,path,timer}
               $SBIN_DIR/ca-strongswan-sync.sh
  4) 统一发布目标的重载命令为： $RELOAD_CMD_DEFAULT
  5) 定时器策略： $([ "$WITH_TIMER" = "1" ] && echo "保留 30 分钟兜底定时器" || echo "关闭 30 分钟兜底定时器")
  6) $([ "$DO_RESTART" = "1" ] && echo "重启 ca-admin.service 并跑 doctor" || echo "不重启（--no-restart）")
  数据目录 $DATA_DIR 不会被删除；回滚用： cli backup --restore <备份文件>
EOF
  exit 0
fi

if [ "${SKIP_SYSTEMCTL:-0}" != "1" ]; then
  case "$BASE_DIR/" in /opt/*/) ;; *) die "正式部署应位于 /opt 下，请按 QUICKSTART 迁移后再升级" ;; esac
  case "$DATA_DIR/" in /home/*|/root/*|/run/*|/tmp/*|/var/tmp/*) die "数据目录不能位于沙箱隐藏/临时目录" ;; esac
  [ -d /etc/swanctl ] || die "缺少 /etc/swanctl，请先配置 swanctl"
  command -v timeout >/dev/null || die "缺少 timeout"
  timeout 10 swanctl --stats || die "swanctl/VICI 不可用，尚未升级"
  if [ -f "$SYSTEMD_DIR/ca-admin.service" ] && ! grep -qx 'User=root' "$SYSTEMD_DIR/ca-admin.service"; then
    die "此升级脚本仅支持 root 服务；非 root 部署请按安装文档单独维护，不能自动切换运行身份"
  fi
  [ "$WITH_TIMER" = 0 ] || die "root 直写模式不需要 --with-timer"
fi

# ---------------------------------------------------------------- 1. 备份
if [ "${SKIP_BACKUP:-0}" = "1" ]; then
  warn "已跳过升级前备份（--skip-backup）：出问题将无法回滚"
else
  say "升级前备份（失败可回滚）"
  if BACKUP_OUT="$("$PY" -m backend.cli backup --name "pre-upgrade" 2>&1)"; then
    say "备份完成（见 $DATA_DIR/backups）"
  else
    echo "$BACKUP_OUT" | tail -3 >&2
    # 备份失败就**不能**继续覆盖代码：否则代码变了、数据没有可回滚点
    die "升级前备份失败，已停止升级（数据目录未改动）。请排查后重试；确实要跳过：--skip-backup"
  fi
fi

# ---------------------------------------------------------------- 2. 覆盖代码
if [ -n "$CODE_SRC" ]; then
  if [ ! -d "$CODE_SRC/backend" ]; then
    # 常见原因：解包多了一层目录（把包解到了 /tmp 而不是 /tmp/ca-new），或解包失败/未完成
    echo "  $CODE_SRC 下的内容：" >&2
    ls -1 "$CODE_SRC" 2>/dev/null | head -8 | sed 's/^/    /' >&2
    # 若只有一层目录且其中有 backend/，直接提示应该用哪个路径
    for sub in "$CODE_SRC"/*/; do
      if [ -d "${sub}backend" ]; then
        die "--code 应指向 ${sub%/}（你把包解到了上一层目录）"
      fi
    done
    die "--code 指向的目录不像本项目（缺少 backend/）。请重新解包：
    rm -rf /tmp/ca-new && mkdir -p /tmp/ca-new && tar xzf <包>.tar.gz -C /tmp/ca-new
    然后确认： ls /tmp/ca-new   # 应直接看到 backend deploy frontend tests"
  fi
  say "用 $CODE_SRC 覆盖代码（保留 data/ 与 .venv/）"
  # 逐个目录"先复制到临时目录，再原子换入"，并保留 .old-* 以便失败回滚。
  # 旧实现是 rm -rf 后再 cp：中途失败会留下半个代码目录（审查指出）。
  SWAPPED=()
  rollback_code() {
    # 注意：必须能把**正在切换的那个目录**也还原 —— 旧实现只回滚已加入 SWAPPED 的目录，
    # 若 $d 已经 mv 成 .old-$d 而换入失败，$d 会缺失、.old-$d 残留（审查复现）。
    for d in "${SWAPPED[@]}"; do
      rm -rf "$BASE_DIR/$d"
      [ -d "$BASE_DIR/.old-$d" ] && mv "$BASE_DIR/.old-$d" "$BASE_DIR/$d"
    done
    # 清掉失败留下的临时目录
    for d in backend frontend deploy tests; do
      rm -rf "$BASE_DIR/.new-$d"
    done
  }
  for d in backend frontend deploy tests; do
    [ -d "$CODE_SRC/$d" ] || continue
    rm -rf "$BASE_DIR/.new-$d"
    if ! cp -a "$CODE_SRC/$d" "$BASE_DIR/.new-$d"; then
      rollback_code
      die "复制新代码失败（$d），已回滚代码目录"
    fi
    rm -rf "$BASE_DIR/.old-$d"
    if [ -d "$BASE_DIR/$d" ]; then
      if ! mv "$BASE_DIR/$d" "$BASE_DIR/.old-$d"; then
        rollback_code
        die "移开旧代码失败（$d），已回滚代码目录"
      fi
    fi
    # 先登记，再换入：这样"换入失败"时也知道要还原 $d
    SWAPPED+=("$d")
    if [ -n "${CA_UPGRADE_FAIL_SWAP:-}" ] && [ "$d" = "$CA_UPGRADE_FAIL_SWAP" ]; then
      rollback_code                     # 内部测试钩子：演练"换入失败时的回滚"
      die "换入新代码失败（$d，注入 CA_UPGRADE_FAIL_SWAP），已回滚代码目录"
    fi
    if ! mv "$BASE_DIR/.new-$d" "$BASE_DIR/$d"; then
      rollback_code
      die "换入新代码失败（$d），已回滚代码目录"
    fi
  done
  for d in "${SWAPPED[@]}"; do rm -rf "$BASE_DIR/.old-$d"; done
  [ -f "$CODE_SRC/README.md" ] && cp -a "$CODE_SRC/README.md" "$BASE_DIR/README.md"
  [ -f "$CODE_SRC/DELIVERY.md" ] && cp -a "$CODE_SRC/DELIVERY.md" "$BASE_DIR/DELIVERY.md"
  [ -f "$CODE_SRC/run.sh" ] && cp -a "$CODE_SRC/run.sh" "$BASE_DIR/run.sh"
  [ -f "$CODE_SRC/requirements.txt" ] && cp -a "$CODE_SRC/requirements.txt" "$BASE_DIR/requirements.txt"
  say "代码已更新"
fi

# ---------------------------------------------------------------- 3. 单元
say "刷新 systemd 单元"
mkdir -p "$SYSTEMD_DIR" "$SBIN_DIR"
# 升级默认沿用现有监听地址，避免原本只监听回环的服务意外暴露到网络。
# 首次没有单元时选回环；--loopback 显式覆盖现有值。
DEPLOY_HOST="${CA_HOST_OVERRIDE:-}"
if [ -z "$DEPLOY_HOST" ] && [ -f "$SYSTEMD_DIR/ca-admin.service" ]; then
  DEPLOY_HOST="$(sed -n 's/^Environment=CA_HOST=//p' "$SYSTEMD_DIR/ca-admin.service" | head -1)"
fi
DEPLOY_HOST="${DEPLOY_HOST:-127.0.0.1}"
DEPLOY_PORT="${CA_PORT:-}"
if [ -z "$DEPLOY_PORT" ] && [ -f "$SYSTEMD_DIR/ca-admin.service" ]; then
  DEPLOY_PORT="$(sed -n 's/^Environment=CA_PORT=//p' "$SYSTEMD_DIR/ca-admin.service" | head -1)"
fi
DEPLOY_PORT="${DEPLOY_PORT:-9443}"
render() {
  "$PY" "$BASE_DIR/deploy/service_tools.py" render --base "$BASE_DIR" --data "$DATA_DIR" \
    --host "$DEPLOY_HOST" --port "$DEPLOY_PORT" --user root --template "$1" --output "$2"
}
UNIT_STAGE="$(mktemp -d "$SYSTEMD_DIR/.ca-admin-verify.XXXXXX")" || die "无法创建单元校验目录"
trap 'rm -rf -- "$UNIT_STAGE"' EXIT
render "$BASE_DIR/deploy/ca-admin-root.service" "$UNIT_STAGE/ca-admin.service" || die "服务单元渲染失败"
if [ "${SKIP_SYSTEMCTL:-0}" != "1" ]; then
  systemd-analyze verify "$UNIT_STAGE/ca-admin.service" || die "服务单元校验失败，原单元保留"
fi
install -m 0644 "$UNIT_STAGE/ca-admin.service" "$SYSTEMD_DIR/ca-admin.service" || die "安装单元失败"
say "监听地址已渲染为：$DEPLOY_HOST:$DEPLOY_PORT"
render "$BASE_DIR/deploy/ca-strongswan-sync.sh" "$SBIN_DIR/ca-strongswan-sync.sh" || die "同步脚本渲染失败"
for unit in ca-strongswan-sync.service ca-strongswan-sync.path ca-strongswan-sync.timer; do
  render "$BASE_DIR/deploy/$unit" "$SYSTEMD_DIR/$unit" || die "同步单元渲染失败"
done
sctl daemon-reload || die "systemd daemon-reload 失败"
say "单元已刷新"

# ---------------------------------------------------------------- 4. 重载命令
say "检查发布目标的重载命令"
# 原则：**不覆盖用户自定义的命令**。只有"空值"或"已被写坏"（历史事故：把子命令名当命令）
# 才对齐到默认值；自定义值只提示、不动它。要强制对齐加 --force-reload-cmd。
# cli reload-cmd 输出 JSON（{"cmd": ..., "updated": [...], ...}），这里只取当前值
CUR_CMD="$("$PY" -m backend.cli reload-cmd 2>/dev/null | \
  "$PY" -c 'import json,sys
try:
    print((json.load(sys.stdin) or {}).get("cmd") or "")
except Exception:
    print("")')"
FORCE_RC="${FORCE_RELOAD_CMD:-0}"
broken=0
case "$CUR_CMD" in
  ""|"none"|"None") broken=1 ;;        # 空值：必须写入默认命令
  *reload-cmd*) broken=1 ;;            # 历史 bug：把子命令名当命令写了进去
  *) broken=0 ;;                       # 任何非空自定义值都**保留**
esac
if [ "$FORCE_RC" = "1" ] || [ "$broken" = "1" ]; then
  RC_OUT="$("$PY" -m backend.cli reload-cmd --set "$RELOAD_CMD_DEFAULT")" || {
    warn "重载命令设置失败：$RC_OUT"; }
  echo "$RC_OUT" | tail -5
  if ! echo "$RC_OUT" | grep -qF "$RELOAD_CMD_DEFAULT"; then
    die "重载命令未正确写入，请检查： cli reload-cmd  （期望：$RELOAD_CMD_DEFAULT）"
  fi
  say "已对齐重载命令：$RELOAD_CMD_DEFAULT"
else
  say "保留现有重载命令（不覆盖自定义值）：$CUR_CMD"
  say "  需要改成默认值： sudo ./deploy/upgrade.sh --code <目录> --force-reload-cmd"
fi

# ---------------------------------------------------------------- 5. 定时器
sctl disable --now ca-strongswan-sync.path 2>/dev/null || true
if [ "$WITH_TIMER" = "1" ]; then
  sctl enable --now ca-strongswan-sync.timer
  say "已保留 30 分钟兜底定时器"
else
  sctl disable --now ca-strongswan-sync.timer 2>/dev/null || true
  say "已关闭 30 分钟兜底定时器（避免无意义重载；需要时 systemctl enable --now ca-strongswan-sync.timer）"
fi

# ---------------------------------------------------------------- 6. 重启与自检
if [ "$DO_RESTART" = "1" ]; then
  say "重启服务"
  sctl enable ca-admin.service || die "ca-admin 开机启动设置失败"
  sctl restart ca-admin.service || die "ca-admin 重启失败，请检查 journalctl -u ca-admin -b -n 50"
  if [ "${SKIP_SYSTEMCTL:-0}" = "1" ]; then
    warn "[演练] 已跳过服务状态检查"
  elif ! "$PY" "$BASE_DIR/deploy/service_tools.py" ready --host "$DEPLOY_HOST" --port "$DEPLOY_PORT"; then
    journalctl -u ca-admin.service -b -n 40 --no-pager >&2 || true
    die "服务未就绪，升级未完成；请处理日志中的错误后重试，数据和升级前备份保留"
  fi
fi

say "部署自检"
CA_DATA_DIR="$DATA_DIR" CA_HOST="$DEPLOY_HOST" CA_PORT="$DEPLOY_PORT" "$PY" -m backend.cli doctor \
  || die "部署自检发现错误，升级验收未通过；请处理上面的错误后重跑"

cat <<EOF

升级完成。建议再确认三件事：
  1) 重载是否只在需要时发生：
       journalctl -u ca-admin -n 50 | grep -i reload
       tail -20 $DATA_DIR/../data/server.log 2>/dev/null || true
  2) strongSwan 侧看到新 CRL：  swanctl --list-certs
  3) 界面能登录（核对加密信道指纹）： http://127.0.0.1:$DEPLOY_PORT/（远程须 SSH 隧道）

回滚：  $PY -m backend.cli backup --restore <升级前的 ca-backup-*.tar.gz>
EOF
