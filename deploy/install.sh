#!/usr/bin/env bash
# 先检查环境，再装依赖，最后确认服务真正就绪。
set -Eeuo pipefail
umask 077
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DATA_DIR="${CA_DATA_DIR:-$BASE_DIR/data}"
HOST="${CA_HOST:-127.0.0.1}"
PORT="${CA_PORT:-9443}"
WITH_SYSTEMD=0
WITH_TIMER=0
DRY_RUN=0
SERVICE_USER="${CA_SERVICE_USER:-root}"
SERVICE_UNIT="ca-admin-root.service"
PIP_INDEX=""
STRONGSWAN_SERVICE="strongswan"
PHASE="参数检查"
say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'rc=$?; printf "[✗] %s失败（退出码 %s），安装未完成。\n" "$PHASE" "$rc" >&2; exit "$rc"' ERR
trap 'printf "\n安装已中断，现有数据没有被删除；排错后可重跑。\n" >&2; exit 130' INT
help() {
  cat <<'EOF'
用法：
  sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua
  sudo ./deploy/install.sh --systemd --loopback --dry-run
  ./deploy/install.sh --loopback                 # 开发：只准备依赖和数据
选项：
  --systemd                  正式安装：/opt 下、root、swanctl/VICI 可用
  --systemd-unprivileged     系统服务以 --user 指定的非 root 用户运行，root 同步 CRL
  --user NAME               非 root 服务账号（须事先创建）
  --loopback                只监听 127.0.0.1（默认）
  --host IP --port NUMBER    自定义监听；远程管理仍须可信加密传输
  --data-dir PATH            数据目录（保留已有数据）
  --pip-mirror tsinghua|pypi 保存镜像到项目 .venv/pip.conf
  --pip-index-url HTTPS_URL  自定义 HTTPS 源，只保存到项目虚拟环境
  --strongswan-service NAME  已运行的 swanctl 服务单元（默认 strongswan）
  --with-timer              非 root 模式启用 30 分钟同步兜底
  --dry-run                 只读检查，不创建文件或访问 pip 镜像
EOF
}
value() { [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || die "$1 缺少参数值"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --systemd) WITH_SYSTEMD=1 ;;
    --systemd-unprivileged) WITH_SYSTEMD=1; SERVICE_UNIT="ca-admin.service" ;;
    --with-timer) WITH_TIMER=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --loopback) HOST="127.0.0.1" ;;
    --host) value "$@"; HOST="$2"; shift ;;
    --port) value "$@"; PORT="$2"; shift ;;
    --data-dir) value "$@"; DATA_DIR="$2"; shift ;;
    --user) value "$@"; SERVICE_USER="$2"; shift ;;
    --strongswan-service) value "$@"; STRONGSWAN_SERVICE="$2"; shift ;;
    --pip-index-url) value "$@"; PIP_INDEX="$2"; shift ;;
    --pip-mirror)
      value "$@"
      case "$2" in
        tsinghua) PIP_INDEX="https://pypi.tuna.tsinghua.edu.cn/simple" ;;
        pypi) PIP_INDEX="https://pypi.org/simple" ;;
        *) die "--pip-mirror 仅接受 tsinghua 或 pypi" ;;
      esac
      shift ;;
    -h|--help) help; exit 0 ;;
    *) die "未知参数: $1（使用 --help 查看用法）" ;;
  esac
  shift
done
PY_BIN="$(command -v python3 || true)"
[ -n "$PY_BIN" ] || die "找不到 python3；Debian/Ubuntu 请安装 python3 python3-venv"
"$PY_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)' \
  || die "Python 版本过低，本项目要求 Python >= 3.10"
DATA_DIR="$("$PY_BIN" -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$DATA_DIR")"
export PYTHONDONTWRITEBYTECODE=1
"$PY_BIN" "$BASE_DIR/deploy/service_tools.py" validate --base "$BASE_DIR" --data "$DATA_DIR" \
  --host "$HOST" --port "$PORT" --user "$SERVICE_USER"
if [ -n "$PIP_INDEX" ]; then
  "$PY_BIN" -c 'import sys,urllib.parse
u=urllib.parse.urlsplit(sys.argv[1])
assert u.scheme=="https" and u.hostname and not u.username and not u.password and not u.fragment
assert not any(c.isspace() for c in sys.argv[1])' "$PIP_INDEX" \
    || die "pip 源必须为不含账号、口令或空白的 HTTPS 地址"
fi
[[ "$STRONGSWAN_SERVICE" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_@.-]*$ ]] || die "无效的 strongSwan 单元名"
if [ "$SERVICE_UNIT" = "ca-admin-root.service" ] && [ "$SERVICE_USER" != root ]; then
  die "--user 仅供 --systemd-unprivileged 使用"
fi
if [ "$SERVICE_UNIT" = "ca-admin.service" ]; then
  [ "$SERVICE_USER" != root ] || die "非 root 模式必须指定 --user 已存在的账号"
  id "$SERVICE_USER" >/dev/null 2>&1 || die "服务账号不存在：$SERVICE_USER"
fi
if [ "$WITH_TIMER" = 1 ] && { [ "$WITH_SYSTEMD" != 1 ] || [ "$SERVICE_UNIT" != "ca-admin.service" ]; }; then
  die "--with-timer 仅用于 --systemd-unprivileged；root 直写不需要同步定时器"
fi
say "项目目录: $BASE_DIR"
say "数据目录: $DATA_DIR"
say "Python: $("$PY_BIN" -V)"
if [ "$WITH_SYSTEMD" = 1 ]; then
  PHASE="systemd / swanctl 前置检查"
  [ "$(id -u)" = 0 ] || die "安装系统服务需要 root，请用 sudo 重跑（数据尚未初始化）"
  case "$BASE_DIR/" in /opt/*/) ;; *) die "正式服务请先把源码放到 /opt/ca-dev，再运行安装；见 deploy/QUICKSTART.md" ;; esac
  case "$DATA_DIR/" in /home/*|/root/*|/run/*|/tmp/*|/var/tmp/*) die "数据目录请放在 /opt/ca-dev/data 或 /var/lib 下，不能放在沙箱隐藏/临时目录" ;; esac
  [ -d /run/systemd/system ] || die "当前环境未运行 systemd；请在完整 Linux 虚拟机内安装"
  for tool in systemctl systemd-analyze timeout; do command -v "$tool" >/dev/null || die "缺少 $tool"; done
  command -v swanctl >/dev/null || die "缺少 swanctl；Debian/Ubuntu 请安装 charon-systemd strongswan-swanctl"
  [ -d /etc/swanctl ] || die "缺少 /etc/swanctl；先完成 swanctl 配置，不要只手工创建空目录"
  systemctl is-active --quiet "$STRONGSWAN_SERVICE" \
    || die "$STRONGSWAN_SERVICE 未运行；先检查对应 strongSwan 服务日志"
  timeout 10 swanctl --stats || die "swanctl 无法连接 VICI（或查询超时）；先检查 charon/VICI，安装尚未开始"
  "$PY_BIN" - "$BASE_DIR" <<'PY'
import pathlib,stat,sys
p=pathlib.Path(sys.argv[1])
for entry in (p, *p.parents):
    s=entry.stat()
    if s.st_uid != 0 or s.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(f"不安全的项目父目录权限：{entry}；请按 QUICKSTART 的 root 属主步骤安装")
PY
fi
if [ "$DRY_RUN" = 1 ]; then
  if [ -x "$BASE_DIR/.venv/bin/python" ]; then
    "$BASE_DIR/.venv/bin/python" -m pip --version || warn ".venv 缺少 pip；正式安装会尝试 ensurepip"
  else
    "$PY_BIN" -c 'import venv, ensurepip' || die "缺少 venv/ensurepip；Debian/Ubuntu 请安装 python3-venv（自定义 Python 需匹配版本）"
  fi
  say "[dry-run] 检查完成；没有创建/修改文件"
  echo "正式安装将准备 .venv、安装 requirements.txt、保留并初始化数据。"
  echo "pip 源：${PIP_INDEX:-沿用现有 pip 配置}；网络超时 15 秒，重试 1 次。"
  [ "$WITH_SYSTEMD" = 0 ] || echo "随后安装并重启 ca-admin，检查稳定进程与 HTTP 健康响应；不重启 strongSwan。"
  exit 0
fi
cd "$BASE_DIR"
export PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
PHASE="创建虚拟环境"
if [ ! -e "$BASE_DIR/.venv" ]; then
  say "创建虚拟环境 .venv"
  "$PY_BIN" -m venv "$BASE_DIR/.venv" \
    || die "创建 .venv 失败；Debian/Ubuntu 请安装 python3-venv 后重跑，现有 data/ 保留"
fi
PY="$BASE_DIR/.venv/bin/python"
[ -x "$PY" ] || die ".venv 不完整；请先把 .venv 改名备份后重跑，不要删除 data/"
"$PY" -c 'import sys; assert sys.prefix != sys.base_prefix and sys.version_info[:2] >= (3,10)' \
  || die ".venv 不是可用的 Python >= 3.10 虚拟环境，请先改名备份 .venv 后重跑"
if ! "$PY" -m pip --version; then
  say ".venv 缺少 pip，尝试用 ensurepip 离线补齐"
  "$PY" -m ensurepip --upgrade \
    || die "ensurepip 不可用；安装对应 Python 的 venv 包后重跑（见 QUICKSTART）"
fi
PHASE="安装 Python 依赖"
PIP_ARGS=()
if [ -n "$PIP_INDEX" ]; then
  "$PY" -m pip config --site set global.index-url "$PIP_INDEX"
  PIP_ARGS=(--index-url "$PIP_INDEX")
fi
say "安装依赖（显示下载过程；网络超时 15 秒，重试 1 次；不自动升级 pip）"
"$PY" -m pip --disable-pip-version-check install --timeout 15 --retries 1 \
  "${PIP_ARGS[@]}" -r "$BASE_DIR/requirements.txt" \
  || die "依赖安装失败；上方为 pip 原始错误。可用 --pip-mirror tsinghua 重试；数据尚未初始化"
"$PY" -m pip check
PHASE="初始化数据"
mkdir -p "$DATA_DIR"
say "初始化数据库、规则集、管理员（保留已有数据）"
MANAGE=0
[ "$WITH_SYSTEMD" = 0 ] || [ "$SERVICE_USER" != root ] || MANAGE=1
CA_DATA_DIR="$DATA_DIR" CA_HOST="$HOST" CA_PORT="$PORT" CA_MANAGE_STRONGSWAN="$MANAGE" \
CA_RELOAD_CMD="${CA_RELOAD_CMD:-swanctl --flush-certs && swanctl --load-creds && systemctl restart $STRONGSWAN_SERVICE}" \
  "$PY" - <<'PY'
from backend import server
info = server.bootstrap(verbose=True)
print("初始化完成：规则集 %d 个，自动化预置 %d 个" % (info["rulesets"], info["automation_tasks"]))
PY
chmod 700 "$DATA_DIR"
if [ "$(id -u)" = 0 ]; then
  OWNER=root
  [ "$WITH_SYSTEMD" = 0 ] || OWNER="$SERVICE_USER"
  chown -R "$OWNER:$(id -gn "$OWNER")" "$DATA_DIR"
fi
service_failed() {
  systemctl status ca-admin.service --no-pager --full >&2 || true
  journalctl -u ca-admin.service -b -n 40 --no-pager >&2 || true
  die "ca-admin 未就绪，安装未完成；请处理上方日志。现有数据保留，不会关闭沙箱"
}
render() {
  "$PY" "$BASE_DIR/deploy/service_tools.py" render --base "$BASE_DIR" --data "$DATA_DIR" \
    --host "$HOST" --port "$PORT" --user "$SERVICE_USER" --template "$1" --output "$2"
}
if [ "$WITH_SYSTEMD" = 1 ]; then
  PHASE="安装 systemd 单元"
  # 先校验候选单元，失败时不得覆盖服务器上已有的服务配置。
  UNIT_STAGE="$(mktemp -d "$DATA_DIR/tmp/install-units.XXXXXX")"
  trap 'rm -rf -- "$UNIT_STAGE"' EXIT
  render "$BASE_DIR/deploy/$SERVICE_UNIT" "$UNIT_STAGE/ca-admin.service"
  systemd-analyze verify "$UNIT_STAGE/ca-admin.service"
  if [ "$SERVICE_USER" != root ]; then
    render "$BASE_DIR/deploy/ca-strongswan-sync.sh" /usr/local/sbin/ca-strongswan-sync.sh
    for unit in ca-strongswan-sync.service ca-strongswan-sync.path ca-strongswan-sync.timer; do
      render "$BASE_DIR/deploy/$unit" "/etc/systemd/system/$unit"
    done
    systemd-analyze verify /etc/systemd/system/ca-strongswan-sync.{service,path,timer}
  fi
  install -m 0644 "$UNIT_STAGE/ca-admin.service" /etc/systemd/system/ca-admin.service
  systemctl daemon-reload
  for unit in ca-strongswan-sync.path ca-strongswan-sync.timer; do
    systemctl disable --now "$unit" 2>/dev/null || true
  done
  PHASE="启动并验收 ca-admin"
  systemctl enable ca-admin.service || service_failed
  systemctl restart ca-admin.service || service_failed
  "$PY" "$BASE_DIR/deploy/service_tools.py" ready --host "$HOST" --port "$PORT" || service_failed
  if [ "$SERVICE_USER" != root ]; then
    systemctl enable --now ca-strongswan-sync.path
    if [ "$WITH_TIMER" = 1 ]; then
      systemctl enable --now ca-strongswan-sync.timer
    else
      systemctl disable --now ca-strongswan-sync.timer 2>/dev/null || true
    fi
  fi
  say "安装成功：ca-admin 服务运行且健康检查通过"
else
  say "环境与数据准备完成；尚未启动服务，前台启动请运行 ./run.sh"
fi
echo "管理员初始口令文件：$DATA_DIR/initial_admin_password.txt（已有账号不会重置）"
echo "本机访问：http://127.0.0.1:$PORT/；远程访问按 deploy/QUICKSTART.md 建立 SSH 隧道。"
echo "安装本身不重启 strongSwan；后续 CRL 默认重载包含 --flush-certs、--load-creds 和重启，会中断所有 VPN 连接。"
