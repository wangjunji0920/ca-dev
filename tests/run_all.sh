#!/usr/bin/env bash
# 跑完整验证（二十四套）。用法：
#
#   ./tests/run_all.sh
#
# 说明：
#  * 所有测试都用临时数据目录 + 自建测试 CA，不碰你的 data/；
#  * 测试**不会调用真实的 systemd / strongSwan**：systemctl/systemd-analyze/swanctl/ipsec
#    在 PATH 最前面被替换为桩，结束时校验调用日志为空；
#  * 前端真实 DOM 测试需要 jsdom（一次性安装）：
#      mkdir -p .tmp/fe-test && cd .tmp/fe-test && npm install --cache ../npm-cache jsdom
#    未安装 node 时自动跳过；
#  * 部署验收会在 127.0.0.1 随机端口起一个**临时**实例，跑完立即停。
set -uo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$BASE_DIR/.venv/bin/python"
FAILED=0

# 发布检查不允许把缺少前端测试依赖当成通过。
if [ "${1:-}" = "--release" ]; then
  command -v node >/dev/null || { echo "发布检查缺少 Node.js" >&2; exit 2; }
  node -e 'require(process.argv[1])' "$BASE_DIR/.tmp/fe-test/node_modules/jsdom" \
    || { echo "发布检查缺少 jsdom；见 deploy/RELEASE.md" >&2; exit 2; }
  export CA_TEST_REQUIRE_DOM=1
elif [ "$#" -gt 0 ]; then
  echo "用法：tests/run_all.sh [--release]" >&2
  exit 2
fi
cd "$BASE_DIR"

step() { printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 互斥锁：**绝不允许两次全量测试并发**（并发会共用日志/桩/守卫日志/端口，产生假结果）。
# 用内核级 flock：进程退出（含被 kill）时锁自动释放，**不存在"陈旧锁"问题**。
# 曾经用"目录锁 + PID 判定"，结果 PID 在跨命名空间的环境里误判为存活，把后续运行全挡死。
# ---------------------------------------------------------------------------
LOCK_FILE="$BASE_DIR/.tmp/run_all.lockf"
mkdir -p "$BASE_DIR/.tmp"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    printf '\n\033[1;31m[✗] 已有一次全量测试在运行（flock %s）。\033[0m\n' "$LOCK_FILE"
    echo "    并发运行会互相污染日志/桩/守卫日志，请等它结束后再跑。"
    exit 2
  fi
  LOCK_KIND="flock"
else
  # 退化方案（无 flock）：目录锁 + 年龄判定（超过 1 小时的锁视为陈旧并自动接管）
  LOCK_DIR="$BASE_DIR/.tmp/run_all.lock"
  if [ -d "$LOCK_DIR" ]; then
    AGE=$(( $(date +%s) - $(stat -c %Y "$LOCK_DIR" 2>/dev/null || echo 0) ))
    if [ "$AGE" -lt 3600 ]; then
      printf '\n\033[1;31m[✗] 已有一次全量测试在运行（%s，%s 秒前）。\033[0m\n' "$LOCK_DIR" "$AGE"
      echo "    如确认没有在跑： rm -rf $LOCK_DIR"
      exit 2
    fi
    printf '\n\033[1;33m[!] 陈旧锁（%s 秒前），自动接管。\033[0m\n' "$AGE"
    rm -rf "$LOCK_DIR"
  fi
  mkdir "$LOCK_DIR" 2>/dev/null || { echo "[✗] 无法获取锁"; exit 2; }
  LOCK_KIND="dir"
fi
echo "已获取测试互斥锁（$LOCK_KIND）"

# ---------------------------------------------------------------------------
# 硬保护：测试期间**不可能**调用真实 systemd / strongSwan 命令。
# 把桩目录放在 PATH 最前面，并记录任何一次调用；结束时检查是否越界。
# （只读查询如 swanctl --list-* 允许；systemctl 与会改动 strongSwan 的命令禁止。）
# ---------------------------------------------------------------------------
GUARD_DIR="$BASE_DIR/.tmp/no-systemd-bin"
GUARD_LOG="$BASE_DIR/.tmp/systemd-calls.log"
mkdir -p "$GUARD_DIR"
: > "$GUARD_LOG"
for tool in systemctl systemd-analyze swanctl ipsec; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' "$tool" "$GUARD_LOG" > "$GUARD_DIR/$tool"
  chmod +x "$GUARD_DIR/$tool"
done
export PATH="$GUARD_DIR:$PATH"
# 测试用的默认重载命令改成无害回显（重载行为本身由 tests/reload_e2e.py 用自家桩验证）
export CA_RELOAD_CMD="echo [test] reload-noop"
echo "已启用测试保护：systemctl/systemd-analyze/swanctl/ipsec 全部走桩（记录于 .tmp/systemd-calls.log）"
echo "测试默认重载命令：$CA_RELOAD_CMD"

step "1/24 后端端到端测试"
if "$PY" "$BASE_DIR/tests/e2e_test.py"; then :; else FAILED=1; fi

step "2/24 登录失败锁定与解锁（回环宽阈值 / cli unlock / 握手不锁账号）"
if "$PY" "$BASE_DIR/tests/login_lockout_e2e.py"; then :; else FAILED=1; fi

step "3/24 CLI 子命令端到端（22 个子命令逐个真跑）"
if "$PY" "$BASE_DIR/tests/cli_e2e.py"; then :; else FAILED=1; fi

step "4/24 API 健壮性扫描（88 条路由灌垃圾输入，查 5xx）"
if "$PY" "$BASE_DIR/tests/api_fuzz_e2e.py"; then :; else FAILED=1; fi

step "5/24 前端真实 DOM 测试（jsdom + 真实后端）"
if command -v node >/dev/null 2>&1; then
  if node "$BASE_DIR/tests/frontend_e2e.js"; then :; else FAILED=1; fi
else
  echo "未安装 node，跳过前端测试"
fi

step "6/24 真实浏览器跳转流程（登录→新页面仍保持登录，无自动登录钩子）"
if command -v node >/dev/null 2>&1; then
  if node "$BASE_DIR/tests/session_flow_e2e.js"; then :; else FAILED=1; fi
else echo "未安装 node，跳过"; fi

step "7/24 前端 CSP 兼容性（内联脚本会被真实浏览器拦掉）"
if "$PY" "$BASE_DIR/tests/csp_compat_e2e.py"; then :; else FAILED=1; fi

step "8/24 重载行为（桩 swanctl/systemctl，真实子进程）"
if "$PY" "$BASE_DIR/tests/reload_e2e.py"; then :; else FAILED=1; fi

step "9/24 明确要求落地（无 openssl 依赖 / Win-Linux 差异 / 规则集全可定制 / 自动化触发器）"
if "$PY" "$BASE_DIR/tests/requirements_e2e.py"; then :; else FAILED=1; fi

step "10/24 发布目标卫生（默认只写一份 CRL，不产生多余文件）"
if "$PY" "$BASE_DIR/tests/publish_hygiene_e2e.py"; then :; else FAILED=1; fi

step "11/24 前端资源完整性（带外核对，能发现中间人篡改）"
if "$PY" "$BASE_DIR/tests/assetguard_e2e.py"; then :; else FAILED=1; fi

step "12/24 批量导入与规模边界（CRL 导入/幂等/脏 CSV/混合目录/300 张）"
if "$PY" "$BASE_DIR/tests/import_edge_e2e.py"; then :; else FAILED=1; fi

step "13/24 密钥类型与私钥格式（RSA/EC/Ed25519 × PKCS#1/PKCS#8/加密/DER）"
if "$PY" "$BASE_DIR/tests/keytypes_e2e.py"; then :; else FAILED=1; fi

step "14/24 并发初始化健壮性（5 进程同时对全新库 bootstrap）"
if "$PY" "$BASE_DIR/tests/concurrent_init_e2e.py"; then :; else FAILED=1; fi

step "15/24 备份/恢复安全性（坏归档不得毁数据）"
if "$PY" "$BASE_DIR/tests/restore_safety_e2e.py"; then :; else FAILED=1; fi

step "16/24 CRL 并发竞态回归（故障注入）"
if "$PY" "$BASE_DIR/tests/crl_race_e2e.py"; then :; else FAILED=1; fi

step "17/24 systemd 单元与部署脚本（渲染后逐项校验 + 回环部署）"
if "$PY" "$BASE_DIR/tests/units_e2e.py"; then :; else FAILED=1; fi

step "18/24 部署验收（临时回环实例）"
PORT=$((20000 + RANDOM % 1000))
DATA="$BASE_DIR/.tmp/verify-$PORT"
rm -rf "$DATA"
# 先播种一个“像真实部署”的状态：导入 CA（含私钥）+ 签一张证书 + 生成 CRL
CA_DATA_DIR="$DATA" "$PY" - <<'PYEOF'
import datetime as dt, sys
sys.path.insert(0, ".")
from backend import server, ca, publish, x509util
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
server.bootstrap(verbose=False)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Verify CA")])
now = x509util.now()
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256()))
row = ca.import_ca(x509util.pem_cert(cert).encode(), x509util.pem_key(key).encode())
ca.issue_certificate(ca_row=row, vpn_identity="verify.example.com", cn="verify-demo")
ca.generate_crl(actor="seed", source="seed")
publish.publish(trigger="seed", reload=False)
print("seeded")
PYEOF
CA_DATA_DIR="$DATA" CA_HOST=127.0.0.1 CA_PORT="$PORT" CA_LEGACY_API=loopback \
  "$PY" -m backend.server > "$BASE_DIR/.tmp/verify-$PORT.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 40); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/api/health" && break
  sleep 0.3
done
if "$PY" "$BASE_DIR/tests/verify_deploy.py" "http://127.0.0.1:$PORT" \
     --pw-file "$DATA/initial_admin_password.txt"; then :; else FAILED=1; fi
kill $SRV 2>/dev/null || true
wait $SRV 2>/dev/null || true

step "19/24 升级演练（旧版本 → 新版本，验证数据不丢）"
if "$PY" "$BASE_DIR/tests/upgrade_e2e.py"; then :; else FAILED=1; fi

step "20/24 交付包验收（解包 → 初始化 → 起服务 → 验收）"
if "$PY" "$BASE_DIR/tests/package_e2e.py"; then :; else FAILED=1; fi

step "21/24 传输安全（明文不得下发会话 cookie / 会话绑定 / 改密撤销信道）"
if "$PY" "$BASE_DIR/tests/transport_security_e2e.py"; then :; else FAILED=1; fi

step "22/24 吊销事实完整性（归档不漏项 / 禁止硬删除 / 导入 CRL 验签）"
if "$PY" "$BASE_DIR/tests/revocation_integrity_e2e.py"; then :; else FAILED=1; fi

step "23/24 公开发布路径边界与默认监听"
if "$PY" "$BASE_DIR/tests/publication_safety_e2e.py"; then :; else FAILED=1; fi

step "24/24 新机安装故障与服务就绪回归"
if "$PY" "$BASE_DIR/tests/install_e2e.py"; then :; else FAILED=1; fi

# 只读查询（swanctl --list-* 等）是允许的；真正要禁止的是
# systemctl 调用与会改动 strongSwan 状态的命令。
READONLY_RE='^swanctl (--list-sas|--list-crls|--list-certs|--list-pools|--list-conns|--list-authorities|--version|--stats|--help)( |$)'
if [ -s "$GUARD_LOG" ]; then
  OFFENDERS="$(grep -vE "$READONLY_RE" "$GUARD_LOG" || true)"
  RO_COUNT="$(grep -cE "$READONLY_RE" "$GUARD_LOG" || true)"
else
  OFFENDERS=""
  RO_COUNT=0
fi
if [ -n "$OFFENDERS" ]; then
  printf '\n\033[1;31m[✗] 测试期间有代码尝试调用 systemd 或改动 strongSwan（已被桩拦截，未接触真实系统）：\033[0m\n'
  printf '%s\n' "$OFFENDERS" | sed 's/^/    /'
  FAILED=1
else
  printf '\n\033[1;32m[✓] 测试期间没有调用任何真实 systemctl，也没有改动 strongSwan 的命令（只读查询 %s 次，全部走桩）。\033[0m\n' "$RO_COUNT"
fi

[ "$LOCK_KIND" = "dir" ] && rm -rf "$LOCK_DIR"

if [ "$FAILED" = "0" ]; then
  printf '\n\033[1;32m全部通过。\033[0m\n'
else
  printf '\n\033[1;31m有测试未通过，见上面输出。\033[0m\n'
fi
exit $FAILED
