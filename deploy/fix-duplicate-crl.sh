#!/usr/bin/env bash
# 清理 strongSwan 目录里"同一 CA 多份 CRL"的隐患（默认只演练，加 --apply 才真动手）。
#
# 背景：charon 按签发者名字索引 CRL，同一签发者**只保留编号最大的那份**。
# 目录里只要残留第二份（哪怕文件名不同），就可能出现"编号更大的旧 CRL 遮蔽新 CRL"，
# 表现为：吊销了、也 reload 了，但对方重连照样通过。
#
# 本脚本做三件事（幂等、可重复执行）：
#   1) cli targets --keep-single：数据库层面同一目录同一内容只保留一个启用目标
#   2) 把 CRL 目录里多余的、属于本 CA 的 CRL 文件移走备份（**只移动 CRL**；
#      CA 证书目录不做任何移动，避免误删签发客户端证书的那张 CA）
#   3) 打印需要执行的 reload/restart 与后续校验命令
#
# 用法：
#   sudo ./deploy/fix-duplicate-crl.sh              # 演练：只显示会做什么
#   sudo ./deploy/fix-duplicate-crl.sh --apply      # 真正执行
set -uo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$BASE_DIR/.venv/bin/python"
[ -x "$PY" ] || { echo "[✗] 找不到 $PY，请先 ./deploy/install.sh"; exit 1; }
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
CRL_DIR="${CA_SWANCTL_CRL_DIR:-/etc/swanctl/x509crl}"
CA_DIR="${CA_SWANCTL_CA_DIR:-/etc/swanctl/x509ca}"
BACKUP="${CA_CLEANUP_BACKUP:-/root/ca-backup-$(date +%Y%m%d-%H%M%S)}"
say() { printf '%s\n' "$*"; }
run() { if [ "$APPLY" = "1" ]; then "$@"; else printf '  [演练] %s\n' "$*"; fi; }

say "== 1) 数据库层面的发布目标 =="
say "--- 当前目标 ---"
"$PY" -m backend.cli targets || true
say "--- 同一目录同一内容只保留一个（保留设置里指定的那个）---"
if [ "$APPLY" = "1" ]; then
  "$PY" -m backend.cli targets --keep-single
else
  printf '  [演练] %s\n' "$PY -m backend.cli targets --keep-single"
fi

say ""
say "== 2) CRL 目录里多余的 CRL 文件 =="
KEEP="$(cd "$BASE_DIR" && "$PY" - <<'PYEOF'
import json, subprocess, sys
out = subprocess.run([sys.executable, "-m", "backend.cli", "targets", "--json"],
                     capture_output=True, text=True).stdout
try:
    data = json.loads(out)
    targets = data.get("targets", [])
except Exception:
    targets = []
crs = [t for t in targets
       if t.get("enabled") and t.get("kind") == "dir_file" and t.get("content") == "crl"]
# 优先选 strongSwan 目录里的那个（/etc 开头），不要选我们自己的暂存目录
pref = [t for t in crs if str(t.get("path", "")).startswith("/etc/")]
picked = (pref or crs)[0] if (pref or crs) else None
print(picked["path"].rstrip("/") + "/" + picked["filename"] if picked else "")
PYEOF
)"
say "  应保留（来自启用目标）：${KEEP:-<未找到>}"
if [ -z "$KEEP" ]; then
  say "  [!] 没有找到启用的 CRL 目标，跳过文件清理（请先在界面确认发布目标）"
else
  keepdir="$(dirname "$KEEP")"; keepname="$(basename "$KEEP")"
  moved=0
  for f in "$keepdir"/*; do
    [ -f "$f" ] || continue
    [ "$(basename "$f")" = "$keepname" ] && continue
    # 只处理"能解析为 CRL 且签发者与本 CA 相同"的文件
    if "$PY" - "$f" <<'PYEOF' >/dev/null 2>&1
import sys
sys.path.insert(0, ".")
from backend import ca, x509util
row = ca.active_ca_row()
crl = x509util.load_crl(open(sys.argv[1], "rb").read())
raise SystemExit(0 if (row and x509util.crl_info(crl)["issuer"] == row["subject"]) else 1)
PYEOF
    then
      say "  移走： $f"
      run mkdir -p "$BACKUP"
      run mv "$f" "$BACKUP/"
      moved=$((moved+1))
    else
      say "  保留（不是本 CA 的 CRL）： $f"
    fi
  done
  [ "$moved" = "0" ] && say "  没有多余的 CRL 文件 ✓"
  say "  备份目录：$BACKUP"
fi

say ""
say "== 3) CA 证书目录（只报告，不移动）=="
if [ -d "$CA_DIR" ]; then
  cnt=$(ls -1 "$CA_DIR" 2>/dev/null | wc -l)
  say "  $CA_DIR 里有 $cnt 个文件；若存在多个 subject 相同的 CA，请人工确认保留哪一张："
  say "    for f in $CA_DIR/*; do openssl x509 -in \"\$f\" -noout -subject -fingerprint -sha256; done"
  say "    sudo $PY -m backend.cli doctor | grep -i \"同名 CA\""
fi

say ""
say "== 4) 让 charon 换用清理后的 CRL =="
say "  sudo systemctl restart strongswan      # reload 不会卸载已消失的 CRL，restart 才会"
say "  sudo swanctl --list-certs | sed -n '/X.509 CRLs/,\$p'   # 确认只剩 1 份、编号=系统最新"
say "  sudo $PY -m backend.cli doctor | grep -E \"CRL 文件唯一性|同名 CA|CRL 加载状态\""
if [ "$APPLY" != "1" ]; then
  say ""
  say "以上是演练。确认无误后执行： sudo $0 --apply"
fi
