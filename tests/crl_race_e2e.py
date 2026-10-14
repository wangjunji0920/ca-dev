"""CRL 并发竞态回归（故障注入，确定性复现"最新 CRL 漏掉已吊销证书"）。

问题（已修）：
    `generate_crl()` 里"读取已吊销集合 → 构造 CRL → 写入 crls 表"不是原子的。
    并发吊销时，先读到**旧快照**的那次生成如果更慢，它会**后**插入，
    于是"最新的 CRL"只包含部分已吊销证书——strongSwan 会继续认为漏掉的那张有效。
    `_next_crl_number()` 同样在插入前读取，两次并发生成还可能撞上同一个编号。

本测试用故障注入把窗口放大到确定可复现：
    给 `_next_crl_number` 打桩——"当前已吊销数少"的那次生成多睡 0.6s，
    模拟"读到旧快照的生成更慢"这一调度情形。

断言：
    1) 修复后：无论并发顺序如何，**最新 CRL 的条目数 == 已吊销证书数**；
    2) 修复后：CRL 编号唯一（不重复）；
    3) 并且并发吊销本身都成功。
"""
from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="crl-race-"))
PY = ROOT / ".venv/bin/python"
import os  # noqa: E402

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

os.environ["CA_DATA_DIR"] = str(TMP / "data")

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def main() -> int:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from backend import ca, db, server, x509util, consistency

    print("\n\033[1m== 准备：CA + 两张证书 ==\033[0m")
    server.bootstrap(verbose=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Race CA")])
    now = x509util.now()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    row = ca.import_ca(x509util.pem_cert(cert).encode(), x509util.pem_key(key).encode())
    a = ca.issue_certificate(ca_row=row, vpn_identity="race-a.example.com", cn="race-a")["cert"]
    b = ca.issue_certificate(ca_row=row, vpn_identity="race-b.example.com", cn="race-b")["cert"]
    check("两张证书已签发", bool(a["id"] and b["id"]))

    # ---------------- 故障注入 ----------------
    real_next = ca._next_crl_number

    def slow_next(ca_id: int, conn=None) -> int:
        revoked_now = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked'") or 0
        # "读到旧快照"的那次生成（吊销数少）故意更慢 —— 正是竞态发生时的调度形态
        # 注意：现在取号在事务内进行（conn 参数），注入的 sleep 仍能放大窗口
        if conn is None:
            time.sleep(0.6 if revoked_now <= 1 else 0.05)
        return real_next(ca_id, conn=conn)

    ca._next_crl_number = slow_next
    try:
        print("\n\033[1m== 并发吊销：A 先开始但更慢，B 后开始但更快 ==\033[0m")
        t = threading.Thread(target=ca.revoke, args=(a["id"],),
                             kwargs={"reason": "keyCompromise"})
        t.start()
        time.sleep(0.15)          # 让 A 的生成先读到"只吊销了 A"的快照
        ca.revoke(b["id"], reason="keyCompromise")   # 主线程吊销 B（会被注入的 sleep 影响）
        t.join(timeout=60)
        check("两次吊销都完成", not t.is_alive())

        revoked = db.scalar("SELECT COUNT(*) FROM certs WHERE status='revoked'") or 0
        latest = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
        numbers = [r["number"] for r in db.q("SELECT number FROM crls ORDER BY id")]
        check("两张证书都已吊销", revoked == 2, f"revoked={revoked}")
        check("最新 CRL 包含全部已吊销证书（不漏签）",
              latest is not None and latest["entries"] == revoked,
              f"最新 CRL entries={latest['entries'] if latest else '无'}，已吊销={revoked}")
        check("CRL 编号唯一（并发下不撞号）",
              len(numbers) == len(set(numbers)), str(numbers))

        # 用真实文件再确认一次：解析落盘的 CRL，条目数应与已吊销数一致
        der = (Path(os.environ["CA_DATA_DIR"]) / latest["der_path"]).read_bytes()
        parsed = x509util.load_crl(der)
        check("落盘 CRL 文件里的条目数与吊销数一致",
              len(list(parsed)) == revoked, f"文件条目={len(list(parsed))} 已吊销={revoked}")
    finally:
        ca._next_crl_number = real_next

    print("\n\033[1m== 跨进程并发取号：服务与 CLI 同时生成不得重号 ==\033[0m")
    # 审查复现：两个进程同时生成，二者都得到编号 2（进程内锁挡不住跨进程）。
    # 修复后：取号与 INSERT 在同一 BEGIN IMMEDIATE 事务内 → 跨进程串行。
    db.set_setting("crl_number_floor", "0")
    before = [int(r["number"]) for r in db.q("SELECT number FROM crls ORDER BY id")
              if str(r["number"]).isdigit()]
    base_n = max(before) if before else 0
    procs = []
    for _ in range(4):
        procs.append(subprocess.Popen(
            [str(PY), "-c",
             "import sys; sys.path.insert(0,'.')\n"
             "from backend import server, ca\n"
             "server.bootstrap(verbose=False)\n"
             "print(ca.generate_crl(actor='race', source='proc')['number'])"],
            cwd=ROOT, env=dict(os.environ), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True))
    outs = []
    for pr in procs:
        o, e = pr.communicate(timeout=180)
        outs.append((pr.returncode, (o or "").strip(), (e or "").strip()[-120:]))
    numbers = [int(o) for rc, o, _ in outs if rc == 0 and o.isdigit()]
    check("4 个并发进程都成功生成了 CRL", len(numbers) == 4, str(outs)[:220])
    check("★ 并发生成的编号互不相同（跨进程不重号）",
          len(set(numbers)) == len(numbers), f"编号={numbers}")
    check("★ 编号在原有基础上连续递增",
          sorted(numbers) == list(range(base_n + 1, base_n + 1 + len(numbers))),
          f"base={base_n} 编号={sorted(numbers)}")
    dup = db.q("SELECT number, COUNT(*) AS n FROM crls GROUP BY ca_id, number HAVING n > 1")
    check("库里没有重复编号", not dup, str(dup))
    codes = {i.get("code") for i in consistency.check().get("issues", [])}
    check("一致性体检未报重复编号", "crl_number_duplicate" not in codes, str(sorted(codes))[:120])

    print("\n\033[1m== 跨进程快照竞态：慢的那次生成不得产出'编号更大但漏项'的 CRL ==\033[0m")
    # 审查复现：吊销集合原本在事务外读取 → "读到旧快照的慢生成"后插入，
    # 结果 #2 有 1 条、随后写入的 #3 却有 0 条（最新 CRL 反而漏项）。
    c_race = ca.issue_certificate(ca_row=ca.active_ca_row(),
                                  vpn_identity="snap.example.com", cn="snap")["cert"]
    slow_script = (
        "import sys, time; sys.path.insert(0,'.')\n"
        "from backend import server, ca\n"
        "server.bootstrap(verbose=False)\n"
        "real = ca._next_crl_number\n"
        "def slow(ca_id, conn=None):\n"
        "    time.sleep(0.8)          # 模拟'读到旧快照但更慢'的生成\n"
        "    return real(ca_id, conn=conn)\n"
        "ca._next_crl_number = slow\n"
        "print(ca.generate_crl(actor='race-slow', source='slow')['number'])\n")
    revoke_script = (
        "import sys, time; sys.path.insert(0,'.')\n"
        "from backend import server, ca\n"
        "server.bootstrap(verbose=False)\n"
        f"time.sleep(0.25)\n"
        f"print(ca.revoke({c_race['id']}, reason='keyCompromise')['crl']['number'])\n")
    p_slow = subprocess.Popen([str(PY), "-c", slow_script], cwd=ROOT, env=dict(os.environ),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p_rev = subprocess.Popen([str(PY), "-c", revoke_script], cwd=ROOT, env=dict(os.environ),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    o_slow, e_slow = p_slow.communicate(timeout=180)
    o_rev, e_rev = p_rev.communicate(timeout=180)
    check("慢生成与并发吊销都成功完成",
          p_slow.returncode == 0 and p_rev.returncode == 0,
          f"slow={e_slow[-80:]} revoke={e_rev[-80:]}")
    latest = db.q1("SELECT * FROM crls ORDER BY id DESC LIMIT 1")
    latest_path = Path(latest["der_path"] or latest["path"])
    if not latest_path.is_absolute():
        latest_path = Path(os.environ["CA_DATA_DIR"]) / latest_path
    entries_now = x509util.load_crl(latest_path.read_bytes())
    check("★ 最新 CRL 必含这次并发吊销的序列号（快照竞态已消除）",
          any(int(e.serial_number) == int(c_race["serial_hex"], 16) for e in entries_now),
          f"# {latest['number']} entries={len(list(entries_now))}")
    revoked_total = db.scalar("SELECT COUNT(*) FROM certs WHERE revoked_at IS NOT NULL "
                              "OR status='revoked'")
    check("★ 最新 CRL 条目数 == 库里已吊销总数（不漏项）",
          len(list(entries_now)) == revoked_total,
          f"CRL={len(list(entries_now))} 库={revoked_total}")

    print(f"\n  通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("  失败明细: " + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)
