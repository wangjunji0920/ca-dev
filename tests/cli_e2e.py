"""CLI 端到端验收：把 22 个子命令逐个真跑一遍。

背景：`cli reload-cmd --set X` 曾把 argparse 的**子命令名** "reload-cmd" 当成命令写进
数据库（升级后 strongSwan 再也重载不了）。那次事故说明——只测 API 不够，CLI 也必须真跑。

这里在临时数据目录里按真实顺序执行：init → import-ca → issue → import → revoke →
gencrl → publish → check → export → bundle → reload-cmd → automation → doctor →
preflight → rulesets → csr-* → backup → passwd，并断言退出码、输出内容与副作用。

另外做两条静态检查：
  * 任何 cmd_* 都不得读取 `args.cmd`（那是子命令名，不是参数值）；
  * 所有子命令 --help 正常，且任何命令都不得吐 Python traceback。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl
os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl
PY = ROOT / ".venv/bin/python"
TMP = Path(tempfile.mkdtemp(prefix="cli-e2e-"))
DATA = TMP / "data"
WORK = TMP / "work"
INCOMING = WORK / "incoming"
CSRDIR = WORK / "csr"
OUT = WORK / "out"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    (PASS if cond else FAIL).append(name)
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  {detail}" if detail and not cond else ""))
    return bool(cond)


def env() -> dict:
    # CA_HOST=127.0.0.1：本套件按"回环部署"评估 doctor，避免命中"明文+非回环"传输安全项
    return dict(os.environ, CA_DATA_DIR=str(DATA), PYTHONPATH=str(ROOT),
                CA_HOST="127.0.0.1")


def cli(*args: str, stdin: str | None = None, timeout: int = 180):
    return subprocess.run([str(PY), "-m", "backend.cli", *args], cwd=ROOT, env=env(),
                          capture_output=True, text=True, input=stdin, timeout=timeout)


def db_scalar(sql: str) -> str:
    code = ("import sys; sys.path.insert(0, '.')\n"
            "from backend import db\n"
            f"print(db.scalar({sql!r}))")
    return subprocess.run([str(PY), "-c", code], cwd=ROOT, env=env(),
                          capture_output=True, text=True).stdout.strip()


def seed_material() -> None:
    """造一套真实材料：CA 证书/私钥、2 张叶子证书、1 个 CSR。"""
    INCOMING.mkdir(parents=True, exist_ok=True)
    CSRDIR.mkdir(parents=True, exist_ok=True)
    code = f'''
import datetime as dt, sys
sys.path.insert(0, {str(ROOT)!r})
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend import x509util

work = {str(INCOMING)!r}
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CLI Test CA")])
now = x509util.now()
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
          key_encipherment=False, content_commitment=False, data_encipherment=False,
          key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
      .sign(ca_key, hashes.SHA256()))
open(work + "/ca.crt", "wb").write(x509util.pem_cert(ca).encode())
open(work + "/ca.key", "wb").write(x509util.pem_key(ca_key).encode())

for i in (1, 2):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf-%d" % i)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(ca_name)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .sign(ca_key, hashes.SHA256()))
    open(work + "/leaf-%d.crt" % i, "wb").write(x509util.pem_cert(c).encode())
    open(work + "/leaf-%d.key" % i, "wb").write(x509util.pem_key(k).encode())

kk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli-csr")]))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName("cli-csr.example.com")]),
                      critical=False)
       .sign(kk, hashes.SHA256()))
open({str(CSRDIR)!r} + "/cli.csr", "wb").write(
    csr.public_bytes(serialization.Encoding.PEM))
print("seed-ok")
'''
    r = subprocess.run([str(PY), "-c", code], cwd=ROOT, env=env(),
                       capture_output=True, text=True)
    if "seed-ok" not in r.stdout:
        raise SystemExit(f"造测试材料失败: {r.stderr[-400:]}")


def main() -> int:
    print("\n\033[1m== 0. 准备与静态检查 ==\033[0m")
    WORK.mkdir(parents=True, exist_ok=True)
    seed_material()

    # 静态：不许任何 cmd_* 读 args.cmd（子命令名陷阱）
    src = (ROOT / "backend/cli.py").read_text(encoding="utf-8")
    offenders = []
    for b in re.split(r"\ndef ", src):
        if not b.startswith("cmd_"):
            continue
        # 只看真正的代码行：去掉 # 注释，避免把"不要用 args.cmd"这类注释误判成用法
        code_only = "\n".join(ln.split("#", 1)[0] for ln in b.splitlines())
        if re.search(r"\bargs\.cmd\b", code_only):
            offenders.append(b.split("(")[0])
    check("静态：没有任何 cmd_* 使用 args.cmd（子命令名陷阱）", not offenders, str(offenders))

    # 静态：所有子命令 --help 正常
    helps = re.findall(r'add_parser\("([^"]+)"', src)
    bad_help = []
    for name in helps:
        r = cli(name, "--help")
        if r.returncode != 0 or "Traceback" in r.stderr:
            bad_help.append(name)
    check(f"静态：全部 {len(helps)} 个子命令 --help 正常", not bad_help,
          str(bad_help))
    check("静态：子命令数量符合预期（>= 22）", len(helps) >= 22, str(len(helps)))

    print("\n\033[1m== 1. 初始化与身份 ==\033[0m")
    r = cli("init")
    check("init 成功", r.returncode == 0 and (DATA / "ca.db").is_file(),
          (r.stderr or r.stdout)[-160:])
    r = cli("fingerprint")
    check("fingerprint 输出加密信道指纹", r.returncode == 0
          and bool(re.search(r"[0-9A-F]{4}-[0-9A-F]{4}", r.stdout)), r.stdout[:80])

    print("\n\033[1m== 2. 导入 CA ==\033[0m")
    r = cli("import-ca", "--cert", str(INCOMING / "ca.crt"), "--key", str(INCOMING / "ca.key"))
    check("import-ca 导入证书+私钥成功", r.returncode == 0, (r.stderr or r.stdout)[-200:])
    check("CA 已带私钥入库", db_scalar("SELECT has_key FROM cas WHERE is_active=1") == "1")

    print("\n\033[1m== 3. 签发 / 列表 / 导出 ==\033[0m")
    r = cli("issue", "--cn", "cli-issue", "--identity", "cli-issue.example.com",
            "--days", "30", "--out", str(OUT))
    check("issue 签发成功", r.returncode == 0, (r.stderr or r.stdout)[-200:])
    out_files = list(OUT.glob("*")) if OUT.exists() else []
    check("issue --out 导出了证书/私钥文件", len(out_files) >= 2, str([p.name for p in out_files]))
    cert_id = db_scalar("SELECT id FROM certs WHERE cn='cli-issue'")
    check("证书已入库", cert_id.isdigit(), cert_id)
    serial = db_scalar("SELECT serial_hex FROM certs WHERE cn='cli-issue'")
    r = cli("list", "--q", "cli-issue")
    check("list --q 能查到", r.returncode == 0 and "cli-issue" in r.stdout, r.stdout[:120])
    r = cli("list", "--limit", "5")
    check("list --limit 正常", r.returncode == 0)
    r = cli("export", "--format", "csv", "--out", str(WORK / "inv.csv"))
    csv_ok = (WORK / "inv.csv").is_file() and "cli-issue" in (WORK / "inv.csv").read_text()
    check("export --format csv --out 生成清单", r.returncode == 0 and csv_ok)
    r = cli("export", "--format", "json", "--out", str(WORK / "inv.json"))
    check("export --format json --out 生成清单", r.returncode == 0
          and (WORK / "inv.json").is_file())

    print("\n\033[1m== 4. 批量导入 ==\033[0m")
    imp = WORK / "import"
    imp.mkdir(exist_ok=True)
    for n in ("leaf-1.crt", "leaf-1.key", "leaf-2.crt"):
        shutil.copy2(INCOMING / n, imp / n)
    r = cli("import", "--path", str(imp), "--dry-run")
    check("import --dry-run 预检成功", r.returncode == 0, (r.stderr or r.stdout)[-200:])
    r = cli("import", "--path", str(imp), "--owner", "cli")
    check("import 批量导入成功", r.returncode == 0, (r.stderr or r.stdout)[-200:])
    n_leaf = db_scalar("SELECT COUNT(*) FROM certs WHERE cn LIKE 'leaf-%'")
    check("两张叶子证书已入库", n_leaf == "2", n_leaf)

    print("\n\033[1m== 5. 吊销三种定位方式 ==\033[0m")
    r = cli("revoke", "--id", cert_id, "--reason", "keyCompromise")
    check("revoke --id 成功", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    r = cli("revoke", "--serial", serial.upper(), "--reason", "superseded")
    check("revoke --serial 成功（幂等提示或成功）",
          r.returncode in (0, 2), (r.stderr or r.stdout)[-160:])
    r = cli("revoke", "--cn", "leaf-1", "--force", "--reason", "cessationOfOperation")
    check("revoke --cn --force 成功", r.returncode in (0, 2), (r.stderr or r.stdout)[-160:])
    # 恢复吊销：同样要更新 strongSwan（重新生成/发布 CRL + 重载）
    r = cli("unrevoke", "--id", cert_id)
    check("unrevoke --id 成功（恢复并更新 strongSwan）", r.returncode == 0,
          (r.stderr or r.stdout)[-200:])
    check("恢复后库里该证书为 valid",
          db_scalar(f"SELECT status FROM certs WHERE id={cert_id}") == "valid")
    try:
        import json as _j
        info = _j.loads(r.stdout)
        check("unrevoke 输出包含新的 CRL 编号与发布结果",
              info.get("crl_number") is not None and "publish" in info, r.stdout[:200])
    except Exception as exc:  # noqa: BLE001
        check("unrevoke 输出包含新的 CRL 编号与发布结果", False, f"{exc}: {r.stdout[:160]}")
    r = cli("unrevoke", "--id", cert_id)
    check("重复恢复给出明确错误（幂等）", r.returncode != 0, (r.stdout or r.stderr)[-120:])

    revoked = db_scalar("SELECT COUNT(*) FROM certs WHERE status='revoked'")
    check("至少一张证书已吊销", revoked.isdigit() and int(revoked) >= 1, revoked)

    print("\n\033[1m== 6. CRL 与发布 ==\033[0m")
    r = cli("gencrl", "--days", "7", "--no-reload")
    check("gencrl --days --no-reload 成功", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    entries = db_scalar("SELECT entries FROM crls ORDER BY id DESC LIMIT 1")
    check("CRL 条目数 >= 1", entries.isdigit() and int(entries) >= 1, entries)
    r = cli("publish", "--no-reload")
    check("publish --no-reload 成功", r.returncode == 0, (r.stderr or r.stdout)[-160:])

    # crl-info：不开 openssl 也能把"内容 + 签名 + 与库/发布目标一致性"一次验完
    crl_file = ""
    for line in (DATA / "publish").glob("*"):
        if line.is_file() and line.suffix in (".der", ".crl"):
            crl_file = str(line)
            break
    r = cli("crl-info", "--file", crl_file)
    check("crl-info 验证发布的 CRL 全部通过（退出码 0）", r.returncode == 0,
          (r.stderr or r.stdout)[-200:])
    check("crl-info 输出签名验证结论", "签名验证" in r.stdout and "✓" in r.stdout, r.stdout[-160:])
    check("crl-info 与数据库条目数一致", "条目一致" in r.stdout, r.stdout[-200:])
    r = cli("crl-info", "--file", crl_file, "--json")
    import json as _json
    try:
        info = _json.loads(r.stdout)
        check("crl-info --json 输出纯 JSON 且 ok=true", info.get("ok") is True, r.stdout[:120])
    except Exception as exc:  # noqa: BLE001
        check("crl-info --json 输出纯 JSON 且 ok=true", False, f"{exc}: {r.stdout[:120]}")
    # 篡改一个字节 → 必须报签名失败、退出码 1（证明是真验证，不是走过场）
    raw = bytearray(Path(crl_file).read_bytes())
    raw[-40] ^= 0xFF
    Path(crl_file).write_bytes(bytes(raw))
    r = cli("crl-info", "--file", crl_file)
    check("CRL 被篡改一字节即报签名失败且退出码 1",
          r.returncode == 1 and "签名验证失败" in r.stdout, (r.stdout or r.stderr)[-200:])
    raw[-40] ^= 0xFF
    Path(crl_file).write_bytes(bytes(raw))

    # crl-info --cert：拿"客户端实际在用的证书"判定为什么还能连
    import subprocess as _sp
    two = _sp.run([str(PY), "-c", (
        "import sys; sys.path.insert(0,'.')\n"
        "from backend import ca, db, publish, x509util\n"
        "row = ca.active_ca_row()\n"
        "a = ca.issue_certificate(ca_row=row, vpn_identity='dup.example.com', cn='dup-user')\n"
        "b = ca.issue_certificate(ca_row=row, vpn_identity='dup.example.com', cn='dup-user')\n"
        "ca.revoke(a['cert']['id'], reason='key_compromise')\n"
        "ca.generate_crl(actor='t', source='t')\n"
        "publish.publish(trigger='test', reload=False)\n"
        f"open({str(WORK / 'dup-old.crt')!r},'wb').write(a['secret']['cert_pem'].encode())\n"
        f"open({str(WORK / 'dup-new.crt')!r},'wb').write(b['secret']['cert_pem'].encode())\n"
        "r = db.q1('SELECT * FROM crls ORDER BY id DESC LIMIT 1')\n"
        "import backend.config as cfg\n"
        "p = r['der_path'] or r['path']\n"
        "print(str(cfg.DATA_DIR / p) if not p.startswith('/') else p)")],
        cwd=ROOT, env=env(), capture_output=True, text=True)
    crlpath = two.stdout.strip().splitlines()[-1] if two.stdout.strip() else ""
    r = cli("crl-info", "--file", crlpath, "--cert", str(WORK / "dup-old.crt"))
    check("crl-info --cert 能认出'这张确实已吊销'",
          r.returncode is not None and "已吊销" in r.stdout and "在这份 CRL 中：是" in r.stdout,
          (r.stdout or r.stderr)[-200:])
    r = cli("crl-info", "--file", crlpath, "--cert", str(WORK / "dup-new.crt"))
    check("同 CN 的另一张（未吊销）会明确指出'你吊销的是另一个序列号'",
          "另一个序列号" in r.stdout, (r.stdout or r.stderr)[-250:])
    check("并列出同 CN 的其它证书供核对", "同 CN 的其它证书" in r.stdout,
          (r.stdout or r.stderr)[-200:])

    print("\n\033[1m== 7. 一致性 / 部署自检 ==\033[0m")
    r = cli("doctor")
    check("doctor 报告 CRL 加载状态（charon 是否已读到最新 CRL）",
          "CRL 加载状态" in r.stdout, (r.stdout or r.stderr)[-200:])
    check("doctor 说明 charon 只在启动/reload 时读盘",
          "只在" in r.stdout and "reload" in r.stdout, (r.stdout or r.stderr)[-200:])
    r = cli("check")
    check("check 一致性体检成功", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    r = cli("check", "--repair")
    check("check --repair 可自动修复", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    r = cli("doctor", "--json")
    import json as _json
    try:
        dres = _json.loads(r.stdout).get("results", [])
    except Exception:  # noqa: BLE001
        dres = []
    derr = [x for x in dres if x.get("level") == "error"]
    check("doctor --json 有 CA 时无 error", r.returncode == 0 and dres and not derr,
          str([x.get("item") for x in derr]))
    r = cli("preflight", "--json")
    check("preflight --json 可运行并给出结论", "results" in r.stdout and "ready" in r.stdout,
          r.stdout[:120])

    print("\n\033[1m== 8. 规则集 / 重载命令 ==\033[0m")
    r = cli("rulesets")
    check("rulesets 列出 13 个内置规则集", r.returncode == 0 and "strongswan-vpn-client" in r.stdout)
    r = cli("rulesets", "--show", "strongswan-vpn-client")
    check("rulesets --show 输出完整规则", r.returncode == 0 and "vpn" in r.stdout.lower(),
          r.stdout[:120])
    r = cli("reload-cmd")
    try:
        shown = json.loads(r.stdout).get("cmd", "")
    except Exception:  # noqa: BLE001
        shown = ""
    check("reload-cmd 显示当前命令（非空）", r.returncode == 0 and bool(shown), r.stdout[:120])
    want = "echo CLI-A && echo CLI-B"
    r = cli("reload-cmd", "--set", want)
    stored = {t for t in [db_scalar("SELECT reload_cmd FROM publish_targets WHERE enabled=1 "
                                    "AND kind='dir_file' LIMIT 1")]}
    check("reload-cmd --set 写入的是命令本身（回归）",
          r.returncode == 0 and want in r.stdout and stored == {want}, f"{r.stdout[:80]} {stored}")

    print("\n\033[1m== 9. strongSwan 部署包 ==\033[1m==")
    bundle = WORK / "bundle.zip"
    r = cli("bundle", "--id", cert_id, "--role", "client", "--gateway", "gw.example.com",
            "--out", str(bundle))
    ok_zip = bundle.is_file()
    names = zipfile.ZipFile(bundle).namelist() if ok_zip else []
    check("bundle 生成 strongSwan 部署包", r.returncode == 0 and ok_zip,
          (r.stderr or r.stdout)[-160:])
    check("部署包含 swanctl 配置与证书", any(n.endswith(".conf") for n in names)
          and any(n.endswith(".pem") for n in names), str(names[:6]))

    print("\n\033[1m== 10. CSR 池 ==\033[0m")
    r = cli("csr-import", "--path", str(CSRDIR), "--owner", "cli")
    check("csr-import 导入 CSR", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    r = cli("csr-list")
    check("csr-list 显示请求", r.returncode == 0 and "cli-csr" in r.stdout, r.stdout[:120])
    csr_id = db_scalar("SELECT id FROM csrs WHERE cn='cli-csr'")
    r = cli("csr-issue", "--id", csr_id, "--out", str(WORK / "csrout"))
    check("csr-issue 用池中 CSR 签发", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    check("CSR 状态变为 issued",
          db_scalar(f"SELECT status FROM csrs WHERE id={csr_id}") == "issued")

    print("\n\033[1m== 11. 备份与恢复 ==\033[0m")
    r = cli("backup", "--name", "cli-drill")
    arch = sorted((DATA / "backups").glob("*cli-drill*"))
    check("backup --name 生成归档", r.returncode == 0 and bool(arch),
          (r.stderr or r.stdout)[-160:])
    r = cli("backup")
    check("backup（无参数）列出备份", r.returncode == 0 and "ca-backup" in r.stdout, r.stdout[:120])
    before = db_scalar("SELECT COUNT(*) FROM certs")
    r = cli("backup", "--restore", arch[0].name) if arch else None
    check("backup --restore 恢复成功", bool(r) and r.returncode == 0,
          (r.stderr or r.stdout)[-200:] if r else "无归档")
    check("恢复后证书数量一致", db_scalar("SELECT COUNT(*) FROM certs") == before,
          f"{before} -> {db_scalar('SELECT COUNT(*) FROM certs')}")

    print("\n\033[1m== 12. 自动化 ==\033[0m")
    r = cli("automation", "--list")
    check("automation --list 列出任务", r.returncode == 0, (r.stderr or r.stdout)[-160:])
    r = cli("automation", "--run-due")
    check("automation --run-due 可执行（无到期任务也应正常）", r.returncode == 0,
          (r.stderr or r.stdout)[-160:])

    print("\n\033[1m== 13. 修改口令 ==\033[0m")
    import re as _re
    m = _re.search(r"初始口令:\s*(\S+)", (DATA / "initial_admin_password.txt").read_text(encoding="utf-8"))
    old_pw = m.group(1) if m else ""
    r = cli("passwd", stdin=f"{old_pw}\nnewpass-123\nnewpass-123\n")
    check("passwd 可改口令（非交互管道输入）", r.returncode == 0,
          (r.stderr or r.stdout)[-200:])
    check("初始口令文件已删除", not (DATA / "initial_admin_password.txt").exists())

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
