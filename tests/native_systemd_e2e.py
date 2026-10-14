"""真实 systemd/swanctl 集成验收。仅在无业务的一次性 VM 上显式运行。

在 /opt/ca-dev 完成全新安装后执行：
  sudo /opt/ca-dev/.venv/bin/python /opt/ca-dev/tests/native_systemd_e2e.py --disposable-vm
会创建测试 CA、发布并吊销测试证书、重启 strongSwan、重跑安装和升级。
不加入 run_all.sh，不允许把缺少 systemd/swanctl 视为跳过成功。
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def run(*argv, check=True, timeout=120):
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{argv[0]} 失败（{result.returncode}）：{result.stderr[-2000:]}')
    return result


def require(ok, label):
    if not ok:
        raise RuntimeError(label)
    print('✓ ' + label, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true')
    args = parser.parse_args()
    require(args.disposable_vm, '必须显式指定 --disposable-vm，仅用于无业务的一次性 VM')
    require(os.geteuid() == 0 and ROOT == Path('/opt/ca-dev'), 'root + /opt/ca-dev')
    require(Path('/run/systemd/system').is_dir(), '真实 systemd 正在运行')
    require(not any(k.startswith('CA_') for k in os.environ), '没有测试环境覆盖生产默认配置')
    require(Path('/usr/bin/systemctl').is_file(), '发行版 systemctl 存在')
    run('/usr/bin/systemctl', 'is-active', '--quiet', 'ca-admin')
    run('swanctl', '--stats')
    database = ROOT / 'data/ca.db'
    require(database.is_file(), '已完成全新安装')
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as conn:
        # 不猜测 CA 表名：已有任意 CA/证书文件也一并拦截。
        require(conn.execute('SELECT COUNT(*) FROM certs').fetchone()[0] == 0,
                '数据库没有业务证书')
    require(not any(p.is_file() for p in (ROOT / 'data/ca').rglob('*')), '尚未导入业务 CA')
    require(not any(p.is_file() for d in ('x509', 'x509ca', 'x509crl', 'private', 'rsa', 'ecdsa', 'pkcs8')
                    for p in (Path('/etc/swanctl') / d).rglob('*')),
            'swanctl 凭据目录为空（禁止在业务 VPN 上执行）')
    require(not run('swanctl', '--list-sas').stdout.strip(), '没有在线 VPN 会话')

    sys.path.insert(0, str(ROOT / 'deploy'))
    from service_tools import render, wait_ready
    with tempfile.TemporaryDirectory(prefix='ca-native-units-') as temp:
        candidate = Path(temp) / 'ca-admin.service'
        text = render(ROOT / 'deploy/ca-admin-root.service', str(ROOT), str(ROOT / 'data'),
                      '127.0.0.1', '9443', 'root')
        candidate.write_text(text)
        run('systemd-analyze', 'verify', str(candidate))
        candidate.write_text(text.replace('WorkingDirectory=/opt/ca-dev',
                                         'WorkingDirectory="/opt/ca-dev"'))
        require(run('systemd-analyze', 'verify', str(candidate), check=False).returncode != 0,
                '真实解析器能拒绝曾经漏检的 WorkingDirectory 引号错误')
        watch = Path(temp) / 'ca-strongswan-sync.path'
        watch.write_text(render(ROOT / 'deploy/ca-strongswan-sync.path', str(ROOT),
                                str(ROOT / 'data'), '127.0.0.1', '9443', 'root'))
        (Path(temp) / 'ca-strongswan-sync.service').write_text(
            '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        run('systemd-analyze', 'verify', str(watch))
    require(wait_ready('127.0.0.1', '9443'), '真实沙箱服务持续就绪')

    run('/usr/bin/systemctl', 'stop', 'ca-admin')
    sys.path.insert(0, str(ROOT))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from backend import ca, db, publish, x509util
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Native Release Test CA')])
    now = x509util.now()
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=1))
                   .not_valid_after(now + dt.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, True, True,
                                                False, False), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .sign(key, hashes.SHA256()))
    ca.import_ca(x509util.pem_cert(certificate).encode(), x509util.pem_key(key).encode())
    db.set_setting('publish_ca_cert', '1')
    db.set_setting('ca_cert_filename', 'ca-release-test.pem')
    publish.apply_swanctl_targets()
    ca.generate_crl(actor='native-test', source='native-test')
    password_file = ROOT / 'data/initial_admin_password.txt'
    original_password = password_file.read_bytes()
    password = re.search(r'初始口令:\s*(\S+)', original_password.decode()).group(1)
    run('/usr/bin/systemctl', 'start', 'ca-admin')
    require(wait_ready('127.0.0.1', '9443'), '导入测试 CA 后服务就绪')
    from verify_deploy import Channel
    channel = Channel('http://127.0.0.1:9443')
    channel.connect()
    channel.data('POST', '/api/login', {'username': 'admin', 'password': password})
    issued = channel.data('POST', '/api/certs/issue', {
        'cn': 'native-release-client', 'vpn_identity': 'native-release.example.com',
        'profile': 'vpn_client', 'validity_days': 30})['cert']
    channel.data('POST', f"/api/certs/{issued['id']}/revoke", {'reason': 'keyCompromise'})
    disk = x509util.load_crl(Path('/etc/swanctl/x509crl/crl.der').read_bytes())
    require(disk.is_signature_valid(certificate.public_key()), '服务沙箱内发布的 CRL 签名有效')
    require(int(issued['serial_hex'], 16) in {entry.serial_number for entry in disk},
            '实际 swanctl 目录含被吊销证书序列号')
    # 不在这里额外调用 load-creds，必须证明服务自己的重载链已经生效。
    loaded = run('swanctl', '--list-certs', '--type', 'x509_crl', '--pem').stdout
    blocks = re.findall(r'-----BEGIN X509 CRL-----.*?-----END X509 CRL-----', loaded, re.S)
    require(any(x509.load_pem_x509_crl(b.encode()).public_bytes(serialization.Encoding.DER)
                == disk.public_bytes(serialization.Encoding.DER) for b in blocks),
            'charon 实际加载的 CRL 与发布文件完全一致')
    require(db.get_setting('last_reload_ok') == '1', '默认 strongSwan 重载链执行成功')
    fingerprint = ca.active_ca_row()['fingerprint']
    count = db.scalar('SELECT COUNT(*) FROM certs')
    before = run('/usr/bin/systemctl', 'show', 'strongswan', '-p', 'MainPID', '--value').stdout
    run('bash', str(ROOT / 'deploy/install.sh'), '--systemd', '--loopback', timeout=300)
    require(before == run('/usr/bin/systemctl', 'show', 'strongswan', '-p', 'MainPID', '--value').stdout,
            '重复安装不重启 strongSwan')
    run('bash', str(ROOT / 'deploy/upgrade.sh'), '--loopback', timeout=300)
    require(ca.active_ca_row()['fingerprint'] == fingerprint
            and db.scalar('SELECT COUNT(*) FROM certs') == count
            and password_file.read_bytes() == original_password,
            '重复安装和升级保留 CA、证书和账号')
    require(wait_ready('127.0.0.1', '9443'), '升级后真实服务就绪')
    run(sys.executable, str(ROOT / 'tests/verify_deploy.py'), timeout=180)
    print('真实 systemd / swanctl 集成验收通过；测试 VM 可销毁。')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'真实集成验收失败：{exc}', file=sys.stderr)
        raise SystemExit(1)
