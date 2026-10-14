"""灾备演练用的播种脚本：把一份"像真实部署"的数据写进 CA_DATA_DIR。

被 tests/e2e_test.py 以子进程方式调用（独立数据目录），用来做
「备份 → 拷到空机器 → 恢复 → 校验」的完整演练。

用法：
    CA_DATA_DIR=/tmp/drill-a .venv/bin/python tests/drill_seed.py
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import os

os.environ.setdefault("CA_RELOAD_CMD", "true")   # 测试环境：默认重载命令用无害 no-op，绝不调用真实 systemctl

from backend import ca, publish, server, x509util  # noqa: E402

CERT_COUNT = 3


def run() -> int:
    server.bootstrap(verbose=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Drill CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Drill Org")])
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
    for i in range(CERT_COUNT):
        ca.issue_certificate(ca_row=row, vpn_identity=f"drill{i}.example.com", cn=f"drill-{i}")
    ca.generate_crl(actor="drill", source="drill")
    publish.publish(trigger="drill", reload=False)
    print(f"seeded {CERT_COUNT} certs")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
