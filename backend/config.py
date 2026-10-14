"""全局配置、路径管理与密钥材料工具。

设计要点
--------
* 所有可变数据集中在 ``data/`` 目录下，便于整体备份/迁移。
* 敏感文件（私钥、会话密钥、初始口令）一律 0600 权限。
* 可通过环境变量覆盖关键路径与监听地址，方便部署到其它服务器。
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

APP_NAME = "CA 证书管理系统"
VERSION = "1.0.1"

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CA_DATA_DIR") or (BASE_DIR / "data")).resolve()
CA_DIR = DATA_DIR / "ca"                 # 导入的 CA 证书/私钥/链
CERT_DIR = DATA_DIR / "certs"            # 签发/导入的证书与私钥
CRL_DIR = DATA_DIR / "crl"               # 生成的 CRL
BACKUP_DIR = DATA_DIR / "backups"
TMP_DIR = DATA_DIR / "tmp"
INCOMING_DIR = DATA_DIR / "incoming"     # 便于用户往这里丢待导入文件
CHANNEL_DIR = DATA_DIR / "channel"       # 自建加密信道的服务端长期密钥
DB_PATH = DATA_DIR / "ca.db"
FRONTEND_DIR = BASE_DIR / "frontend"

SECRET_FILE = DATA_DIR / ".session_secret"
CHANNEL_KEY_FILE = CHANNEL_DIR / "server.key"
INITIAL_PW_FILE = DATA_DIR / "initial_admin_password.txt"

# 监听配置
HOST = os.environ.get("CA_HOST", "127.0.0.1")
PORT = int(os.environ.get("CA_PORT", "9443"))
# 传输层：默认 **不启用 HTTPS**，而是在 HTTP 之上自建应用层加密信道
# （见 backend/secure_channel.py）。设为 on 可额外启用 TLS（例如放在反向代理后面）。
TLS_ENABLED = os.environ.get("CA_TLS", "off").lower() in ("on", "1", "true", "yes")
# 明文 REST 接口的可用范围：off=完全关闭 / loopback=仅本机(默认，便于运维与自动化) / on=任意来源
LEGACY_API = (os.environ.get("CA_LEGACY_API", "loopback") or "loopback").lower()
TRUST_PROXY = os.environ.get("CA_TRUST_PROXY", "0") in ("1", "true", "yes")
ALLOWED_HOSTS = [h.strip() for h in (os.environ.get("CA_ALLOWED_HOSTS") or "").split(",")
                 if h.strip()]
MAX_BODY_BYTES = int(os.environ.get("CA_MAX_BODY", str(64 * 1024 * 1024)))

# 运行身份：以 root 运行时可以直接写 /etc/swanctl 并执行 swanctl/ipsec
RUN_AS_ROOT = (os.geteuid() == 0)
MANAGE_STRONGSWAN = os.environ.get("CA_MANAGE_STRONGSWAN", "1" if RUN_AS_ROOT else "0") in (
    "1", "true", "yes", "on")
SWANCTL_DIR = Path(os.environ.get("CA_SWANCTL_DIR", "/etc/swanctl"))
SWANCTL_CRL_DIR = SWANCTL_DIR / "x509crl"
SWANCTL_CA_DIR = SWANCTL_DIR / "x509ca"
# strongSwan CRL 文件名/格式：沿用现场既有约定（本机现场是 x509crl/crl.der）
SWANCTL_CRL_FILENAME = os.environ.get("CA_CRL_FILENAME", "crl.der")
SWANCTL_CRL_FORMAT = os.environ.get("CA_CRL_FORMAT", "der").lower()

# 会话
SESSION_COOKIE = "ca_session"
SESSION_TTL = int(os.environ.get("CA_SESSION_TTL", str(12 * 3600)))   # 绝对超时（秒）
SESSION_IDLE = int(os.environ.get("CA_SESSION_IDLE", str(2 * 3600)))  # 空闲超时（秒）

# 默认业务参数（可被数据库 settings 覆盖）
# 代码里的默认重载命令（不受 CA_RELOAD_CMD 影响）：测试据此断言"默认值应该是什么"
# 默认重载命令。**为什么是 restart 而不是 reload**（现场实测）：
#   `systemctl reload strongswan` 虽然会让 charon 读到新 CRL（日志里能看到
#   "crl #0c is newer - existing crl #0b replaced"），但 charon 对**证书状态**的
#   判定结果仍走缓存（日志 "using cached crl"），于是"吊销/恢复不生效"，
#   必须重启守护进程才真正按新 CRL 判定。因此默认采用实测有效的 restart；
#   restart 会短暂断开所有在线连接，不能接受时可用
#   `cli reload-cmd --preset flush`（先 --flush-certs 再 reload，较轻，需实测）。
DEFAULT_RELOAD_CMD = "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan"

# 三个预设，供 cli reload-cmd --preset 使用（现场按自己 strongSwan 版本实测选择）
RELOAD_PRESETS = {
    # 最可靠：清缓存 + 载入凭据 + 重启（会短暂断开所有在线连接）
    "restart": "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan",
    # 较轻（官方文档给了这个用法）：只清 CRL 缓存再重新载入，不断开连接。
    # 依据：swanctl --flush-certs [--type x509|x509_ac|x509_crl|ocsp_response|pubkey]，
    # 文档示例即 "swanctl --flush-certs --type x509_crl"。
    "flush": "swanctl --flush-certs --type x509_crl && swanctl --load-creds",
    # 重新载入（现场可能仍需要 restart，需在自己的版本上实测）
    "reload": "swanctl --flush-certs && swanctl --load-creds && systemctl reload strongswan",
}

DEFAULTS = {
    "org_name": "Example Organization",
    "default_validity_days": "825",
    "crl_validity_days": "30",
    # CRL 编号下限：接管现场已有 CA/CRL 时，若现场编号已经到 9，而系统从 1 开始，
    # strongSwan 只会保留编号更大的旧 CRL → 新吊销永远不生效（遮蔽）。
    # 迁移时用 `cli crl-number --set <≥现场最大编号+1>` 跳号即可。
    "crl_number_floor": "0",
    "crl_url": "",
    "serial_mode": "random",
    "key_type": "rsa",
    "key_size": "2048",
    # 默认规则集（slug）；不填则用规则集列表里的第一个
    "default_ruleset": "strongswan-vpn-client",
    # strongSwan：客户端连接的对端网关地址（生成 swanctl 配置片段时使用）
    "vpn_gateway": "",
    # ---- CRL 的“消费方式”：全部是可编辑设置，不写死在代码里 ----
    # 想换目录/文件名/格式/重载命令，改设置即可（界面「CRL 自动发布 → 消费设置」）
    "swanctl_dir": "/etc/swanctl",
    "swanctl_crl_dir": "/etc/swanctl/x509crl",
    "swanctl_ca_dir": "/etc/swanctl/x509ca",
    "crl_filename": "crl.der",          # 留空则自动沿用目标目录里已有的本 CA 的 CRL 文件名
    "crl_format": "der",                # der | pem
    # 重载命令：按现场要求同时执行 swanctl 与 systemctl（支持 && / ; 组合）
    # 可用 CA_RELOAD_CMD 覆盖默认值：
    #  · 现场若 strongSwan 单元名不同（如 strongswan-starter），改这里即可；
    #  · 自动化测试用它指向无害命令，确保测试**不会调用真实 systemctl**。
    "crl_reload_cmd": os.environ.get("CA_RELOAD_CMD") or DEFAULT_RELOAD_CMD,
    # 防"重载风暴"：同一轮发布只重载一次，且两次重载之间至少间隔这么多秒
    "reload_min_interval_seconds": "30",
    # 内容未变化时是否跳过写入与重载（默认开，避免无意义的 strongSwan 重载）
    "publish_only_if_changed": "1",
    # 是否同时把 CA 证书发布到 strongSwan 的 x509ca/。
    # **默认关闭**：需要持续自动化的是 CRL（吊销），CA 证书几乎不变；
    # 而且同目录里出现多份同名 CA 证书会让 charon 的 CRL 选择变得不确定。
    # 需要分发 CA 证书时在「CRL 自动发布」页勾选，或设 publish_ca_cert=1。
    "publish_ca_cert": "0",
    "ca_cert_filename": "",             # 留空则自动沿用现场已有的本 CA 文件名
    # CRL/自动化
    "auto_publish": "1",
    "auto_publish_lead_hours": "72",
    "auto_publish_interval_minutes": "60",
    "auto_reload": "1",
}

ALL_DIRS = (DATA_DIR, CA_DIR, CERT_DIR, CRL_DIR, BACKUP_DIR, TMP_DIR, INCOMING_DIR,
            CHANNEL_DIR)


def ensure_dirs() -> None:
    for d in ALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except OSError:
            pass


def chmod_private(path: Path) -> None:
    """把敏感文件权限收紧到 0600（尽力而为）。"""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def atomic_write(path: Path, data: bytes, private: bool = False) -> None:
    """原子写入：先写临时文件再 rename，避免半截文件破坏一致性。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp{secrets.token_hex(4)}")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if private:
        chmod_private(tmp)
    os.replace(tmp, path)


def atomic_write_text(path: Path, text: str, private: bool = False) -> None:
    atomic_write(path, text.encode("utf-8"), private=private)


def session_secret() -> bytes:
    """会话签名密钥，首次运行时随机生成并持久化。"""
    ensure_dirs()
    if SECRET_FILE.exists():
        raw = SECRET_FILE.read_bytes().strip()
        if len(raw) >= 32:
            return raw
    raw = secrets.token_bytes(48)
    atomic_write(SECRET_FILE, raw, private=True)
    return raw
