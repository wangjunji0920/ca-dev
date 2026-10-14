"""SQLite 数据层。

单一事实来源（single source of truth）说明
----------------------------------------
本系统的权威数据是 SQLite 库：证书清单、CA 清单、吊销状态、CRL 记录、审计日志。
OpenSSL 的 ``index.txt`` 与 CRL 文件都是**从数据库派生**出来的产物
（见 ``ca.py`` 的 ``export_index_txt``），因此不存在“数据库与 OpenSSL 库不一致”的问题。

并发模型
--------
单管理员系统，流量极低。这里刻意使用**一个共享连接 + 可重入锁**，而不是每线程一个连接：

* 事务内不会被其它线程插入写操作（``BEGIN IMMEDIATE`` + 全局锁），数据一致性最好证明；
* 备份/恢复时可以在锁内安全地关闭并替换数据库文件，不会出现“某个线程还握着旧 inode”的
  幽灵写入问题；
* 代价只是写操作串行化，对本场景完全可接受。

一致性保障手段：
1. 所有多步写操作都在一个事务里完成（``with tx() as conn``）。
2. 证书/CRL 的 PEM 文件在事务内原子落盘，提交后必然与数据库一致。
3. 外键 + 唯一索引（指纹、CA 内序列号）在数据库层面阻止重复数据。
4. ``consistency.py`` 做全量体检：文件缺失、指纹不符、CRL 与吊销状态不一致等。
"""
from __future__ import annotations

import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from typing import Any, Iterable

from . import config, x509util

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS cas (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subject       TEXT NOT NULL,
    cn            TEXT,
    serial_hex    TEXT NOT NULL UNIQUE,
    fingerprint   TEXT NOT NULL UNIQUE,
    not_before    TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    key_type      TEXT,
    key_size      INTEGER,
    signature_algorithm TEXT,
    has_key       INTEGER NOT NULL DEFAULT 0,
    is_active     INTEGER NOT NULL DEFAULT 0,
    cert_path     TEXT,
    key_path      TEXT,
    chain_path    TEXT,
    source        TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex    TEXT NOT NULL,
    serial_dec    TEXT,
    subject       TEXT NOT NULL,
    cn            TEXT,
    issuer        TEXT,
    fingerprint   TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'valid',
    not_before    TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    revoked_at    TEXT,
    revocation_reason TEXT,
    revocation_notes  TEXT,
    profile       TEXT,
    key_type      TEXT,
    key_size      INTEGER,
    signature_algorithm TEXT,
    sans_json     TEXT NOT NULL DEFAULT '[]',
    key_usage_json TEXT NOT NULL DEFAULT '[]',
    eku_json      TEXT NOT NULL DEFAULT '[]',
    owner         TEXT,
    tags_json     TEXT NOT NULL DEFAULT '[]',
    notes         TEXT,
    cert_path     TEXT,
    key_path      TEXT,
    has_key       INTEGER NOT NULL DEFAULT 0,
    ca_id         INTEGER REFERENCES cas(id) ON DELETE SET NULL,
    replaces_id   INTEGER,
    replaced_by_id INTEGER,
    source        TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (ca_id, serial_hex)
);
CREATE INDEX IF NOT EXISTS idx_certs_status  ON certs(status);
CREATE INDEX IF NOT EXISTS idx_certs_cn      ON certs(cn);
CREATE INDEX IF NOT EXISTS idx_certs_na      ON certs(not_after);
CREATE INDEX IF NOT EXISTS idx_certs_serial  ON certs(serial_hex);

CREATE TABLE IF NOT EXISTS crls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    number        TEXT,
    this_update   TEXT NOT NULL,
    next_update   TEXT NOT NULL,
    entries       INTEGER NOT NULL DEFAULT 0,
    sha256        TEXT,
    ca_id         INTEGER REFERENCES cas(id) ON DELETE SET NULL,
    path          TEXT,
    der_path      TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    action        TEXT NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    target_label  TEXT,
    actor         TEXT NOT NULL DEFAULT 'admin',
    detail_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS serial_counter (
    ca_id  INTEGER PRIMARY KEY,
    next_serial INTEGER NOT NULL DEFAULT 1
);

-- CRL 发布目标（面向 strongSwan：把 CRL 落到 /etc/swanctl/x509crl 或 /etc/ipsec.d/crls）
CREATE TABLE IF NOT EXISTS publish_targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'dir_file',
    path        TEXT NOT NULL,
    filename    TEXT NOT NULL,
    format      TEXT NOT NULL DEFAULT 'der',
    content     TEXT NOT NULL DEFAULT 'crl',   -- crl | ca_cert | ca_chain
    create_dir  INTEGER NOT NULL DEFAULT 0,    -- 目标目录不存在时是否允许创建（默认否）
    only_if_changed INTEGER NOT NULL DEFAULT 1, -- 内容未变则不写、不重载（防重载风暴）
    reload_cmd  TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    mode        TEXT DEFAULT '0644',
    owner       TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS publish_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    target_id   INTEGER,
    target_name TEXT,
    path        TEXT,
    sha256      TEXT,
    ok          INTEGER NOT NULL DEFAULT 0,
    message     TEXT,
    reload_output TEXT,
    trigger     TEXT DEFAULT 'manual',
    crl_id      INTEGER,
    actor       TEXT DEFAULT 'admin'
);
CREATE INDEX IF NOT EXISTS idx_publish_log_ts ON publish_log(ts DESC);

-- 规则集：证书怎么签，全部是可编辑的数据（见 backend/rules.py）
CREATE TABLE IF NOT EXISTS rulesets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT,
    platform    TEXT NOT NULL DEFAULT 'any',   -- strongswan | linux | windows | macos | any
    purpose     TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    builtin     INTEGER NOT NULL DEFAULT 0,
    spec_json   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- CSR 池：批量收进来的证书请求，审核后再签发（见 backend/csrs.py）
CREATE TABLE IF NOT EXISTS csrs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    spki_fingerprint TEXT NOT NULL UNIQUE,      -- 公钥指纹，防止同一请求重复入库
    subject          TEXT NOT NULL,
    cn               TEXT,
    pem              TEXT NOT NULL,
    key_type         TEXT,
    key_size         INTEGER,
    sans_json        TEXT NOT NULL DEFAULT '[]',
    signature_valid  INTEGER NOT NULL DEFAULT 1,
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending | issued | rejected
    requested_profile TEXT,
    owner            TEXT,
    tags_json        TEXT NOT NULL DEFAULT '[]',
    notes            TEXT,
    source           TEXT,
    cert_id          INTEGER,
    issued_at        TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csrs_status ON csrs(status);
CREATE INDEX IF NOT EXISTS idx_csrs_cn ON csrs(cn);

-- 通用自动化任务：触发器 + 内容 + 动作（见 backend/automation.py）
CREATE TABLE IF NOT EXISTS automation_tasks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL DEFAULT 'file',      -- file | command | webhook
    content          TEXT NOT NULL DEFAULT 'none',      -- crl_der / ca_cert_pem / ...
    trigger          TEXT NOT NULL DEFAULT 'manual',    -- on_revoke / schedule / crl_expiry ...
    target_json      TEXT NOT NULL DEFAULT '{}',
    interval_minutes INTEGER NOT NULL DEFAULT 0,
    lead_hours       INTEGER NOT NULL DEFAULT 0,
    only_if_changed  INTEGER NOT NULL DEFAULT 1,
    reload_cmd       TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    note             TEXT,
    last_run         TEXT,
    last_ok          INTEGER,
    last_message     TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS automation_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    task_id   INTEGER,
    task_name TEXT,
    trigger   TEXT,
    ok        INTEGER NOT NULL DEFAULT 0,
    skipped   INTEGER NOT NULL DEFAULT 0,
    message   TEXT,
    sha256    TEXT,
    output    TEXT,
    actor     TEXT DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_automation_log_ts ON automation_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_automation_log_task ON automation_log(task_id);
"""


def _new_conn() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH, timeout=30, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # 先设忙等，再切 journal_mode：切换 WAL 需要短暂独占锁，且**不一定**遵守 busy_timeout
    # （并发初始化时会立刻返回 SQLITE_BUSY）。真实场景：服务正在首次 bootstrap 时，
    # 管理员同时跑 `cli doctor` —— 旧实现会直接抛 "database is locked"。
    conn.execute("PRAGMA busy_timeout=30000")
    for _attempt in range(40):
        try:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() == "wal":
                break
        except sqlite3.OperationalError:
            pass
        # 也许别的进程已经切成 WAL 了 —— 那就是成功
        if str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal":
            break
        time.sleep(0.25)
    else:
        # 如实抛出，不静默降级为非 WAL
        if str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def connect() -> sqlite3.Connection:
    """返回共享连接（调用方若需原子性请使用 ``tx()``）。"""
    global _conn
    with _lock:
        if _conn is None:
            _conn = _new_conn()
        return _conn


@contextmanager
def locked():
    """需要在锁内做文件级替换（备份/恢复）时使用。"""
    with _lock:
        yield


def close() -> None:
    """关闭共享连接（恢复数据前调用）。"""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except sqlite3.Error:
                pass
            _conn = None


@contextmanager
def tx():
    """事务上下文；异常自动回滚，正常结束自动提交。全程持有全局锁。"""
    with _lock:
        conn = connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")


def init_db() -> None:
    config.ensure_dirs()
    with _lock:
        conn = connect()
        conn.executescript(SCHEMA)
        cur = conn.execute("PRAGMA user_version").fetchone()[0]
        if cur < SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        for k, v in config.DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        _migrate(conn)
        _ensure_crl_number_unique(conn)


def _ensure_crl_number_unique(conn) -> None:
    """给 crls(ca_id, number) 加唯一约束（跨进程取号的最后一道保险）。

    老库可能已有历史重复编号（旧版本的进程内锁挡不住并发），此时**不能**让启动失败：
    记下来交给 doctor/一致性检查报告，用户重新生成 CRL 即可。
    """
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_crls_ca_number "
                     "ON crls(ca_id, number)")
    except sqlite3.IntegrityError:
        name = "crl_number_duplicate_index_failed"
        try:
            conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                         (name, x509util.to_iso(x509util.now())))
        except sqlite3.Error:
            pass


# 轻量迁移：新增列时不必重建库（老版本升级也能平滑进行）
MIGRATIONS = [
    ("publish_targets", "content", "TEXT NOT NULL DEFAULT 'crl'"),
    ("publish_targets", "create_dir", "INTEGER NOT NULL DEFAULT 0"),
    ("publish_targets", "only_if_changed", "INTEGER NOT NULL DEFAULT 1"),
    # 1 = 允许该目标与同目录其它目标写同名内容（默认 0：由护栏阻止，避免 CRL 互相遮蔽）
    ("publish_targets", "shadow_ok", "INTEGER NOT NULL DEFAULT 0"),
]


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, ddl in MIGRATIONS:
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


# ---------------------------------------------------------------- 查询助手
def q(sql: str, args: Iterable[Any] = ()) -> list[dict]:
    with _lock:
        return [dict(r) for r in connect().execute(sql, tuple(args)).fetchall()]


def q1(sql: str, args: Iterable[Any] = ()) -> dict | None:
    with _lock:
        row = connect().execute(sql, tuple(args)).fetchone()
        return dict(row) if row is not None else None


def scalar(sql: str, args: Iterable[Any] = (), default: Any = 0) -> Any:
    with _lock:
        row = connect().execute(sql, tuple(args)).fetchone()
    if row is None or row[0] is None:
        return default
    return row[0]


def get_setting(key: str, default: str | None = None) -> str | None:
    row = q1("SELECT value FROM settings WHERE key=?", (key,))
    if row is None:
        return config.DEFAULTS.get(key, default)
    return row["value"]


def set_setting(key: str, value: str) -> None:
    with tx() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )


def settings_dict() -> dict:
    out = dict(config.DEFAULTS)
    for row in q("SELECT key,value FROM settings"):
        out[row["key"]] = row["value"]
    return out


def next_serial(ca_id: int) -> int:
    """顺序序列号分配（必须在调用方的事务/锁内执行）。"""
    with _lock:
        conn = connect()
        conn.execute("INSERT OR IGNORE INTO serial_counter(ca_id,next_serial) VALUES(?,1)",
                     (ca_id,))
        row = conn.execute("SELECT next_serial FROM serial_counter WHERE ca_id=?",
                           (ca_id,)).fetchone()
        value = int(row[0])
        conn.execute("UPDATE serial_counter SET next_serial=? WHERE ca_id=?", (value + 1, ca_id))
        return value


def json_load(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default
