"""SQLite persistence: modems, ports, bandwidth counters, SMS, rotation log."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import get_config

SCHEMA = """
CREATE TABLE IF NOT EXISTS modems (
    imei            TEXT PRIMARY KEY,
    name            TEXT,                -- friendly nick (e.g. dongle1)
    kind            TEXT DEFAULT 'mm',   -- mm (ModemManager) | netdev (HiLink/net-mode)
    iface           TEXT,                -- network interface (wwan0 / enx<mac>)
    mm_path         TEXT,                -- ModemManager object path
    bind_ip         TEXT,                -- local source IP for 3proxy egress binding
    mgmt_host       TEXT,                -- net-mode dongle web API host (e.g. 192.168.0.1)
    rt_table        INTEGER,             -- policy-routing table id (net-mode dongles)
    manual          INTEGER DEFAULT 0,   -- 1 = manually added (LAN 4G/5G router via ethernet)
    model           TEXT,
    operator        TEXT,
    ip              TEXT,                -- current public WAN IP
    signal          INTEGER,            -- signal quality %
    status          TEXT DEFAULT 'unknown', -- online | offline | unknown
    last_seen       INTEGER,
    created_at      INTEGER
);

CREATE TABLE IF NOT EXISTS ports (
    imei            TEXT PRIMARY KEY REFERENCES modems(imei) ON DELETE CASCADE,
    http_port       INTEGER,
    socks_port      INTEGER,
    username        TEXT,
    password        TEXT,
    rotation_interval INTEGER DEFAULT 0,  -- seconds; 0 = manual
    rotation_url    TEXT,                 -- optional GET hook to trigger rotation
    rotation_token  TEXT,                 -- secret token for the public rotation hook
    white_list      TEXT,                 -- JSON list of allowed client IPs/CIDRs
    quota_bytes     INTEGER DEFAULT 0,    -- monthly traffic cap in bytes; 0 = unlimited
    quota_direction TEXT DEFAULT 'both',  -- in | out | both
    quota_locked    INTEGER DEFAULT 0,    -- 1 = auto-disabled by quota check
    vpn_enabled     INTEGER DEFAULT 0,    -- 1 = per-modem OpenVPN server running
    expires_at      INTEGER,              -- subscription expiry epoch; NULL = never
    enabled         INTEGER DEFAULT 1,
    created_at      INTEGER
);

CREATE TABLE IF NOT EXISTS alert_log (
    akey            TEXT PRIMARY KEY,    -- dedupe key (e.g. "rotfail:<imei>")
    ts              INTEGER              -- last time this alert was sent
);

CREATE TABLE IF NOT EXISTS bandwidth (
    imei            TEXT REFERENCES modems(imei) ON DELETE CASCADE,
    ts              INTEGER,
    rx_bytes        INTEGER,
    tx_bytes        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_bw_imei_ts ON bandwidth(imei, ts);

CREATE TABLE IF NOT EXISTS sms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    imei            TEXT REFERENCES modems(imei) ON DELETE CASCADE,
    direction       TEXT,                -- in | out
    number          TEXT,
    text            TEXT,
    ts              INTEGER
);

CREATE TABLE IF NOT EXISTS rotation_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    imei            TEXT REFERENCES modems(imei) ON DELETE CASCADE,
    old_ip          TEXT,
    new_ip          TEXT,
    reason          TEXT,
    ts              INTEGER
);

CREATE TABLE IF NOT EXISTS sticky (
    key             TEXT PRIMARY KEY,    -- caller-supplied session key
    imei            TEXT REFERENCES modems(imei) ON DELETE CASCADE,
    expires_at      INTEGER
);

CREATE TABLE IF NOT EXISTS api_keys (
    key             TEXT PRIMARY KEY,    -- secret token
    label           TEXT,                -- human note (e.g. "scraper-1")
    created_at      INTEGER,
    last_used       INTEGER
);
"""


def _connect() -> sqlite3.Connection:
    cfg = get_config()
    Path(cfg.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cfg.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first release to existing DBs."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(ports)")}
    if "white_list" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN white_list TEXT")
    if "rotation_token" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN rotation_token TEXT")
    if "quota_bytes" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN quota_bytes INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE ports ADD COLUMN quota_direction TEXT DEFAULT 'both'")
        conn.execute("ALTER TABLE ports ADD COLUMN quota_locked INTEGER DEFAULT 0")
    if "vpn_enabled" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN vpn_enabled INTEGER DEFAULT 0")
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN expires_at INTEGER")

    mcols = {r["name"] for r in conn.execute("PRAGMA table_info(modems)")}
    if "kind" not in mcols:
        conn.execute("ALTER TABLE modems ADD COLUMN kind TEXT DEFAULT 'mm'")
    if "bind_ip" not in mcols:
        conn.execute("ALTER TABLE modems ADD COLUMN bind_ip TEXT")
    if "mgmt_host" not in mcols:
        conn.execute("ALTER TABLE modems ADD COLUMN mgmt_host TEXT")
    if "rt_table" not in mcols:
        conn.execute("ALTER TABLE modems ADD COLUMN rt_table INTEGER")
    if "manual" not in mcols:
        conn.execute("ALTER TABLE modems ADD COLUMN manual INTEGER DEFAULT 0")


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> int:
    return int(time.time())


# --- modem helpers ---------------------------------------------------------

def upsert_modem(imei: str, **fields: Any) -> None:
    fields = {k: v for k, v in fields.items() if v is not None}
    with db() as conn:
        row = conn.execute("SELECT imei FROM modems WHERE imei=?", (imei,)).fetchone()
        if row:
            if fields:
                cols = ", ".join(f"{k}=?" for k in fields)
                conn.execute(f"UPDATE modems SET {cols} WHERE imei=?",
                             (*fields.values(), imei))
        else:
            fields.setdefault("created_at", now())
            keys = ["imei", *fields.keys()]
            ph = ", ".join("?" * len(keys))
            conn.execute(f"INSERT INTO modems ({', '.join(keys)}) VALUES ({ph})",
                         (imei, *fields.values()))


def list_modems() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT m.*, p.http_port, p.socks_port, p.username, p.password, "
            "p.rotation_interval, p.white_list, p.rotation_token, "
            "p.quota_bytes, p.quota_direction, p.quota_locked, p.vpn_enabled, "
            "p.expires_at, p.enabled "
            "FROM modems m LEFT JOIN ports p ON p.imei = m.imei "
            "ORDER BY m.name"
        ).fetchall()
        return [dict(r) for r in rows]


def get_modem(imei: str) -> dict[str, Any] | None:
    with db() as conn:
        r = conn.execute("SELECT * FROM modems WHERE imei=?", (imei,)).fetchone()
        return dict(r) if r else None


def set_port(imei: str, **fields: Any) -> None:
    with db() as conn:
        row = conn.execute("SELECT imei FROM ports WHERE imei=?", (imei,)).fetchone()
        if row:
            cols = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE ports SET {cols} WHERE imei=?",
                         (*fields.values(), imei))
        else:
            fields.setdefault("created_at", now())
            keys = ["imei", *fields.keys()]
            ph = ", ".join("?" * len(keys))
            conn.execute(f"INSERT INTO ports ({', '.join(keys)}) VALUES ({ph})",
                         (imei, *fields.values()))


def get_port(imei: str) -> dict[str, Any] | None:
    with db() as conn:
        r = conn.execute("SELECT * FROM ports WHERE imei=?", (imei,)).fetchone()
        return dict(r) if r else None


def delete_port(imei: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM ports WHERE imei=?", (imei,))


def sticky_get(key: str) -> str | None:
    """Return the IMEI bound to a session key if still valid, else None."""
    with db() as conn:
        r = conn.execute(
            "SELECT imei, expires_at FROM sticky WHERE key=?", (key,)
        ).fetchone()
        if not r:
            return None
        if r["expires_at"] and r["expires_at"] < now():
            conn.execute("DELETE FROM sticky WHERE key=?", (key,))
            return None
        return r["imei"]


def sticky_set(key: str, imei: str, ttl: int) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO sticky (key, imei, expires_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET imei=excluded.imei, expires_at=excluded.expires_at",
            (key, imei, now() + ttl),
        )


def sticky_purge_expired() -> None:
    with db() as conn:
        conn.execute("DELETE FROM sticky WHERE expires_at < ?", (now(),))


def api_key_create(label: str = "") -> str:
    import secrets
    key = "mk_" + secrets.token_urlsafe(24)
    with db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, label, created_at) VALUES (?,?,?)",
            (key, label, now()),
        )
    return key


def api_key_list() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT key, label, created_at, last_used FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def api_key_revoke(key: str) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM api_keys WHERE key=?", (key,))
        return cur.rowcount > 0


def api_key_valid(key: str) -> bool:
    if not key:
        return False
    with db() as conn:
        r = conn.execute("SELECT key FROM api_keys WHERE key=?", (key,)).fetchone()
        if r:
            conn.execute("UPDATE api_keys SET last_used=? WHERE key=?", (now(), key))
            return True
    return False


def get_port_by_token(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    with db() as conn:
        r = conn.execute(
            "SELECT * FROM ports WHERE rotation_token=?", (token,)
        ).fetchone()
        return dict(r) if r else None


def alert_should_send(akey: str, mute_seconds: int) -> bool:
    """True if this alert key wasn't sent within the mute window; records send."""
    t = now()
    with db() as conn:
        r = conn.execute("SELECT ts FROM alert_log WHERE akey=?", (akey,)).fetchone()
        if r and mute_seconds > 0 and (t - r["ts"]) < mute_seconds:
            return False
        conn.execute(
            "INSERT INTO alert_log (akey, ts) VALUES (?,?) "
            "ON CONFLICT(akey) DO UPDATE SET ts=excluded.ts",
            (akey, t),
        )
    return True


def log_rotation(imei: str, old_ip: str | None, new_ip: str | None, reason: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO rotation_log (imei, old_ip, new_ip, reason, ts) VALUES (?,?,?,?,?)",
            (imei, old_ip, new_ip, reason, now()),
        )


def rotation_log(imei: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        if imei:
            rows = conn.execute(
                "SELECT * FROM rotation_log WHERE imei=? ORDER BY ts DESC LIMIT ?",
                (imei, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM rotation_log ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def due_for_rotation() -> list[str]:
    """IMEIs whose rotation_interval elapsed since their last rotation."""
    t = now()
    with db() as conn:
        rows = conn.execute(
            "SELECT p.imei, p.rotation_interval, "
            "       (SELECT MAX(ts) FROM rotation_log r WHERE r.imei=p.imei) AS last_ts "
            "FROM ports p "
            "JOIN modems m ON m.imei = p.imei "
            "WHERE p.enabled=1 AND p.rotation_interval > 0 AND m.status='online'"
        ).fetchall()
    due = []
    for r in rows:
        last = r["last_ts"] or 0
        if t - last >= r["rotation_interval"]:
            due.append(r["imei"])
    return due
