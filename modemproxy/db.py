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
    iface           TEXT,                -- network interface (wwan0 / wwan_dongle1)
    mm_path         TEXT,                -- ModemManager object path
    model           TEXT,
    operator        TEXT,
    ip              TEXT,                -- current WAN IP from operator
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
    enabled         INTEGER DEFAULT 1,
    created_at      INTEGER
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
            "p.rotation_interval, p.white_list, p.rotation_token, p.enabled "
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


def get_port_by_token(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    with db() as conn:
        r = conn.execute(
            "SELECT * FROM ports WHERE rotation_token=?", (token,)
        ).fetchone()
        return dict(r) if r else None


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
