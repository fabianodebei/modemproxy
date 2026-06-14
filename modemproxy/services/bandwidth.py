"""Bandwidth accounting.

Samples per-interface counters from /sys/class/net/<iface>/statistics and
stores cumulative rx/tx into the `bandwidth` table. Reports aggregate usage
over today / yesterday / this month / last month / lifetime.

Counters reset to zero when an interface disappears (modem unplug / reconnect),
so on each sample we store the *absolute* counter and compute deltas on read,
ignoring negative deltas (a reset boundary).
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .. import db


def _read_iface_counters(iface: str) -> tuple[int, int] | None:
    base = Path(f"/sys/class/net/{iface}/statistics")
    try:
        rx = int((base / "rx_bytes").read_text())
        tx = int((base / "tx_bytes").read_text())
        return rx, tx
    except (FileNotFoundError, ValueError):
        return None


def sample() -> int:
    """Record one counter sample per known modem interface. Returns count."""
    n = 0
    with db.db() as conn:
        for m in conn.execute("SELECT imei, iface FROM modems WHERE iface IS NOT NULL"):
            counters = _read_iface_counters(m["iface"])
            if not counters:
                continue
            rx, tx = counters
            conn.execute(
                "INSERT INTO bandwidth (imei, ts, rx_bytes, tx_bytes) VALUES (?,?,?,?)",
                (m["imei"], db.now(), rx, tx),
            )
            n += 1
    return n


def _delta_in_range(rows: list, start: int, end: int) -> tuple[int, int]:
    """Sum positive deltas of absolute counters within [start, end)."""
    rx_total = tx_total = 0
    prev_rx = prev_tx = None
    for r in rows:
        if prev_rx is not None and start <= r["ts"] < end:
            drx, dtx = r["rx_bytes"] - prev_rx, r["tx_bytes"] - prev_tx
            if drx >= 0:
                rx_total += drx
            if dtx >= 0:
                tx_total += dtx
        prev_rx, prev_tx = r["rx_bytes"], r["tx_bytes"]
    return rx_total, tx_total


def report(imei: str | None = None) -> dict:
    """Aggregate usage windows. If imei is None, sums across all modems."""
    today = dt.date.today()
    midnight = int(dt.datetime.combine(today, dt.time()).timestamp())
    y_midnight = midnight - 86400
    month_start = int(dt.datetime.combine(today.replace(day=1), dt.time()).timestamp())
    prev_month_last = today.replace(day=1) - dt.timedelta(days=1)
    prev_month_start = int(
        dt.datetime.combine(prev_month_last.replace(day=1), dt.time()).timestamp()
    )

    with db.db() as conn:
        if imei:
            rows = conn.execute(
                "SELECT * FROM bandwidth WHERE imei=? ORDER BY ts", (imei,)
            ).fetchall()
            by_modem = {imei: rows}
        else:
            by_modem = {}
            for r in conn.execute("SELECT * FROM bandwidth ORDER BY imei, ts"):
                by_modem.setdefault(r["imei"], []).append(r)

    def agg(start, end):
        rx = tx = 0
        for rows in by_modem.values():
            drx, dtx = _delta_in_range(rows, start, end)
            rx += drx
            tx += dtx
        return rx, tx

    now = db.now()
    d_in, d_out = agg(midnight, now)
    y_in, y_out = agg(y_midnight, midnight)
    m_in, m_out = agg(month_start, now)
    pm_in, pm_out = agg(prev_month_start, month_start)
    life_in, life_out = agg(0, now)

    return {
        "day_in": d_in, "day_out": d_out,
        "yesterday_in": y_in, "yesterday_out": y_out,
        "month_in": m_in, "month_out": m_out,
        "prevmonth_in": pm_in, "prevmonth_out": pm_out,
        "lifetime_in": life_in, "lifetime_out": life_out,
    }


def series(imei: str, hours: int = 24, buckets: int = 48) -> list[dict]:
    """Time-bucketed throughput series for charts (bytes/bucket)."""
    now = db.now()
    start = now - hours * 3600
    width = max(1, (now - start) // buckets)
    with db.db() as conn:
        rows = conn.execute(
            "SELECT * FROM bandwidth WHERE imei=? AND ts>=? ORDER BY ts",
            (imei, start),
        ).fetchall()
    out = []
    for b in range(buckets):
        b0 = start + b * width
        b1 = b0 + width
        rx, tx = _delta_in_range(rows, b0, b1)
        out.append({"ts": b0, "rx": rx, "tx": tx})
    return out
