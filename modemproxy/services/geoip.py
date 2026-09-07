"""GeoIP labels ("IT · Milano") for each modem's public IP.

Looked up via ipinfo.io (basic fields need no key) and cached per IP in the
``geoip`` table, so a rotation only costs a lookup when the IP is new.
Best-effort throughout: a failed lookup leaves the previous label untouched.
"""
from __future__ import annotations

import httpx

from .. import db
from ..config import get_config

LOOKUP_URL = "https://ipinfo.io/{ip}/json"
TIMEOUT = 5.0


def _fetch(ip: str) -> str | None:
    """One network lookup -> 'CC · City' (or 'CC'), None on any failure."""
    try:
        r = httpx.get(LOOKUP_URL.format(ip=ip), timeout=TIMEOUT,
                      headers={"Accept": "application/json"})
        if r.status_code != 200:
            return None
        j = r.json()
    except Exception:
        return None
    country = (j.get("country") or "").strip()
    city = (j.get("city") or "").strip()
    if not country:
        return None
    return f"{country} · {city}" if city else country


def lookup(ip: str) -> str | None:
    """Cached label for an IP (fetches and stores it the first time)."""
    if not ip:
        return None
    with db.db() as conn:
        row = conn.execute("SELECT label FROM geoip WHERE ip=?", (ip,)).fetchone()
    if row:
        return row["label"]
    label = _fetch(ip)
    if label:
        with db.db() as conn:
            conn.execute("INSERT OR REPLACE INTO geoip (ip, label, ts) VALUES (?,?,?)",
                         (ip, label, db.now()))
    return label


def refresh_modems() -> int:
    """Relabel every modem whose public IP changed. Returns modems updated."""
    if not get_config().geoip_enable:
        return 0
    n = 0
    for m in db.list_modems():
        ip = m.get("ip")
        if not ip:
            continue
        label = lookup(ip)
        if label and label != m.get("geo"):
            db.upsert_modem(m["imei"], geo=label)
            n += 1
    return n
