"""Subscription expiry for sold proxies.

A port can carry an ``expires_at`` epoch. ``check()`` disables proxies whose
time is up (so the pool stops handing them out) and fires a Telegram warning
ahead of expiry. Run it from a daily timer.
"""
from __future__ import annotations

import time
from typing import Any

from .. import db
from ..config import get_config
from . import alerts


def set_expiry(imei: str, expires_at: int | None) -> dict[str, Any]:
    """Set (or clear, with None) the subscription expiry for a proxy."""
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    db.set_port(imei, expires_at=expires_at)
    return status(imei)


def extend(imei: str, days: int) -> dict[str, Any]:
    """Extend (or start) a subscription by N days from the later of now/current."""
    p = db.get_port(imei)
    if not p:
        raise ValueError(f"no proxy configured for {imei}")
    base = max(int(time.time()), p.get("expires_at") or 0)
    return set_expiry(imei, base + days * 86400)


def status(imei: str) -> dict[str, Any]:
    p = db.get_port(imei) or {}
    exp = p.get("expires_at")
    now = int(time.time())
    return {
        "imei": imei,
        "expires_at": exp,
        "expired": bool(exp and exp <= now),
        "days_left": (round((exp - now) / 86400, 1) if exp else None),
    }


def check() -> list[dict[str, Any]]:
    """Disable expired proxies; warn about ones expiring soon. Returns actions."""
    from ..proxy import generator
    cfg = get_config()
    now = int(time.time())
    warn_window = max(0, int(cfg.alert_expiry_days)) * 86400
    actions: list[dict[str, Any]] = []
    for m in db.list_modems():
        exp = m.get("expires_at")
        if not exp:
            continue
        name = m.get("name") or m["imei"][-6:]
        if exp <= now:
            if m.get("enabled"):
                generator.stop_proxy(m["imei"])
                alerts.expired(m["imei"], name)
                actions.append({"imei": m["imei"], "action": "disabled-expired"})
        elif exp - now <= warn_window:
            days = max(1, round((exp - now) / 86400))
            alerts.expiring(m["imei"], name, days)
            actions.append({"imei": m["imei"], "action": "expiring", "days": days})
    return actions
