"""Customer accounts for the read-only user panel.

Customers log in at /panel and see only the modems assigned to them: live
status, signal, public IP, bandwidth, expiry, and ready-to-use proxy
credentials (formatted per the configured remote-access mode). Passwords are
hashed with PBKDF2 (stdlib, no extra deps).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

from .. import db
from . import bandwidth, publish, subscriptions

_ITER = 120_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


def create(username: str, password: str, label: str = "") -> None:
    db.customer_upsert(username, password_hash=hash_password(password), label=label)


def set_password(username: str, password: str) -> None:
    db.customer_upsert(username, password_hash=hash_password(password))


def authenticate(username: str, password: str) -> bool:
    c = db.customer_get(username)
    return bool(c and c.get("password_hash") and verify_password(password, c["password_hash"]))


def proxies_for(username: str) -> list[dict[str, Any]]:
    """Read-only view of a customer's assigned proxies."""
    imeis = set(db.customer_imeis(username))
    if not imeis:
        return []
    now = int(time.time())
    out = []
    for m in db.list_modems():
        if m["imei"] not in imeis or not m.get("http_port"):
            continue
        ep = publish.customer_endpoints(m)
        bw = bandwidth.report(m["imei"])
        sub = subscriptions.status(m["imei"])
        expired = bool(m.get("expires_at") and m["expires_at"] <= now)
        out.append({
            "imei": m["imei"], "name": m.get("name") or m["imei"][-6:],
            "operator": m.get("operator"), "signal": m.get("signal"),
            "ip": m.get("ip"),
            "status": "expired" if expired else m.get("status"),
            "http": ep.get("http"), "socks5": ep.get("socks5"),
            "host": ep.get("host"), "http_port": ep.get("http_port"),
            "socks_port": ep.get("socks_port"),
            "rotation_token": m.get("rotation_token"),
            "month_bytes": (bw.get("month_in", 0) + bw.get("month_out", 0)),
            "today_bytes": (bw.get("day_in", 0) + bw.get("day_out", 0)),
            "expires_at": sub.get("expires_at"), "days_left": sub.get("days_left"),
        })
    return out
