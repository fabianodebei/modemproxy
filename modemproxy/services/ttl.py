"""Egress TTL rewriting (anti-tethering).

Mobile carriers often detect tethering by watching the IP TTL: packets from a
phone leave with TTL 64, but a device *behind* the phone is forwarded with TTL
63 (decremented), which gives the tethering away. Forcing every egress packet
to a fixed TTL on the modem interface masks that.

Applied with an iptables mangle POSTROUTING rule per modem interface.
"""
from __future__ import annotations

import subprocess

from ..config import get_config


def _iptables(args: list[str]) -> int:
    try:
        return subprocess.run(["iptables", *args], capture_output=True, text=True).returncode
    except FileNotFoundError:
        return 127


def ensure_ttl(iface: str) -> bool:
    """Idempotently set a fixed egress TTL on iface (no-op if custom_ttl=0)."""
    ttl = int(get_config().custom_ttl or 0)
    if ttl <= 0 or not iface:
        return False
    rule = ["-t", "mangle", "POSTROUTING", "-o", iface, "-j", "TTL", "--ttl-set", str(ttl)]
    if _iptables(["-C", *rule]) == 0:
        return True  # already present
    return _iptables(["-A", *rule]) == 0


def clear_ttl(iface: str, ttl: int | None = None) -> None:
    t = ttl if ttl is not None else int(get_config().custom_ttl or 65)
    _iptables(["-t", "mangle", "-D", "POSTROUTING", "-o", iface,
               "-j", "TTL", "--ttl-set", str(t)])
