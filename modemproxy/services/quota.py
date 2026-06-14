"""Monthly traffic quota enforcement.

For each proxy with a quota set, compares this month's usage (from the
bandwidth accounting) against the cap. Over the cap → auto-stop the proxy and
flag it `quota_locked`. Back under the cap (e.g. after month rollover) → an
auto-locked proxy is started again. Manually disabled proxies are left alone.
"""
from __future__ import annotations

from .. import db
from ..proxy import generator
from . import bandwidth


def _month_usage(imei: str, direction: str) -> int:
    rep = bandwidth.report(imei)
    if direction == "in":
        return rep["month_in"]
    if direction == "out":
        return rep["month_out"]
    return rep["month_in"] + rep["month_out"]


def status(imei: str) -> dict:
    """Quota status for one proxy."""
    port = db.get_port(imei) or {}
    quota = port.get("quota_bytes") or 0
    direction = port.get("quota_direction") or "both"
    used = _month_usage(imei, direction) if quota else 0
    return {
        "imei": imei,
        "quota_bytes": quota,
        "quota_direction": direction,
        "used_bytes": used,
        "left_bytes": max(0, quota - used) if quota else None,
        "over_quota": bool(quota) and used >= quota,
        "locked": bool(port.get("quota_locked")),
    }


def check() -> list[dict]:
    """Enforce quotas across all proxies. Returns the actions taken."""
    actions = []
    for port in (db.get_port(m["imei"]) for m in db.list_modems()):
        if not port:
            continue
        imei = port["imei"]
        quota = port.get("quota_bytes") or 0
        if not quota:
            continue
        used = _month_usage(imei, port.get("quota_direction") or "both")
        locked = bool(port.get("quota_locked"))
        if used >= quota and not locked and port.get("enabled"):
            generator.stop_proxy(imei, locked=True)
            actions.append({"imei": imei, "action": "locked", "used": used, "quota": quota})
        elif used < quota and locked:
            generator.start_proxy(imei)
            actions.append({"imei": imei, "action": "unlocked", "used": used, "quota": quota})
    return actions


def set_quota(imei: str, quota_bytes: int, direction: str = "both") -> dict:
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    if direction not in ("in", "out", "both"):
        direction = "both"
    db.set_port(imei, quota_bytes=max(0, int(quota_bytes)), quota_direction=direction)
    # re-evaluate immediately so the UI reflects lock/unlock without waiting
    check()
    return status(imei)
