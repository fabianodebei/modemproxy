"""Modem auto-reboot by failure scoring.

Each failure (rotation fail, IP not detected, offline) adds points to a
modem's score within a sliding window. When the score crosses the threshold
the modem is rebooted (ModemManager reset, or the dongle/router web API) and
the score resets. A minimum interval between reboots prevents reboot loops.
"""
from __future__ import annotations

from .. import db
from ..config import get_config
from . import alerts


def record(imei: str, points: int) -> None:
    cfg = get_config()
    if not cfg.autoreboot_enable or points <= 0:
        return
    m = db.get_modem(imei) or {}
    now = db.now()
    start = m.get("score_window_start") or 0
    score = m.get("reboot_score") or 0
    if now - start > cfg.autoreboot_window:
        score, start = 0, now
    score += points
    db.upsert_modem(imei, reboot_score=score, score_window_start=start)
    if score >= cfg.autoreboot_max_score:
        _reboot(imei, m)


def _reboot(imei: str, m: dict) -> None:
    cfg = get_config()
    # Rate-limit reboots (also stands in for a minimum-uptime guard).
    if not db.alert_should_send(f"reboot:{imei}", cfg.autoreboot_min_uptime):
        return
    db.upsert_modem(imei, reboot_score=0, score_window_start=db.now())
    name = m.get("name") or imei[-6:]
    ok = False
    try:
        if m.get("kind") == "netdev":
            from ..modems import netdev
            host = m.get("mgmt_host")
            ok = bool(host) and netdev.reboot_zte(host)
        else:
            from ..modems import control, manager
            mid = manager._mm_id_for(imei)
            if mid:
                control.reset(mid)
                ok = True
    except Exception:
        ok = False
    alerts.notify(f"♻️ {name}: auto-reboot ({'ok' if ok else 'attempted'}) "
                  f"after {cfg.autoreboot_max_score} fault score", key=f"rebootmsg:{imei}")
