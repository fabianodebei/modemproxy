"""Telegram alerts.

Sends operational notifications (IP rotation, proxy down, expiring ports) to a
Telegram chat. Repetitive identical alerts are muted for a configurable window
so a flapping modem doesn't spam the chat.
"""
from __future__ import annotations

import httpx

from .. import db
from ..config import get_config


def _send_raw(text: str) -> bool:
    cfg = get_config()
    if not (cfg.tg_alerts_enable and cfg.tg_bot_token and cfg.tg_chat_id):
        return False
    url = f"https://api.telegram.org/bot{cfg.tg_bot_token}/sendMessage"
    try:
        r = httpx.post(url, json={"chat_id": cfg.tg_chat_id, "text": text,
                                  "disable_web_page_preview": True}, timeout=8.0)
        return r.status_code < 400
    except httpx.HTTPError:
        return False


def notify(text: str, *, key: str | None = None) -> bool:
    """Send an alert, honouring the per-key mute window when key is given."""
    cfg = get_config()
    if key is not None:
        mute = max(0, int(cfg.alert_mute_minutes)) * 60
        if not db.alert_should_send(key, mute):
            return False
    brand = cfg.brand_name or "modemproxy"
    return _send_raw(f"[{brand}] {text}")


# --- typed events ----------------------------------------------------------

def rotation_ok(imei: str, name: str, old_ip: str | None, new_ip: str | None) -> None:
    if get_config().alert_rotation_ok:
        notify(f"🔁 {name}: IP rotated {old_ip or '?'} → {new_ip or '?'}",
               key=f"rotok:{imei}")


def rotation_fail(imei: str, name: str, err: str) -> None:
    if get_config().alert_rotation_fail:
        notify(f"⚠️ {name}: IP rotation failed — {err}", key=f"rotfail:{imei}")


def proxy_down(imei: str, name: str) -> None:
    if get_config().alert_proxy_down:
        notify(f"🔴 {name}: proxy offline / no IP", key=f"down:{imei}")


def expiring(imei: str, name: str, days: int) -> None:
    if get_config().alert_expiry:
        notify(f"⏳ {name}: proxy expires in {days} day(s)", key=f"exp:{imei}:{days}")


def expired(imei: str, name: str) -> None:
    if get_config().alert_expiry:
        notify(f"⛔ {name}: proxy expired and was disabled", key=f"expd:{imei}")
