"""Modem lifecycle orchestration: discovery, status sync, rotation."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import db
from ..config import get_config
from ..services import alerts
from . import control, netdev


def discover() -> list[dict[str, Any]]:
    """Enumerate modems from ModemManager + net-mode dongles into the DB."""
    cfg = get_config()
    results: list[dict[str, Any]] = []

    def _one(mid: str) -> dict[str, Any] | None:
        try:
            info = control.modem_info(mid)
        except control.MMError:
            return None
        if not info.get("imei"):
            return None
        status = "online" if info.get("state") == "connected" else "offline"
        db.upsert_modem(
            info["imei"],
            kind="mm",
            mm_path=info["mm_path"],
            model=info.get("model"),
            operator=info.get("operator"),
            iface=info.get("iface"),
            signal=info.get("signal"),
            ip=control_safe_ip(mid),
            status=status,
            last_seen=db.now(),
        )
        info["status"] = status
        return info

    # ModemManager modems (may be empty if mmcli absent / no AT-mode modems).
    try:
        ids = control.list_modem_ids()
    except control.MMError:
        ids = []
    if ids:
        with ThreadPoolExecutor(max_workers=cfg.max_parallel_workers) as ex:
            for r in ex.map(_one, ids):
                if r:
                    results.append(r)

    # Net-mode (HiLink/RNDIS) dongles ModemManager can't drive.
    try:
        results.extend(netdev.discover())
    except Exception:  # discovery of net dongles must never break mm discovery
        pass

    # Alert + score proxies that should be up but went offline.
    try:
        cfg = get_config()
        for m in db.list_modems():
            if m.get("enabled") and m.get("http_port") and m.get("status") == "offline":
                alerts.proxy_down(m["imei"], m.get("name") or m["imei"][-6:])
                if cfg.autoreboot_enable:
                    from ..services import autoreboot
                    autoreboot.record(m["imei"], cfg.score_offline)
    except Exception:
        pass
    return results


def control_safe_ip(mid: str) -> str | None:
    try:
        return control.bearer_ip(mid)
    except control.MMError:
        return None


def _mm_id_for(imei: str) -> str | None:
    """Map a stored IMEI back to the live ModemManager id."""
    for mid in control.list_modem_ids():
        try:
            if control.modem_info(mid).get("imei") == imei:
                return mid
        except control.MMError:
            continue
    return None


def _reconnect_once(imei: str, old: dict[str, Any]) -> str | None:
    """Trigger one reconnect and return the resulting public IP."""
    if old.get("kind") == "netdev":
        return netdev.rotate(old)
    mid = _mm_id_for(imei)
    if not mid:
        raise control.MMError(f"modem {imei} not present")
    control.reconnect(mid)
    time.sleep(3)
    return control_safe_ip(mid)


def rotate(imei: str, reason: str = "manual") -> dict[str, Any]:
    """Force a new public IP, with optional retry until the IP actually changes."""
    cfg = get_config()
    old = db.get_modem(imei)
    old_ip = old.get("ip") if old else None
    name = (old or {}).get("name") or imei[-6:]

    # Rate-limit: skip if rotated too recently.
    if cfg.rotation_min_interval > 0:
        last = db.rotation_log(imei, limit=1)
        if last and (db.now() - last[0]["ts"]) < cfg.rotation_min_interval:
            return {"imei": imei, "old_ip": old_ip, "new_ip": old_ip, "skipped": "min_interval"}

    attempts = 1 if cfg.rotation_dirty or not cfg.rotation_retry else max(1, cfg.rotation_max_retry)
    new_ip = None
    try:
        for _ in range(attempts):
            new_ip = _reconnect_once(imei, old or {})
            if cfg.rotation_dirty:
                break
            ok = bool(new_ip) and (not cfg.rotation_unique or new_ip != old_ip)
            if ok:
                break
    except Exception as e:
        alerts.rotation_fail(imei, name, str(e))
        if cfg.autoreboot_enable:
            from ..services import autoreboot
            autoreboot.record(imei, cfg.score_rotation_fail)
        raise

    db.upsert_modem(imei, ip=new_ip, last_seen=db.now())
    db.log_rotation(imei, old_ip, new_ip, reason)
    if not new_ip and cfg.autoreboot_enable:
        from ..services import autoreboot
        autoreboot.record(imei, cfg.score_ip_not_detected)
    if cfg.rotation_unique and new_ip and new_ip == old_ip:
        alerts.rotation_fail(imei, name, f"IP unchanged after {attempts} tries ({new_ip})")
    else:
        alerts.rotation_ok(imei, name, old_ip, new_ip)
    return {"imei": imei, "old_ip": old_ip, "new_ip": new_ip}


def rotate_all(reason: str = "manual") -> list[dict[str, Any]]:
    return [rotate(m["imei"], reason) for m in db.list_modems() if m.get("status") == "online"]


def rotate_due(reason: str = "schedule") -> list[dict[str, Any]]:
    """Rotate only modems whose per-port rotation interval has elapsed."""
    out = []
    for imei in db.due_for_rotation():
        try:
            out.append(rotate(imei, reason))
        except control.MMError:
            continue
    return out


def reset_modem(imei: str) -> None:
    mid = _mm_id_for(imei)
    if not mid:
        raise control.MMError(f"modem {imei} not present")
    control.reset(mid)


def send_ussd(imei: str, code: str) -> str:
    mid = _mm_id_for(imei)
    if not mid:
        raise control.MMError(f"modem {imei} not present")
    return control.send_ussd(mid, code)
