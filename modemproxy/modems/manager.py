"""Modem lifecycle orchestration: discovery, status sync, rotation."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import db
from ..config import get_config
from . import control


def discover() -> list[dict[str, Any]]:
    """Enumerate modems from ModemManager and upsert them into the DB."""
    cfg = get_config()
    ids = control.list_modem_ids()
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

    with ThreadPoolExecutor(max_workers=cfg.max_parallel_workers) as ex:
        for r in ex.map(_one, ids):
            if r:
                results.append(r)
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


def rotate(imei: str, reason: str = "manual") -> dict[str, Any]:
    """Force a new public IP for one modem by reconnecting its data bearer."""
    old = db.get_modem(imei)
    old_ip = old.get("ip") if old else None
    mid = _mm_id_for(imei)
    if not mid:
        raise control.MMError(f"modem {imei} not present")
    control.reconnect(mid)
    time.sleep(3)
    new_ip = control_safe_ip(mid)
    db.upsert_modem(imei, ip=new_ip, last_seen=db.now())
    db.log_rotation(imei, old_ip, new_ip, reason)
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
