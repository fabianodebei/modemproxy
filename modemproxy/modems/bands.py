"""Lock a modem to specific radio bands, and find out which ones are worth it.

Left to itself a modem camps where the operator steers it, not where it works
best: Modem 01 sat on LTE B7 at -88 dBm while B3 was there at -62, which is
~400x the received power. Locking is the only lever we have over that, and the
ZTE firmware exposes it through the same commands its own web UI uses —
``BAND_SELECT`` with a bitmask for LTE, ``WAN_PERFORM_NR5G_BAND_LOCK`` with a
band list for 5G NR.

Three pieces live here:

* ``read``/``apply``/``clear`` — the lock itself, with the device's original
  mask remembered on first lock so "unlock" really restores what it had.
* ``scan`` — walk the candidate bands one at a time, measure each, rank them.
  Slow (tens of seconds per band) and disruptive, so callers run it in a thread
  and preferably at night.
* ``guard`` — a lock is a loaded gun: if the locked band disappears the modem
  stays out of the network. The guard unlocks automatically after a sustained
  failure and says so, so a dead cell never costs a night of downtime.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from .. import db
from . import netdev

log = logging.getLogger("modemproxy.bands")

# How long to let the radio settle before believing its numbers, and how many
# consecutive failed health checks a locked band gets before we unlock it.
SETTLE_SECONDS = 25
GUARD_STRIKES = 3


class BandError(RuntimeError):
    pass


# --- band masks -------------------------------------------------------------

def mask_to_bands(mask: str | int) -> list[int]:
    """ZTE LTE mask -> band numbers. Band N is bit N-1."""
    if isinstance(mask, str):
        mask = mask.strip()
        if not mask:
            return []
        try:
            mask = int(mask, 16 if mask.lower().startswith("0x") else 10)
        except ValueError:
            return []
    return [i + 1 for i in range(64) if mask >> i & 1]


def bands_to_mask(bands: list[int]) -> str:
    value = 0
    for b in bands:
        if b < 1 or b > 64:
            raise BandError(f"banda LTE non valida: {b}")
        value |= 1 << (b - 1)
    if not value:
        raise BandError("nessuna banda selezionata")
    return f"0x{value:x}"


def _nr_list(raw: str | None) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", raw or "")]


# --- device access ----------------------------------------------------------

def _zte(modem: dict) -> tuple[str, str | None, str, dict[str, str], str]:
    host = modem.get("mgmt_host")
    if not host or "deco" in (modem.get("model") or "").lower():
        raise BandError("blocco banda non supportato su questo modem")
    iface = None if modem.get("manual") else modem.get("iface")
    cj = netdev._zte_session(host, iface)
    binder = netdev._zte_bind(host, iface)
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    return host, binder, cj, headers, netdev.zte_base_hash(host, binder, cj, headers)


def _get(modem: dict, cmd: str) -> dict[str, Any]:
    host, binder, cj, headers, _ = _zte(modem)
    ok, text = netdev._http(binder, f"http://{host}/goform/goform_get_cmd_process"
                            f"?isTest=false&multi_data=1&cmd={cmd}",
                            headers=headers, cookies=cj)
    try:
        return json.loads(text) if ok else {}
    except ValueError:
        return {}


_STATUS_CMD = ("lte_band_lock,nr5g_band_lock,wan_active_band,nr5g_action_band,"
               "network_type,lte_rsrp,lte_rsrq,lte_snr,Z5g_rsrp,Z5g_SINR,signalbar")


def _popcount(mask: str) -> int:
    return len(mask_to_bands(mask))


def _remember_capabilities(imei: str, mask: str) -> dict[str, Any]:
    """Keep the widest band mask the device has ever shown.

    ``lte_band_lock`` is NOT a stable "configured lock" on this firmware: while
    the radio re-attaches it reports the band currently in use (seen live:
    0x4, then 0x20000000000, then the full mask again). Taking whatever it says
    as "the device's own mask" once wrote a single-band mask as the restore
    point — i.e. unlocking would have left the modem locked. So the widest mask
    seen wins, and a narrow reading never overwrites it.
    """
    state = _saved_lock(imei)
    if mask and _popcount(mask) > max(1, _popcount(state.get("default_mask", ""))):
        state["default_mask"] = mask
        _save_lock(imei, state)
    return state


def read(modem: dict) -> dict[str, Any]:
    """Current lock + what the modem is actually using right now."""
    d = _get(modem, _STATUS_CMD)
    saved = _remember_capabilities(modem["imei"], d.get("lte_band_lock", ""))
    allowed = mask_to_bands(saved.get("default_mask") or d.get("lte_band_lock", ""))
    return {
        "imei": modem["imei"],
        "locked": bool(saved.get("lte")),
        "lte": saved.get("lte") or [],
        "nr": saved.get("nr") or [],
        "mask": d.get("lte_band_lock", ""),
        "supported_lte": allowed,
        "supported_nr": _nr_list(saved.get("default_nr") or d.get("nr5g_band_lock")),
        "active_band": d.get("wan_active_band", ""),
        "active_nr_band": d.get("nr5g_action_band", ""),
        "network_type": d.get("network_type", ""),
        "rsrp": netdev._num(d.get("lte_rsrp")),
        "sinr": netdev._num(d.get("lte_snr")),
    }


def _saved_lock(imei: str) -> dict[str, Any]:
    m = db.get_modem(imei) or {}
    try:
        return json.loads(m.get("band_lock") or "{}")
    except ValueError:
        return {}


def _save_lock(imei: str, data: dict[str, Any]) -> None:
    db.upsert_modem(imei, band_lock=json.dumps(data))


def _set_mask(modem: dict, mask: str) -> None:
    """Write an LTE mask straight to the device (no bookkeeping)."""
    host, binder, cj, headers, base_hash = _zte(modem)
    r = netdev.zte_set(host, binder, cj, headers, base_hash, goformId="BAND_SELECT",
                       is_gw_band="0", gw_band_mask="0", is_lte_band="1", lte_band_mask=mask)
    if "success" not in r.lower():
        raise BandError(f"il modem ha rifiutato la maschera {mask}: {r or 'nessuna risposta'}")


def apply(modem: dict, lte: list[int] | None = None, nr: list[int] | None = None,
          *, remember: bool = True) -> dict[str, Any]:
    """Lock the modem to ``lte`` (and optionally ``nr``) bands."""
    host, binder, cj, headers, base_hash = _zte(modem)
    now = _get(modem, "lte_band_lock,nr5g_band_lock")
    state = _remember_capabilities(modem["imei"], now.get("lte_band_lock", ""))
    state.setdefault("default_nr", now.get("nr5g_band_lock", ""))
    if _popcount(state.get("default_mask", "")) < 2:
        # Without a trustworthy "all bands" mask we could never unlock again.
        raise BandError("maschera bande del modem non ancora nota: riprova fra un minuto")

    if lte:
        mask = bands_to_mask(lte)
        r = netdev.zte_set(host, binder, cj, headers, base_hash, goformId="BAND_SELECT",
                           is_gw_band="0", gw_band_mask="0", is_lte_band="1",
                           lte_band_mask=mask)
        if "success" not in r.lower():
            raise BandError(f"il modem ha rifiutato il blocco LTE: {r or 'nessuna risposta'}")
    if nr:
        r = netdev.zte_set(host, binder, cj, headers, base_hash,
                           goformId="WAN_PERFORM_NR5G_BAND_LOCK",
                           nr5g_band_mask=",".join(str(b) for b in nr))
        if "success" not in r.lower():
            raise BandError(f"il modem ha rifiutato il blocco 5G: {r or 'nessuna risposta'}")

    if remember:
        state.update({"lte": lte or [], "nr": nr or [], "strikes": 0, "ts": db.now()})
        _save_lock(modem["imei"], state)
    time.sleep(2)
    return read(modem)


def clear(modem: dict) -> dict[str, Any]:
    """Unlock: put the device's original band mask back."""
    host, binder, cj, headers, base_hash = _zte(modem)
    state = _saved_lock(modem["imei"])
    mask = state.get("default_mask")
    if not mask:
        raise BandError("nessun blocco da togliere")
    r = netdev.zte_set(host, binder, cj, headers, base_hash, goformId="BAND_SELECT",
                       is_gw_band="0", gw_band_mask="0", is_lte_band="1",
                       lte_band_mask=mask)
    if "success" not in r.lower():
        raise BandError(f"il modem ha rifiutato lo sblocco: {r or 'nessuna risposta'}")
    if state.get("default_nr"):
        netdev.zte_set(host, binder, cj, headers, base_hash,
                       goformId="WAN_PERFORM_NR5G_BAND_LOCK",
                       nr5g_band_mask=state["default_nr"])
    _save_lock(modem["imei"], {"default_mask": mask, "default_nr": state.get("default_nr", ""),
                               "lte": [], "nr": [], "strikes": 0, "ts": db.now()})
    time.sleep(2)
    return read(modem)


# --- scan -------------------------------------------------------------------

def _sample(modem: dict) -> dict[str, Any]:
    d = _get(modem, _STATUS_CMD)
    iface = modem.get("iface")
    bind = modem.get("bind_ip") if modem.get("manual") else None
    ip = netdev.public_ip(iface, bind, max_time=8) if iface else None
    return {
        "band": d.get("wan_active_band", ""),
        "network_type": d.get("network_type", ""),
        "rsrp": netdev._num(d.get("lte_rsrp")),
        "rsrq": netdev._num(d.get("lte_rsrq")),
        "sinr": netdev._num(d.get("lte_snr")),
        "nr_rsrp": netdev._num(d.get("Z5g_rsrp")),
        "nr_sinr": netdev._num(d.get("Z5g_SINR")),
        "online": bool(ip),
        "ip": ip,
    }


def _score(s: dict[str, Any]) -> float:
    """Rank a band: usable signal first, quality second. Offline scores last."""
    if not s.get("online"):
        return -1e6
    rsrp = s.get("rsrp")
    sinr = s.get("sinr")
    if rsrp is None:
        return -1e5
    return rsrp + 2 * (sinr if sinr is not None else 0)


def scan(modem: dict, bands: list[int] | None = None, *,
         settle: int = SETTLE_SECONDS) -> dict[str, Any]:
    """Try each band in turn and report how the modem fared on it.

    The modem is left on the band it started from (or its original mask), so an
    interrupted scan never leaves a customer stuck on a test band.
    """
    before = read(modem)
    # The mask as the device has it right now: the scan must put exactly this
    # back, otherwise an unlocked modem would be left on the last band tried.
    original_mask = _saved_lock(modem["imei"]).get("default_mask") or before["mask"]
    candidates = bands or before["supported_lte"]
    # A full mask can list 40+ bands the operator doesn't even run here; testing
    # all of them would take an hour. The common Italian LTE set first.
    if not bands:
        common = [1, 3, 7, 8, 20, 28, 32, 38, 40, 42]
        candidates = [b for b in common if b in candidates] or candidates[:10]
    results: list[dict[str, Any]] = []
    name = modem.get("name") or modem["imei"]
    log.info("scan bande %s: provo %s", name, candidates)
    try:
        for band in candidates:
            try:
                apply(modem, [band], remember=False)
            except BandError as exc:
                results.append({"band": band, "error": str(exc), "online": False})
                continue
            time.sleep(settle)
            s = _sample(modem)
            s["band"] = band
            s["score"] = _score(s)
            results.append(s)
            log.info("scan bande %s: B%s rsrp=%s sinr=%s online=%s",
                     name, band, s.get("rsrp"), s.get("sinr"), s.get("online"))
    finally:
        if before["locked"] and before["lte"]:
            apply(modem, before["lte"], before["nr"] or None)
        else:
            _set_mask(modem, original_mask)
    ranked = sorted(results, key=lambda r: r.get("score", -1e6), reverse=True)
    best = ranked[0] if ranked and ranked[0].get("online") else None
    out = {"imei": modem["imei"], "ts": db.now(), "results": ranked,
           "best": best["band"] if best else None}
    db.upsert_modem(modem["imei"], band_scan=json.dumps(out))
    return out


# --- guard ------------------------------------------------------------------

def guard(modem: dict) -> str | None:
    """Unlock a modem whose locked band stopped working.

    Called from the periodic health check. Returns a message when it acts.
    """
    state = _saved_lock(modem["imei"])
    if not state.get("lte"):
        return None
    iface, bind = modem.get("iface"), modem.get("bind_ip") if modem.get("manual") else None
    online = bool(netdev.public_ip(iface, bind, max_time=8)) if iface else False
    if online:
        if state.get("strikes"):
            state["strikes"] = 0
            _save_lock(modem["imei"], state)
        return None
    state["strikes"] = int(state.get("strikes") or 0) + 1
    _save_lock(modem["imei"], state)
    if state["strikes"] < GUARD_STRIKES:
        return None
    name = modem.get("name") or modem["imei"]
    bands = ", ".join(f"B{b}" for b in state["lte"])
    try:
        clear(modem)
    except BandError as exc:
        return f"⚠️ {name}: bloccato su {bands} e offline, sblocco fallito ({exc})"
    return (f"🔓 {name}: offline da {GUARD_STRIKES} controlli sulla banda {bands} — "
            f"blocco rimosso, modem libero di riagganciarsi")
