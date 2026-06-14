"""Modem control via ModemManager (`mmcli`).

Using ModemManager as the universal abstraction means we support every modem
MM already knows (Huawei, Quectel, Fibocom, Sierra, ZTE, Telit, ...) without
hand-writing per-vendor scripts. libqmi/libmbim sit underneath MM.
"""
from __future__ import annotations

import subprocess
from typing import Any


class MMError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 30) -> str:
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError as e:
        raise MMError(f"command not found: {args[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise MMError(f"timeout running {' '.join(args)}") from e
    if out.returncode != 0:
        raise MMError(out.stderr.strip() or f"{args[0]} exited {out.returncode}")
    return out.stdout


def _kv(text: str) -> dict[str, str]:
    """Parse `mmcli --output-keyvalue` output into a flat dict."""
    d: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if v and v != "--":
            d[k.strip()] = v
    return d


def list_modem_ids() -> list[str]:
    """Return ModemManager numeric modem ids currently present."""
    out = _run(["mmcli", "-L", "--output-keyvalue"])
    ids: list[str] = []
    for line in out.splitlines():
        # modem.list.value[1] : /org/freedesktop/ModemManager1/Modem/0
        if ".value" in line and "/Modem/" in line:
            path = line.split(":", 1)[1].strip()
            ids.append(path.rsplit("/", 1)[-1])
    return ids


def modem_info(mid: str) -> dict[str, Any]:
    kv = _kv(_run(["mmcli", "-m", mid, "--output-keyvalue"]))
    return {
        "mm_id": mid,
        "imei": kv.get("modem.3gpp.imei") or kv.get("modem.generic.equipment-identifier"),
        "model": kv.get("modem.generic.model"),
        "operator": kv.get("modem.3gpp.operator-name"),
        "signal": _to_int(kv.get("modem.generic.signal-quality.value")),
        "state": kv.get("modem.generic.state"),
        "iface": _primary_port(kv),
        "mm_path": f"/org/freedesktop/ModemManager1/Modem/{mid}",
    }


def _primary_port(kv: dict[str, str]) -> str | None:
    # modem.generic.ports.value[N] : "wwan0 (net)"
    for k, v in kv.items():
        if k.startswith("modem.generic.ports") and "(net)" in v:
            return v.split(" ", 1)[0]
    return kv.get("modem.generic.primary-port")


def _to_int(v: str | None) -> int | None:
    try:
        return int(float(v)) if v is not None else None
    except ValueError:
        return None


def connect(mid: str, apn: str | None = None) -> None:
    """Bring the modem's data bearer up via MM simple-connect."""
    arg = f"apn={apn}" if apn else ""
    _run(["mmcli", "-m", mid, f"--simple-connect={arg}" if arg else "--simple-connect="],
         timeout=60)


def disconnect(mid: str) -> None:
    _run(["mmcli", "-m", mid, "--simple-disconnect"], timeout=30)


def reconnect(mid: str, apn: str | None = None) -> None:
    try:
        disconnect(mid)
    except MMError:
        pass
    connect(mid, apn)


def reset(mid: str) -> None:
    """Soft modem reset (re-registers on network, usually yields a new IP)."""
    _run(["mmcli", "-m", mid, "--reset"], timeout=60)


def bearer_ip(mid: str) -> str | None:
    out = _run(["mmcli", "-m", mid, "--output-keyvalue"])
    kv = _kv(out)
    for k, v in kv.items():
        if k.endswith("bearer.value") or "bearer" in k.lower() and "/Bearer/" in v:
            bid = v.rsplit("/", 1)[-1]
            bkv = _kv(_run(["mmcli", "-b", bid, "--output-keyvalue"]))
            return bkv.get("bearer.ipv4.address")
    return None


# --- SMS -------------------------------------------------------------------

def list_sms(mid: str) -> list[dict[str, str]]:
    out = _run(["mmcli", "-m", mid, "--messaging-list-sms", "--output-keyvalue"])
    msgs: list[dict[str, str]] = []
    for line in out.splitlines():
        if ".value" in line and "/SMS/" in line:
            sid = line.split(":", 1)[1].strip().rsplit("/", 1)[-1]
            kv = _kv(_run(["mmcli", "-s", sid, "--output-keyvalue"]))
            msgs.append({
                "id": sid,
                "number": kv.get("sms.content.number", ""),
                "text": kv.get("sms.content.text", ""),
                "timestamp": kv.get("sms.properties.timestamp", ""),
            })
    return msgs


def send_sms(mid: str, number: str, text: str) -> None:
    create = _run([
        "mmcli", "-m", mid,
        f"--messaging-create-sms=number={number},text='{text}'",
    ])
    sid = create.strip().rsplit("/", 1)[-1].rstrip("'\"")
    _run(["mmcli", "-s", sid, "--send"], timeout=30)


# --- USSD ------------------------------------------------------------------

def send_ussd(mid: str, code: str) -> str:
    """Initiate a USSD session (e.g. balance check) and return the response."""
    out = _run(
        ["mmcli", "-m", mid, f"--3gpp-ussd-initiate={code}", "--output-keyvalue"],
        timeout=45,
    )
    kv = _kv(out)
    resp = kv.get("modem.3gpp.ussd.network-response") or kv.get(
        "3gpp.ussd.network-response"
    )
    if resp:
        return resp
    # fall back to plain output when key form differs across MM versions
    return out.strip()
