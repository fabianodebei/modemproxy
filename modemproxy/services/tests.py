"""Per-modem connectivity + speed tests.

Traffic is forced through a specific modem by binding curl to that modem's
network interface (`curl --interface <iface>`), so the test reflects that SIM's
egress regardless of the host default route.
"""
from __future__ import annotations

import subprocess
import time

from .. import db

IP_ECHO_URL = "https://api.ipify.org"
# ~10 MB sample served over HTTPS; small enough to be quick, big enough to measure.
SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"


def _iface(imei: str) -> str:
    m = db.get_modem(imei)
    if not m or not m.get("iface"):
        raise ValueError(f"no interface known for {imei} (run discover)")
    return m["iface"]


def conn_test(imei: str, timeout: int = 15) -> dict:
    """Fetch the public IP seen when egressing through this modem."""
    iface = _iface(imei)
    t0 = time.time()
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "--interface", iface, IP_ECHO_URL],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return {"imei": imei, "ok": False, "error": "timeout"}
    ip = out.stdout.strip()
    ok = out.returncode == 0 and bool(ip) and "." in ip
    return {
        "imei": imei, "ok": ok, "ip": ip if ok else None,
        "latency_ms": round((time.time() - t0) * 1000),
        "error": None if ok else (out.stderr.strip() or "no response"),
    }


def speedtest(imei: str, timeout: int = 30) -> dict:
    """Measure download throughput through this modem (Mbps)."""
    iface = _iface(imei)
    try:
        out = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
             "--interface", iface,
             "-w", "%{size_download} %{speed_download} %{time_total}", SPEEDTEST_URL],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return {"imei": imei, "ok": False, "error": "timeout"}
    if out.returncode != 0 or not out.stdout.strip():
        return {"imei": imei, "ok": False, "error": out.stderr.strip() or "failed"}
    size, speed_bps, secs = (float(x) for x in out.stdout.split())
    return {
        "imei": imei, "ok": True,
        "bytes": int(size),
        "mbps": round(speed_bps * 8 / 1_000_000, 2),
        "seconds": round(secs, 2),
    }
