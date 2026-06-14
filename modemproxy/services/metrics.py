"""Prometheus text-exposition metrics.

No external dependency: we render the exposition format by hand. Exposes pool
health plus per-modem signal and monthly traffic, so a single scrape covers
both fleet overview and individual SIMs.
"""
from __future__ import annotations

from .. import db
from . import bandwidth


def _line(name: str, value, labels: dict | None = None) -> str:
    if labels:
        lbl = ",".join(f'{k}="{_esc(str(v))}"' for k, v in labels.items())
        return f"{name}{{{lbl}}} {value}"
    return f"{name} {value}"


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render() -> str:
    modems = db.list_modems()
    online = sum(1 for m in modems if m.get("status") == "online")
    active = sum(1 for m in modems if m.get("http_port") and m.get("enabled"))
    locked = sum(1 for m in modems if m.get("quota_locked"))

    out: list[str] = []
    out += [
        "# HELP modemproxy_modems_total Number of known modems.",
        "# TYPE modemproxy_modems_total gauge",
        _line("modemproxy_modems_total", len(modems)),
        "# HELP modemproxy_modems_online Modems currently online.",
        "# TYPE modemproxy_modems_online gauge",
        _line("modemproxy_modems_online", online),
        "# HELP modemproxy_proxies_active Enabled proxies with a port.",
        "# TYPE modemproxy_proxies_active gauge",
        _line("modemproxy_proxies_active", active),
        "# HELP modemproxy_quota_locked Proxies auto-disabled by quota.",
        "# TYPE modemproxy_quota_locked gauge",
        _line("modemproxy_quota_locked", locked),
    ]

    out += [
        "# HELP modemproxy_modem_signal Signal quality percent per modem.",
        "# TYPE modemproxy_modem_signal gauge",
    ]
    for m in modems:
        labels = {"imei": m["imei"], "name": m.get("name") or "",
                  "operator": m.get("operator") or ""}
        out.append(_line("modemproxy_modem_signal", m.get("signal") or 0, labels))

    out += [
        "# HELP modemproxy_modem_online Modem online state (1/0).",
        "# TYPE modemproxy_modem_online gauge",
    ]
    for m in modems:
        labels = {"imei": m["imei"], "name": m.get("name") or ""}
        out.append(_line("modemproxy_modem_online", 1 if m.get("status") == "online" else 0, labels))

    out += [
        "# HELP modemproxy_modem_month_bytes Traffic this month per modem and direction.",
        "# TYPE modemproxy_modem_month_bytes counter",
    ]
    for m in modems:
        rep = bandwidth.report(m["imei"])
        base = {"imei": m["imei"], "name": m.get("name") or ""}
        out.append(_line("modemproxy_modem_month_bytes", rep["month_in"], {**base, "direction": "in"}))
        out.append(_line("modemproxy_modem_month_bytes", rep["month_out"], {**base, "direction": "out"}))

    return "\n".join(out) + "\n"
