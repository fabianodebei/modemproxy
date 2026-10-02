"""End-to-end health check with self-healing, for unattended recovery.

A power cut leaves the box in states nothing else notices: an interface back
without its address, a 3proxy instance pointed at a dead resolver, the router
handing the server a different LAN IP, the DDNS name still on the old public
address, WireGuard down. Each of those looks fine from the inside while every
customer sees a dead proxy.

So this walks the whole chain the way a customer does — proxy port -> modem ->
internet, plus the paths the admin needs (LAN address, DDNS, VPN) — fixes what
is mechanically fixable (restart a proxy, re-run discovery) and reports the
rest on Telegram. It is quiet by design: an alert goes out when a check
*changes* state, so a long outage doesn't spam, and recovery is announced too.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .. import db
from ..config import STATE_DIR, get_config
from . import alerts

STATE_FILE = STATE_DIR / "healthcheck.json"
CURL_TIMEOUT = 20


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return 1, ""
    return p.returncode, (p.stdout or "").strip()


def _curl(args: list[str], timeout: int = CURL_TIMEOUT) -> str | None:
    rc, out = _run(["curl", "-s", "--max-time", str(timeout), *args], timeout + 10)
    return out if rc == 0 and out else None


def _systemctl(*args: str) -> bool:
    return _run(["systemctl", *args], 60)[0] == 0


def _svc(imei: str) -> str:
    from ..proxy.generator import _svc as svc
    return svc(imei)


# --- individual checks ------------------------------------------------------

def _check_proxy(m: dict) -> tuple[bool, str, bool]:
    """Fetch the egress IP through the modem's own proxy port.

    Returns (ok, detail, healed). A failure is retried after restarting the
    proxy, then after a discovery pass: both are the fixes a human would try
    first, and after a power cut they are usually enough.
    """
    port, user, pw = m.get("http_port"), m.get("username"), m.get("password")
    if not port:
        return True, "nessuna porta", False
    proxy = f"http://{user}:{pw}@127.0.0.1:{port}" if user else f"http://127.0.0.1:{port}"
    args = ["-x", proxy, "https://api.ipify.org"]
    if ip := _curl(args):
        return True, ip, False
    healed = False
    if _systemctl("restart", f"modemproxy-proxy@{_svc(m['imei'])}.service"):
        healed = True
        if ip := _curl(args):
            return True, f"{ip} (dopo riavvio del proxy)", True
    _run(["/opt/modemproxy/venv/bin/modemproxy", "discover"], 180)
    if ip := _curl(args):
        return True, f"{ip} (dopo discovery)", True
    return False, "nessuna uscita internet", healed


def _check_band_locks(modems: list[dict]) -> tuple[bool, str, list[str]]:
    """A band lock is a loaded gun: if the locked band goes away the modem stays
    out of the network. The guard unlocks after a few failed checks (see
    bands.guard) so a dead cell costs minutes, not a night."""
    from ..modems import bands
    locked, freed = [], []
    for m in modems:
        try:
            msg = bands.guard(m)
        except Exception as exc:                        # device unreachable, etc.
            log.debug("guard bande %s: %s", m.get("name"), exc)
            continue
        if msg:
            freed.append(msg)
        elif (m.get("band_lock") or "").find('"lte": []') == -1 and m.get("band_lock"):
            locked.append(m.get("name") or m["imei"])
    if freed:
        return False, " · ".join(freed), freed
    if locked:
        return True, "bloccati su banda fissa: " + ", ".join(locked), []
    return True, "nessun blocco attivo", []


def _check_dns() -> tuple[bool, str]:
    """At least one of the proxies' resolvers must answer."""
    from ..proxy.generator import DEFAULT_DNS
    cfg = get_config()
    alive = [s for s in (cfg.dns_servers or DEFAULT_DNS)
             if _run(["dig", "+time=3", "+tries=1", "+short", f"@{s}", "example.com"], 15)[1]]
    if not alive:
        return False, "nessun DNS raggiungibile"
    return True, ", ".join(alive)


def _check_lan() -> tuple[bool, str]:
    """The server must still hold the LAN address the panel/DNS are published
    on, and reach its gateway (a power cut can hand it a different lease)."""
    rc, out = _run(["ip", "-4", "-br", "addr"], 15)
    addrs = {w.split("/")[0] for line in out.splitlines() for w in line.split()[2:]}
    rc, route = _run(["ip", "route", "show", "default"], 15)
    gws = [line.split()[2] for line in route.splitlines() if " via " in line]
    gw_ok = any(_run(["ping", "-c2", "-W2", gw], 15)[0] == 0 for gw in gws)
    expected = get_config().lan_address
    if expected and expected not in addrs:
        return False, f"indirizzo LAN {expected} non presente (ora: {', '.join(sorted(addrs))})"
    if not gw_ok:
        return False, f"gateway non raggiungibile ({', '.join(gws) or 'nessuna rotta'})"
    return True, f"{expected or 'ok'}, gateway ok"


def _check_public(modems: list[dict]) -> tuple[bool, str]:
    """DDNS + port forwarding, tested from the outside.

    The check leaves through a modem's SIM, so it really traverses the internet
    and the home router's forwarding, exactly like a customer.
    """
    cfg = get_config()
    host = cfg.public_host
    if not host:
        return True, "nessun host pubblico configurato"
    binder = next((m["bind_ip"] for m in modems
                   if m.get("bind_ip") and m.get("status") == "online"), None)
    if not binder:
        return True, "nessun modem online per la prova"
    code = _curl(["--interface", binder, "-k", "-o", "/dev/null", "-w", "%{http_code}",
                  f"https://{host}/"])
    if code in (None, "000"):
        return False, f"{host} non raggiungibile da internet"
    ddns = _run(["dig", "+short", "+time=3", "@8.8.8.8", host], 15)[1].splitlines()
    real = _curl(["https://api.ipify.org"])
    if real and ddns and real not in ddns:
        return False, f"DDNS fermo su {ddns[-1]}, IP attuale {real}"
    return True, f"{host} raggiungibile ({ddns[-1] if ddns else '?'})"


def _check_vpn() -> tuple[bool, str]:
    rc, out = _run(["wg", "show", "wg0", "listen-port"], 15)
    if rc != 0 or not out:
        if _systemctl("restart", "wg-quick@wg0.service"):
            rc, out = _run(["wg", "show", "wg0", "listen-port"], 15)
        if rc != 0 or not out:
            return False, "WireGuard non attivo"
        return True, f"porta {out} (riavviata)"
    return True, f"porta {out}"


# --- runner -----------------------------------------------------------------

def _load_state() -> dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_state(state: dict[str, Any]) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except OSError:
        pass


def run(*, boot: bool = False, notify: bool = True) -> dict[str, Any]:
    """Run every check, self-heal, and report. Returns the full result."""
    modems = [m for m in db.list_modems() if m.get("http_port") and m.get("enabled")]
    checks: list[dict[str, Any]] = []
    healed: list[str] = []

    for m in sorted(modems, key=lambda x: x.get("name") or x["imei"]):
        ok, detail, did_heal = _check_proxy(m)
        name = m.get("name") or m["imei"]
        checks.append({"key": f"proxy:{m['imei']}", "name": name, "ok": ok, "detail": detail})
        if did_heal and ok:
            healed.append(name)

    band_ok, band_detail, band_freed = _check_band_locks(modems)
    checks.append({"key": "bands", "name": "Blocco bande", "ok": band_ok,
                   "detail": band_detail})
    healed.extend(band_freed)

    for key, name, (ok, detail) in (
        ("dns", "DNS", _check_dns()),
        ("lan", "Rete locale", _check_lan()),
        ("vpn", "VPN", _check_vpn()),
    ):
        checks.append({"key": key, "name": name, "ok": ok, "detail": detail})
    ok_pub, detail_pub = _check_public(modems)
    checks.append({"key": "public", "name": "Accesso da internet", "ok": ok_pub,
                   "detail": detail_pub})

    failed = [c for c in checks if not c["ok"]]
    prev = _load_state().get("failed", [])
    now_keys = sorted(c["key"] for c in failed)
    changed = now_keys != sorted(prev)
    _save_state({"failed": now_keys, "ts": db.now()})

    if notify and (boot or changed or healed):
        alerts.notify(_report(checks, healed, boot))
    return {"checks": checks, "healed": healed, "ok": not failed}


def _report(checks: list[dict], healed: list[str], boot: bool) -> str:
    failed = [c for c in checks if not c["ok"]]
    head = ("🔌 Ripartenza dopo riavvio/blackout: " if boot else "")
    if not failed:
        body = f"{head}tutto ok ({len(checks)} controlli)."
    else:
        body = (f"{head}⚠️ {len(failed)} problemi su {len(checks)} controlli:\n"
                + "\n".join(f"• {c['name']}: {c['detail']}" for c in failed))
    if healed:
        body += "\n🔧 Riparati da solo: " + ", ".join(healed)
    return body
