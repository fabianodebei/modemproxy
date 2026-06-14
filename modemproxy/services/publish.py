"""Remote access: expose each modem's proxy to external customers.

Two modes (config ``access_mode``):

* ``direct`` — the box has a public/static IP (or a port forwarded on the
  router). Customers connect straight to ``public_host:<proxy port>``. We just
  make sure the host firewall lets those ports in and hand out the right URLs.

* ``relay`` — the box is behind NAT/CGNAT. A bundled ``frpc`` opens a reverse
  tunnel to a relay VPS running ``frps`` and re-publishes every proxy port
  there. Customers connect to ``relay_host:<remote port>``. No router config,
  the home IP stays hidden.

``sync()`` is called whenever proxies change (apply/purge/start/stop) so the
firewall rules / tunnel config always track the live set of proxies.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .. import db
from ..config import AUTOGEN_DIR, get_config

FRPC_CONF = AUTOGEN_DIR.parent / "frpc.toml"
FRPC_SERVICE = "modemproxy-frpc.service"


def _live() -> list[dict[str, Any]]:
    """Modems with an enabled proxy and allocated ports."""
    out = []
    for m in db.list_modems():
        if m.get("enabled") and m.get("http_port"):
            out.append(m)
    return out


def _remote_port(local_port: int) -> int:
    return local_port + int(get_config().relay_remote_offset or 0)


def public_host() -> str:
    cfg = get_config()
    if cfg.access_mode == "relay":
        return cfg.relay_host or "<relay-host>"
    return cfg.public_host or "<public-ip>"


def customer_endpoints(modem: dict[str, Any]) -> dict[str, Any]:
    """Build the host/port a customer uses for one modem, per access mode."""
    cfg = get_config()
    host = public_host()
    hp, sp = modem.get("http_port"), modem.get("socks_port")
    if cfg.access_mode == "relay":
        hp = _remote_port(hp) if hp else None
        sp = _remote_port(sp) if sp else None
    user = modem.get("username")
    pw = modem.get("password")
    auth = f"{user}:{pw}@" if user and pw else ""
    return {
        "host": host,
        "http_port": hp,
        "socks_port": sp,
        "http": f"http://{auth}{host}:{hp}" if hp else None,
        "socks5": f"socks5://{auth}{host}:{sp}" if sp else None,
    }


# --- frpc (relay mode) -----------------------------------------------------

def render_frpc() -> str:
    cfg = get_config()
    lines = [
        f'serverAddr = "{cfg.relay_host}"',
        f"serverPort = {int(cfg.relay_port)}",
    ]
    if cfg.relay_token:
        lines += ['auth.method = "token"', f'auth.token = "{cfg.relay_token}"']
    lines.append("")
    for m in _live():
        name = m.get("name") or m["imei"][-6:]
        for kind, lp in (("http", m.get("http_port")), ("socks", m.get("socks_port"))):
            if not lp:
                continue
            lines += [
                "[[proxies]]",
                f'name = "modemproxy-{name}-{kind}"',
                'type = "tcp"',
                'localIP = "127.0.0.1"',
                f"localPort = {lp}",
                f"remotePort = {_remote_port(lp)}",
                "",
            ]
    return "\n".join(lines) + "\n"


def _sync_relay() -> dict[str, Any]:
    cfg = get_config()
    if not cfg.relay_host:
        return {"mode": "relay", "ok": False, "error": "relay_host not configured"}
    FRPC_CONF.parent.mkdir(parents=True, exist_ok=True)
    FRPC_CONF.write_text(render_frpc())
    _systemctl("enable", FRPC_SERVICE)
    _systemctl("restart", FRPC_SERVICE)
    return {"mode": "relay", "ok": True, "config": str(FRPC_CONF),
            "tunnels": len(_live()) * 2}


# --- direct mode -----------------------------------------------------------

def _sync_direct() -> dict[str, Any]:
    cfg = get_config()
    # Tunnel not needed; stop frpc if it was running from a previous relay setup.
    _systemctl("disable", FRPC_SERVICE)
    _systemctl("stop", FRPC_SERVICE)
    opened = []
    if cfg.open_firewall and _have("ufw"):
        for m in _live():
            for p in (m.get("http_port"), m.get("socks_port")):
                if p:
                    r = subprocess.run(["ufw", "allow", f"{p}/tcp"],
                                       capture_output=True, text=True)
                    if r.returncode == 0:
                        opened.append(p)
    return {"mode": "direct", "ok": True, "firewall_opened": opened}


# --- public API ------------------------------------------------------------

def sync() -> dict[str, Any]:
    """Reconcile remote-access plumbing with the current set of proxies."""
    cfg = get_config()
    return _sync_relay() if cfg.access_mode == "relay" else _sync_direct()


def status() -> dict[str, Any]:
    cfg = get_config()
    modems = []
    for m in _live():
        ep = customer_endpoints(m)
        modems.append({"imei": m["imei"], "name": m.get("name"),
                       "operator": m.get("operator"), **ep})
    st: dict[str, Any] = {
        "mode": cfg.access_mode,
        "host": public_host(),
        "proxies": modems,
    }
    if cfg.access_mode == "relay":
        st["relay_host"] = cfg.relay_host
        st["relay_port"] = cfg.relay_port
        st["frpc_active"] = _is_active(FRPC_SERVICE)
        st["frpc_installed"] = _have("frpc")
    return st


def _have(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


def _is_active(unit: str) -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True)
        return r.stdout.strip() == "active"
    except FileNotFoundError:
        return False


def _systemctl(action: str, unit: str) -> None:
    try:
        subprocess.run(["systemctl", action, unit], check=False,
                       capture_output=True, text=True)
    except FileNotFoundError:
        pass
