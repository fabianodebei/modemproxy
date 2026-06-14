"""Allocate proxy ports and render per-modem 3proxy configs + systemd units."""
from __future__ import annotations

import json
import secrets
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import db
from ..config import AUTOGEN_DIR, get_config

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(enabled_extensions=()),
    keep_trailing_newline=True,
)


def _gw_of(bind_ip: str) -> str:
    """Derive the dongle gateway (x.x.x.1) from a /24 interface IP."""
    import ipaddress
    net = ipaddress.ip_network(f"{bind_ip}/24", strict=False)
    return str(net.network_address + 1)


def _modem_index(imei: str) -> int:
    """Stable small integer per modem, used to derive default ports."""
    modems = sorted(m["imei"] for m in db.list_modems())
    return modems.index(imei) + 1 if imei in modems else len(modems) + 1


def allocate_port(imei: str, *, username: str | None = None,
                  password: str | None = None, auth: bool = True) -> dict:
    """Create/refresh the port record for a modem and pick free ports."""
    cfg = get_config()
    existing = db.get_port(imei)
    idx = _modem_index(imei)
    http_port = (existing or {}).get("http_port") or cfg.http_port_base + idx
    socks_port = (existing or {}).get("socks_port") or cfg.socks_port_base + idx
    if auth:
        username = username or (existing or {}).get("username") or f"u{idx}"
        password = password or (existing or {}).get("password") or secrets.token_hex(8)
    else:
        username = password = None
    token = (existing or {}).get("rotation_token") or secrets.token_urlsafe(18)
    db.set_port(imei, http_port=http_port, socks_port=socks_port,
                username=username, password=password,
                rotation_token=token, enabled=1)
    return db.get_port(imei)


def render_modem(imei: str) -> Path:
    """Write the 3proxy config for one modem; return its path."""
    cfg = get_config()
    modem = db.get_modem(imei)
    port = db.get_port(imei)
    if not modem or not port:
        raise ValueError(f"modem/port not configured for {imei}")
    dns = " ".join(cfg.dns_servers) if cfg.dns_servers else "1.1.1.1"
    name = modem.get("name") or imei[-6:]
    white_list = json.loads(port.get("white_list") or "[]")
    text = _env.get_template("3proxy.cfg.j2").render(
        imei=imei,
        name=name,
        dns=dns,
        username=port.get("username"),
        password=port.get("password"),
        http_port=port["http_port"],
        socks_port=port["socks_port"],
        # net-mode dongles egress from their local interface IP (bind_ip);
        # MM modems bind to the operator-assigned WAN IP.
        modem_ip=modem.get("bind_ip") or modem.get("ip") or "0.0.0.0",
        bind_address=cfg.bind_address,
        white_list=",".join(white_list) if white_list else "",
    )
    AUTOGEN_DIR.mkdir(parents=True, exist_ok=True)
    out = AUTOGEN_DIR / f"3proxy.{name}.cfg"
    out.write_text(text)
    return out


def set_password(imei: str, password: str) -> dict:
    """Change a modem's proxy password and restart its proxy."""
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    db.set_port(imei, password=password)
    return apply_port(imei)


def regenerate_credentials(imei: str) -> dict:
    """Issue a fresh username+password for a modem's proxy."""
    idx = _modem_index(imei)
    db.set_port(imei, username=f"u{idx}", password=secrets.token_hex(8))
    return apply_port(imei)


def set_rotation_interval(imei: str, seconds: int) -> dict:
    """Set per-port auto-rotation interval (0 = manual). No restart needed."""
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    db.set_port(imei, rotation_interval=max(0, int(seconds)))
    return db.get_port(imei)


def set_whitelist(imei: str, ips: list[str]) -> dict:
    """Restrict a proxy to a list of client IPs/CIDRs ([] = unrestricted)."""
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    clean = [s.strip() for s in ips if s and s.strip()]
    db.set_port(imei, white_list=json.dumps(clean))
    return apply_port(imei)


def purge_port(imei: str) -> None:
    modem = db.get_modem(imei) or {}
    name = modem.get("name") or imei[-6:]
    db.delete_port(imei)
    cfg_file = AUTOGEN_DIR / f"3proxy.{name}.cfg"
    cfg_file.unlink(missing_ok=True)
    _systemctl("stop", f"modemproxy-proxy@{name}.service")
    _systemctl("disable", f"modemproxy-proxy@{name}.service")


def apply_port(imei: str, **alloc_kwargs) -> dict:
    """Allocate, render and (re)start the proxy for one modem."""
    port = allocate_port(imei, **alloc_kwargs)
    render_modem(imei)
    modem = db.get_modem(imei) or {}
    # Net-mode dongles need source-based policy routing in place so 3proxy's
    # egress bind actually leaves through the right interface.
    if modem.get("kind") == "netdev" and modem.get("bind_ip") and modem.get("rt_table"):
        from ..modems import netdev
        try:
            netdev.setup_routing(modem["iface"], modem["bind_ip"],
                                 modem.get("mgmt_host") or _gw_of(modem["bind_ip"]),
                                 int(modem["rt_table"]))
        except Exception:
            pass
    name = modem.get("name") or imei[-6:]
    _systemctl("enable", f"modemproxy-proxy@{name}.service")
    _systemctl("restart", f"modemproxy-proxy@{name}.service")
    return port


def stop_proxy(imei: str, *, locked: bool = False) -> None:
    """Stop a modem's proxy without deleting its config/credentials."""
    modem = db.get_modem(imei) or {}
    name = modem.get("name") or imei[-6:]
    db.set_port(imei, enabled=0, quota_locked=1 if locked else 0)
    _systemctl("stop", f"modemproxy-proxy@{name}.service")


def start_proxy(imei: str) -> dict:
    """Re-enable + start a previously stopped proxy."""
    db.set_port(imei, quota_locked=0)
    return apply_port(imei)


def _systemctl(action: str, unit: str) -> None:
    try:
        subprocess.run(["systemctl", action, unit], check=False,
                       capture_output=True, text=True)
    except FileNotFoundError:
        pass  # not on a systemd host (dev/macOS)
