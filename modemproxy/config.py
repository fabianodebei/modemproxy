"""Configuration loading.

Reads /etc/modemproxy/config.yaml (overridable via MODEMPROXY_CONFIG).
All keys have sane defaults so a fresh install runs with an empty file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = os.environ.get("MODEMPROXY_CONFIG", "/etc/modemproxy/config.yaml")
STATE_DIR = Path(os.environ.get("MODEMPROXY_STATE_DIR", "/var/lib/modemproxy"))
AUTOGEN_DIR = Path(os.environ.get("MODEMPROXY_AUTOGEN_DIR", "/etc/modemproxy/autogen"))


@dataclass
class Config:
    # Web panel
    web_host: str = "127.0.0.1"
    web_port: int = 6997
    admin_user: str = "admin"
    admin_password: str = "admin"  # change on first install
    session_secret: str = "change-me-in-config"  # signs the login cookie

    # Proxy port allocation
    http_port_base: int = 8000      # modem N -> http_port_base + N
    socks_port_base: int = 9000     # modem N -> socks_port_base + N
    bind_address: str = "0.0.0.0"   # external interface proxies listen on

    # Rotation
    rotation_default_interval: int = 0   # seconds; 0 = manual only
    dns_servers: list[str] = field(default_factory=list)  # empty = use modem DNS

    # Modem handling
    dhcp_method: str = "modemmanager"    # modemmanager | dhcpcd
    usb_reset_method: str = "usbreset"   # usbreset | uhubctl
    online_check_url: str = "http://connectivitycheck.gstatic.com/generate_204"
    max_parallel_workers: int = 4

    # OpenVPN export
    vpn_public_host: str = ""   # public IP/host clients dial; blank = placeholder

    # Remote access for customers (how external clients reach the proxies)
    #   direct  -> box has a public/static IP (or a forwarded port); customers
    #              connect straight to public_host:<proxy port>.
    #   relay   -> box is behind NAT/CGNAT; an frpc reverse tunnel exposes each
    #              proxy on a relay VPS running frps. Customers connect to
    #              relay_host:<remote port>.
    access_mode: str = "direct"           # direct | relay
    public_host: str = ""                 # static IP / DDNS hostname (direct mode)
    open_firewall: bool = True            # auto `ufw allow` proxy ports (direct)
    relay_host: str = ""                  # frps VPS host (relay mode)
    relay_port: int = 7000               # frps bind port
    relay_token: str = ""                 # shared auth token with frps
    relay_remote_offset: int = 0          # remote_port = local_port + offset
                                          # (lets several boxes share one relay)

    # White-label branding (shown in the panel / login / page titles)
    brand_name: str = "modemproxy"
    company_name: str = ""
    company_url: str = ""
    creds_style: str = "default"          # default (host:port:user:pass) | curl

    # Telegram alerts
    tg_alerts_enable: bool = False
    tg_bot_token: str = ""
    tg_chat_id: str = ""                   # numeric user id or -group id
    alert_rotation_ok: bool = False
    alert_rotation_fail: bool = True
    alert_proxy_down: bool = True
    alert_expiry: bool = True
    alert_expiry_days: int = 7             # warn this many days before a port expires
    alert_mute_minutes: int = 3           # skip identical alerts within this window

    # Database
    db_path: str = str(STATE_DIR / "modemproxy.db")

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        p = Path(path or DEFAULT_CONFIG_PATH)
        data: dict[str, Any] = {}
        if p.exists():
            data = yaml.safe_load(p.read_text()) or {}
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}
        return cls(**clean)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_cached: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _cached
    if _cached is None or reload:
        _cached = Config.load()
    return _cached


def update_config(updates: dict[str, Any], path: str | os.PathLike[str] | None = None) -> Config:
    """Merge keys into the YAML config file and reload the cached config.

    Only keys defined on Config are written; everything else is ignored.
    """
    p = Path(path or DEFAULT_CONFIG_PATH)
    data: dict[str, Any] = {}
    if p.exists():
        data = yaml.safe_load(p.read_text()) or {}
    known = {f for f in Config.__dataclass_fields__}
    for k, v in updates.items():
        if k in known:
            data[k] = v
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    return get_config(reload=True)
