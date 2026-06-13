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
