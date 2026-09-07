"""Allocate proxy ports and render per-modem 3proxy configs + systemd units."""
from __future__ import annotations

import json
import os
import re
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


def _svc(imei: str) -> str:
    """Stable, filesystem/systemd-safe id for a modem's proxy (its config file
    name and systemd instance). Derived from the imei, NOT the display name, so
    renaming a modem never orphans or breaks its running proxy."""
    slug = re.sub(r"[^A-Za-z0-9]", "", imei)
    return slug or imei[-6:]


def allocate_port(imei: str, *, username: str | None = None,
                  password: str | None = None, auth: bool = True) -> dict:
    """Create/refresh the port record for a modem and pick free ports."""
    cfg = get_config()
    existing = db.get_port(imei)
    http_port = (existing or {}).get("http_port")
    socks_port = (existing or {}).get("socks_port")
    if not http_port or not socks_port:
        # Ports already handed to OTHER modems — the positional index alone can
        # collide (indices shift as modems are added/removed), so skip taken ports.
        used_http, used_socks = set(), set()
        for m in db.list_modems():
            if m["imei"] == imei:
                continue
            p = db.get_port(m["imei"])
            if p and p.get("http_port"):
                used_http.add(p["http_port"])
            if p and p.get("socks_port"):
                used_socks.add(p["socks_port"])
        idx = _modem_index(imei)
        h = cfg.http_port_base + idx
        while h in used_http:
            h += 1
        s = cfg.socks_port_base + idx
        while s in used_socks:
            s += 1
        http_port = http_port or h
        socks_port = socks_port or s
    idx = _modem_index(imei)
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
        svc=_svc(imei),
        dns=dns,
        username=port.get("username"),
        password=port.get("password"),
        all_users=_all_users(port),
        http_port=port["http_port"],
        socks_port=port["socks_port"],
        # net-mode dongles egress from their local interface IP (bind_ip);
        # MM modems bind to the operator-assigned WAN IP.
        modem_ip=modem.get("bind_ip") or modem.get("ip") or "0.0.0.0",
        bind_address=cfg.bind_address,
        white_list=",".join(white_list) if white_list else "",
    )
    AUTOGEN_DIR.mkdir(parents=True, exist_ok=True)
    out = AUTOGEN_DIR / f"3proxy.{_svc(imei)}.cfg"
    out.write_text(text)
    return out


# --- extra logins -----------------------------------------------------------
# Besides its main username/password, a modem proxy can accept additional
# logins, each tagged with an "owner" (e.g. "proxybet" for storefront
# customers). They share the same ports/egress; only the credentials differ,
# so a storefront can hand out its own login without touching the main one.

def list_extra_users(imei: str) -> list[dict]:
    port = db.get_port(imei) or {}
    try:
        users = json.loads(port.get("extra_users") or "[]")
    except ValueError:
        users = []
    return [u for u in users if isinstance(u, dict) and u.get("username")]


def _all_users(port: dict) -> list[dict]:
    """Main login first, then extra logins (deduplicated by username)."""
    out, seen = [], set()
    if port.get("username") and port.get("password"):
        out.append({"username": port["username"], "password": port["password"]})
        seen.add(port["username"])
    try:
        extra = json.loads(port.get("extra_users") or "[]")
    except ValueError:
        extra = []
    for u in extra:
        if isinstance(u, dict) and u.get("username") and u.get("password") \
                and u["username"] not in seen:
            out.append({"username": u["username"], "password": u["password"]})
            seen.add(u["username"])
    return out


def get_extra_user(imei: str, owner: str) -> dict | None:
    return next((u for u in list_extra_users(imei) if u.get("owner") == owner), None)


def set_extra_user(imei: str, owner: str, username: str, password: str) -> dict:
    """Create or update the extra login tagged ``owner``. Does NOT restart the
    proxy: call apply_port() afterwards (mirrors store_port + apply_port)."""
    if not db.get_port(imei):
        raise ValueError(f"no proxy configured for {imei}")
    if not username or not password:
        raise ValueError("username and password required")
    users = [u for u in list_extra_users(imei) if u.get("owner") != owner]
    entry = {"owner": owner, "username": username, "password": password}
    users.append(entry)
    db.set_port(imei, extra_users=json.dumps(users))
    return entry


def remove_extra_user(imei: str, owner: str) -> None:
    if not db.get_port(imei):
        return
    users = [u for u in list_extra_users(imei) if u.get("owner") != owner]
    db.set_port(imei, extra_users=json.dumps(users))


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
    svc = _svc(imei)
    db.delete_port(imei)
    cfg_file = AUTOGEN_DIR / f"3proxy.{svc}.cfg"
    cfg_file.unlink(missing_ok=True)
    _systemctl("stop", f"modemproxy-proxy@{svc}.service")
    _systemctl("disable", f"modemproxy-proxy@{svc}.service")
    _publish_sync()


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
    # Anti-tethering TTL on this modem's egress interface (no-op if disabled).
    if modem.get("iface"):
        try:
            from ..services import ttl
            ttl.ensure_ttl(modem["iface"])
        except Exception:
            pass
    svc = _svc(imei)
    _systemctl("enable", f"modemproxy-proxy@{svc}.service")
    _systemctl("restart", f"modemproxy-proxy@{svc}.service")
    _publish_sync()
    return port


def stop_proxy(imei: str, *, locked: bool = False) -> None:
    """Stop a modem's proxy without deleting its config/credentials."""
    db.set_port(imei, enabled=0, quota_locked=1 if locked else 0)
    _systemctl("stop", f"modemproxy-proxy@{_svc(imei)}.service")
    _publish_sync()


def start_proxy(imei: str) -> dict:
    """Re-enable + start a previously stopped proxy."""
    db.set_port(imei, quota_locked=0)
    return apply_port(imei)


def _publish_sync() -> None:
    """Keep remote-access plumbing (firewall / frpc tunnel) and the rotating
    pool port in sync with the live proxy set. Best-effort: never let it break
    a proxy operation."""
    try:
        from ..services import publish
        publish.sync()
    except Exception:
        pass
    try:
        sync_pool()
    except Exception:
        pass


# --- rotating pool port ----------------------------------------------------
# One HTTP + one SOCKS port (defaults: http_port_base / socks_port_base) whose
# every new client connection is handed to a different live modem proxy. Done
# by 3proxy itself via weighted "parent" chains to the per-modem instances, so
# no extra daemon: it's just another modemproxy-proxy@<POOL_SVC> instance.
POOL_SVC = "pool"


def _pool_members() -> list[dict]:
    """Live per-modem proxies eligible for the pool, with 3proxy weights
    summing to 1000 (equal share; remainder on the first)."""
    import time as _time
    now = int(_time.time())
    live = []
    for m in db.list_modems():
        expired = m.get("expires_at") and m["expires_at"] <= now
        if (m.get("status") == "online" and m.get("http_port") and m.get("enabled")
                and not m.get("quota_locked") and not expired):
            live.append(m)
    n = len(live)
    out = []
    for i, m in enumerate(live):
        w = 1000 // n + (1000 % n if i == 0 else 0)
        out.append({"imei": m["imei"], "name": m.get("name") or m["imei"][-6:],
                    "http_port": m["http_port"], "socks_port": m["socks_port"],
                    "username": m.get("username"), "password": m.get("password"),
                    "weight": w})
    return out


def _pool_ports(cfg) -> tuple[int, int]:
    return (cfg.pool_http_port or cfg.http_port_base,
            cfg.pool_socks_port or cfg.socks_port_base)


def _pool_password(cfg) -> str:
    """The pool's own password: generated once and persisted to the config."""
    if cfg.pool_password:
        return cfg.pool_password
    from ..config import update_config
    pw = secrets.token_hex(8)
    try:
        update_config({"pool_password": pw})
    except Exception:
        pass
    return pw


def _render_pool_text() -> str | None:
    cfg = get_config()
    members = _pool_members()
    if not members:
        return None
    http_port, socks_port = _pool_ports(cfg)
    dns = " ".join(cfg.dns_servers) if cfg.dns_servers else "1.1.1.1"
    return _env.get_template("3proxy.pool.cfg.j2").render(
        dns=dns, username=cfg.pool_username or "pool", password=_pool_password(cfg),
        http_port=http_port, socks_port=socks_port, bind_address=cfg.bind_address,
        members=members,
    )


def render_pool() -> Path | None:
    """Write the pool config; None (and no file) when no modem is live."""
    text = _render_pool_text()
    out = AUTOGEN_DIR / f"3proxy.{POOL_SVC}.cfg"
    if text is None:
        out.unlink(missing_ok=True)
        return None
    AUTOGEN_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    return out


def sync_pool() -> dict:
    """Bring the pool instance in line with config + live modems. Restarts the
    instance ONLY when its config actually changed (discover runs every few
    minutes; a blind restart would cut in-flight pool connections)."""
    cfg = get_config()
    unit = f"modemproxy-proxy@{POOL_SVC}.service"
    out = AUTOGEN_DIR / f"3proxy.{POOL_SVC}.cfg"
    text = _render_pool_text() if cfg.pool_enable else None
    if text is None:
        _systemctl("stop", unit)
        _systemctl("disable", unit)
        out.unlink(missing_ok=True)
        return pool_status()
    AUTOGEN_DIR.mkdir(parents=True, exist_ok=True)
    changed = not out.exists() or out.read_text() != text
    if changed:
        out.write_text(text)
    _systemctl("enable", unit)
    _systemctl("restart" if changed else "start", unit)
    return pool_status()


def pool_status() -> dict:
    cfg = get_config()
    http_port, socks_port = _pool_ports(cfg)
    members = _pool_members()
    return {
        "enabled": bool(cfg.pool_enable),
        "active": bool(cfg.pool_enable and members),
        "http_port": http_port, "socks_port": socks_port,
        "username": cfg.pool_username or "pool", "password": cfg.pool_password,
        "members": [{"imei": m["imei"], "name": m["name"], "weight": m["weight"]}
                    for m in members],
    }


def _systemctl(action: str, unit: str) -> None:
    # Only root drives real units. Tests and dev runs execute as a normal user
    # and polkit may still let an active-session user enable/start units —
    # which once left stray modemproxy-proxy@<test-imei> instances running on
    # the production box. So: no-op unless we are root.
    if os.geteuid() != 0:
        return
    try:
        subprocess.run(["systemctl", action, unit], check=False,
                       capture_output=True, text=True)
    except FileNotFoundError:
        pass  # not on a systemd host (dev/macOS)
