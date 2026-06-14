"""Net-mode (HiLink / RNDIS / CDC-Ethernet) USB dongle support.

Many consumer 4G dongles (Huawei E3372h, ZTE MF-series, ...) ship in
"HiLink" / net mode: the stick is a self-contained NAT router that exposes a
plain Ethernet interface to the host (driver ``cdc_ether`` / ``rndis_host`` /
``cdc_ncm``) plus a small HTTP API on a private gateway (192.168.0.1 for ZTE,
192.168.8.1 for Huawei). ModemManager cannot drive these — ``mmcli`` reports
``not supported by any plugin``.

This module discovers such interfaces, sets up source-based policy routing so
several dongles sharing the same private subnet still egress through the right
interface, exposes the public IP via a per-interface ``curl``, and rotates the
public IP through the dongle's own web API.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

import httpx

from .. import db
from ..config import get_config

# Drivers used by net-mode dongles (NOT the QMI/MBIM control drivers, which
# ModemManager handles itself).
NETDEV_DRIVERS = {"cdc_ether", "rndis_host", "cdc_ncm"}

# Known dongle web-API gateways, in probe order.
KNOWN_GATEWAYS = ("192.168.0.1", "192.168.8.1", "192.168.1.1", "192.168.9.1")

ROUTE_TABLE_BASE = 100  # per-dongle policy-routing table id = base + index


def _run(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "", f"{args[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    return p.returncode, p.stdout, p.stderr


def _driver(iface: str) -> str | None:
    link = Path(f"/sys/class/net/{iface}/device/driver")
    try:
        return link.resolve().name
    except OSError:
        return None


def _usb_ids(iface: str) -> tuple[str | None, str | None]:
    """Best-effort (idVendor, idProduct) for the USB device behind an iface."""
    base = Path(f"/sys/class/net/{iface}/device")
    for p in (base, base.parent, base.parent.parent):
        try:
            vid = (p / "idVendor").read_text().strip()
            pid = (p / "idProduct").read_text().strip()
            return vid, pid
        except OSError:
            continue
    return None, None


def _default_route_ifaces() -> set[str]:
    rc, out, _ = _run(["ip", "-j", "route", "show", "default"])
    if rc != 0:
        return set()
    try:
        return {r.get("dev") for r in json.loads(out) if r.get("dev")}
    except (ValueError, KeyError):
        return set()


def _addrs() -> list[dict[str, Any]]:
    rc, out, _ = _run(["ip", "-j", "addr"])
    if rc != 0:
        return []
    try:
        return json.loads(out)
    except ValueError:
        return []


def list_netdevs() -> list[dict[str, Any]]:
    """Enumerate candidate net-mode dongle interfaces with their local IPv4."""
    primary = _default_route_ifaces()
    found: list[dict[str, Any]] = []
    for entry in _addrs():
        iface = entry.get("ifname")
        if not iface or iface == "lo" or iface.startswith(("wl", "docker", "veth", "br-", "tun", "tap")):
            continue
        drv = _driver(iface)
        if drv not in NETDEV_DRIVERS:
            continue
        ipv4 = None
        for a in entry.get("addr_info", []):
            if a.get("family") == "inet" and not a.get("local", "").startswith("169.254"):
                ipv4 = a["local"]
                break
        if not ipv4:
            continue
        net = ipaddress.ip_interface(f"{ipv4}/{_prefix(entry, ipv4)}").network
        if not net[0].is_private:
            continue
        mac = (entry.get("address") or "").replace(":", "")
        found.append({
            "iface": iface,
            "driver": drv,
            "bind_ip": ipv4,
            "subnet": str(net),
            "gateway": str(net.network_address + 1),  # x.x.x.1 (ZTE/Huawei default)
            "mac": mac,
            # iface name is the stable per-dongle id: net-mode sticks often
            # report a zeroed/duplicate MAC, so MAC is not unique.
            "id": f"net-{iface}",
            "is_primary": iface in primary,
        })
    return found


def _prefix(entry: dict[str, Any], ipv4: str) -> int:
    for a in entry.get("addr_info", []):
        if a.get("local") == ipv4:
            return int(a.get("prefixlen", 24))
    return 24


def public_ip(iface: str) -> str | None:
    """Public WAN IP as seen through a specific interface."""
    for url in ("https://api.ipify.org", "http://ifconfig.me/ip"):
        rc, out, _ = _run(["curl", "-s", "--max-time", "12", "--interface", iface, url], timeout=15)
        ip = out.strip()
        if rc == 0 and ip and len(ip) <= 45 and ip.count(".") == 3:
            return ip
    return None


def setup_routing(iface: str, bind_ip: str, gateway: str, table: int) -> None:
    """Source-based policy routing so this dongle egresses out its own iface.

    Needed because multiple HiLink dongles often share 192.168.0.0/24, which
    would otherwise be ambiguous in the main routing table.
    """
    subnet = str(ipaddress.ip_network(f"{bind_ip}/24", strict=False))
    # Idempotent: flush then re-add this table + rule.
    _run(["ip", "route", "flush", "table", str(table)])
    _run(["ip", "route", "add", subnet, "dev", iface, "scope", "link",
          "src", bind_ip, "table", str(table)])
    _run(["ip", "route", "add", "default", "via", gateway, "dev", iface,
          "table", str(table)])
    # Drop any stale rule for this source, then add a fresh one.
    _run(["ip", "rule", "del", "from", bind_ip])
    _run(["ip", "rule", "add", "from", bind_ip, "table", str(table)])


def teardown_routing(bind_ip: str, table: int) -> None:
    _run(["ip", "rule", "del", "from", bind_ip])
    _run(["ip", "route", "flush", "table", str(table)])


# --- discovery -------------------------------------------------------------

def _refresh_dev(dev: dict[str, Any], table: int, *, manual: bool = False,
                 mgmt_host: str | None = None, model: str | None = None) -> dict[str, Any]:
    """Set up routing, read status, and upsert one net-mode device."""
    setup_routing(dev["iface"], dev["bind_ip"], dev["gateway"], table)
    gw = mgmt_host or _detect_gateway(dev)
    pub = public_ip(dev["iface"])
    if model is None:
        vid, pid = _usb_ids(dev["iface"])
        model = _model_label(vid, pid, dev.get("driver"))
    info = device_status(gw)  # signal %, operator from the device web API
    # Online if it has a public IP OR the device reports signal/operator
    # (public_ip can transiently time out on a shared subnet).
    status = "online" if (pub or info.get("signal") or info.get("operator")) else "offline"
    db.upsert_modem(
        dev["id"],
        kind="netdev",
        iface=dev["iface"],
        bind_ip=dev["bind_ip"],
        mgmt_host=gw,
        rt_table=table,
        model=model,
        ip=pub,
        signal=info.get("signal"),
        operator=info.get("operator"),
        status=status,
        manual=1 if manual else 0,
        last_seen=db.now(),
    )
    return {**dev, "mgmt_host": gw, "public_ip": pub, "status": status,
            "model": model, "imei": dev["id"], **info}


def discover() -> list[dict[str, Any]]:
    """Find net-mode dongles + refresh manual LAN routers; upsert as modems."""
    results: list[dict[str, Any]] = []
    auto_ifaces = set()
    # Auto-detected USB net-mode dongles. They legitimately appear as
    # default-route interfaces (they ARE the uplink), so don't exclude
    # is_primary — just route each one out its own table.
    for idx, d in enumerate(list_netdevs()):
        results.append(_refresh_dev(d, ROUTE_TABLE_BASE + idx))
        auto_ifaces.add(d["iface"])

    # Manually added LAN 4G/5G routers (ethernet NICs the driver filter skips).
    for m in db.list_modems():
        if m.get("kind") != "netdev" or not m.get("manual") or m.get("iface") in auto_ifaces:
            continue
        iface = m["iface"]
        ipv4 = _iface_ipv4(iface)
        if not ipv4:
            db.upsert_modem(m["imei"], status="offline", last_seen=db.now())
            continue
        gw = m.get("mgmt_host") or _gateway_of(ipv4)
        dev = {"iface": iface, "bind_ip": ipv4, "gateway": gw,
               "id": m["imei"], "driver": None}
        table = m.get("rt_table") or _next_table()
        results.append(_refresh_dev(dev, table, manual=True, mgmt_host=gw,
                                    model=m.get("model")))
    return results


def _gateway_of(ipv4: str) -> str:
    return str(ipaddress.ip_network(f"{ipv4}/24", strict=False).network_address + 1)


def _iface_ipv4(iface: str) -> str | None:
    for entry in _addrs():
        if entry.get("ifname") != iface:
            continue
        for a in entry.get("addr_info", []):
            if a.get("family") == "inet" and not a.get("local", "").startswith("169.254"):
                return a["local"]
    return None


def _next_table() -> int:
    used = {m.get("rt_table") for m in db.list_modems() if m.get("rt_table")}
    t = ROUTE_TABLE_BASE
    while t in used:
        t += 1
    return t


def register_manual(iface: str, *, gateway: str | None = None,
                    mgmt_host: str | None = None, name: str | None = None,
                    model: str | None = None) -> dict[str, Any]:
    """Register a LAN 4G/5G router (cabled ethernet) as a net-mode modem.

    Unlike auto-discovery, this works for real NIC drivers (the router is on
    the other end of an ethernet cable, not a USB stick).
    """
    ipv4 = _iface_ipv4(iface)
    if not ipv4:
        raise NetdevError(f"interface {iface} has no IPv4 address")
    gw = gateway or mgmt_host or _gateway_of(ipv4)
    dev = {"iface": iface, "bind_ip": ipv4, "gateway": gw,
           "id": f"net-{iface}", "driver": None}
    table = _next_table()
    out = _refresh_dev(dev, table, manual=True, mgmt_host=mgmt_host or gw,
                       model=model or "LAN router (net-mode)")
    if name:
        db.upsert_modem(out["imei"], name=name)
        out["name"] = name
    return out


def device_status(host: str) -> dict[str, Any]:
    """Signal quality (%) and operator name from the dongle web API."""
    return _status_zte(host) or _status_huawei(host) or {}


def _status_zte(host: str) -> dict[str, Any] | None:
    """ZTE goform: signalbar (0-5), network_provider, network_type."""
    url = (f"http://{host}/goform/goform_get_cmd_process"
           "?isTest=false&multi_data=1"
           "&cmd=signalbar,network_provider,network_type,rssi,rscp")
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    try:
        r = httpx.get(url, headers=headers, timeout=5.0)
        if r.status_code >= 400:
            return None
        d = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    if "signalbar" not in d and "network_provider" not in d:
        return None
    out: dict[str, Any] = {}
    bars = d.get("signalbar")
    if bars not in (None, ""):
        try:
            out["signal"] = int(round(int(bars) / 5 * 100))
        except (TypeError, ValueError):
            pass
    op = d.get("network_provider")
    if op:
        out["operator"] = op
    return out or None


def _status_huawei(host: str) -> dict[str, Any] | None:
    """Huawei HiLink: /api/device/signal + /api/net/current-plmn."""
    try:
        sig = httpx.get(f"http://{host}/api/device/signal", timeout=5.0)
        if sig.status_code >= 400 or "<rsrp>" not in sig.text and "<rssi>" not in sig.text:
            return None
    except httpx.HTTPError:
        return None
    out: dict[str, Any] = {}
    # rsrp dBm -> rough %: -140 (0%) .. -44 (100%)
    if "<rsrp>" in sig.text:
        try:
            rsrp = int(sig.text.split("<rsrp>")[1].split("dBm")[0].strip())
            out["signal"] = max(0, min(100, round((rsrp + 140) / 96 * 100)))
        except (ValueError, IndexError):
            pass
    try:
        plmn = httpx.get(f"http://{host}/api/net/current-plmn", timeout=5.0)
        if "<FullName>" in plmn.text:
            out["operator"] = plmn.text.split("<FullName>")[1].split("</FullName>")[0]
    except httpx.HTTPError:
        pass
    return out or None


def _detect_gateway(dev: dict[str, Any]) -> str:
    """Probe known dongle API hosts reachable through this interface."""
    candidates = [dev["gateway"], *[g for g in KNOWN_GATEWAYS if g != dev["gateway"]]]
    for host in candidates:
        try:
            r = httpx.get(f"http://{host}/", timeout=3.0)
            if r.status_code < 500:
                return host
        except httpx.HTTPError:
            continue
    return dev["gateway"]


def _model_label(vid: str | None, pid: str | None, driver: str | None) -> str:
    vendors = {"12d1": "Huawei", "19d2": "ZTE", "2c7c": "Quectel", "1c9e": "Alcatel"}
    if vid:
        return f"{vendors.get(vid, vid)} {pid or ''} (net-mode)".strip()
    return f"net-mode dongle ({driver})" if driver else "net-mode dongle"


# --- rotation --------------------------------------------------------------

class NetdevError(RuntimeError):
    pass


def rotate(modem: dict[str, Any]) -> str | None:
    """Force a new public IP by reconnecting the dongle's data link via its
    web API. Returns the new public IP (best-effort)."""
    host = modem.get("mgmt_host")
    iface = modem.get("iface")
    if not host or not iface:
        raise NetdevError("net-mode dongle missing mgmt_host/iface")

    ok = _rotate_zte(host) or _rotate_huawei(host)
    if not ok:
        raise NetdevError(f"no supported web API at {host} for {iface}")

    import time
    time.sleep(8)  # let the link re-dial
    return public_ip(iface)


def _zte_client(host: str) -> httpx.Client:
    """Authenticated httpx client for ZTE goform set-commands.

    Set commands (rotation, reboot) on CPE like the MC801A require a login
    session. Status/get commands usually don't. Uses the configured HiLink
    admin password; falls back to an unauthenticated client if none is set.
    """
    c = httpx.Client(timeout=8.0, headers={
        "Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"})
    pw = get_config().default_hilink_password
    if not pw:
        return c
    base = f"http://{host}/goform"
    try:
        # ZTE LD-challenge: final = SHA256( SHA256(pw)_UPPER + LD )_UPPER
        ld = ""
        r = c.get(f"{base}/goform_get_cmd_process?isTest=false&cmd=LD")
        try:
            ld = r.json().get("LD", "")
        except ValueError:
            ld = ""
        if ld:
            h1 = hashlib.sha256(pw.encode()).hexdigest().upper()
            pwd = hashlib.sha256((h1 + ld).encode()).hexdigest().upper()
        else:
            pwd = base64.b64encode(pw.encode()).decode()
        c.post(f"{base}/goform_set_cmd_process",
               data={"isTest": "false", "goformId": "LOGIN", "password": pwd})
    except httpx.HTTPError:
        pass
    return c


def _rotate_zte(host: str) -> bool:
    """ZTE goform: disconnect then connect the data network (authed)."""
    base = f"http://{host}/goform/goform_set_cmd_process"
    try:
        with _zte_client(host) as c:
            r1 = c.post(base, data={"isTest": "false", "goformId": "DISCONNECT_NETWORK"})
            if r1.status_code >= 400:
                return False
            import time
            time.sleep(2)
            c.post(base, data={"isTest": "false", "goformId": "CONNECT_NETWORK"})
        return True
    except httpx.HTTPError:
        return False


def reboot_zte(host: str) -> bool:
    """Reboot a ZTE dongle/router via the web API (authed)."""
    try:
        with _zte_client(host) as c:
            r = c.post(f"http://{host}/goform/goform_set_cmd_process",
                       data={"isTest": "false", "goformId": "REBOOT_DEVICE"})
            return r.status_code < 400
    except httpx.HTTPError:
        return False


def _rotate_huawei(host: str) -> bool:
    """Huawei HiLink: toggle mobile data off/on via the dialup API."""
    api = f"http://{host}/api"
    try:
        with httpx.Client(timeout=8.0) as c:
            tok = c.get(f"{api}/webserver/SesTokInfo", timeout=5.0)
            headers = {}
            if "<TokInfo>" in tok.text:
                token = tok.text.split("<TokInfo>")[1].split("</TokInfo>")[0]
                headers["__RequestVerificationToken"] = token
                if "<SesInfo>" in tok.text:
                    sess = tok.text.split("<SesInfo>")[1].split("</SesInfo>")[0]
                    headers["Cookie"] = sess
            off = ('<?xml version="1.0" encoding="UTF-8"?>'
                   "<request><dataswitch>0</dataswitch></request>")
            on = ('<?xml version="1.0" encoding="UTF-8"?>'
                  "<request><dataswitch>1</dataswitch></request>")
            r = c.post(f"{api}/dialup/mobile-dataswitch", content=off,
                       headers={**headers, "Content-Type": "text/xml"})
            if r.status_code >= 400 or "error" in r.text.lower():
                return False
            import time
            time.sleep(2)
            c.post(f"{api}/dialup/mobile-dataswitch", content=on,
                   headers={**headers, "Content-Type": "text/xml"})
        return True
    except httpx.HTTPError:
        return False
