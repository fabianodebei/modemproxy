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

import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

import httpx

from .. import db

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
            "id": f"net-{mac or iface}",
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

def discover() -> list[dict[str, Any]]:
    """Find net-mode dongles, set up routing, and upsert them as modems."""
    results: list[dict[str, Any]] = []
    devs = [d for d in list_netdevs() if not d["is_primary"]]
    for idx, d in enumerate(devs):
        table = ROUTE_TABLE_BASE + idx
        setup_routing(d["iface"], d["bind_ip"], d["gateway"], table)
        gw = _detect_gateway(d)
        pub = public_ip(d["iface"])
        status = "online" if pub else "offline"
        vid, pid = _usb_ids(d["iface"])
        model = _model_label(vid, pid, d["driver"])
        db.upsert_modem(
            d["id"],
            kind="netdev",
            iface=d["iface"],
            bind_ip=d["bind_ip"],
            mgmt_host=gw,
            rt_table=table,
            model=model,
            ip=pub,
            status=status,
            last_seen=db.now(),
        )
        results.append({**d, "mgmt_host": gw, "public_ip": pub, "status": status,
                        "model": model, "imei": d["id"]})
    return results


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


def _rotate_zte(host: str) -> bool:
    """ZTE goform: disconnect then connect the data network."""
    base = f"http://{host}/goform/goform_set_cmd_process"
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    try:
        with httpx.Client(timeout=8.0, headers=headers) as c:
            r1 = c.post(base, data={"isTest": "false", "goformId": "DISCONNECT_NETWORK"})
            if r1.status_code >= 400:
                return False
            import time
            time.sleep(2)
            c.post(base, data={"isTest": "false", "goformId": "CONNECT_NETWORK"})
        return True
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
