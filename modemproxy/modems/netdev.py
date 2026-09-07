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
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("modemproxy.netdev")

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


def public_ip(iface: str, bind: str | None = None, max_time: int = 12) -> str | None:
    """Public WAN IP as seen through a modem.

    ``bind`` (a source IP) is used when given: curl's ``--interface`` accepts an
    address and binds the source, which is reliable for macvlan LAN routers whose
    subnet overlaps the parent (SO_BINDTODEVICE onto them is flaky). Without it we
    bind to the interface by name — needed for USB dongles that share a source IP
    but sit on their own link.
    """
    binder = bind or iface
    for url in ("https://api.ipify.org", "http://ifconfig.me/ip"):
        rc, out, _ = _run(["curl", "-s", "--max-time", str(max_time), "--interface", binder, url],
                          timeout=max_time + 3)
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
    pub = public_ip(dev["iface"], dev["bind_ip"] if manual else None)
    if model is None:
        vid, pid = _usb_ids(dev["iface"])
        model = _model_label(vid, pid, dev.get("driver"))
    # TP-Link Deco has no goform/HiLink API — read operator/signal via its own
    # local API. Others: bind status calls to the iface only for auto USB dongles
    # (shared IPs); manual LAN routers have a unique IP reached via the main table.
    if "deco" in (model or "").lower():
        info = _status_deco(gw)
    else:
        info = device_status(gw, None if manual else dev["iface"])
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


def _http(iface: str | None, url: str, *, method: str = "GET",
          data: dict[str, str] | None = None, body: str | None = None,
          headers: dict[str, str] | None = None, cookies: str | None = None,
          timeout: int = 8) -> tuple[bool, str]:
    """HTTP request via curl, optionally bound to a network interface.

    Two net-mode dongles frequently share the SAME gateway IP (e.g. two ZTE
    sticks both at 192.168.0.1) and even the same host IP, so binding to the
    dongle's *interface* (SO_BINDTODEVICE, what ``curl --interface`` does) is the
    only way to reach the intended device. ``cookies`` is a cookie-jar path
    reused across calls to keep a login session. Returns (ok, response_text).
    """
    args = ["curl", "-s", "--max-time", str(timeout)]
    if iface:
        args += ["--interface", iface]
    if cookies:
        args += ["-c", cookies, "-b", cookies]
    for k, v in (headers or {}).items():
        args += ["-H", f"{k}: {v}"]
    if method == "POST":
        args += ["-X", "POST"]
        if body is not None:
            args += ["--data-binary", body]
        for k, v in (data or {}).items():
            args += ["--data-urlencode", f"{k}={v}"]
    try:
        p = subprocess.run(args + [url], capture_output=True, text=True,
                           timeout=timeout + 4)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, ""
    return p.returncode == 0, p.stdout


def device_status(host: str, iface: str | None = None) -> dict[str, Any]:
    """Signal quality (%) and operator name from the dongle web API."""
    return _status_zte(host, iface) or _status_huawei(host, iface) or {}


def _status_zte(host: str, iface: str | None = None) -> dict[str, Any] | None:
    """ZTE goform: signalbar (0-5), network_provider, network_type."""
    url = (f"http://{host}/goform/goform_get_cmd_process"
           "?isTest=false&multi_data=1"
           "&cmd=signalbar,network_provider,network_type,rssi,rscp")
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    ok, text = _http(iface, url, headers=headers, timeout=5)
    if not ok or not text:
        return None
    try:
        d = json.loads(text)
    except ValueError:
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


def _status_huawei(host: str, iface: str | None = None) -> dict[str, Any] | None:
    """Huawei HiLink: /api/device/signal + /api/net/current-plmn."""
    ok, text = _http(iface, f"http://{host}/api/device/signal", timeout=5)
    if not ok or ("<rsrp>" not in text and "<rssi>" not in text):
        return None
    out: dict[str, Any] = {}
    # rsrp dBm -> rough %: -140 (0%) .. -44 (100%)
    if "<rsrp>" in text:
        try:
            rsrp = int(text.split("<rsrp>")[1].split("dBm")[0].strip())
            out["signal"] = max(0, min(100, round((rsrp + 140) / 96 * 100)))
        except (ValueError, IndexError):
            pass
    ok2, plmn = _http(iface, f"http://{host}/api/net/current-plmn", timeout=5)
    if ok2 and "<FullName>" in plmn:
        out["operator"] = plmn.split("<FullName>")[1].split("</FullName>")[0]
    return out or None


def _detect_gateway(dev: dict[str, Any]) -> str:
    """Probe known dongle API hosts reachable through this interface."""
    iface = dev.get("iface")
    candidates = [dev["gateway"], *[g for g in KNOWN_GATEWAYS if g != dev["gateway"]]]
    for host in candidates:
        ok, _ = _http(iface, f"http://{host}/", timeout=3)
        if ok:
            return host
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

    # TP-Link Deco (app-managed CPE, no goform/HiLink API): rotate by rebooting
    # the unit via its local encrypted API — the SIM re-dials and the carrier
    # hands out a new CGNAT IP. Slower than a data re-dial (the Deco 5G takes a
    # few minutes to come back), but it's the only exposed lever on this model.
    if "deco" in (modem.get("model") or "").lower():
        return _rotate_deco(host, iface)

    # Interface-bind the web-API calls ONLY for auto-discovered USB dongles,
    # which can share a gateway IP (two ZTE sticks at 192.168.0.1) and each sit
    # on their own link. Manually-added LAN routers (MC801A) have a unique IP
    # reachable via the main table; SO_BINDTODEVICE onto their macvlan is both
    # unnecessary and flaky (same subnet as the parent), so don't bind.
    api_iface = None if modem.get("manual") else iface
    import time
    t0 = time.monotonic()
    ok = _rotate_zte(host, api_iface) or _rotate_huawei(host, api_iface)
    if not ok:
        raise NetdevError(f"no supported web API at {host} for {iface}")
    t_api = time.monotonic() - t0

    # Egress-bind by source IP for manual LAN routers (reliable on a same-subnet
    # macvlan), by interface for USB dongles. Poll while the link re-registers so
    # the caller gets the new IP on the first try (no needless rotation retries).
    bind = modem.get("bind_ip") if modem.get("manual") else None
    ip = None
    # Short probes, tight cadence: while the link re-registers a probe with the
    # default 12 s timeout just hangs and adds up to 12 s to every rotation.
    # Callers (rotation hook, extension) give up after ~15 s, so detect the new
    # IP as soon as it is really there. Still up to ~36 s overall.
    deadline = time.monotonic() + 36
    time.sleep(2)
    while True:
        ip = public_ip(iface, bind, max_time=4)
        if ip or time.monotonic() >= deadline:
            break
        time.sleep(1.5)
    log.info("rotate %s: web-api %.1fs, new ip after %.1fs total (%s)",
             iface, t_api, time.monotonic() - t0, "ok" if ip else "no ip")
    return ip


DECO_PASSWORD_FILE = "/etc/modemproxy/deco5g.pass"


def _deco_password() -> str | None:
    """Deco admin password: config.deco_password, else the root-only file."""
    try:
        pw = get_config().deco_password
    except AttributeError:
        pw = ""
    if pw:
        return pw
    try:
        return Path(DECO_PASSWORD_FILE).read_text().strip() or None
    except OSError:
        return None


_DECO_NET_TYPE = {"nr": "5G", "5g": "5G", "lte": "4G", "4g": "4G",
                  "wcdma": "3G", "umts": "3G", "hspa": "3G"}


def _status_deco(host: str) -> dict[str, Any]:
    """Operator + signal for a TP-Link Deco.

    The library's ``get_lte_status`` is thin; the device's own
    ``admin/network?form=internet`` read returns the full ``mobile_cpe`` block
    (signal %, SIM/dial state, radio type, data usage), which is what the app
    shows. SMS and the mobile-data toggle are NOT in this local API — they are
    cloud/app-only on this model — so rotation stays reboot-only elsewhere.
    """
    from json import dumps
    try:
        from tplinkrouterc6u.client.deco import TPLinkDecoClient
    except ImportError:
        return {}
    pw = _deco_password()
    if not pw:
        return {}
    try:
        c = TPLinkDecoClient(host, pw, verify_ssl=False, timeout=15)
        c.authorize()
        data = c.request("admin/network?form=internet", dumps({"operation": "read"}))
    except Exception:
        return {}
    finally:
        try:
            c.logout()
        except Exception:
            pass
    cpe = (data or {}).get("mobile_cpe") or {}
    if not cpe:
        return {}
    out: dict[str, Any] = {}
    # Operator: profile_name is base64 (e.g. "V2luZA==" -> "Wind"); tag the RAT.
    op = ""
    prof = cpe.get("profile_name")
    if prof:
        try:
            op = base64.b64decode(prof).decode("utf-8", "replace").strip()
        except Exception:
            op = str(prof)
    rat = _DECO_NET_TYPE.get(str(cpe.get("network_type", "")).lower())
    if op and rat:
        out["operator"] = f"{op} · {rat}"
    elif op:
        out["operator"] = op
    elif rat:
        out["operator"] = rat
    sig = cpe.get("signal_strength")
    if sig not in (None, ""):
        try:
            out["signal"] = max(0, min(100, int(round(float(sig)))))
        except (TypeError, ValueError):
            pass
    return out


def _rotate_deco(host: str, iface: str) -> str | None:
    """Reboot a TP-Link Deco via its local encrypted API (tplinkrouterc6u).

    The reboot re-dials the SIM, yielding a new public IP. The Deco 5G can take
    several minutes to reboot and re-register, so we wait (bounded) for the
    egress IP to reappear and return it.
    """
    try:
        from tplinkrouterc6u.client.deco import TPLinkDecoClient
    except ImportError as e:
        raise NetdevError("tplinkrouterc6u not installed "
                          "(pip install tplinkrouterc6u)") from e
    pw = _deco_password()
    if not pw:
        raise NetdevError(f"no Deco admin password (set {DECO_PASSWORD_FILE})")
    before = public_ip(iface)
    try:
        c = TPLinkDecoClient(host, pw, verify_ssl=False, timeout=30)
        c.authorize()
        c.reboot()
    except Exception as e:
        raise NetdevError(f"Deco reboot failed: {e}") from e
    import time
    for _ in range(40):            # up to ~10 min for reboot + 5G re-registration
        time.sleep(15)
        ip = public_ip(iface)
        if ip and ip != before:
            return ip
    return public_ip(iface)


def _zte_login(host: str, iface: str | None, cj: str) -> None:
    """Log into a ZTE goform session (cookie jar ``cj``), if a password is set.

    Set commands (rotation, reboot) on CPE like the MC801A require a login
    session; status/get commands usually don't. Bound to ``iface`` so two ZTE
    devices sharing 192.168.0.1 don't get crossed.
    """
    pw = get_config().default_hilink_password
    if not pw:
        return
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    base = f"http://{host}/goform"
    # ZTE LD-challenge: final = SHA256( SHA256(pw)_UPPER + LD )_UPPER
    ld = ""
    ok, text = _http(iface, f"{base}/goform_get_cmd_process?isTest=false&cmd=LD",
                     headers=headers, cookies=cj)
    if ok and text:
        try:
            ld = json.loads(text).get("LD", "")
        except ValueError:
            ld = ""
    if ld:
        # Newer CPE (MC801A): SHA256 challenge, password only.
        h1 = hashlib.sha256(pw.encode()).hexdigest().upper()
        pwd = hashlib.sha256((h1 + ld).encode()).hexdigest().upper()
        data = {"isTest": "false", "goformId": "LOGIN", "password": pwd}
    else:
        # Older MF-series dongles: base64 username + password.
        data = {"isTest": "false", "goformId": "LOGIN",
                "username": base64.b64encode(b"admin").decode(),
                "password": base64.b64encode(pw.encode()).decode()}
    _http(iface, f"{base}/goform_set_cmd_process", method="POST",
          data=data, headers=headers, cookies=cj)


def _zte_get(host: str, iface: str | None, cj: str,
             headers: dict[str, str], cmd: str) -> dict[str, Any]:
    """One ZTE goform get-command -> parsed JSON dict (empty on failure)."""
    ok, text = _http(iface, f"http://{host}/goform/goform_get_cmd_process"
                     f"?isTest=false&cmd={cmd}", headers=headers, cookies=cj)
    if not ok or not text:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return {}


def _rotate_zte(host: str, iface: str | None = None) -> bool:
    """ZTE goform rotation.

    Newer CPE (e.g. MC801A) reject every set-command that lacks an ``AD``
    anti-CSRF token — ``AD = MD5( MD5(wa_inner_version + cr_version) + RD )`` with
    a fresh ``RD`` nonce per request — and rotate reliably via a bearer-preference
    toggle (drop to 3G, back to 4G/5G) that forces a full re-registration. Older
    MF-series dongles just need DISCONNECT/CONNECT and have no AD. We do the full
    sequence best-effort, so both families work.
    """
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    base = f"http://{host}/goform/goform_set_cmd_process"
    cj = tempfile.mktemp(prefix="mp_zte_")
    import time
    try:
        _zte_login(host, iface, cj)
        wv = _zte_get(host, iface, cj, headers, "wa_inner_version").get("wa_inner_version", "")
        cv = _zte_get(host, iface, cj, headers, "cr_version").get("cr_version", "")
        base_hash = hashlib.md5((wv + cv).encode()).hexdigest() if (wv or cv) else ""

        def _set(**params: str) -> bool:
            data = {"isTest": "false", **params}
            rd = _zte_get(host, iface, cj, headers, "RD").get("RD", "")
            if rd and base_hash:
                data["AD"] = hashlib.md5((base_hash + rd).encode()).hexdigest()
            ok, r = _http(iface, base, method="POST", headers=headers,
                          cookies=cj, data=data)
            return ok and "failure" not in r.lower()

        ok1 = _set(notCallback="true", goformId="DISCONNECT_NETWORK")
        # Toggle RAT to force a fresh attach: drop to 3G, then restore auto.
        _set(goformId="SET_BEARER_PREFERENCE", BearerPreference="Only_WCDMA")
        time.sleep(1)
        # Restore value differs by firmware — NETWORK_auto (MF-series dongles),
        # 4G_AND_5G (MC801A 5G CPE). The unsupported one returns "failure" and is
        # ignored, so the right one wins and neither family is left stuck on 3G.
        _set(goformId="SET_BEARER_PREFERENCE", BearerPreference="NETWORK_auto")
        _set(goformId="SET_BEARER_PREFERENCE", BearerPreference="4G_AND_5G")
        time.sleep(1)
        ok2 = _set(notCallback="true", goformId="CONNECT_NETWORK")
        return ok1 or ok2
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass


def reboot_zte(host: str, iface: str | None = None) -> bool:
    """Reboot a ZTE dongle/router via the web API (authed)."""
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    cj = tempfile.mktemp(prefix="mp_zte_")
    try:
        _zte_login(host, iface, cj)
        ok, _ = _http(iface, f"http://{host}/goform/goform_set_cmd_process",
                      method="POST", headers=headers, cookies=cj,
                      data={"isTest": "false", "goformId": "REBOOT_DEVICE"})
        return ok
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass


# --- SMS (net-mode ZTE goform) --------------------------------------------
# ZTE stores SMS in UCS2 big-endian hex; each message has a numeric ``tag``:
#   0 = received unread, 1 = received read, 2 = sent, 3 = draft,
#   4 = send failed, 5 = sending. We treat 2/4/5 as outbound, the rest inbound.
_ZTE_SENT_TAGS = {"2", "4", "5"}


def _ucs2_decode(hexstr: str) -> str:
    try:
        return bytes.fromhex(hexstr).decode("utf-16-be", "replace")
    except (ValueError, TypeError):
        return hexstr or ""


def _ucs2_encode(text: str) -> str:
    return text.encode("utf-16-be").hex().upper()


def _maybe_ucs2(s: str) -> str:
    """Decode a field that ZTE may return as UCS2 hex (some firmwares hex-encode
    the sender number too); leave plain text (alphanumeric sender IDs) as-is."""
    if s and len(s) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", s) and "00" in s:
        return _ucs2_decode(s)
    return s or ""


def _zte_date(raw: str) -> str:
    """ZTE date 'yy,mm,dd,hh,mm,ss,tz' (comma or ';') -> 'YYYY-MM-DD HH:MM'."""
    parts = re.split(r"[;,]", raw or "")
    if len(parts) >= 6:
        yy, mm, dd, hh, mi = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            return f"20{int(yy):02d}-{int(mm):02d}-{int(dd):02d} {int(hh):02d}:{int(mi):02d}"
        except ValueError:
            pass
    return ""


# --- ZTE "web encryption" (MF-series dongles, e.g. MF833) -------------------
# Newer MF-series firmware AES-256-GCM-encrypts sensitive goform fields (SMS
# number/body, both directions). The browser generates a random 32-byte key,
# RSA-PKCS1v15-encrypts its 64-char hex form with the device's public key
# (``cmd=web_crt_get``) and posts it via ``web_http_enstr_set``; from then on
# the session's fields are base64( IV[12] || GCM-tag[16] || ciphertext ) and
# the plaintext is the usual UCS2-hex string. Devices without this scheme
# (MC801A CPE) return no certificate and keep sending plain UCS2-hex.

def _zte_enc_key(host: str, iface: str | None, cj: str, headers: dict[str, str],
                 base_hash: str) -> bytes | None:
    """Do the key handshake for this session; returns the AES key or None."""
    crt = _zte_get(host, iface, cj, headers, "web_crt_get").get("result", "")
    if "BEGIN PUBLIC KEY" not in crt:
        return None
    try:
        from Crypto.Cipher import PKCS1_v1_5
        from Crypto.PublicKey import RSA
        der = base64.b64decode(re.sub(r"-----[^-]+-----", "", crt).strip())
        pub = RSA.import_key(der)
        key = os.urandom(32)
        enstr = base64.b64encode(
            PKCS1_v1_5.new(pub).encrypt(key.hex().encode())).decode()
    except Exception:
        return None
    data = {"isTest": "false", "goformId": "web_http_enstr_set", "web_enstr": enstr}
    rd = _zte_get(host, iface, cj, headers, "RD").get("RD", "")
    if rd and base_hash:
        data["AD"] = hashlib.md5((base_hash + rd).encode()).hexdigest()
    ok, r = _http(iface, f"http://{host}/goform/goform_set_cmd_process", method="POST",
                  headers=headers, cookies=cj, data=data)
    return key if ok and "failure" not in r.lower() else None


def _zte_gcm_decrypt(key: bytes | None, field: str) -> str:
    """Decrypt one encrypted field; falls back to the raw value (plain devices)."""
    if not key or not field:
        return field or ""
    try:
        from Crypto.Cipher import AES
        blob = base64.b64decode(field + "=" * (-len(field) % 4))
        iv, tag, ct = blob[:12], blob[12:28], blob[28:]
        return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag) \
            .decode("ascii", "replace")
    except Exception:
        return field


def _zte_gcm_encrypt(key: bytes | None, text: str) -> str:
    if not key:
        return text
    from Crypto.Cipher import AES
    iv = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(text.encode())
    return base64.b64encode(iv + tag + ct).decode()


def _zte_base_hash(host: str, iface: str | None, cj: str, headers: dict[str, str]) -> str:
    wv = _zte_get(host, iface, cj, headers, "wa_inner_version").get("wa_inner_version", "")
    cv = _zte_get(host, iface, cj, headers, "cr_version").get("cr_version", "")
    return hashlib.md5((wv + cv).encode()).hexdigest() if (wv or cv) else ""


def list_sms_zte(host: str, iface: str | None = None) -> list[dict[str, Any]]:
    """Read the ZTE inbox/outbox. Returns newest-first list of dicts:
    {id, number, text, date, direction ('in'|'out'), unread(bool)}."""
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    cj = tempfile.mktemp(prefix="mp_zte_")
    try:
        _zte_login(host, iface, cj)
        key = _zte_enc_key(host, iface, cj, headers, _zte_base_hash(host, iface, cj, headers))
        url = (f"http://{host}/goform/goform_get_cmd_process?isTest=false"
               "&cmd=sms_data_total&page=0&data_per_page=500&mem_store=1"
               "&tags=10&order_by=order+by+id+desc")
        ok, text = _http(iface, url, headers=headers, cookies=cj, timeout=12)
        if not ok or not text:
            return []
        try:
            msgs = json.loads(text).get("messages", []) or []
        except ValueError:
            return []
        out = []
        for m in msgs:
            tag = str(m.get("tag", ""))
            out.append({
                "id": str(m.get("id", "")),
                "number": _maybe_ucs2(_zte_gcm_decrypt(key, m.get("number", ""))),
                "text": _ucs2_decode(_zte_gcm_decrypt(key, m.get("content", ""))),
                "date": _zte_date(m.get("date", "")),
                "direction": "out" if tag in _ZTE_SENT_TAGS else "in",
                "unread": tag == "0",
            })
        return out
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass


def send_sms_zte(host: str, iface: str | None, number: str, text: str) -> bool:
    """Send an SMS via the ZTE goform API (authed, AD-token for MC801A CPE)."""
    import time
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    base = f"http://{host}/goform/goform_set_cmd_process"
    cj = tempfile.mktemp(prefix="mp_zte_")
    try:
        _zte_login(host, iface, cj)
        base_hash = _zte_base_hash(host, iface, cj, headers)
        # Encrypted-web dongles expect Number/MessageBody AES-GCM'd with the
        # session key; plain devices get the raw values (key is None).
        key = _zte_enc_key(host, iface, cj, headers, base_hash)
        sms_time = time.strftime("%y;%m;%d;%H;%M;%S;+8")
        data = {
            "isTest": "false", "goformId": "SEND_SMS", "notCallback": "true",
            "Number": _zte_gcm_encrypt(key, number), "sms_time": sms_time,
            "MessageBody": _zte_gcm_encrypt(key, _ucs2_encode(text)),
            "ID": "-1", "encode_type": "UNICODE",
        }
        rd = _zte_get(host, iface, cj, headers, "RD").get("RD", "")
        if rd and base_hash:
            data["AD"] = hashlib.md5((base_hash + rd).encode()).hexdigest()
        ok, r = _http(iface, base, method="POST", headers=headers, cookies=cj,
                      data=data, timeout=15)
        return ok and "failure" not in r.lower()
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass


def delete_sms_zte(host: str, iface: str | None, ids: list[str]) -> bool:
    """Delete one or more SMS on a ZTE device (authed, AD-token for MC801A).
    ZTE expects msg_id as ';'-joined ids with a trailing ';' (e.g. '3;5;')."""
    if not ids:
        return True
    headers = {"Referer": f"http://{host}/", "X-Requested-With": "XMLHttpRequest"}
    base = f"http://{host}/goform/goform_set_cmd_process"
    cj = tempfile.mktemp(prefix="mp_zte_")
    try:
        _zte_login(host, iface, cj)
        wv = _zte_get(host, iface, cj, headers, "wa_inner_version").get("wa_inner_version", "")
        cv = _zte_get(host, iface, cj, headers, "cr_version").get("cr_version", "")
        base_hash = hashlib.md5((wv + cv).encode()).hexdigest() if (wv or cv) else ""
        data = {"isTest": "false", "goformId": "DELETE_SMS",
                "msg_id": ";".join(ids) + ";", "notCallback": "true"}
        rd = _zte_get(host, iface, cj, headers, "RD").get("RD", "")
        if rd and base_hash:
            data["AD"] = hashlib.md5((base_hash + rd).encode()).hexdigest()
        ok, r = _http(iface, base, method="POST", headers=headers, cookies=cj,
                      data=data, timeout=12)
        return ok and "failure" not in r.lower()
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass


def sms_list(modem: dict[str, Any]) -> list[dict[str, Any]]:
    """Inbox/outbox for a net-mode modem (ZTE only; others return [])."""
    host = modem.get("mgmt_host")
    if not host or "deco" in (modem.get("model") or "").lower():
        return []
    # Bind by source IP for manual LAN routers, by iface for USB dongles.
    binder = modem.get("bind_ip") if modem.get("manual") else modem.get("iface")
    return list_sms_zte(host, binder)


def sms_send(modem: dict[str, Any], number: str, text: str) -> bool:
    """Send an SMS through a net-mode modem (ZTE only)."""
    host = modem.get("mgmt_host")
    if not host or "deco" in (modem.get("model") or "").lower():
        raise NetdevError("SMS not supported on this modem")
    binder = modem.get("bind_ip") if modem.get("manual") else modem.get("iface")
    return send_sms_zte(host, binder, number, text)


def sms_delete(modem: dict[str, Any], ids: list[str]) -> bool:
    """Delete SMS by id on a net-mode modem (ZTE only). Removes on the router."""
    host = modem.get("mgmt_host")
    if not host or "deco" in (modem.get("model") or "").lower():
        raise NetdevError("SMS not supported on this modem")
    binder = modem.get("bind_ip") if modem.get("manual") else modem.get("iface")
    return delete_sms_zte(host, binder, ids)


def _rotate_huawei(host: str, iface: str | None = None) -> bool:
    """Huawei HiLink: toggle mobile data off/on via the dialup API."""
    api = f"http://{host}/api"
    cj = tempfile.mktemp(prefix="mp_hw_")
    try:
        ok, tok = _http(iface, f"{api}/webserver/SesTokInfo", cookies=cj, timeout=5)
        headers = {"Content-Type": "text/xml"}
        if ok and "<TokInfo>" in tok:
            headers["__RequestVerificationToken"] = tok.split("<TokInfo>")[1].split("</TokInfo>")[0]
        off = ('<?xml version="1.0" encoding="UTF-8"?>'
               "<request><dataswitch>0</dataswitch></request>")
        on = ('<?xml version="1.0" encoding="UTF-8"?>'
              "<request><dataswitch>1</dataswitch></request>")
        ok1, resp = _http(iface, f"{api}/dialup/mobile-dataswitch", method="POST",
                          body=off, headers=headers, cookies=cj)
        if not ok1 or "error" in resp.lower():
            return False
        import time
        time.sleep(2)
        _http(iface, f"{api}/dialup/mobile-dataswitch", method="POST",
              body=on, headers=headers, cookies=cj)
        return True
    finally:
        try:
            os.unlink(cj)
        except OSError:
            pass
