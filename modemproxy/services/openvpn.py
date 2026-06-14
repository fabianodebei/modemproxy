"""Per-modem OpenVPN export.

Each modem can expose its own OpenVPN server instance whose client traffic
egresses through that modem's interface. We keep a single internal CA and issue
EC certificates with plain openssl (no easy-rsa, no slow DH params — `dh none`
with an EC curve). A client `.ovpn` is rendered with inlined ca/cert/key so it
works as a single downloadable file.

Routing (done on the box at enable time): a per-modem subnet is policy-routed
out the modem interface and MASQUERADEd, so VPN clients get that SIM's IP.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .. import db
from ..config import get_config

VPN_DIR = Path(os.environ.get("MODEMPROXY_VPN_DIR", "/etc/modemproxy/vpn"))
CA_DIR = VPN_DIR / "ca"
BASE_PORT = 1190          # modem index N -> udp port BASE_PORT + N
SUBNET_PREFIX = "10.8"    # modem index N -> 10.8.N.0/24
CURVE = "prime256v1"


class VPNError(RuntimeError):
    pass


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        raise VPNError(p.stderr.strip() or f"{args[0]} failed")
    return p


def _index(imei: str) -> int:
    modems = sorted(m["imei"] for m in db.list_modems())
    return (modems.index(imei) + 1) if imei in modems else len(modems) + 1


def ensure_ca() -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = CA_DIR / "ca.key", CA_DIR / "ca.crt"
    if ca_crt.exists() and ca_key.exists():
        return
    _run(["openssl", "ecparam", "-name", CURVE, "-genkey", "-noout",
          "-out", str(ca_key)])
    _run(["openssl", "req", "-x509", "-new", "-key", str(ca_key),
          "-days", "3650", "-out", str(ca_crt), "-subj", "/CN=modemproxy-CA"])


def _issue(name: str) -> tuple[str, str]:
    """Issue an EC key+cert signed by the CA. Returns (key_pem, cert_pem)."""
    ensure_ca()
    d = VPN_DIR / "issued"
    d.mkdir(parents=True, exist_ok=True)
    key, csr, crt = d / f"{name}.key", d / f"{name}.csr", d / f"{name}.crt"
    _run(["openssl", "ecparam", "-name", CURVE, "-genkey", "-noout", "-out", str(key)])
    _run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr),
          "-subj", f"/CN={name}"])
    _run(["openssl", "x509", "-req", "-in", str(csr),
          "-CA", str(CA_DIR / "ca.crt"), "-CAkey", str(CA_DIR / "ca.key"),
          "-CAcreateserial", "-days", "1825", "-out", str(crt)])
    return key.read_text(), crt.read_text()


def _server_conf(imei: str, name: str, idx: int, iface: str) -> Path:
    port = BASE_PORT + idx
    subnet = f"{SUBNET_PREFIX}.{idx}.0"
    skey, scrt = _issue(f"server-{name}")
    (VPN_DIR / f"server-{name}.key").write_text(skey)
    (VPN_DIR / f"server-{name}.crt").write_text(scrt)
    conf = f"""# modemproxy OpenVPN server for {name} ({imei})
port {port}
proto udp
dev tun-{name[:10]}
ca {CA_DIR / 'ca.crt'}
cert {VPN_DIR / f'server-{name}.crt'}
key {VPN_DIR / f'server-{name}.key'}
dh none
ecdh-curve {CURVE}
topology subnet
server {subnet} 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
keepalive 10 60
persist-key
persist-tun
# route this subnet out the modem interface
up "{VPN_DIR / 'route-up.sh'} {iface} {subnet}/24"
script-security 2
verb 3
"""
    path = VPN_DIR / f"server-{name}.conf"
    path.write_text(conf)
    _write_route_script()
    return path


def _write_route_script() -> None:
    script = VPN_DIR / "route-up.sh"
    script.write_text("""#!/usr/bin/env bash
# args: <iface> <subnet/cidr> — policy-route a VPN subnet out a modem interface
set -e
IFACE="$1"; SUBNET="$2"
GW=$(ip route show dev "$IFACE" default | awk '{print $3; exit}')
TABLE=$((100 + $(echo "$IFACE" | cksum | cut -d' ' -f1) % 100))
ip rule add from "$SUBNET" lookup "$TABLE" 2>/dev/null || true
[ -n "$GW" ] && ip route replace default via "$GW" dev "$IFACE" table "$TABLE" \
    || ip route replace default dev "$IFACE" table "$TABLE"
iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
sysctl -q -w net.ipv4.ip_forward=1
""")
    script.chmod(0o755)


def _systemctl(action: str, unit: str) -> None:
    try:
        subprocess.run(["systemctl", action, unit], check=False,
                       capture_output=True, text=True)
    except FileNotFoundError:
        pass


def enable_vpn(imei: str) -> dict:
    modem = db.get_modem(imei)
    if not modem:
        raise VPNError(f"unknown modem {imei}")
    iface = modem.get("iface")
    if not iface:
        raise VPNError(f"no interface for {imei} (run discover)")
    name = modem.get("name") or imei[-6:]
    idx = _index(imei)
    _server_conf(imei, name, idx, iface)
    db.set_port(imei, vpn_enabled=1)
    _systemctl("enable", f"modemproxy-vpn@{name}.service")
    _systemctl("restart", f"modemproxy-vpn@{name}.service")
    return {"imei": imei, "port": BASE_PORT + idx, "subnet": f"{SUBNET_PREFIX}.{idx}.0/24"}


def disable_vpn(imei: str) -> None:
    modem = db.get_modem(imei) or {}
    name = modem.get("name") or imei[-6:]
    db.set_port(imei, vpn_enabled=0)
    _systemctl("stop", f"modemproxy-vpn@{name}.service")
    _systemctl("disable", f"modemproxy-vpn@{name}.service")


def export_client(imei: str) -> str:
    """Render a single-file .ovpn client config with inlined certs."""
    cfg = get_config()
    modem = db.get_modem(imei)
    if not modem:
        raise VPNError(f"unknown modem {imei}")
    name = modem.get("name") or imei[-6:]
    idx = _index(imei)
    port = BASE_PORT + idx
    ca = (CA_DIR / "ca.crt").read_text() if (CA_DIR / "ca.crt").exists() else _need_enable()
    ckey, ccrt = _issue(f"client-{name}")
    remote = cfg.vpn_public_host or "SERVER_PUBLIC_IP"
    return f"""# modemproxy client config for {name}
client
dev tun
proto udp
remote {remote} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ecdh-curve {CURVE}
verb 3
<ca>
{ca.strip()}
</ca>
<cert>
{ccrt.strip()}
</cert>
<key>
{ckey.strip()}
</key>
"""


def _need_enable() -> str:
    raise VPNError("VPN not enabled for this modem yet (enable it first)")
