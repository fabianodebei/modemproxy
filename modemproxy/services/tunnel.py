"""Reverse SSH tunnel — vendor remote access channel.

The server generates an SSH keypair at install time. The admin (vendor) takes
the public key, adds it to their VPS authorized_keys, configures the VPS host
here, and the box keeps a persistent reverse tunnel:

    autossh -R <tunnel_port>:localhost:22 <user>@<host>

Vendor then does:  ssh -p <tunnel_port> <server_user>@localhost  on the VPS.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

KEY_PATH = Path("/etc/modemproxy/tunnel_key")
ENV_PATH = Path("/etc/modemproxy/tunnel.env")
SERVICE = "modemproxy-tunnel"


def machine_data() -> str:
    """Hardware fingerprint string (mirrors ProxySmart format)."""
    parts: dict[str, object] = {}
    try:
        parts["n_cpu"] = int(subprocess.check_output(["nproc"], text=True).strip())
    except Exception:
        parts["n_cpu"] = 0
    try:
        lines = subprocess.check_output(["df", "/", "--output=size", "-m"],
                                        text=True).splitlines()
        parts["rootfs"] = int(lines[-1].strip())
    except Exception:
        parts["rootfs"] = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                parts["mem"] = int(line.split()[1]) // 1024
                break
    except Exception:
        parts["mem"] = 0
    try:
        uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
        parts["bios_uuid"] = uuid
    except Exception:
        parts["bios_uuid"] = "unavailable"
    return ",".join(f"{k}={v}" for k, v in parts.items())


def public_key() -> str | None:
    pub = KEY_PATH.with_suffix(".pub")
    return pub.read_text().strip() if pub.exists() else None


def tunnel_active() -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", SERVICE],
                           capture_output=True, text=True)
        return r.stdout.strip() == "active"
    except Exception:
        return False


def sync(host: str, user: str, port: int) -> None:
    """Write tunnel.env and (re)start modemproxy-tunnel service."""
    if host:
        ENV_PATH.write_text(
            f"TUNNEL_HOST={host}\nTUNNEL_USER={user}\nTUNNEL_PORT={port}\n"
        )
        subprocess.run(["systemctl", "enable", "--now", SERVICE], check=False)
        subprocess.run(["systemctl", "restart", SERVICE], check=False)
    else:
        subprocess.run(["systemctl", "stop", SERVICE], check=False)
        subprocess.run(["systemctl", "disable", SERVICE], check=False)
        if ENV_PATH.exists():
            ENV_PATH.unlink()
