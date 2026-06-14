# Roadmap

Status of feature parity with a full commercial modem-proxy manager.

## Done (v0.1)
- ModemManager-based discovery (vendor-agnostic)
- SQLite store: modems, ports, rotation log, SMS, bandwidth schema
- Per-modem 3proxy generation (HTTP + SOCKS5, per-modem egress IP)
- Manual IP rotation (single + all) with logging
- Modern web panel (Tailwind + Alpine + Chart.js) — login, dashboard with
  detail drawer (QR + connection strings + credential edit), bandwidth page
- Bandwidth accounting — per-interface counter sampler + usage reports + charts
- Per-port auto-rotation timers — honour `ports.rotation_interval` via
  `rotate-due` + systemd timer; configurable from the panel
- Per-proxy client IP whitelist (3proxy ACL), editable from the panel
- JSON API + CLI
- SMS list/send via ModemManager
- systemd units (bandwidth + pinger + rotator timers), udev auto-discovery,
  one-command installer

## Next
- **USSD** — balance checks (`send_ussd_json`).
- **Connectivity tests / speedtest** — per-modem `conn_test`, `speedtest`,
  `test_proxy_http`.
- **Rotation hooks** — trigger rotation via authenticated URL (link rotation).
- **Allocation API** — Redis-backed pool endpoint that hands out a random live
  proxy (the residential-style allocation layer).

## Later
- OpenVPN per-modem export
- OS/TCP fingerprint spoofing layer
- Multi-IP / sticky sessions
- Prometheus metrics endpoint
- Postgres backend option for multi-node
