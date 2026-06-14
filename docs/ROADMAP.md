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
- USSD (balance checks) via ModemManager
- Per-modem connectivity test + speedtest (egress-bound via interface)
- Token-authenticated rotation hook URL (link rotation), from the panel
- Monthly quota / bandwidth caps — auto lock/unlock a proxy over its cap;
  configurable per modem from the panel
- Allocation pool API — `/api/pool` + `/api/pool/random` hand out live proxies
  (excludes offline / disabled / quota-locked), optional operator filter
- Sticky sessions — `/api/pool/sticky/{key}` pins a key to one live modem for a
  TTL window
- Prometheus `/metrics` — pool health + per-modem signal, online, month traffic
- Web panel: Pool page (live proxies + copy) and Activity page (rotation log)
- OpenVPN per-modem export — internal EC CA, per-modem server instance +
  policy-routed egress, single-file `.ovpn` download from the panel

## Next
- **OS/TCP fingerprint spoofing layer** (p0f / osfooler) — last major
  ProxySmart parity item.
- **API keys** — let pool consumers authenticate without the admin password.

## Later
- Multi-IP allocation / sticky IP pinning
- Postgres backend option for multi-node
- Redis-backed pool for cross-node allocation at scale
