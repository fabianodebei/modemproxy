# modemproxy

Turn an Ubuntu box full of 4G/LTE USB modems into a pool of **rotating
HTTP/SOCKS5 proxies**, each egressing through its own SIM and public IP.

Self-hosted, single stack (Python + SQLite + 3proxy). Modern dark web panel,
CLI, and REST API. One-command install.

## Web panel

A modern, server-rendered dashboard (Tailwind + Alpine.js + Chart.js — no Node
build step):

- **Login** — cookie session (no browser basic-auth popup).
- **Dashboard** — modem grid with live signal, status, public IP, ports; stat
  cards; per-modem detail drawer with copy-paste HTTP/SOCKS/curl strings, a QR
  code, password change / credential regeneration, and rotate / reset / disable.
- **Bandwidth** — today / yesterday / month / lifetime usage table plus a
  24-hour throughput chart per modem.

> Original, independent implementation. Not affiliated with any commercial
> proxy-management product.

## Development

```bash
pip install -e ".[dev]"
pytest          # 34 tests: db, generator, bandwidth, quota, openvpn, metrics, API
```

CI runs the suite on Python 3.10 and 3.12 (see `.github/workflows/ci.yml`).

## Install (Ubuntu 22.04 / 24.04)

```bash
curl -fsSL https://raw.githubusercontent.com/fabianodebei/modemproxy/main/install.sh | sudo bash
```

(Private fork? Pass a GitHub PAT instead:
`curl -fsSL -H "Authorization: token $TOKEN" .../install.sh | sudo MODEMPROXY_TOKEN=$TOKEN bash`.)

The installer pulls dependencies (ModemManager, libqmi/libmbim, 3proxy),
creates a venv under `/opt/modemproxy`, writes `/etc/modemproxy/config.yaml`
with a random admin password, and starts the panel on port `6997`.

Then plug in your modems and:

```bash
modemproxy status
```

## How it works

```
USB modems ──► ModemManager (libqmi / libmbim / AT)
                     │
                     ▼
              modemproxy core  ──►  SQLite (modems, ports, rotation log)
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
   3proxy per     FastAPI        CLI
   modem          panel + API   (modemproxy …)
   (HTTP+SOCKS)   :6997
```

- **Modem layer** — ModemManager handles every supported modem
  (Huawei, Quectel, Fibocom, Sierra, ZTE, Telit…), so there are no per-vendor
  scripts to maintain.
- **Net-mode dongles** — consumer "HiLink"/RNDIS sticks (e.g. Huawei E3372h,
  ZTE MF-series) that present as a plain Ethernet interface rather than an AT
  modem are also supported: `discover` finds them, sets up source-based policy
  routing (so several dongles on the same `192.168.0.0/24` still egress out the
  right interface), binds 3proxy to each dongle's local IP, and rotates the
  public IP through the stick's own web API (ZTE goform / Huawei HiLink API).
- **One proxy per modem** — each modem gets an HTTP and a SOCKS5 port, with
  outbound traffic bound to that modem's interface/IP via 3proxy.
- **Rotation** — force a new public IP per modem on demand (reconnect bearer)
  or on a timer; every change is logged.
- **Panel + API** — modern dashboard (Tailwind + Alpine, no Node build) and a
  JSON API under `/api`.

## CLI

```bash
modemproxy discover               # scan ModemManager, sync DB
modemproxy list                   # table of modems + assigned ports
modemproxy name <imei> dongle1    # friendly nick
modemproxy apply-port <imei>      # allocate ports + start the proxy
modemproxy rotate <imei>          # force a new IP
modemproxy rotate-all
modemproxy purge-port <imei>      # stop + remove a proxy
modemproxy list-sms <imei>
modemproxy send-sms <imei> <number> "<text>"
modemproxy rotation-log [imei]
```

Add `--json` to `list` / `status` / `discover` for machine-readable output.

## Using a proxy

After `apply-port`, find the credentials with `modemproxy list`:

```bash
curl -x http://USER:PASS@SERVER_IP:8001 https://api.ipify.org   # HTTP
curl -x socks5h://USER:PASS@SERVER_IP:9001 https://api.ipify.org # SOCKS5
```

## Allocation pool API

Hand out a live proxy to external tools (offline / disabled / quota-locked
modems are excluded):

```bash
curl -u admin:PASS http://SERVER_IP:6997/api/pool          # all live proxies
curl -u admin:PASS http://SERVER_IP:6997/api/pool/random   # one at random
curl -u admin:PASS "http://SERVER_IP:6997/api/pool/random?operator=TIM"
```

Each entry includes ready-to-use `http` and `socks5` connection strings.

**API keys** — pool consumers can authenticate without the admin password.
Create one on the **Settings** page or via `modemproxy apikey-create`, then:

```bash
curl -H "Authorization: Bearer mk_xxx" http://SERVER_IP:6997/api/pool/random
# or:  -H "X-API-Key: mk_xxx"
```

**Sticky sessions** — keep one caller on the same modem for a TTL window:

```bash
curl -u admin:PASS "http://SERVER_IP:6997/api/pool/sticky/user-42?ttl=600"
```

## OpenVPN per-modem

Each modem can run its own OpenVPN server whose clients egress through that
SIM. Set `vpn_public_host` in the config to your server's public IP, then from
the panel drawer: **Enable VPN server** → **Download .ovpn**. Or via CLI:

```bash
modemproxy vpn-enable <imei>
modemproxy vpn-export <imei> --out modem1.ovpn
```

An internal EC CA is created on first use; each modem gets a UDP port
(`1190 + index`) and a `10.8.<index>.0/24` subnet, policy-routed and
MASQUERADEd out the modem interface. Requires the box to run as root with
IP forwarding (the installer pulls `openvpn`, `iproute2`, `iptables`).

## Monitoring

Prometheus metrics (no auth) at `/metrics`: `modemproxy_modems_total`,
`_modems_online`, `_proxies_active`, `_quota_locked`, plus per-modem
`_modem_signal`, `_modem_online`, and `_modem_month_bytes{direction=...}`.

## Configuration

All keys in [`docs/CONFIG.md`](docs/CONFIG.md). Edit
`/etc/modemproxy/config.yaml`, then `systemctl restart modemproxy-web`.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) — bandwidth accounting, per-port
timers, USSD, OpenVPN export, multi-IP allocation API.

## License

MIT.
