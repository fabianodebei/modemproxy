# modemproxy

Turn an Ubuntu box full of 4G/LTE USB modems into a pool of **rotating
HTTP/SOCKS5 proxies**, each egressing through its own SIM and public IP.

Self-hosted, single binary stack (Python + SQLite + 3proxy), web panel + CLI +
REST API. One-command install.

> Original, independent implementation. Not affiliated with any commercial
> proxy-management product.

## Install (Ubuntu 22.04 / 24.04)

```bash
curl -fsSL https://raw.githubusercontent.com/fabianodebei/modemproxy/main/install.sh | sudo bash
```

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
- **One proxy per modem** — each modem gets an HTTP and a SOCKS5 port, with
  outbound traffic bound to that modem's interface/IP via 3proxy.
- **Rotation** — force a new public IP per modem on demand (reconnect bearer)
  or on a timer; every change is logged.
- **Panel + API** — server-rendered dashboard (HTMX, no Node build) and a JSON
  API under `/api`.

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

## Configuration

All keys in [`docs/CONFIG.md`](docs/CONFIG.md). Edit
`/etc/modemproxy/config.yaml`, then `systemctl restart modemproxy-web`.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) — bandwidth accounting, per-port
timers, USSD, OpenVPN export, multi-IP allocation API.

## License

MIT.
