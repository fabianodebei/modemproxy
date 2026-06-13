# Configuration

`/etc/modemproxy/config.yaml`. Restart after changes: `systemctl restart modemproxy-web`.

| Key | Default | Meaning |
|---|---|---|
| `web_host` | `127.0.0.1` | Panel bind address |
| `web_port` | `6997` | Panel port |
| `admin_user` | `admin` | Panel basic-auth user |
| `admin_password` | random | Panel basic-auth password (set by installer) |
| `http_port_base` | `8000` | Modem index N → HTTP port `base + N` |
| `socks_port_base` | `9000` | Modem index N → SOCKS port `base + N` |
| `bind_address` | `0.0.0.0` | Interface the proxies listen on |
| `rotation_default_interval` | `0` | Auto-rotate seconds; `0` = manual only |
| `dns_servers` | `[]` | Override DNS in proxies; empty = modem DNS |
| `dhcp_method` | `modemmanager` | `modemmanager` or `dhcpcd` |
| `usb_reset_method` | `usbreset` | `usbreset` or `uhubctl` |
| `online_check_url` | gstatic 204 | Connectivity probe URL |
| `max_parallel_workers` | `4` | Concurrency for discovery |
| `db_path` | `/var/lib/modemproxy/modemproxy.db` | SQLite file |

## Security

The panel listens on `0.0.0.0:6997` by default with basic auth. Put it behind
a firewall or reverse proxy with TLS, and **change the admin password**. The
modem proxies themselves use per-modem username/password generated on
`apply-port`.
