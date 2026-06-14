# Relay VPS setup (for boxes behind NAT / CGNAT)

If a modemproxy box has **no public IP** (home fibre with CGNAT, mobile uplink,
etc.) customers can't reach it directly. In **relay mode** the box dials *out*
to a small public VPS running `frps`, which re-publishes every proxy port. The
home IP stays hidden and you never touch the customer's router.

```
customer ──► VPS:remote_port (frps) ──tunnel──► home box:local_port (frpc) ──► SIM
```

One cheap VPS (1 vCPU / 1 GB, any provider) relays many boxes.

## 1. On the VPS — install frps

```bash
FRP_VER=0.61.1
curl -fsSL "https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_linux_amd64.tar.gz" \
  | tar -xz --strip-components=1 -C /usr/local/bin --wildcards '*/frps'

mkdir -p /etc/frp
cat >/etc/frp/frps.toml <<'EOF'
bindPort = 7000
auth.method = "token"
auth.token = "CHANGE-ME-LONG-RANDOM"
# Range of ports frpc clients may publish on:
allowPorts = [ { start = 8000, end = 9999 } ]
EOF

cat >/etc/systemd/system/frps.service <<'EOF'
[Unit]
Description=frp server (relay)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now frps
```

Open the VPS firewall: the relay control port (`7000`) **and** the proxy
ports customers will use (e.g. `8000-9999`):

```bash
ufw allow 7000/tcp
ufw allow 8000:9999/tcp
```

## 2. On each home box — switch to relay mode

Panel → **Settings → Remote access → Relay**, fill in:

| Field        | Value                                  |
|--------------|----------------------------------------|
| Relay VPS host | the VPS public IP                    |
| Relay port   | `7000`                                 |
| Token        | the same token as `frps.toml`          |
| Port offset  | `0` (or per-box offset to share a relay) |

Save & apply. `frpc` starts, opens a tunnel per proxy, and the **Customer
addresses** list shows the public `host:port` to hand out.

Equivalent via CLI / config (`/etc/modemproxy/config.yaml`):

```yaml
access_mode: relay
relay_host: "203.0.113.10"
relay_port: 7000
relay_token: "CHANGE-ME-LONG-RANDOM"
relay_remote_offset: 0
```

```bash
modemproxy publish-sync       # render frpc.toml + (re)start the tunnel
modemproxy publish-status     # show customer addresses
```

## Sharing one relay between several boxes

Each box must publish on **distinct** remote ports. Give each box a different
`relay_remote_offset` (e.g. box A `0`, box B `100`, box C `200`) so their
`local_port + offset` ranges don't collide on the VPS.
