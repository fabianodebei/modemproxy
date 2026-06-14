#!/usr/bin/env bash
#
# modemproxy one-command installer for Ubuntu.
#
#   curl -fsSL https://raw.githubusercontent.com/fabianodebei/modemproxy/main/install.sh | sudo bash
#
# Private fork? Pass a GitHub token (fine-grained PAT with repo read, or classic
# PAT with `repo` scope):
#
#   curl -fsSL -H "Authorization: token GHP_xxx" \
#     https://raw.githubusercontent.com/fabianodebei/modemproxy/main/install.sh \
#     | sudo MODEMPROXY_TOKEN=GHP_xxx bash
#
# Idempotent: safe to re-run to upgrade.
set -euo pipefail

TOKEN="${MODEMPROXY_TOKEN:-}"
BRANCH="${MODEMPROXY_BRANCH:-main}"
if [ -n "$TOKEN" ]; then
    REPO="${MODEMPROXY_REPO:-https://${TOKEN}@github.com/fabianodebei/modemproxy.git}"
else
    REPO="${MODEMPROXY_REPO:-https://github.com/fabianodebei/modemproxy.git}"
fi
PREFIX="/opt/modemproxy"
SRC="$PREFIX/src"
VENV="$PREFIX/venv"
CONF_DIR="/etc/modemproxy"
CONF="$CONF_DIR/config.yaml"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (use sudo)"
command -v apt-get >/dev/null || die "this installer targets Ubuntu/Debian"

log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    git make gcc build-essential pkg-config \
    python3 python3-venv python3-pip python3-dev \
    libffi-dev libssl-dev \
    modemmanager libqmi-utils libmbim-utils \
    usb-modeswitch usb-modeswitch-data ppp \
    usbutils uhubctl curl wget ca-certificates \
    openvpn openssl iproute2 iptables \
    isc-dhcp-client \
    net-tools dnsutils procps jq \
    || die "apt install failed"

# 3proxy: try package first, fall back to build from source
if apt-get install -y -qq 3proxy 2>/dev/null; then
    log "3proxy installed via apt"
elif [ -x /usr/bin/3proxy ] || [ -x /usr/local/bin/3proxy ]; then
    log "3proxy already present"
else
    log "Building 3proxy from source (not in apt repos)"
    BUILD_DIR="$(mktemp -d)"
    git clone --quiet --depth 1 https://github.com/3proxy/3proxy.git "$BUILD_DIR"
    make -C "$BUILD_DIR" -f Makefile.Linux -j"$(nproc)" 2>/dev/null \
        || make -C "$BUILD_DIR" -f Makefile.Linux 2>/dev/null \
        || die "3proxy build failed"
    install -m 755 "$BUILD_DIR/bin/3proxy" /usr/bin/3proxy
    rm -rf "$BUILD_DIR"
    log "3proxy built and installed to /usr/bin/3proxy"
fi

systemctl enable --now ModemManager.service || true

log "Fetching modemproxy source ($BRANCH)"
mkdir -p "$PREFIX"
if [ -d "$SRC/.git" ]; then
    git -C "$SRC" fetch --quiet "$REPO" "$BRANCH"
    git -C "$SRC" reset --hard --quiet FETCH_HEAD
elif [ -f "$(dirname "$0")/pyproject.toml" ]; then
    # running from a local checkout
    cp -a "$(cd "$(dirname "$0")" && pwd)/." "$SRC/" 2>/dev/null || true
    [ -f "$SRC/pyproject.toml" ] || { rm -rf "$SRC"; git clone --quiet --branch "$BRANCH" "$REPO" "$SRC"; }
else
    git clone --quiet --branch "$BRANCH" "$REPO" "$SRC"
fi

# Don't persist the token inside .git/config
if [ -n "$TOKEN" ] && [ -d "$SRC/.git" ]; then
    git -C "$SRC" remote set-url origin \
        "https://github.com/fabianodebei/modemproxy.git" 2>/dev/null || true
fi

log "Creating Python virtualenv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet "$SRC"
ln -sf "$VENV/bin/modemproxy" /usr/local/bin/modemproxy

log "Setting up modemproxy group"
groupadd -f modemproxy
# Add the human who invoked sudo to the group, so CLI works without sudo
TARGET_USER="${SUDO_USER:-}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
    usermod -aG modemproxy "$TARGET_USER" || true
fi

log "Writing config"
mkdir -p "$CONF_DIR/autogen"
mkdir -p /var/lib/modemproxy /var/log/modemproxy
# Group-readable state so non-root group members can use the CLI.
# DB dir is group-writable + setgid so the CLI (as a group member) can
# write modemproxy.db and new files inherit the modemproxy group.
chgrp -R modemproxy "$CONF_DIR" /var/lib/modemproxy /var/log/modemproxy || true
chmod 750 "$CONF_DIR" "$CONF_DIR/autogen" /var/log/modemproxy || true
chmod 2770 /var/lib/modemproxy || true
if [ ! -f "$CONF" ]; then
    PW="$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c16)"
    SECRET="$(head -c32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c40)"
    cat > "$CONF" <<EOF
# modemproxy configuration — see docs/CONFIG.md for all keys
web_host: 0.0.0.0
web_port: 6997
admin_user: admin
admin_password: "$PW"
session_secret: "$SECRET"

http_port_base: 8000
socks_port_base: 9000
bind_address: 0.0.0.0

rotation_default_interval: 0
dns_servers: []
EOF
    GENERATED_PW="$PW"
fi
# config holds admin_password + session_secret: root-write, group-read only
chown root:modemproxy "$CONF" || true
chmod 640 "$CONF" || true

log "Installing systemd units + udev rules"
cp "$SRC/systemd/"*.service "$SRC/systemd/"*.timer /etc/systemd/system/
cp "$SRC/udev/99-modemproxy.rules" /etc/udev/rules.d/
udevadm control --reload-rules || true
systemctl daemon-reload
systemctl enable --now modemproxy-web.service
systemctl enable --now modemproxy-pinger.timer
systemctl enable --now modemproxy-bandwidth.timer
systemctl enable --now modemproxy-rotator.timer
systemctl enable --now modemproxy-quota.timer

log "Initial modem discovery"
"$VENV/bin/modemproxy" init-db
"$VENV/bin/modemproxy" discover || true
# DB created by root above: make it group read/write for the CLI
chgrp -R modemproxy /var/lib/modemproxy || true
chmod -R g+rw /var/lib/modemproxy || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
log "modemproxy installed."
echo "    Panel:  http://${IP:-<server-ip>}:6997"
echo "    User:   admin"
if [ -n "${GENERATED_PW:-}" ]; then
    echo "    Pass:   ${GENERATED_PW}   (saved in $CONF)"
else
    echo "    Pass:   (unchanged — see $CONF)"
fi
echo "    CLI:    modemproxy list"
echo
echo "Next: plug in your 4G modems, then run 'modemproxy status'."
