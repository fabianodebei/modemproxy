#!/usr/bin/env bash
#
# modemproxy one-command installer for Ubuntu.
#
# Private repo — pass a GitHub token (a fine-grained PAT with read access to
# the repo, or a classic PAT with `repo` scope):
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
    git python3 python3-venv python3-pip \
    modemmanager libqmi-utils libmbim-utils \
    3proxy usbutils uhubctl curl ca-certificates \
    || die "apt install failed"

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

log "Writing config"
mkdir -p "$CONF_DIR/autogen"
mkdir -p /var/lib/modemproxy /var/log/modemproxy
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
    chmod 600 "$CONF"
    GENERATED_PW="$PW"
fi

log "Installing systemd units + udev rules"
cp "$SRC/systemd/"*.service "$SRC/systemd/"*.timer /etc/systemd/system/
cp "$SRC/udev/99-modemproxy.rules" /etc/udev/rules.d/
udevadm control --reload-rules || true
systemctl daemon-reload
systemctl enable --now modemproxy-web.service
systemctl enable --now modemproxy-pinger.timer
systemctl enable --now modemproxy-bandwidth.timer

log "Initial modem discovery"
"$VENV/bin/modemproxy" init-db
"$VENV/bin/modemproxy" discover || true

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
