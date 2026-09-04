#!/usr/bin/env bash
#
# Installazione ISOLATA di modemproxy accanto a proxysmart.
# - pannello web su 7997 (6997 è occupata)
# - porte proxy base 18000/19000 (proxysmart usa 5000/8000)
# - NON apre il firewall automaticamente
# - lascia ModemManager MASKED -> proxysmart resta padrone dei modem
#
# Uso:  sudo bash /home/proxybet/modemproxy/install-isolated.sh
#
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Esegui con sudo."; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF=/etc/modemproxy/config.yaml

echo "==> Lancio l'installer modemproxy (dal checkout locale)"
bash "$HERE/install.sh"

echo "==> Metto in sicurezza il config (porte non in conflitto, no firewall)"
if [ -f "$CONF" ]; then
    sed -i 's/^web_port:.*/web_port: 7997/'            "$CONF"
    sed -i 's/^http_port_base:.*/http_port_base: 18000/' "$CONF"
    sed -i 's/^socks_port_base:.*/socks_port_base: 19000/' "$CONF"
    sed -i 's/^open_firewall:.*/open_firewall: false/'  "$CONF"
fi

echo "==> Riavvio il pannello e ri-asserisco ModemManager masked"
systemctl restart modemproxy-web.service || true
systemctl mask ModemManager.service 2>/dev/null || true

echo
echo "==> STATO FINALE"
echo -n "modemproxy-web: "; systemctl is-active modemproxy-web.service || true
echo -n "proxysmart:     "; systemctl is-active proxysmart.service || true
echo -n "ModemManager:   "; systemctl is-enabled ModemManager.service 2>/dev/null || true
echo "Pannello in ascolto:"; ss -tlnH 'sport = :7997' 2>/dev/null || true
echo
echo "Pannello:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):7997   (user: admin, pw stampata sopra)"
echo "NB: nessun modem comparira' finche' ModemManager resta masked (proxysmart in controllo)."
