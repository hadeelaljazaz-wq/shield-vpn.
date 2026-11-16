#!/usr/bin/env bash
set -euo pipefail

CLIENT_NAME="${1:-client_$(date +%s)}"
WG_DIR="/etc/wireguard"
MAIN_CONF="$WG_DIR/wg0.conf"

SERVER_PUBLIC_IP=$(curl -s4 https://api.ipify.org || echo "YOUR_SERVER_IP")
SERVER_PUB=$(cat "$WG_DIR/server_public.key")

# Determine next available IP
LAST_OCTET=$(grep AllowedIPs "$MAIN_CONF" | grep -oE '10\.66\.66\.[0-9]+' | cut -d. -f4 | sort -n | tail -n1 || echo "2")
NEXT_OCTET=$((LAST_OCTET + 1))
CLIENT_IP="10.66.66.$NEXT_OCTET"
CLIENT_IPV6="fd66:6666::$NEXT_OCTET"

CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Add peer to server config
cat <<EOF >> "$MAIN_CONF"

# Peer: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = $CLIENT_IP/32, $CLIENT_IPV6/128
EOF

wg addconf wg0 <(echo -e "[Peer]\nPublicKey = $CLIENT_PUB\nAllowedIPs = $CLIENT_IP/32, $CLIENT_IPV6/128") || true

CLIENT_FILE="$WG_DIR/${CLIENT_NAME}.conf"
cat <<EOF > "$CLIENT_FILE"
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_IP/32, $CLIENT_IPV6/128
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo "Created client $CLIENT_NAME with IP $CLIENT_IP."
echo "Config file: $CLIENT_FILE"
which qrencode >/dev/null 2>&1 && qrencode -t ansiutf8 < "$CLIENT_FILE" || true
