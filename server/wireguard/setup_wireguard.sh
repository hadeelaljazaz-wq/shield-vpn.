#!/usr/bin/env bash
set -euo pipefail

echo "Installing WireGuard packages..."
apt install -y wireguard wireguard-tools

MAIN_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1 || echo "eth0")
SERVER_PUBLIC_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://icanhazip.com || echo "YOUR_SERVER_IP")

WG_PORT=51820
WG_DIR="/etc/wireguard"
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

if [ ! -f "$WG_DIR/server_private.key" ]; then
    echo "Generating WireGuard cryptographic keys..."
    wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
    wg genkey | tee "$WG_DIR/client_private.key" | wg pubkey > "$WG_DIR/client_public.key"
fi

SERVER_PRIV=$(cat "$WG_DIR/server_private.key")
SERVER_PUB=$(cat "$WG_DIR/server_public.key")
CLIENT_PRIV=$(cat "$WG_DIR/client_private.key")
CLIENT_PUB=$(cat "$WG_DIR/client_public.key")

cat <<EOF > "$WG_DIR/wg0.conf"
[Interface]
Address = 10.66.66.1/24, fd66:6666::1/64
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE

[Peer]
# Default Android Client
PublicKey = $CLIENT_PUB
AllowedIPs = 10.66.66.2/32, fd66:6666::2/128
EOF

cat <<EOF > "$WG_DIR/client_android.conf"
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.66.66.2/32, fd66:6666::2/128
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

systemctl enable --now wg-quick@wg0 || true
echo "WireGuard setup complete. Client config generated at $WG_DIR/client_android.conf"
