#!/usr/bin/env bash
# ==============================================================================
# Ultimate Android VPN Server Deployment Script
# Supports: Ubuntu 20.04/22.04/24.04 LTS & Debian 11/12
# Installs & Configures: WireGuard Server + Xray VLESS-REALITY + NAT Forwarding
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   Ultimate Android VPN - Automated Server Setup      ${NC}"
echo -e "${BLUE}======================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SERVER_DIR/wireguard/setup_wireguard.sh"
chmod +x "$SERVER_DIR/wireguard/add_client.sh"
chmod +x "$SERVER_DIR/xray/setup_xray.sh"

echo -e "${YELLOW}[1/4] Updating package repositories and installing prerequisites...${NC}"
apt update -y
apt install -y curl wget git iptables iptables-persistent qrencode ufw net-tools

echo -e "${YELLOW}[2/4] Enabling IPv4 and IPv6 kernel packet forwarding...${NC}"
cat <<EOF > /etc/sysctl.d/99-vpn-forwarding.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
sysctl -p /etc/sysctl.d/99-vpn-forwarding.conf || true

echo -e "${YELLOW}[3/4] Configuring WireGuard VPN Server...${NC}"
"$SERVER_DIR/wireguard/setup_wireguard.sh"

echo -e "${YELLOW}[4/4] Configuring Xray VLESS-REALITY Anti-Censorship Server...${NC}"
"$SERVER_DIR/xray/setup_xray.sh"

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}  ✓ VPN Server Deployment Finished Successfully!     ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "WireGuard client configuration: /etc/wireguard/client_android.conf"
echo -e "Use '/etc/wireguard/add_client.sh <client_name>' to generate new client keys."
