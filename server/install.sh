#!/usr/bin/env bash
# Smart Ad Shield VPN — gateway installer (Ubuntu 22.04/24.04, amd64/arm64).
#
# Installs and configures, idempotently:
#   * WireGuard  (UDP $SHIELD_WG_PORT)       — fast path
#   * Xray VLESS + REALITY + Vision (TCP $SHIELD_XRAY_PORT) — censorship-resistant path
#   * Provisioning API (HTTPS, pinned self-signed cert, TCP $SHIELD_API_PORT)
#     The phone generates its own WireGuard key pair; only the PUBLIC key is
#     sent here. Private keys never leave the device.
#
# Inputs (environment):
#   SHIELD_TOKEN          required  enrollment bearer token (>= 32 chars)
#   SHIELD_TLS_CERT_B64   optional  base64 PEM cert for the API (generated if absent)
#   SHIELD_TLS_KEY_B64    optional  base64 PEM key  for the API
#   SHIELD_PUBLIC_IP      optional  endpoint address given to clients (auto-detected)
#   SHIELD_NAME / SHIELD_CC          display name / ISO country code
#   SHIELD_WG_PORT=51820 SHIELD_XRAY_PORT=443 SHIELD_API_PORT=8443
#   SHIELD_REALITY_DEST=www.microsoft.com
#   SHIELD_XRAY_VERSION   optional  pin an Xray release tag (e.g. v25.10.15)
#   SHIELD_SKIP_XRAY=1    optional  WireGuard only
set -euo pipefail

log() { echo "[shield-install] $*"; }
die() { echo "[shield-install] ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"

: "${SHIELD_TOKEN:?SHIELD_TOKEN is required}"
[ "${#SHIELD_TOKEN}" -ge 32 ] || die "SHIELD_TOKEN too short"
WG_PORT="${SHIELD_WG_PORT:-51820}"
XRAY_PORT="${SHIELD_XRAY_PORT:-443}"
API_PORT="${SHIELD_API_PORT:-8443}"
REALITY_DEST="${SHIELD_REALITY_DEST:-www.microsoft.com}"
NAME="${SHIELD_NAME:-Shield Gateway}"
CC="${SHIELD_CC:-}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETC=/etc/shieldvpn
OPT=/opt/shieldvpn
mkdir -p "$ETC" "$OPT"
chmod 700 "$ETC"

export DEBIAN_FRONTEND=noninteractive
log "installing packages"
apt-get update -y -q
apt-get install -y -q --no-install-recommends wireguard-tools iptables python3 curl openssl ca-certificates iproute2 unzip jq

# ---------- kernel / sysctl ----------
cat > /etc/sysctl.d/90-shieldvpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=7500000
net.core.wmem_max=7500000
EOF
sysctl -q --system || true

WAN_IF="$(ip -4 route show default | awk '{print $5; exit}')"
[ -n "$WAN_IF" ] || die "cannot find default route interface"
log "WAN interface: $WAN_IF"

if [ -z "${SHIELD_PUBLIC_IP:-}" ]; then
  SHIELD_PUBLIC_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)"
  [ -n "$SHIELD_PUBLIC_IP" ] || SHIELD_PUBLIC_IP="$(ip -4 addr show "$WAN_IF" | awk '/inet /{sub(/\/.*/,"",$2);print $2;exit}')"
fi
log "public endpoint: $SHIELD_PUBLIC_IP"

# ---------- secrets ----------
umask 077
printf '%s' "$SHIELD_TOKEN" > "$ETC/token"
if [ -n "${SHIELD_TLS_CERT_B64:-}" ] && [ -n "${SHIELD_TLS_KEY_B64:-}" ]; then
  echo "$SHIELD_TLS_CERT_B64" | base64 -d > "$ETC/api.crt"
  echo "$SHIELD_TLS_KEY_B64" | base64 -d > "$ETC/api.key"
elif [ ! -s "$ETC/api.crt" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=shieldvpn" -keyout "$ETC/api.key" -out "$ETC/api.crt" 2>/dev/null
fi

# ---------- WireGuard ----------
if [ ! -s "$ETC/wg.key" ]; then wg genkey > "$ETC/wg.key"; fi
WG_PUB="$(wg pubkey < "$ETC/wg.key")"
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.66.1/24, fd66:66::1/64
ListenPort = $WG_PORT
MTU = 1420
PostUp = wg set %i private-key $ETC/wg.key
PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o $WAN_IF -j MASQUERADE
PostUp = ip6tables -t nat -A POSTROUTING -s fd66:66::/64 -o $WAN_IF -j MASQUERADE || true
PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 1 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -I FORWARD 1 -i %i -j ACCEPT || true; ip6tables -I FORWARD 1 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT || true
PostUp = iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o $WAN_IF -j MASQUERADE || true
PostDown = ip6tables -t nat -D POSTROUTING -s fd66:66::/64 -o $WAN_IF -j MASQUERADE || true
PostDown = iptables -D FORWARD -i %i -j ACCEPT || true; iptables -D FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT || true
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT || true; ip6tables -D FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl restart wg-quick@wg0

# ---------- host firewall (Oracle Ubuntu images ship a REJECT-all INPUT chain) ----------
open_port() { # proto port
  iptables -C INPUT -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p "$1" --dport "$2" -j ACCEPT
}
open_port udp "$WG_PORT"
open_port tcp "$API_PORT"
[ "${SHIELD_SKIP_XRAY:-0}" = 1 ] || open_port tcp "$XRAY_PORT"
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi

# ---------- Xray ----------
XRAY_JSON="null"
if [ "${SHIELD_SKIP_XRAY:-0}" != 1 ]; then
  XRAY_VERSION="${SHIELD_XRAY_VERSION:-v26.11.9}"
  if [ "$(/usr/local/bin/xray version 2>/dev/null | awk 'NR==1{print "v"$2}')" != "$XRAY_VERSION" ]; then
    log "installing Xray-core $XRAY_VERSION from the official GitHub release"
    case "$(uname -m)" in
      x86_64) XZ=Xray-linux-64.zip ;;
      aarch64|arm64) XZ=Xray-linux-arm64-v8a.zip ;;
      *) die "unsupported CPU $(uname -m)" ;;
    esac
    BASE="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION"
    TMPX="$(mktemp -d)"
    curl -fsSL --retry 4 -o "$TMPX/x.zip" "$BASE/$XZ"
    curl -fsSL --retry 4 -o "$TMPX/x.dgst" "$BASE/$XZ.dgst"
    WANT="$(grep -i 'SHA2-256' "$TMPX/x.dgst" | awk -F'= ' '{print $2}' | tr -d '[:space:]')"
    GOT="$(sha256sum "$TMPX/x.zip" | cut -d' ' -f1)"
    [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || die "Xray download checksum mismatch ($GOT != $WANT)"
    unzip -q -o "$TMPX/x.zip" -d "$TMPX/x"
    install -m 755 "$TMPX/x/xray" /usr/local/bin/xray
    mkdir -p /usr/local/share/xray /usr/local/etc/xray
    install -m 644 "$TMPX/x/geoip.dat" "$TMPX/x/geosite.dat" /usr/local/share/xray/
    rm -rf "$TMPX"
  fi
  [ -s /usr/local/etc/xray/config.json ] || echo '{}' > /usr/local/etc/xray/config.json
  cat > /etc/systemd/system/xray.service <<UNIT
[Unit]
Description=Xray Service
After=network-online.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 /usr/local/etc/xray/config.json
  systemctl daemon-reload
  systemctl enable xray >/dev/null 2>&1 || true
  XRAY_BIN="$(command -v xray || echo /usr/local/bin/xray)"
  if [ ! -s "$ETC/reality.json" ]; then
    # `xray x25519` prints the private key on line 1 and the public key
    # ("Public key:" in old releases, "Password:" in new ones) on line 2.
    OUT="$("$XRAY_BIN" x25519)"
    PRIV="$(echo "$OUT" | sed -n 1p | awk -F': ' '{print $2}' | tr -d '[:space:]')"
    PUB="$(echo "$OUT" | sed -n 2p | awk -F': ' '{print $2}' | tr -d '[:space:]')"
    [ -n "$PRIV" ] && [ -n "$PUB" ] || die "could not parse xray x25519 output: $OUT"
    SID="$(openssl rand -hex 8)"
    jq -n --arg priv "$PRIV" --arg pub "$PUB" --arg sid "$SID" '{private_key:$priv, public_key:$pub, short_id:$sid}' > "$ETC/reality.json"
  fi
  XRAY_JSON="$(jq -c --argjson port "$XRAY_PORT" --arg sni "$REALITY_DEST" \
      '{port:$port, public_key:.public_key, short_id:.short_id, sni:$sni, flow:"xtls-rprx-vision"}' "$ETC/reality.json")"
fi

jq -n --arg name "$NAME" --arg cc "$CC" --arg ip "$SHIELD_PUBLIC_IP" --arg wgpub "$WG_PUB" \
      --argjson wgport "$WG_PORT" --argjson xray "$XRAY_JSON" \
      '{name:$name, cc:$cc, public_ip:$ip, wg:{public_key:$wgpub, port:$wgport, mtu:1280}, xray:$xray}' > "$ETC/server.json"
chmod 600 "$ETC/server.json"

# ---------- provisioning API ----------
install -m 755 "$SRC_DIR/provision.py" "$OPT/provision.py"
cat > /etc/systemd/system/shieldvpn-api.service <<EOF
[Unit]
Description=Smart Ad Shield VPN provisioning API
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Environment=SHIELD_API_PORT=$API_PORT
Environment=SHIELD_REALITY_DEST=$REALITY_DEST
Environment=SHIELD_XRAY_PORT=$XRAY_PORT
ExecStart=/usr/bin/python3 $OPT/provision.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable shieldvpn-api >/dev/null 2>&1 || true
systemctl restart shieldvpn-api

for i in $(seq 1 30); do
  if curl -fsS -k --max-time 3 "https://127.0.0.1:$API_PORT/v1/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS -k "https://127.0.0.1:$API_PORT/v1/health" || die "provisioning API did not start"
echo
log "OK — WireGuard $WG_PUB on udp/$WG_PORT, API on tcp/$API_PORT"
