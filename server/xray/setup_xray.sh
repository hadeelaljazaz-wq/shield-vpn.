#!/usr/bin/env bash
set -euo pipefail

echo "Setting up Xray Core..."
XRAY_INSTALL_SCRIPT="/tmp/install-xray.sh"
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$XRAY_INSTALL_SCRIPT" || true

if [ -f "$XRAY_INSTALL_SCRIPT" ]; then
    bash "$XRAY_INSTALL_SCRIPT" || true
    rm -f "$XRAY_INSTALL_SCRIPT"
fi

XRAY_CONF_DIR="/usr/local/etc/xray"
mkdir -p "$XRAY_CONF_DIR"

if [ -f "$(dirname "$0")/config.json" ]; then
    cp "$(dirname "$0")/config.json" "$XRAY_CONF_DIR/config.json"
fi

systemctl enable --now xray || true
echo "Xray configuration installed at $XRAY_CONF_DIR/config.json"
