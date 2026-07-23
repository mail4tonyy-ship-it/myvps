#!/usr/bin/env bash
set -euo pipefail

ORIGIN="${1:-}"
VPS_IP="${2:-}"
TOKEN="${3:-}"

if [ -z "$ORIGIN" ] || [ -z "$VPS_IP" ] || [ -z "$TOKEN" ]; then
  echo "Usage: install.sh <origin> <ip> <token>" >&2
  exit 1
fi

if [ "$(id -u)" != "0" ]; then
  echo "Please run as root." >&2
  exit 1
fi

APP_DIR="/opt/probe-panorama"
SERVICE="/etc/systemd/system/probe-panorama-agent.service"

mkdir -p "$APP_DIR"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3 curl
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 curl
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 curl
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache python3 curl
fi

curl -fsSL "$ORIGIN/vps/agent.py" -o "$APP_DIR/agent.py"
chmod 700 "$APP_DIR/agent.py"

cat > "$APP_DIR/config.json" <<EOF
{
  "origin": "$ORIGIN",
  "ip": "$VPS_IP",
  "token": "$TOKEN"
}
EOF
chmod 600 "$APP_DIR/config.json"

cat > "$SERVICE" <<EOF
[Unit]
Description=Probe Panorama Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/env python3 $APP_DIR/agent.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now probe-panorama-agent
systemctl status probe-panorama-agent --no-pager || true

echo
echo "Probe Panorama Agent installed."
echo "Service: probe-panorama-agent"
