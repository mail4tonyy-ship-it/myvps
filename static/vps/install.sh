#!/bin/sh
set -eu

API_URL=""
VPS_IP=""
TOKEN=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api) API_URL="$2"; shift ;;
    --ip) VPS_IP="$2"; shift ;;
    --token) TOKEN="$2"; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
  shift
done

[ -n "$API_URL" ] || { echo "缺少 --api"; exit 1; }
[ -n "$VPS_IP" ] || { echo "缺少 --ip"; exit 1; }
[ -n "$TOKEN" ] || { echo "缺少 --token"; exit 1; }
case "$API_URL" in https://*) ;; *) echo "--api 必须是 https://"; exit 1 ;; esac

if [ -f /etc/os-release ]; then . /etc/os-release; OS="${ID:-linux}"; else OS="linux"; fi

echo "==> 安装服务器全景探针 agent"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3 curl iproute2 iputils-ping
elif command -v apk >/dev/null 2>&1; then
  apk update
  apk add python3 curl iproute2 iputils-ping
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 curl iproute iputils
fi

mkdir -p /opt/panorama-probe /etc/panorama-probe
cat > /etc/panorama-probe/env <<EOF
API_URL="$API_URL"
VPS_IP="$VPS_IP"
TOKEN="$TOKEN"
EOF
chmod 600 /etc/panorama-probe/env

curl -fsSL "$API_URL/api/agent/script" -o /opt/panorama-probe/agent.py
chmod +x /opt/panorama-probe/agent.py

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/panorama-probe.service <<'EOF'
[Unit]
Description=Server Panorama Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/panorama-probe/env
ExecStart=/usr/bin/python3 /opt/panorama-probe/agent.py
Restart=always
RestartSec=8

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now panorama-probe
  systemctl status panorama-probe --no-pager || true
else
  cat > /etc/init.d/panorama-probe <<'EOF'
#!/sbin/openrc-run
name="panorama-probe"
command="/usr/bin/python3"
command_args="/opt/panorama-probe/agent.py"
command_background=true
pidfile="/run/panorama-probe.pid"
output_log="/var/log/panorama-probe.log"
error_log="/var/log/panorama-probe.log"
depend() { need net; }
start_pre() { . /etc/panorama-probe/env; export API_URL VPS_IP TOKEN; }
EOF
  chmod +x /etc/init.d/panorama-probe
  rc-update add panorama-probe default
  rc-service panorama-probe restart
fi

echo "==> 已完成，面板将在下一次上报后显示数据"
