#!/bin/sh
set -eu

API_URL=""
VPS_IP=""
TOKEN=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --api) [ "$#" -ge 2 ] || { echo "--api 缺少参数"; exit 1; }; API_URL="$2"; shift ;;
        --ip) [ "$#" -ge 2 ] || { echo "--ip 缺少参数"; exit 1; }; VPS_IP="$2"; shift ;;
        --token) [ "$#" -ge 2 ] || { echo "--token 缺少参数"; exit 1; }; TOKEN="$2"; shift ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
    shift
done

[ -n "$API_URL" ] && [ -n "$VPS_IP" ] && [ -n "$TOKEN" ] || { echo "缺少必要参数"; exit 1; }
case "$API_URL" in https://*) ;; *) echo "--api 必须使用 https://"; exit 1 ;; esac

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS="${ID:-}"
else
    echo "无法识别操作系统"
    exit 1
fi

case "$OS" in
    alpine|debian|ubuntu) ;;
    *) echo "不支持的发行版: $OS"; exit 1 ;;
esac

detect_init_system() {
    if [ -d /run/systemd/system ] && [ "$(cat /proc/1/comm 2>/dev/null || true)" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
        echo systemd
    elif [ -x /sbin/openrc-run ] && command -v rc-service >/dev/null 2>&1; then
        echo openrc
    else
        echo none
    fi
}

INIT_SYS="$(detect_init_system)"
[ "$INIT_SYS" != none ] || { echo "需要 systemd 或 OpenRC"; exit 1; }

echo "=========================================="
echo " MyVps Agent 安装启动"
echo " 目标系统: ${OS}"
echo "=========================================="

echo "[1/5] 清理旧版监控服务"
if [ "$INIT_SYS" = "openrc" ]; then
    rc-service myvps-agent stop >/dev/null 2>&1 || true
    rc-update del myvps-agent default >/dev/null 2>&1 || true
    rm -f /etc/init.d/myvps-agent
else
    systemctl stop myvps-agent >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/myvps-agent.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "[2/5] 安装基础依赖"
if [ "$INIT_SYS" = "openrc" ]; then
    apk update || true
    apk add python3 py3-websocket-client curl coreutils iputils
else
    apt-get update -y
    apt-get install -y python3 python3-websocket curl coreutils iputils-ping
fi

echo "[3/5] 初始化工作目录"
mkdir -p /opt/myvps
API_URL="$API_URL" VPS_IP="$VPS_IP" TOKEN="$TOKEN" python3 -c 'import json, os; json.dump({"api_url": os.environ["API_URL"] + "/api/config", "report_url": os.environ["API_URL"] + "/api/report", "ip": os.environ["VPS_IP"], "token": os.environ["TOKEN"]}, open("/opt/myvps/config.json", "w"))'
chmod 600 /opt/myvps/config.json

verify_agent_manifest() {
    component="$1"; file="$2"; headers="$3"
    expected_sha=$(tr -d '\r' < "$headers" | awk '/^[Xx]-[Aa]gent-[Ss][Hh][Aa]256:/ {print tolower($2)}' | tail -n 1)
    version=$(tr -d '\r' < "$headers" | awk '/^[Xx]-[Aa]gent-[Mm]anifest-[Vv]ersion:/ {print $2}' | tail -n 1)
    expected_length=$(tr -d '\r' < "$headers" | awk '/^[Xx]-[Aa]gent-[Ll]ength:/ {print $2}' | tail -n 1)
    supplied_mac=$(tr -d '\r' < "$headers" | awk '/^[Xx]-[Aa]gent-[Mm][Aa][Cc]:/ {print tolower($2)}' | tail -n 1)
    actual_sha=$(sha256sum "$file" | awk '{print $1}')
    actual_length=$(wc -c < "$file" | tr -d ' ')
    expected_mac=$(printf 'v1\n%s\n%s\n%s\n' "$component" "$expected_sha" "$actual_length" | openssl dgst -sha256 -mac HMAC -macopt "key:${TOKEN}" | awk '{print tolower($NF)}')
    [ "$version" = "1" ] && [ "$expected_length" = "$actual_length" ] && [ "$expected_sha" = "$actual_sha" ] && [ "$supplied_mac" = "$expected_mac" ]
}

echo "[4/5] 下载监控组件"
CURL_USER_AGENT="MyVps-Agent-Installer/1.0"
AGENT_URL="${API_URL}/api/agent_update?ip=${VPS_IP}&component=agent"
AGENT_TEMP="/opt/myvps/agent.py.download"
AGENT_HEADERS="/opt/myvps/agent.py.headers"
curl -fsSL --retry 3 --retry-delay 2 -A "$CURL_USER_AGENT" -D "$AGENT_HEADERS" -H "Authorization: ${TOKEN}" "$AGENT_URL" -o "$AGENT_TEMP"
verify_agent_manifest agent "$AGENT_TEMP" "$AGENT_HEADERS" || { echo "agent.py 清单校验失败"; exit 1; }
python3 -m py_compile "$AGENT_TEMP"
mv "$AGENT_TEMP" /opt/myvps/agent.py
rm -f "$AGENT_HEADERS"
chmod 700 /opt/myvps/agent.py

REALTIME_CLIENT_URL="${API_URL}/api/agent_update?ip=${VPS_IP}&component=realtime-client"
REALTIME_CLIENT_TEMP="/opt/myvps/realtime_client.py.download"
REALTIME_CLIENT_HEADERS="/opt/myvps/realtime_client.py.headers"
curl -fsSL --retry 3 --retry-delay 2 -A "$CURL_USER_AGENT" -D "$REALTIME_CLIENT_HEADERS" -H "Authorization: ${TOKEN}" "$REALTIME_CLIENT_URL" -o "$REALTIME_CLIENT_TEMP"
verify_agent_manifest realtime-client "$REALTIME_CLIENT_TEMP" "$REALTIME_CLIENT_HEADERS" || { echo "realtime_client.py 清单校验失败"; exit 1; }
python3 -m py_compile "$REALTIME_CLIENT_TEMP"
mv "$REALTIME_CLIENT_TEMP" /opt/myvps/realtime_client.py
rm -f "$REALTIME_CLIENT_HEADERS"
chmod 700 /opt/myvps/realtime_client.py

cat > /opt/myvps/run-agent.sh <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/myvps/agent.py
EOF
chmod 700 /opt/myvps/run-agent.sh

echo "[5/5] 注册并启动服务"
if [ "$INIT_SYS" = "openrc" ]; then
    cat > /etc/init.d/myvps-agent <<'EOF'
#!/sbin/openrc-run
description="MyVps Server Monitor Agent"
command="/opt/myvps/run-agent.sh"
command_background="yes"
pidfile="/run/myvps-agent.pid"
output_log="/var/log/myvps-agent.log"
error_log="/var/log/myvps-agent.log"
depend() { need net; }
EOF
    chmod +x /etc/init.d/myvps-agent
    rc-update add myvps-agent default
    rc-service myvps-agent start
else
    cat > /etc/systemd/system/myvps-agent.service <<'EOF'
[Unit]
Description=MyVps Server Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/myvps/run-agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable myvps-agent
    systemctl restart myvps-agent
fi

echo "=========================================="
echo " MyVps 监控 Agent 部署成功"
echo " 服务器 IP: ${VPS_IP}"
echo "=========================================="
