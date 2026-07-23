#!/bin/sh
set -eu

ENV_FILE="/etc/panorama-probe/env"
AGENT_PATH="/opt/panorama-probe/agent.py"

[ -f "$ENV_FILE" ] || { echo "未找到 $ENV_FILE，请先安装 Agent。"; exit 1; }
. "$ENV_FILE"

[ -n "${API_URL:-}" ] || { echo "缺少 API_URL"; exit 1; }

echo "==> 下载最新服务器全景探针 Agent"
mkdir -p /opt/panorama-probe
curl -fsSL "$API_URL/api/agent/script" -o "$AGENT_PATH.tmp"
python3 -m py_compile "$AGENT_PATH.tmp"
mv "$AGENT_PATH.tmp" "$AGENT_PATH"
chmod +x "$AGENT_PATH"

echo "==> 重启 Agent 服务"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl restart panorama-probe
  systemctl status panorama-probe --no-pager || true
elif command -v rc-service >/dev/null 2>&1; then
  rc-service panorama-probe restart
else
  echo "未检测到 systemd/OpenRC，请手动重启 Agent 进程。"
fi

echo "==> Agent 已升级到最新版本"
