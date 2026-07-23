# -*- coding: utf-8 -*-
import json
import hashlib
import hmac
import os
import platform
import py_compile
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime

try:
    from realtime_client import RealtimeChannel
except ImportError:
    class RealtimeChannel:
        def __init__(self, *args, **kwargs):
            self.connected = False
            self.enabled = False
            self.ever_connected = False
            self.last_disconnected = 0
            self.started_at = 0
        def start(self): pass
        def stop(self): pass
        def send(self, data, message_type="status"): return False

if sys.stdout.encoding != "UTF-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

CONF_FILE = "/opt/myvps/config.json"
AGENT_DIR = "/opt/myvps"

try:
    with open(CONF_FILE, "r", encoding="utf-8") as config_file:
        env = json.load(config_file)
except Exception:
    print("Failed to read config file.")
    raise SystemExit(1)

API_URL = env["api_url"].rstrip("/")
REPORT_URL = env["report_url"].rstrip("/")
BASE_URL = ""
VPS_IP = env["ip"]
TOKEN = env["token"]
REALTIME_URL = env.get("realtime_url", "")
HEADERS = {"Content-Type": "application/json", "Authorization": TOKEN, "User-Agent": "MyVps-Agent/1.0"}

global_interval = 90
fast_mode = False
prev_cpu_total = 0
prev_cpu_idle = 0
prev_rx = 0
prev_tx = 0
realtime_status_interval = 30
last_self_update = 0
heartbeat_wakeup = threading.Event()
config_wakeup = threading.Event()
SELF_UPDATE_INTERVAL = 21600

def require_https_url(value, name):
    parsed = urllib.parse.urlsplit(value or "")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError(f"{name} must be HTTPS without credentials or fragment")
    return value.rstrip("/")

API_URL = require_https_url(API_URL, "api_url")
REPORT_URL = require_https_url(REPORT_URL, "report_url")
base_parts = urllib.parse.urlsplit(API_URL)
BASE_URL = f"{base_parts.scheme}://{base_parts.netloc}"
if REALTIME_URL:
    REALTIME_URL = require_https_url(REALTIME_URL, "realtime_url")

def persist_agent_token(token):
    global TOKEN, HEADERS
    if not token or token == TOKEN:
        return
    updated = dict(env)
    updated["token"] = token
    temp_config = CONF_FILE + ".tmp"
    with open(temp_config, "w", encoding="utf-8") as config_file:
        json.dump(updated, config_file)
        config_file.flush()
        os.fsync(config_file.fileno())
    os.chmod(temp_config, 0o600)
    os.replace(temp_config, CONF_FILE)
    TOKEN = token
    HEADERS["Authorization"] = token
    print("[agent] migrated to server-specific token", flush=True)

def request_json(url, method="GET", payload=None, timeout=20):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def verify_component_manifest(component, file_path, headers):
    expected_sha = (headers.get("X-Agent-SHA256") or "").strip().lower()
    version = (headers.get("X-Agent-Manifest-Version") or "").strip()
    expected_length = (headers.get("X-Agent-Length") or "").strip()
    supplied_mac = (headers.get("X-Agent-MAC") or "").strip().lower()
    actual_length = str(os.path.getsize(file_path))
    actual_sha = file_sha256(file_path)
    manifest = f"v1\n{component}\n{expected_sha}\n{actual_length}\n"
    expected_mac = hmac.new(TOKEN.encode("utf-8"), manifest.encode("utf-8"), hashlib.sha256).hexdigest()
    return (
        version == "1"
        and expected_length == actual_length
        and expected_sha == actual_sha
        and supplied_mac
        and hmac.compare_digest(supplied_mac, expected_mac)
    )

def download_component(component, target_path):
    url = f"{BASE_URL}/api/agent_update?ip={urllib.parse.quote(VPS_IP)}&component={urllib.parse.quote(component)}"
    request = urllib.request.Request(url, headers={**HEADERS, "User-Agent": "MyVps-Agent-Updater/1.0"})
    temp_path = target_path + ".download"
    with urllib.request.urlopen(request, timeout=45) as response:
        with open(temp_path, "wb") as handle:
            handle.write(response.read())
        headers = response.headers
    if not verify_component_manifest(component, temp_path, headers):
        try:
            os.remove(temp_path)
        except Exception:
            pass
        raise RuntimeError(f"{component} manifest verification failed")
    py_compile.compile(temp_path, doraise=True)
    current_sha = file_sha256(target_path) if os.path.exists(target_path) else ""
    new_sha = file_sha256(temp_path)
    if current_sha == new_sha:
        os.remove(temp_path)
        return False
    os.chmod(temp_path, 0o700)
    os.replace(temp_path, target_path)
    return True

def maybe_self_update(force=False):
    global last_self_update
    now = time.time()
    if not force and now - last_self_update < SELF_UPDATE_INTERVAL:
        return False
    last_self_update = now
    changed = False
    try:
        changed = download_component("realtime-client", os.path.join(AGENT_DIR, "realtime_client.py")) or changed
        changed = download_component("agent", os.path.join(AGENT_DIR, "agent.py")) or changed
    except Exception as error:
        print(f"[agent] self update skipped: {error}", flush=True)
        return False
    if changed:
        print("[agent] updated components, restarting process", flush=True)
        os.execv(sys.executable, [sys.executable, os.path.join(AGENT_DIR, "agent.py")])
    return changed

def read_first_line(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.readline().strip()
    except Exception:
        return default

def cpu_percent():
    global prev_cpu_total, prev_cpu_idle
    line = read_first_line("/proc/stat")
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        return 0
    values = [int(x) for x in parts[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    if prev_cpu_total == 0:
        prev_cpu_total, prev_cpu_idle = total, idle
        return 0
    total_delta = total - prev_cpu_total
    idle_delta = idle - prev_cpu_idle
    prev_cpu_total, prev_cpu_idle = total, idle
    if total_delta <= 0:
        return 0
    return round(max(0, min(100, (1 - idle_delta / total_delta) * 100)), 2)

def mem_info():
    values = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0])
    except Exception:
        pass
    total = values.get("MemTotal", 0) // 1024
    available = values.get("MemAvailable", 0) // 1024
    used = max(0, total - available)
    swap_total = values.get("SwapTotal", 0) // 1024
    swap_free = values.get("SwapFree", 0) // 1024
    return {
        "mem": round((used / total) * 100, 2) if total else 0,
        "ram_total": total,
        "ram_used": used,
        "swap_total": swap_total,
        "swap_used": max(0, swap_total - swap_free),
    }

def disk_info():
    usage = os.statvfs("/")
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    used = max(0, total - free)
    return {
        "disk": round((used / total) * 100, 2) if total else 0,
        "disk_total": total // 1024 // 1024,
        "disk_used": used // 1024 // 1024,
    }

def net_totals():
    rx = 0
    tx = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle.readlines()[2:]:
                name, values = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                parts = values.split()
                rx += int(parts[0])
                tx += int(parts[8])
    except Exception:
        pass
    return rx, tx

def net_speeds(rx, tx):
    global prev_rx, prev_tx
    if prev_rx == 0 and prev_tx == 0:
        prev_rx, prev_tx = rx, tx
        return 0, 0
    in_speed = max(0, rx - prev_rx) / max(1, global_interval)
    out_speed = max(0, tx - prev_tx) / max(1, global_interval)
    prev_rx, prev_tx = rx, tx
    return round(in_speed, 2), round(out_speed, 2)

def count_connections():
    tcp = 0
    udp = 0
    for file_path, kind in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp")):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                count = max(0, len(handle.readlines()) - 1)
                if kind == "tcp":
                    tcp += count
                else:
                    udp += count
        except Exception:
            pass
    return tcp, udp

DEFAULT_PING_HOSTS = {
    "ct": "180.76.76.76",
    "cu": "119.29.29.29",
    "cm": "223.5.5.5",
    "bd": "www.bytedance.com",
}

def ping_ms(host):
    if not host:
        return 0
    try:
        output = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=4).stdout
        marker = "time="
        if marker in output:
            return int(float(output.split(marker, 1)[1].split()[0]))
    except Exception:
        pass
    return 0

def policy_ping_host(policy, key):
    host = (policy or {}).get(f"ping_{key}")
    if not host or host == "default":
        return DEFAULT_PING_HOSTS[key]
    return host

def uptime_text():
    try:
        seconds = int(float(read_first_line("/proc/uptime", "0").split()[0]))
    except Exception:
        seconds = 0
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    return f"{days}d {hours}h {minutes}m"

def collect_status(policy=None):
    rx, tx = net_totals()
    net_in_speed, net_out_speed = net_speeds(rx, tx)
    tcp_conn, udp_conn = count_connections()
    mem = mem_info()
    disk = disk_info()
    load_avg = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0
    boot_time = datetime.fromtimestamp(time.time() - float(read_first_line("/proc/uptime", "0").split()[0])).strftime("%Y-%m-%d %H:%M:%S")
    cpu_name = " ".join(platform.processor().split()) or read_first_line("/proc/cpuinfo").replace("model name", "").replace(":", "").strip()
    return {
        "ip": VPS_IP,
        "name": socket.gethostname(),
        "report_id": f"{VPS_IP}:{int(time.time() * 1000)}",
        "cpu": cpu_percent(),
        "load": f"{load_avg:.2f}",
        "uptime": uptime_text(),
        "net_rx": rx,
        "net_tx": tx,
        "net_in_speed": net_in_speed,
        "net_out_speed": net_out_speed,
        "tcp_conn": tcp_conn,
        "udp_conn": udp_conn,
        "node_traffic": [],
        "argo_urls": [],
        "os": platform.platform(),
        "arch": platform.machine(),
        "virt": "",
        "cpu_info": cpu_name[:160],
        "boot_time": boot_time,
        "processes": len(os.listdir("/proc")) if os.path.isdir("/proc") else 0,
        "ping_ct": ping_ms(policy_ping_host(policy, "ct")),
        "ping_cu": ping_ms(policy_ping_host(policy, "cu")),
        "ping_cm": ping_ms(policy_ping_host(policy, "cm")),
        "ping_bd": ping_ms(policy_ping_host(policy, "bd")),
        **mem,
        **disk,
    }

def report_status(policy=None, force_http=False, allow_http=True):
    global global_interval, fast_mode, REALTIME_URL
    if policy is None:
        policy = {}
    payload = collect_status(policy)
    sent_ws = False
    if not force_http and realtime_channel and realtime_channel.connected:
        sent_ws = realtime_channel.send(payload, "status")
    if allow_http and (force_http or not sent_ws):
        response = request_json(REPORT_URL, method="POST", payload=payload, timeout=30)
        global_interval = int(response.get("interval", global_interval) or global_interval)
        fast_mode = bool(response.get("fast_mode", False))
        for key in ("ping_ct", "ping_cu", "ping_cm", "ping_bd", "report_interval"):
            if response.get(key) is not None:
                policy[key] = response[key]
        if response.get("realtime_url") and not REALTIME_URL:
            REALTIME_URL = require_https_url(response["realtime_url"], "realtime_url")
    return True

def fetch_policy():
    global REALTIME_URL
    try:
        data = request_json(f"{API_URL}?ip={urllib.parse.quote(VPS_IP)}", timeout=20)
        if data.get("agent_token"):
            persist_agent_token(data["agent_token"])
        if data.get("realtime_url"):
            REALTIME_URL = require_https_url(data["realtime_url"], "realtime_url")
        return data
    except Exception as error:
        print(f"[agent] config fetch failed: {error}", flush=True)
        return {}

def on_realtime_message(message):
    global realtime_status_interval
    if message.get("type") == "status.interval":
        realtime_status_interval = max(5, min(600, int(message.get("seconds", 30))))
        heartbeat_wakeup.set()
    if message.get("type") in {"config.refresh", "transport.connected", "transport.disconnected"}:
        config_wakeup.set()
        heartbeat_wakeup.set()

if __name__ == "__main__":
    policy = fetch_policy()
    maybe_self_update(force=True)
    realtime_channel = RealtimeChannel(REALTIME_URL, VPS_IP, TOKEN, "core", on_realtime_message)
    realtime_channel.start()

    while True:
        started = time.monotonic()
        try:
            maybe_self_update()
            websocket_online = bool(realtime_channel and realtime_channel.connected)
            fallback_ready = not realtime_channel or not realtime_channel.enabled or time.time() - (realtime_channel.last_disconnected or realtime_channel.started_at) >= 30
            report_status(policy, force_http=not websocket_online, allow_http=websocket_online or fallback_ready)
            if config_wakeup.is_set():
                policy = fetch_policy()
                config_wakeup.clear()
        except Exception as error:
            print(f"[agent] loop error: {error}", flush=True)
        elapsed = time.monotonic() - started
        interval = realtime_status_interval if realtime_channel and realtime_channel.connected else (30 if fast_mode else global_interval)
        heartbeat_wakeup.wait(timeout=max(1, interval - min(interval - 1, elapsed)))
        heartbeat_wakeup.clear()
