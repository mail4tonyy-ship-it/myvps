#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os
import platform
import subprocess
import time
import urllib.request

APP_DIR = "/opt/probe-panorama"
CONF_FILE = os.path.join(APP_DIR, "config.json")

with open(CONF_FILE, "r", encoding="utf-8") as config_file:
    CONF = json.load(config_file)

ORIGIN = CONF["origin"].rstrip("/")
VPS_IP = CONF["ip"]
TOKEN = CONF["token"]
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": TOKEN,
    "User-Agent": "Probe-Panorama-Agent/1.0"
}

last_net = None

def read_file(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read().strip()
    except Exception:
        return default

def run(command, timeout=4):
    try:
        return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, timeout=timeout, text=True).strip()
    except Exception:
        return ""

def post_json(path, payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(ORIGIN + path, data=body, headers=HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8") or "{}")

def get_json(path):
    req = urllib.request.Request(ORIGIN + path, headers=HEADERS, method="GET")
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8") or "{}")

def cpu_percent():
    def sample():
        parts = read_file("/proc/stat").splitlines()[0].split()[1:]
        vals = [int(v) for v in parts]
        idle = vals[3] + vals[4]
        total = sum(vals)
        return total, idle
    a_total, a_idle = sample()
    time.sleep(0.25)
    b_total, b_idle = sample()
    total = max(1, b_total - a_total)
    idle = max(0, b_idle - a_idle)
    return round((1 - idle / total) * 100, 1)

def mem_info():
    data = {}
    for line in read_file("/proc/meminfo").splitlines():
        key, value = line.split(":", 1)
        data[key] = int(value.strip().split()[0]) * 1024
    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    used = max(0, total - available)
    swap_total = data.get("SwapTotal", 0)
    swap_free = data.get("SwapFree", 0)
    return {
        "mem": round((used / total) * 100, 1) if total else 0,
        "ram_total": total,
        "ram_used": used,
        "swap_total": swap_total,
        "swap_used": max(0, swap_total - swap_free)
    }

def disk_info():
    st = os.statvfs("/")
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = max(0, total - free)
    return {
        "disk": round((used / total) * 100, 1) if total else 0,
        "disk_total": total,
        "disk_used": used
    }

def net_info():
    global last_net
    rx = tx = 0
    for line in read_file("/proc/net/dev").splitlines()[2:]:
        name, values = line.split(":", 1)
        if name.strip() == "lo":
            continue
        parts = values.split()
        rx += int(parts[0])
        tx += int(parts[8])
    now = time.time()
    if not last_net:
        last_net = (now, rx, tx)
        return {"net_rx": rx, "net_tx": tx, "net_in_speed": 0, "net_out_speed": 0}
    prev_time, prev_rx, prev_tx = last_net
    elapsed = max(1, now - prev_time)
    last_net = (now, rx, tx)
    return {
        "net_rx": rx,
        "net_tx": tx,
        "net_in_speed": max(0, int((rx - prev_rx) / elapsed)),
        "net_out_speed": max(0, int((tx - prev_tx) / elapsed))
    }

def conn_count(proto):
    path = "/proc/net/tcp" if proto == "tcp" else "/proc/net/udp"
    lines = read_file(path).splitlines()
    return max(0, len(lines) - 1)

def public_ips():
    ip_v4 = run("curl -4 -fsS --max-time 4 https://api.ipify.org") or VPS_IP
    ip_v6 = run("curl -6 -fsS --max-time 4 https://api64.ipify.org")
    return ip_v4, ip_v6

def uptime_text():
    seconds = int(float(read_file("/proc/uptime", "0").split()[0]))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}天 {hours}小时"
    return f"{hours}小时 {minutes}分钟"

def collect():
    ip_v4, ip_v6 = public_ips()
    mem = mem_info()
    disk = disk_info()
    net = net_info()
    load = read_file("/proc/loadavg", "0 0 0").split()[:3]
    os_name = read_file("/etc/os-release")
    pretty = "Linux"
    for line in os_name.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip('"')
            break
    boot_time = run("who -b | awk '{print $3\" \"$4}'") or ""
    virt = run("systemd-detect-virt 2>/dev/null || true") or "unknown"
    payload = {
        "ip": VPS_IP,
        "cpu": cpu_percent(),
        "load": " ".join(load),
        "uptime": uptime_text(),
        "os": pretty,
        "cpu_info": read_file("/proc/cpuinfo").split("model name", 1)[-1].split(":", 1)[-1].splitlines()[0].strip() if "model name" in read_file("/proc/cpuinfo") else platform.processor(),
        "arch": platform.machine(),
        "boot_time": boot_time,
        "processes": run("ps -e --no-headers | wc -l") or "0",
        "tcp_conn": conn_count("tcp"),
        "udp_conn": conn_count("udp"),
        "ip_v4": ip_v4,
        "ip_v6": ip_v6,
        "virt": virt,
        **mem,
        **disk,
        **net
    }
    return payload

def main():
    interval = 60
    while True:
        try:
            response = post_json("/api/report", collect())
            interval = int(response.get("interval") or interval)
        except Exception as exc:
            print("[probe-agent] report failed:", exc, flush=True)
            try:
                interval = int(get_json(f"/api/config?ip={VPS_IP}").get("interval") or interval)
            except Exception:
                pass
        time.sleep(max(15, min(interval, 300)))

if __name__ == "__main__":
    main()
