#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os
import platform
import socket
import ssl
import subprocess
import time
import urllib.request

APP_DIR = "/opt/probe-panorama"
CONF_FILE = os.path.join(APP_DIR, "config.json")
AGENT_VERSION = "1.3.0"

with open(CONF_FILE, "r", encoding="utf-8") as config_file:
    CONF = json.load(config_file)

ORIGIN = CONF["origin"].rstrip("/")
VPS_IP = CONF["ip"]
TOKEN = CONF["token"]
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": TOKEN,
    "User-Agent": f"Probe-Panorama-Agent/{AGENT_VERSION}"
}

last_net = None
runtime_config = {
    "ping_targets": "",
    "port_checks": "",
    "ssl_domains": ""
}

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

def ping_targets():
    result = {}
    targets = [item.strip() for item in runtime_config.get("ping_targets", "").split(",") if item.strip()][:8]
    for target in targets:
        output = run(f"ping -c 1 -W 2 {target}", timeout=4)
        marker = "time="
        if marker in output:
            value = output.split(marker, 1)[1].split()[0]
            result[target] = {"ok": True, "ms": float(value)}
        else:
            result[target] = {"ok": False}
    return result

def check_ports():
    result = {}
    items = [item.strip() for item in runtime_config.get("port_checks", "").replace("，", ",").split(",") if item.strip()][:20]
    host = "127.0.0.1"
    for item in items:
        target_host = host
        target_port = item
        if ":" in item:
            target_host, target_port = item.rsplit(":", 1)
        try:
            port = int(target_port)
            with socket.create_connection((target_host, port), timeout=2):
                result[item] = {"ok": True}
        except Exception:
            result[item] = {"ok": False}
    return result

def check_ssl_domains():
    result = {}
    domains = [item.strip() for item in runtime_config.get("ssl_domains", "").replace("，", ",").split(",") if item.strip()][:10]
    context = ssl.create_default_context()
    for domain in domains:
      try:
          with socket.create_connection((domain, 443), timeout=4) as sock:
              with context.wrap_socket(sock, server_hostname=domain) as ssock:
                  cert = ssock.getpeercert()
          expires = cert.get("notAfter", "")
          expires_ts = time.mktime(time.strptime(expires, "%b %d %H:%M:%S %Y %Z"))
          days_left = int((expires_ts - time.time()) / 86400)
          result[domain] = {"ok": True, "expires_at": int(expires_ts * 1000), "expires_date": time.strftime("%Y-%m-%d", time.gmtime(expires_ts)), "days_left": days_left}
      except Exception as exc:
          result[domain] = {"ok": False, "error": str(exc)[:120]}
    return result

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
        "agent_version": AGENT_VERSION,
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
        "ping_result": ping_targets(),
        "port_result": check_ports(),
        "ssl_result": check_ssl_domains(),
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
            runtime_config["ping_targets"] = response.get("ping_targets", runtime_config.get("ping_targets", ""))
            runtime_config["port_checks"] = response.get("port_checks", runtime_config.get("port_checks", ""))
            runtime_config["ssl_domains"] = response.get("ssl_domains", runtime_config.get("ssl_domains", ""))
        except Exception as exc:
            print("[probe-agent] report failed:", exc, flush=True)
            try:
                config = get_json(f"/api/config?ip={VPS_IP}")
                interval = int(config.get("interval") or interval)
                runtime_config["ping_targets"] = config.get("ping_targets", runtime_config.get("ping_targets", ""))
                runtime_config["port_checks"] = config.get("port_checks", runtime_config.get("port_checks", ""))
                runtime_config["ssl_domains"] = config.get("ssl_domains", runtime_config.get("ssl_domains", ""))
            except Exception:
                pass
        time.sleep(max(15, min(interval, 300)))

if __name__ == "__main__":
    main()
