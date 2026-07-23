#!/usr/bin/env python3
import json
import os
import platform
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request

AGENT_VERSION = "2026.07.23.1"
API_URL = os.environ.get("API_URL", "").rstrip("/")
VPS_IP = os.environ.get("VPS_IP", "")
TOKEN = os.environ.get("TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

last_net_rx = None
last_net_tx = None
last_net_ts = None
interval = 15
ping_targets = {
    "ping_ct": "223.5.5.5",
    "ping_cu": "119.29.29.29",
    "ping_cm": "120.196.165.24",
    "ping_bd": "180.76.76.76",
    "ping_v4": "1.1.1.1",
}


def read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return default


def run(command, timeout=3):
    try:
        return subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout=timeout, text=True).strip()
    except Exception:
        return ""


def parse_meminfo():
    data = {}
    for line in read("/proc/meminfo").splitlines():
        parts = line.replace(":", "").split()
        if len(parts) >= 2:
            data[parts[0]] = int(parts[1]) * 1024
    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    swap_total = data.get("SwapTotal", 0)
    swap_free = data.get("SwapFree", 0)
    used = max(0, total - available)
    return total, used, swap_total, max(0, swap_total - swap_free)


def cpu_percent():
    def sample():
        fields = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
        return idle, sum(fields)
    idle1, total1 = sample()
    time.sleep(0.25)
    idle2, total2 = sample()
    total = total2 - total1
    idle = idle2 - idle1
    return round(max(0, min(100, 100 * (1 - idle / total))), 2) if total else 0


def disk_usage():
    st = os.statvfs("/")
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = max(0, total - free)
    percent = round(used * 100 / total, 2) if total else 0
    return total, used, percent


def network_totals():
    rx = 0
    tx = 0
    for line in read("/proc/net/dev").splitlines()[2:]:
        iface, raw = line.split(":", 1)
        iface = iface.strip()
        if iface == "lo" or iface.startswith(("docker", "veth", "br-")):
            continue
        fields = raw.split()
        rx += int(fields[0])
        tx += int(fields[8])
    return rx, tx


def net_speed(rx, tx):
    global last_net_rx, last_net_tx, last_net_ts
    now = time.time()
    if last_net_rx is None:
        last_net_rx, last_net_tx, last_net_ts = rx, tx, now
        return 0, 0
    elapsed = max(1, now - last_net_ts)
    speed_in = max(0, (rx - last_net_rx) / elapsed)
    speed_out = max(0, (tx - last_net_tx) / elapsed)
    last_net_rx, last_net_tx, last_net_ts = rx, tx, now
    return round(speed_in, 2), round(speed_out, 2)


def conn_count(kind):
    path = "/proc/net/tcp" if kind == "tcp" else "/proc/net/udp"
    total = max(0, len(read(path).splitlines()) - 1)
    if os.path.exists(path + "6"):
        total += max(0, len(read(path + "6").splitlines()) - 1)
    return total


def ping_ms(target):
    if not target or target == "default":
        return 0
    out = run(["ping", "-c", "1", "-W", "2", target], timeout=3)
    match = re.search(r"time[=<]([0-9.]+)", out)
    return int(float(match.group(1))) if match else 0


def ping4_ms(target):
    if not target or target == "default":
        return 0
    out = run(["ping", "-4", "-c", "1", "-W", "2", target], timeout=3)
    match = re.search(r"time[=<]([0-9.]+)", out)
    return int(float(match.group(1))) if match else 0


def ip_versions():
    ip4 = run(["sh", "-c", "ip -4 route get 1.1.1.1 | awk '{print $7; exit}'"])
    ip6 = run(["sh", "-c", "ip -6 route get 2606:4700:4700::1111 | awk '{print $9; exit}'"])
    return ip4, ip6


def os_name():
    os_release = read("/etc/os-release")
    match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', os_release, re.M)
    return match.group(1) if match else platform.platform()


def boot_time():
    stat = read("/proc/stat")
    match = re.search(r"^btime\s+(\d+)", stat, re.M)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(match.group(1)))) if match else ""


def collect():
    ram_total, ram_used, swap_total, swap_used = parse_meminfo()
    disk_total, disk_used, disk_percent = disk_usage()
    rx, tx = network_totals()
    speed_in, speed_out = net_speed(rx, tx)
    ip4, ip6 = ip_versions()
    uptime_seconds = int(float(read("/proc/uptime", "0").split()[0]))
    cpu_info = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            cpu_info = line.split(":", 1)[1].strip()
            break
    load = " ".join(read("/proc/loadavg", "0 0 0").split()[:3])
    return {
        "ip": VPS_IP,
        "report_id": f"{VPS_IP}:{time.time_ns()}",
        "agent_version": AGENT_VERSION,
        "cpu": cpu_percent(),
        "mem": round(ram_used * 100 / ram_total, 2) if ram_total else 0,
        "disk": disk_percent,
        "load": load,
        "uptime": str(uptime_seconds),
        "os": os_name(),
        "cpu_info": cpu_info,
        "arch": platform.machine(),
        "virt": run(["systemd-detect-virt"], timeout=1) or "",
        "boot_time": boot_time(),
        "ram_total": ram_total,
        "ram_used": ram_used,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "processes": len([p for p in os.listdir("/proc") if p.isdigit()]),
        "tcp_conn": conn_count("tcp"),
        "udp_conn": conn_count("udp"),
        "net_rx": rx,
        "net_tx": tx,
        "net_in_speed": speed_in,
        "net_out_speed": speed_out,
        "ping_ct": ping_ms(ping_targets["ping_ct"]),
        "ping_cu": ping_ms(ping_targets["ping_cu"]),
        "ping_cm": ping_ms(ping_targets["ping_cm"]),
        "ping_bd": ping_ms(ping_targets["ping_bd"]),
        "ping_v4": ping4_ms(ping_targets["ping_v4"]),
        "ip_v4": ip4,
        "ip_v6": ip6,
    }


def post(path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{API_URL}{path}", data=body, headers=HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=12) as response:
        return json.loads(response.read().decode() or "{}")


def main():
    global interval, ping_targets
    if not API_URL or not VPS_IP or not TOKEN:
        raise SystemExit("API_URL, VPS_IP and TOKEN are required")
    socket.setdefaulttimeout(12)
    while True:
        started = time.time()
        try:
            result = post("/api/report", collect())
            interval = int(result.get("interval") or interval)
            for key in ping_targets:
                if result.get(key):
                    ping_targets[key] = result[key]
            print(f"[panorama-probe] report ok, next={interval}s", flush=True)
        except urllib.error.HTTPError as error:
            print(f"[panorama-probe] http error {error.code}: {error.read().decode(errors='ignore')}", flush=True)
        except Exception as error:
            print(f"[panorama-probe] report failed: {error}", flush=True)
        time.sleep(max(5, interval - int(time.time() - started)))


if __name__ == "__main__":
    main()
