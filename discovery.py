#!/usr/bin/env python3

# ==========================================
# Network Asset Monitor - discovery.py
# Version: v2.4.3
# ==========================================
#
# New in v2.4.3:
# - Much stricter verification logic
# - Strict mode keeps only strongly verified devices
# - Better handling for hotel / guest Wi-Fi false positives
#
# ==========================================

import csv
import html
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple


DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,81,88,110,111,135,137,138,139,143,161,389,443,445,"
    "465,500,514,515,548,554,587,631,902,993,995,1025,1433,1723,1883,2049,"
    "2375,2376,3306,3389,5353,5432,5672,5900,5985,5986,6379,7001,8000,8080,"
    "8081,8443,8888,9000,9100,10000,27017"
)

JSON_OUTPUT = "scan_results.json"
CSV_OUTPUT = "scan_results.csv"
BASELINE_FILE = "baseline.json"
EVENTS_FILE = "events.jsonl"
LOG_FILE = "monitor.log"
HTML_REPORT = "report.html"

DEFAULT_MONITOR_INTERVAL = 300


# ==========================================
# Logging
# ==========================================

def setup_logging() -> None:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))


# ==========================================
# Helpers
# ==========================================

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_command(command: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out: {' '.join(command)}"
    except Exception as exc:
        return 1, "", str(exc)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_lower(value: Optional[str]) -> str:
    return value.lower() if isinstance(value, str) else ""


def html_escape(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def ip_sort_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def looks_like_meaningful_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    h = hostname.strip().lower()

    if h == "":
        return False

    # Ignore plain IP-like values
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h):
        return False

    # Must contain at least one letter to count as meaningful
    if not re.search(r"[a-z]", h):
        return False

    return True


# ==========================================
# Local network detection
# ==========================================

def get_local_ip() -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return None


def get_default_gateway_linux() -> Optional[str]:
    if not os.path.exists("/proc/net/route"):
        return None

    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    gateway_hex = fields[2]
                    gateway = socket.inet_ntoa(bytes.fromhex(gateway_hex)[::-1])
                    return gateway
    except Exception:
        return None

    return None


def get_default_gateway() -> Optional[str]:
    system = platform.system().lower()

    if system == "linux":
        gw = get_default_gateway_linux()
        if gw:
            return gw

    if command_exists("ip"):
        code, out, _ = run_command(["ip", "route"])
        if code == 0:
            for line in out.splitlines():
                if line.startswith("default via "):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]

    if command_exists("route"):
        code, out, _ = run_command(["route", "-n"])
        if code == 0:
            for line in out.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]

    return None


def get_interface_network_from_ip(local_ip: str) -> Optional[str]:
    if not command_exists("ip"):
        return None

    code, out, _ = run_command(["ip", "-o", "-f", "inet", "addr", "show"], timeout=30)
    if code != 0:
        return None

    for line in out.splitlines():
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+\/\d+)", line)
        if not match:
            continue

        cidr = match.group(1)
        try:
            iface_ip = cidr.split("/")[0]
            if iface_ip == local_ip:
                network = ipaddress.ip_network(cidr, strict=False)
                return str(network)
        except Exception:
            continue

    return None


def get_reasonable_scan_network(local_ip: str) -> str:
    detected = get_interface_network_from_ip(local_ip)
    if not detected:
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))

    try:
        net = ipaddress.ip_network(detected, strict=False)
        if net.prefixlen < 24:
            smaller = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(smaller)
        return str(net)
    except Exception:
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))


def resolve_scan_network(user_network: Optional[str] = None) -> Tuple[str, Optional[str], Optional[str]]:
    local_ip = get_local_ip()
    gateway = get_default_gateway()

    if user_network:
        return user_network, local_ip, gateway

    if local_ip:
        return get_reasonable_scan_network(local_ip), local_ip, gateway

    return "192.168.1.0/24", None, gateway


# ==========================================
# Nmap parsing
# ==========================================

def parse_nmap_grepable_host_discovery(output: str) -> List[str]:
    hosts = []

    for line in output.splitlines():
        if not line.startswith("Host:"):
            continue
        if "Status: Up" not in line:
            continue

        match = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            hosts.append(match.group(1))

    return hosts


def parse_nmap_service_scan(output: str) -> Dict[str, Dict]:
    hosts: Dict[str, Dict] = {}
    current_ip = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()

        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            target = host_match.group(1).strip()

            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", target)
            if ip_match:
                current_ip = ip_match.group(1)
                hostname = target.replace(f"({current_ip})", "").strip()
            else:
                ip_only = re.match(r"(\d+\.\d+\.\d+\.\d+)", target)
                if ip_only:
                    current_ip = ip_only.group(1)
                    hostname = ""
                else:
                    current_ip = None
                    hostname = ""

            if current_ip:
                hosts[current_ip] = {
                    "ip": current_ip,
                    "hostname": hostname,
                    "state": "up",
                    "mac": "",
                    "vendor": "",
                    "latency": "",
                    "os_guess": "Unknown",
                    "ports": [],
                    "banners": [],
                    "raw_lines": [],
                }
            continue

        if current_ip is None:
            continue

        hosts[current_ip]["raw_lines"].append(line)

        latency_match = re.search(r"Host is up \((.*?) latency\)", line)
        if latency_match:
            hosts[current_ip]["latency"] = latency_match.group(1)

        mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?", line)
        if mac_match:
            hosts[current_ip]["mac"] = mac_match.group(1)
            hosts[current_ip]["vendor"] = mac_match.group(2) if mac_match.group(2) else ""

        os_match = re.search(r"Aggressive OS guesses:\s*(.+)", line)
        if os_match:
            hosts[current_ip]["os_guess"] = os_match.group(1).strip()
            continue

        os_running_match = re.search(r"Running:\s*(.+)", line)
        if os_running_match and hosts[current_ip]["os_guess"] == "Unknown":
            hosts[current_ip]["os_guess"] = os_running_match.group(1).strip()

        port_match = re.match(
            r"(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)(?:\s+(.*))?",
            line.strip()
        )
        if port_match:
            port = int(port_match.group(1))
            proto = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            extra = port_match.group(5).strip() if port_match.group(5) else ""

            port_record = {
                "port": port,
                "protocol": proto,
                "state": state,
                "service": service,
                "banner": extra
            }
            hosts[current_ip]["ports"].append(port_record)

            if extra:
                hosts[current_ip]["banners"].append(f"{port}:{extra}")

    return hosts


# ==========================================
# Host filtering
# ==========================================

def filter_hosts_to_network(hosts: List[str], network_cidr: str) -> List[str]:
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        valid_hosts = set(str(h) for h in network.hosts())
        filtered = [ip for ip in hosts if ip in valid_hosts]
        return sorted(set(filtered), key=ip_sort_key)
    except Exception:
        return sorted(set(hosts), key=ip_sort_key)


# ==========================================
# Scanning
# ==========================================

def discover_hosts(network: str) -> List[str]:
    if not command_exists("nmap"):
        raise RuntimeError("nmap is not installed. Please install nmap first.")

    command = ["nmap", "-sn", network, "-oG", "-"]
    code, out, err = run_command(command, timeout=180)

    if code != 0:
        raise RuntimeError(f"Host discovery failed: {err.strip()}")

    hosts = parse_nmap_grepable_host_discovery(out)
    hosts = filter_hosts_to_network(hosts, network)
    return hosts


def service_scan(hosts: List[str]) -> Dict[str, Dict]:
    if not hosts:
        return {}

    command = [
        "nmap",
        "-Pn",
        "-n",
        "-O",
        "-sV",
        "--version-light",
        "-T4",
        "-p",
        DEFAULT_SCAN_PORTS,
        *hosts
    ]

    code, out, err = run_command(command, timeout=900)

    if code != 0 and not out.strip():
        raise RuntimeError(f"Service scan failed: {err.strip()}")

    return parse_nmap_service_scan(out)


# ==========================================
# Fingerprinting helpers
# ==========================================

def open_ports_list(device: Dict) -> List[int]:
    return sorted([
        p["port"]
        for p in device.get("ports", [])
        if p.get("state") == "open"
    ])


def port_summary(device: Dict) -> str:
    parts = []
    for p in sorted(device.get("ports", []), key=lambda x: x["port"]):
        if p.get("state") == "open":
            parts.append(f'{p["port"]}({p.get("service", "unknown")})')
    return ", ".join(parts) if parts else "None"


def banners_summary(device: Dict) -> str:
    banners = device.get("banners", [])
    return " | ".join(banners) if banners else "None"


def detect_role(ip: str, local_ip: Optional[str], gateway: Optional[str]) -> str:
    if local_ip and ip == local_ip:
        return "Local Host"
    if gateway and ip == gateway:
        return "Gateway"
    return "Device"


def guess_os_from_ports_and_banners(device: Dict) -> str:
    os_guess = safe_lower(device.get("os_guess", ""))
    hostname = safe_lower(device.get("hostname", ""))
    banners = safe_lower(" ".join(device.get("banners", [])))
    ports = set(open_ports_list(device))

    if "windows" in os_guess or 3389 in ports or 5985 in ports or 5986 in ports:
        return "Windows"

    if "linux" in os_guess or "unix" in os_guess:
        return "Linux"

    if 445 in ports and 139 in ports:
        return "Windows"

    if 22 in ports and (2049 in ports or 111 in ports):
        return "Linux"

    if any(word in hostname for word in ["ubuntu", "debian", "centos", "fedora", "linux"]):
        return "Linux"

    if any(word in hostname for word in ["win", "windows"]):
        return "Windows"

    if "microsoft" in banners:
        return "Windows"

    if "openssh" in banners:
        return "Linux"

    return "Unknown"


def classify_device_type(device: Dict, role: str) -> str:
    hostname = safe_lower(device.get("hostname", ""))
    vendor = safe_lower(device.get("vendor", ""))
    os_guess = safe_lower(device.get("os_guess", ""))
    banners = safe_lower(" ".join(device.get("banners", [])))
    ports = set(open_ports_list(device))

    if role == "Gateway":
        return "Gateway / Router"

    if (
        53 in ports or 161 in ports or 500 in ports or 1723 in ports
        or any(k in hostname for k in ["router", "gateway", "ap", "switch", "firewall"])
        or any(k in banners for k in ["router", "mikrotik", "ubiquiti", "openwrt", "dd-wrt", "cisco ios", "junos"])
        or any(k in vendor for k in ["cisco", "juniper", "ubiquiti", "mikrotik", "aruba", "tp-link", "netgear", "asus", "linksys"])
    ):
        return "Router / Network Device"

    if (
        9100 in ports or 515 in ports or 631 in ports
        or any(k in hostname for k in ["printer", "print", "xerox", "epson", "brother", "canon"])
        or any(k in banners for k in ["jetdirect", "ipp", "printer", "cups"])
        or any(k in vendor for k in ["hewlett", "xerox", "epson", "brother", "canon", "lexmark", "ricoh", "kyocera"])
    ):
        return "Printer"

    if (
        (445 in ports and 139 in ports)
        or 2049 in ports
        or 548 in ports
        or any(k in hostname for k in ["nas", "synology", "qnap", "storage"])
        or any(k in banners for k in ["samba", "netbios", "afp", "nfs", "synology", "qnap"])
        or any(k in vendor for k in ["synology", "qnap", "western digital", "wd"])
    ):
        return "NAS / File Server"

    if (
        554 in ports
        or any(k in hostname for k in ["cam", "camera", "ipcam", "nvr", "dvr"])
        or any(k in banners for k in ["rtsp", "onvif", "ip camera", "network camera", "dahua", "hikvision", "axis"])
        or any(k in vendor for k in ["hikvision", "dahua", "axis", "reolink", "amcrest", "foscam"])
    ):
        return "Camera / Surveillance"

    if (
        "windows" in os_guess
        or 3389 in ports
        or 5985 in ports
        or 5986 in ports
        or (445 in ports and 135 in ports)
    ):
        return "Windows Host"

    if (
        "linux" in os_guess
        or "unix" in os_guess
        or 22 in ports
        or 111 in ports
        or 2049 in ports
    ):
        return "Linux Host"

    if (
        1883 in ports
        or 5353 in ports
        or any(k in hostname for k in ["iot", "sensor", "plug", "light", "thermo", "echo", "roku", "tv"])
        or any(k in banners for k in ["mqtt", "upnp", "chromecast", "smart tv", "iot"])
        or any(k in vendor for k in ["amazon", "google", "roku", "tuya", "espressif", "sonos", "ring"])
    ):
        return "IoT Device"

    return "Unknown Device"


def calculate_risk(device: Dict, role: str, device_type: str) -> Tuple[str, List[str]]:
    ports = set(open_ports_list(device))
    flags = []

    if 23 in ports:
        flags.append("Telnet exposed")
    if 21 in ports:
        flags.append("FTP exposed")
    if 445 in ports:
        flags.append("SMB exposed")
    if 3389 in ports:
        flags.append("RDP exposed")
    if 5900 in ports:
        flags.append("VNC exposed")
    if 80 in ports and 443 not in ports:
        flags.append("HTTP without HTTPS")
    if 2375 in ports:
        flags.append("Docker remote API exposed")
    if 3306 in ports or 5432 in ports or 27017 in ports:
        flags.append("Database port exposed")
    if 9100 in ports:
        flags.append("Raw printer port open")
    if 554 in ports:
        flags.append("RTSP camera stream exposed")
    if 161 in ports:
        flags.append("SNMP exposed")

    if device_type == "Camera / Surveillance" and 554 in ports:
        flags.append("Surveillance device reachable on network")

    if device_type == "NAS / File Server" and (445 in ports or 2049 in ports):
        flags.append("File sharing service exposed")

    if role == "Gateway" and 80 in ports:
        flags.append("Router web management exposed")

    if any(flag in flags for flag in [
        "Telnet exposed",
        "Docker remote API exposed",
        "Database port exposed",
        "RDP exposed",
        "VNC exposed"
    ]):
        risk = "High"
    elif len(flags) >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not flags:
        flags = ["No obvious issues"]

    return risk, flags


# ==========================================
# Verification logic
# ==========================================

def calculate_confidence(raw: Dict, role: str) -> Tuple[int, str, List[str], int]:
    score = 0
    reasons = []
    hard_evidence = 0

    ports = open_ports_list(raw)
    hostname = raw.get("hostname", "").strip()
    mac = raw.get("mac", "").strip()
    vendor = raw.get("vendor", "").strip()
    banners = raw.get("banners", [])
    os_guess = raw.get("os_guess", "").strip()

    if role == "Local Host":
        score = 100
        reasons.append("Matched local host IP")
        return score, "Verified", reasons, 99

    if role == "Gateway":
        score = 100
        reasons.append("Matched default gateway")
        return score, "Verified", reasons, 99

    if ports:
        score += 45
        hard_evidence += 1
        reasons.append("Open ports detected")

        if len(ports) >= 2:
            score += 10
            reasons.append("Multiple open ports detected")

    if mac:
        score += 25
        hard_evidence += 1
        reasons.append("MAC address detected")

    if vendor:
        score += 10
        hard_evidence += 1
        reasons.append("Vendor detected")

    if banners:
        score += 20
        hard_evidence += 1
        reasons.append("Service banners detected")

    if os_guess and os_guess.lower() != "unknown":
        score += 10
        hard_evidence += 1
        reasons.append("OS fingerprint detected")

    if looks_like_meaningful_hostname(hostname):
        score += 5
        reasons.append("Meaningful hostname resolved")

    if hard_evidence >= 2 and score >= 60:
        status = "Verified"
    elif hard_evidence >= 1 and score >= 25:
        status = "Likely Real"
    else:
        status = "Unverified"

    return score, status, reasons, hard_evidence


def should_keep_device(device: Dict, strict: bool = False) -> bool:
    if not strict:
        return True

    if device.get("role") in ["Local Host", "Gateway"]:
        return True

    return device.get("verification_status") == "Verified"


# ==========================================
# Build final record
# ==========================================

def build_device_record(ip: str, raw: Dict, local_ip: Optional[str], gateway: Optional[str]) -> Dict:
    hostname = raw.get("hostname") or get_hostname(ip)
    raw["hostname"] = hostname

    role = detect_role(ip, local_ip, gateway)
    guessed_os = guess_os_from_ports_and_banners(raw)
    device_type = classify_device_type(raw, role)
    risk_level, risk_flags = calculate_risk(raw, role, device_type)
    confidence_score, verification_status, confidence_reasons, hard_evidence_count = calculate_confidence(raw, role)

    return {
        "ip": ip,
        "hostname": hostname,
        "role": role,
        "device_type": device_type,
        "os_guess": guessed_os,
        "state": raw.get("state", "up"),
        "mac": raw.get("mac", ""),
        "vendor": raw.get("vendor", ""),
        "latency": raw.get("latency", ""),
        "open_ports": open_ports_list(raw),
        "open_ports_summary": port_summary(raw),
        "banners": raw.get("banners", []),
        "banners_summary": banners_summary(raw),
        "risk_level": risk_level,
        "security_flags": risk_flags,
        "confidence_score": confidence_score,
        "verification_status": verification_status,
        "confidence_reasons": confidence_reasons,
        "hard_evidence_count": hard_evidence_count,
        "last_seen": now_str(),
    }


# ==========================================
# Baseline / snapshots
# ==========================================

def load_json_file(path: str, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def normalize_baseline_data(raw_data) -> List[Dict]:
    if isinstance(raw_data, list):
        return [d for d in raw_data if isinstance(d, dict) and "ip" in d]

    if isinstance(raw_data, dict):
        devices = raw_data.get("devices")
        if isinstance(devices, list):
            return [d for d in devices if isinstance(d, dict) and "ip" in d]

    return []


def append_event(event_type: str, message: str, data: Optional[Dict] = None) -> None:
    entry = {
        "timestamp": now_str(),
        "event_type": event_type,
        "message": message,
        "data": data or {}
    }

    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def devices_to_map(devices: List[Dict]) -> Dict[str, Dict]:
    return {
        d["ip"]: d
        for d in devices
        if isinstance(d, dict) and "ip" in d
    }


def compare_snapshots(previous: List[Dict], current: List[Dict]) -> Dict[str, List[Dict]]:
    previous_map = devices_to_map(previous)
    current_map = devices_to_map(current)

    added = []
    removed = []
    changed = []

    for ip, current_device in current_map.items():
        if ip not in previous_map:
            added.append(current_device)
        else:
            prev = previous_map[ip]
            diff_fields = {}

            for field in [
                "device_type",
                "os_guess",
                "open_ports",
                "risk_level",
                "security_flags",
                "hostname",
                "confidence_score",
                "verification_status",
                "hard_evidence_count"
            ]:
                if prev.get(field) != current_device.get(field):
                    diff_fields[field] = {
                        "old": prev.get(field),
                        "new": current_device.get(field)
                    }

            if diff_fields:
                changed.append({
                    "ip": ip,
                    "changes": diff_fields,
                    "current": current_device
                })

    for ip, previous_device in previous_map.items():
        if ip not in current_map:
            removed.append(previous_device)

    return {
        "added": sorted(added, key=lambda x: ip_sort_key(x["ip"])),
        "removed": sorted(removed, key=lambda x: ip_sort_key(x["ip"])),
        "changed": sorted(changed, key=lambda x: ip_sort_key(x["ip"])),
    }


def update_baseline(current_devices: List[Dict]) -> None:
    save_json_file(BASELINE_FILE, current_devices)


# ==========================================
# Output
# ==========================================

def save_csv(devices: List[Dict], path: str = CSV_OUTPUT) -> None:
    fieldnames = [
        "ip",
        "hostname",
        "role",
        "device_type",
        "os_guess",
        "state",
        "mac",
        "vendor",
        "latency",
        "open_ports_summary",
        "banners_summary",
        "risk_level",
        "security_flags",
        "confidence_score",
        "verification_status",
        "hard_evidence_count",
        "confidence_reasons",
        "last_seen",
    ]

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for device in devices:
            row = {
                "ip": device.get("ip", ""),
                "hostname": device.get("hostname", ""),
                "role": device.get("role", ""),
                "device_type": device.get("device_type", ""),
                "os_guess": device.get("os_guess", ""),
                "state": device.get("state", ""),
                "mac": device.get("mac", ""),
                "vendor": device.get("vendor", ""),
                "latency": device.get("latency", ""),
                "open_ports_summary": device.get("open_ports_summary", ""),
                "banners_summary": device.get("banners_summary", ""),
                "risk_level": device.get("risk_level", ""),
                "security_flags": " | ".join(device.get("security_flags", [])),
                "confidence_score": device.get("confidence_score", 0),
                "verification_status": device.get("verification_status", ""),
                "hard_evidence_count": device.get("hard_evidence_count", 0),
                "confidence_reasons": " | ".join(device.get("confidence_reasons", [])),
                "last_seen": device.get("last_seen", ""),
            }
            writer.writerow(row)


def save_scan_json(scan_metadata: Dict, devices: List[Dict], path: str = JSON_OUTPUT) -> None:
    payload = {
        "scan_metadata": scan_metadata,
        "devices": devices
    }
    save_json_file(path, payload)


# ==========================================
# HTML report
# ==========================================

def risk_badge_class(risk: str) -> str:
    return {
        "High": "risk-high",
        "Medium": "risk-medium",
        "Low": "risk-low",
    }.get(risk, "risk-low")


def verification_badge_class(status: str) -> str:
    return {
        "Verified": "verify-high",
        "Likely Real": "verify-medium",
        "Unverified": "verify-low",
    }.get(status, "verify-low")


def generate_summary_counts(devices: List[Dict]) -> Dict[str, Dict]:
    risk_counts = Counter(d.get("risk_level", "Low") for d in devices)
    type_counts = Counter(d.get("device_type", "Unknown Device") for d in devices)
    verification_counts = Counter(d.get("verification_status", "Unverified") for d in devices)

    return {
        "risk_counts": dict(risk_counts),
        "type_counts": dict(type_counts),
        "verification_counts": dict(verification_counts),
        "total_devices": len(devices)
    }


def generate_html_report(scan_metadata: Dict, devices: List[Dict], changes: Dict, path: str = HTML_REPORT) -> None:
    summary = generate_summary_counts(devices)

    cards = f"""
    <div class="cards">
        <div class="card">
            <div class="card-title">Total Devices</div>
            <div class="card-value">{summary['total_devices']}</div>
        </div>
        <div class="card">
            <div class="card-title">Verified</div>
            <div class="card-value">{summary['verification_counts'].get('Verified', 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Likely Real</div>
            <div class="card-value">{summary['verification_counts'].get('Likely Real', 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Unverified</div>
            <div class="card-value">{summary['verification_counts'].get('Unverified', 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">High Risk</div>
            <div class="card-value">{summary['risk_counts'].get('High', 0)}</div>
        </div>
    </div>
    """

    type_rows = ""
    for device_type, count in sorted(summary["type_counts"].items(), key=lambda x: (-x[1], x[0])):
        type_rows += f"""
        <tr>
            <td>{html_escape(device_type)}</td>
            <td>{count}</td>
        </tr>
        """

    device_rows = ""
    sort_rank = {"High": 3, "Medium": 2, "Low": 1}
    verify_rank = {"Verified": 3, "Likely Real": 2, "Unverified": 1}

    for d in sorted(
        devices,
        key=lambda x: (
            -verify_rank.get(x.get("verification_status", "Unverified"), 1),
            -sort_rank.get(x.get("risk_level", "Low"), 1),
            -int(x.get("confidence_score", 0)),
            ip_sort_key(x.get("ip", ""))
        )
    ):
        flags = "<br>".join(html_escape(flag) for flag in d.get("security_flags", []))
        reasons = "<br>".join(html_escape(r) for r in d.get("confidence_reasons", []))

        device_rows += f"""
        <tr>
            <td>{html_escape(d.get('ip'))}</td>
            <td>{html_escape(d.get('hostname'))}</td>
            <td>{html_escape(d.get('role'))}</td>
            <td>{html_escape(d.get('device_type'))}</td>
            <td>{html_escape(d.get('os_guess'))}</td>
            <td>{html_escape(d.get('open_ports_summary'))}</td>
            <td>{html_escape(d.get('banners_summary'))}</td>
            <td><span class="risk-badge {risk_badge_class(d.get('risk_level', 'Low'))}">{html_escape(d.get('risk_level'))}</span></td>
            <td><span class="verify-badge {verification_badge_class(d.get('verification_status', 'Unverified'))}">{html_escape(d.get('verification_status'))}</span></td>
            <td>{html_escape(d.get('confidence_score'))}</td>
            <td>{html_escape(d.get('hard_evidence_count'))}</td>
            <td>{reasons}</td>
            <td>{flags}</td>
        </tr>
        """

    added_rows = ""
    for item in changes.get("added", []):
        added_rows += f"<li><strong>{html_escape(item['ip'])}</strong> - {html_escape(item.get('device_type'))} - {html_escape(item.get('verification_status'))}</li>"

    removed_rows = ""
    for item in changes.get("removed", []):
        removed_rows += f"<li><strong>{html_escape(item['ip'])}</strong> - {html_escape(item.get('device_type'))}</li>"

    changed_rows = ""
    for item in changes.get("changed", []):
        change_parts = []
        for field, values in item["changes"].items():
            change_parts.append(
                f"{html_escape(field)}: {html_escape(values.get('old'))} → {html_escape(values.get('new'))}"
            )
        changed_rows += f"<li><strong>{html_escape(item['ip'])}</strong> - " + "; ".join(change_parts) + "</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Asset Monitor Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #0f172a;
            color: #e5e7eb;
        }}
        .container {{
            max-width: 1500px;
            margin: 0 auto;
            padding: 24px;
        }}
        h1, h2, h3 {{
            color: #f8fafc;
        }}
        .subtle {{
            color: #cbd5e1;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 20px 0 28px 0;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.25);
        }}
        .card-title {{
            font-size: 14px;
            color: #94a3b8;
            margin-bottom: 8px;
        }}
        .card-value {{
            font-size: 32px;
            font-weight: bold;
            color: #f8fafc;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111827;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 28px;
        }}
        th, td {{
            border-bottom: 1px solid #1f2937;
            padding: 12px;
            text-align: left;
            vertical-align: top;
            font-size: 14px;
        }}
        th {{
            background: #1e293b;
            color: #f8fafc;
        }}
        tr:hover {{
            background: #0b1220;
        }}
        .risk-badge, .verify-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}
        .risk-high {{
            background: #7f1d1d;
            color: #fecaca;
        }}
        .risk-medium {{
            background: #78350f;
            color: #fde68a;
        }}
        .risk-low {{
            background: #14532d;
            color: #bbf7d0;
        }}
        .verify-high {{
            background: #0c4a6e;
            color: #bae6fd;
        }}
        .verify-medium {{
            background: #3f3f46;
            color: #e4e4e7;
        }}
        .verify-low {{
            background: #3f1d38;
            color: #f5d0fe;
        }}
        .panel {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 24px;
        }}
        ul {{
            margin-top: 8px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        @media (max-width: 900px) {{
            .grid-2 {{
                grid-template-columns: 1fr;
            }}
        }}
        code {{
            color: #93c5fd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Asset Monitor Report</h1>
        <p class="subtle">Generated: {html_escape(scan_metadata.get('scan_time'))}</p>
        <p class="subtle">
            Network: <code>{html_escape(scan_metadata.get('network'))}</code> |
            Local IP: <code>{html_escape(scan_metadata.get('local_ip'))}</code> |
            Gateway: <code>{html_escape(scan_metadata.get('gateway'))}</code> |
            Strict Mode: <code>{html_escape(scan_metadata.get('strict_mode'))}</code> |
            Filtered Out: <code>{html_escape(scan_metadata.get('filtered_out_count'))}</code>
        </p>

        {cards}

        <div class="grid-2">
            <div class="panel">
                <h2>Device Type Summary</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Device Type</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {type_rows}
                    </tbody>
                </table>
            </div>

            <div class="panel">
                <h2>Change Summary</h2>
                <h3>Added</h3>
                <ul>
                    {added_rows if added_rows else "<li>No new devices detected</li>"}
                </ul>

                <h3>Removed</h3>
                <ul>
                    {removed_rows if removed_rows else "<li>No removed devices detected</li>"}
                </ul>

                <h3>Changed</h3>
                <ul>
                    {changed_rows if changed_rows else "<li>No changed devices detected</li>"}
                </ul>
            </div>
        </div>

        <h2>Discovered Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>Role</th>
                    <th>Device Type</th>
                    <th>OS Guess</th>
                    <th>Open Ports</th>
                    <th>Banners</th>
                    <th>Risk</th>
                    <th>Verification</th>
                    <th>Confidence</th>
                    <th>Hard Evidence</th>
                    <th>Confidence Reasons</th>
                    <th>Security Flags</th>
                </tr>
            </thead>
            <tbody>
                {device_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)


# ==========================================
# Console output
# ==========================================

def print_table(devices: List[Dict]) -> None:
    headers = [
        "IP",
        "ROLE",
        "DEVICE_TYPE",
        "OS_GUESS",
        "OPEN_PORTS",
        "RISK",
        "VERIFY",
        "CONF",
        "HARD",
    ]

    rows = []
    for d in devices:
        rows.append([
            d.get("ip", ""),
            d.get("role", ""),
            d.get("device_type", ""),
            d.get("os_guess", ""),
            d.get("open_ports_summary", ""),
            d.get("risk_level", ""),
            d.get("verification_status", ""),
            d.get("confidence_score", 0),
            d.get("hard_evidence_count", 0),
        ])

    widths = [len(h) for h in headers]
    for row in rows:
        for idx, col in enumerate(row):
            widths[idx] = max(widths[idx], len(str(col)))

    def fmt_row(row_values):
        return "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(row_values))

    print()
    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row(row))
    print()


# ==========================================
# Main workflow
# ==========================================

def run_single_scan(network: Optional[str] = None, strict: bool = False) -> Tuple[Dict, List[Dict], Dict]:
    resolved_network, local_ip, gateway = resolve_scan_network(network)

    print(f"\nScanning network: {resolved_network}")
    print(f"Gateway detected: {gateway or 'Unknown'}")
    print(f"Local host IP: {local_ip or 'Unknown'}")
    print(f"Strict mode: {'ON' if strict else 'OFF'}")
    print(f"Scan time: {now_str()}")

    logging.info(
        "Starting scan | network=%s | local_ip=%s | gateway=%s | strict=%s",
        resolved_network,
        local_ip,
        gateway,
        strict
    )

    discovered_hosts = discover_hosts(resolved_network)
    raw_results = service_scan(discovered_hosts)

    devices = []
    filtered_out = 0

    for ip in discovered_hosts:
        raw = raw_results.get(ip, {
            "ip": ip,
            "hostname": "",
            "state": "up",
            "mac": "",
            "vendor": "",
            "latency": "",
            "os_guess": "Unknown",
            "ports": [],
            "banners": [],
            "raw_lines": [],
        })

        record = build_device_record(ip, raw, local_ip, gateway)

        if should_keep_device(record, strict=strict):
            devices.append(record)
        else:
            filtered_out += 1

    devices = sorted(devices, key=lambda x: ip_sort_key(x["ip"]))

    scan_metadata = {
        "scan_time": now_str(),
        "network": resolved_network,
        "local_ip": local_ip,
        "gateway": gateway,
        "device_count": len(devices),
        "strict_mode": strict,
        "filtered_out_count": filtered_out,
    }

    previous_raw = load_json_file(BASELINE_FILE, [])
    previous_baseline = normalize_baseline_data(previous_raw)
    changes = compare_snapshots(previous_baseline, devices)

    for item in changes["added"]:
        append_event("device_added", f"New device detected: {item['ip']}", item)
        logging.info("New device detected: %s", item["ip"])

    for item in changes["removed"]:
        append_event("device_removed", f"Device removed: {item['ip']}", item)
        logging.info("Device removed: %s", item["ip"])

    for item in changes["changed"]:
        append_event("device_changed", f"Device changed: {item['ip']}", item)
        logging.info("Device changed: %s", item["ip"])

    save_scan_json(scan_metadata, devices, JSON_OUTPUT)
    save_csv(devices, CSV_OUTPUT)
    generate_html_report(scan_metadata, devices, changes, HTML_REPORT)
    update_baseline(devices)

    print(f"\nFiltered out unverified hosts: {filtered_out}")
    print("\nDevices discovered:")
    print_table(devices)

    print(f"Saved JSON snapshot to: {JSON_OUTPUT}")
    print(f"Saved CSV snapshot to: {CSV_OUTPUT}")
    print(f"Saved HTML report to: {HTML_REPORT}")

    return scan_metadata, devices, changes


# ==========================================
# Monitor mode
# ==========================================

def run_monitor_mode(network: Optional[str], interval: int, strict: bool) -> None:
    print(f"\nContinuous monitoring enabled. Interval: {interval} seconds")
    logging.info("Continuous monitoring mode started | interval=%s | strict=%s", interval, strict)

    while True:
        try:
            run_single_scan(network, strict=strict)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            logging.info("Monitoring stopped by user")
            break
        except Exception as exc:
            print(f"\nError during monitoring scan: {exc}")
            logging.exception("Error during monitoring scan")

        print(f"Waiting {interval} seconds for next scan...\n")
        time.sleep(interval)


# ==========================================
# CLI
# ==========================================

def print_usage() -> None:
    print("""
Usage:
    sudo python3 discovery.py
    sudo python3 discovery.py --network 172.16.24.0/24
    sudo python3 discovery.py --network 172.16.24.0/24 --strict
    sudo python3 discovery.py --monitor
    sudo python3 discovery.py --monitor --interval 300
    sudo python3 discovery.py --monitor --interval 300 --strict
""")


def parse_args(argv: List[str]) -> Tuple[Optional[str], bool, int, bool]:
    network = None
    monitor = False
    interval = DEFAULT_MONITOR_INTERVAL
    strict = False

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg == "--network" and i + 1 < len(argv):
            network = argv[i + 1]
            i += 2
        elif arg == "--monitor":
            monitor = True
            i += 1
        elif arg == "--interval" and i + 1 < len(argv):
            try:
                interval = int(argv[i + 1])
            except ValueError:
                print("Invalid interval value. Using default.")
            i += 2
        elif arg == "--strict":
            strict = True
            i += 1
        elif arg in ["-h", "--help"]:
            print_usage()
            sys.exit(0)
        else:
            print(f"Unknown argument: {arg}")
            print_usage()
            sys.exit(1)

    return network, monitor, interval, strict


# ==========================================
# Main
# ==========================================

def main() -> None:
    setup_logging()

    if not command_exists("nmap"):
        print("Error: nmap is not installed.")
        print("Install it with:")
        print("sudo apt update && sudo apt install -y nmap")
        sys.exit(1)

    network, monitor, interval, strict = parse_args(sys.argv[1:])

    try:
        if monitor:
            run_monitor_mode(network, interval, strict)
        else:
            run_single_scan(network, strict=strict)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        logging.info("Operation cancelled by user")
    except Exception as exc:
        print(f"\nError: {exc}")
        logging.exception("Unhandled error")
        sys.exit(1)


if __name__ == "__main__":
    main()
