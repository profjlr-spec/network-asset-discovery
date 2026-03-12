# ==============================
# Imports
# ==============================

import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
import socket
import ssl
from datetime import datetime


# ==============================
# Network detection functions
# ==============================

def detect_network_gateway_and_local_ip():
    try:
        route = subprocess.check_output(
            "ip route | grep default", shell=True, text=True
        ).strip()

        parts = route.split()
        gateway = parts[2]
        interface = parts[4]

        ip_info = subprocess.check_output(
            f"ip -o -f inet addr show {interface}", shell=True, text=True
        ).strip()

        cidr = ip_info.split()[3]
        interface_ip = cidr.split("/")[0]
        network = str(ipaddress.ip_interface(cidr).network)

        return network, gateway, interface_ip

    except Exception:
        return "10.0.0.0/24", "N/A", "N/A"


# ==============================
# Device role classification
# ==============================

def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    return "Device"


# ==============================
# Basic device type guessing
# ==============================

def guess_device_type(role, hostname, vendor):
    hostname_lower = hostname.lower() if hostname != "N/A" else ""
    vendor_lower = vendor.lower() if vendor != "N/A" else ""

    if role == "Gateway":
        return "Gateway / Router"

    if role == "Local Host":
        return "Local Computer"

    if "nest" in vendor_lower:
        return "IoT Device"

    if "arris" in vendor_lower:
        return "Network Device"

    if "apple" in vendor_lower:
        return "Phone / Computer"

    if "samsung" in vendor_lower:
        return "Phone / Smart Device"

    if "intel" in vendor_lower or "dell" in vendor_lower or "lenovo" in vendor_lower:
        return "Computer / Laptop"

    if "hp" in vendor_lower or "epson" in vendor_lower or "canon" in vendor_lower:
        return "Printer"

    if "iphone" in hostname_lower or "android" in hostname_lower:
        return "Phone / Mobile Device"

    if "printer" in hostname_lower:
        return "Printer"

    if "tv" in hostname_lower:
        return "Smart TV"

    if "cam" in hostname_lower or "camera" in hostname_lower:
        return "Camera"

    if "raspberry" in hostname_lower:
        return "Single Board Computer"

    if "laptop" in hostname_lower or "desktop" in hostname_lower or "pc" in hostname_lower:
        return "Computer / Laptop"

    if vendor == "N/A" and hostname == "N/A":
        return "Unknown Device"

    return "Smart / Connected Device"


# ==============================
# Port to service mapping
# ==============================

def get_service_name(port):
    port_map = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        3389: "RDP",
        8080: "HTTP-Alt"
    }
    return port_map.get(port, "Unknown")


# ==============================
# Common port scanning
# ==============================

def scan_common_ports(host):
    common_ports = "21,22,23,53,80,443,445,554,3389,8080"
    open_ports = []

    try:
        port_scanner = nmap.PortScanner()
        port_scanner.scan(hosts=host, arguments=f"-Pn -p {common_ports} --open")

        if host in port_scanner.all_hosts():
            protocols = port_scanner[host].all_protocols()

            for protocol in protocols:
                ports = port_scanner[host][protocol].keys()

                for port in sorted(ports):
                    state = port_scanner[host][protocol][port].get("state", "")
                    if state == "open":
                        service_name = get_service_name(port)
                        open_ports.append(f"{port}({service_name})")

    except Exception:
        pass

    if not open_ports:
        return "None"

    return ", ".join(open_ports)


# ==============================
# OS detection
# ==============================

def detect_os_guess(host):
    try:
        os_scanner = nmap.PortScanner()
        os_scanner.scan(hosts=host, arguments="-Pn -O --osscan-guess")

        if host in os_scanner.all_hosts():
            os_matches = os_scanner[host].get("osmatch", [])
            if os_matches:
                return os_matches[0].get("name", "Unknown")

    except Exception:
        pass

    return "Unknown"


# ==============================
# OS guess simplification
# ==============================

def simplify_os_guess(os_guess):
    guess = os_guess.lower()

    if guess == "unknown":
        return "Unknown"
    if "windows" in guess or "microsoft" in guess:
        return "Windows"
    if "mac os" in guess or "macos" in guess or "darwin" in guess or "ios" in guess:
        return "macOS / iOS"
    if "embedded" in guess and "linux" in guess:
        return "Embedded Linux"
    if "linux" in guess:
        return "Linux"
    if "router" in guess or "switch" in guess or "network" in guess or "cisco" in guess:
        return "Router / Network OS"
    if "printer" in guess:
        return "Printer"
    if "bsd" in guess:
        return "BSD / Unix-like"

    return "Other / Unknown"


# ==============================
# OS detection decision
# ==============================

def should_run_os_detection(role, open_ports):
    if role in ["Gateway", "Local Host"]:
        return True
    if open_ports != "None":
        return True
    return False


# ==============================
# Banner detection helpers
# ==============================

def grab_tcp_banner(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")
    except Exception:
        pass
    return "N/A"


def grab_http_banner(host, port, use_ssl=False, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: banner-check\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            data = sock.recv(2048).decode(errors="ignore")

            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()

            if data:
                return data.splitlines()[0].strip()

    except Exception:
        pass

    return "N/A"


def detect_banners(host, open_ports):
    banners = []

    if open_ports == "None":
        return "None"

    ports = []
    for item in open_ports.split(","):
        item = item.strip()
        if "(" in item:
            port_str = item.split("(")[0]
            try:
                ports.append(int(port_str))
            except ValueError:
                pass

    for port in ports:
        banner = "N/A"

        if port == 22:
            banner = grab_tcp_banner(host, 22)

        elif port == 23:
            banner = grab_tcp_banner(host, 23)

        elif port in [80, 8080]:
            banner = grab_http_banner(host, port, use_ssl=False)

        elif port == 443:
            banner = grab_http_banner(host, 443, use_ssl=True)

        if banner != "N/A" and banner:
            banners.append(f"{port}:{banner[:60]}")

    if not banners:
        return "None"

    return " | ".join(banners)


# ==============================
# Advanced device fingerprinting
# ==============================

def fingerprint_device(device_type, open_ports, vendor, hostname, os_guess, role, banners):
    vendor_lower = vendor.lower() if vendor != "N/A" else ""
    hostname_lower = hostname.lower() if hostname != "N/A" else ""
    banners_lower = banners.lower() if banners != "None" else ""
    ports = set() if open_ports == "None" else set(
        port.strip() for port in open_ports.split(",")
    )

    if role == "Gateway":
        return "Gateway / Router"

    if role == "Local Host":
        return "Workstation"

    # IP camera detection
    if "554(RTSP)" in ports:
        if "80(HTTP)" in ports or "8080(HTTP-Alt)" in ports or "443(HTTPS)" in ports:
            return "IP Camera / Web Admin"
        return "IP Camera"

    if "camera" in hostname_lower or "cam" in hostname_lower:
        return "IP Camera"

    if "goahead" in banners_lower or "hikvision" in banners_lower or "dahua" in banners_lower:
        return "IP Camera / Web Admin"

    if "printer" in hostname_lower:
        return "Printer"

    if "hp" in vendor_lower or "epson" in vendor_lower or "canon" in vendor_lower:
        return "Printer"

    if "445(SMB)" in ports:
        return "NAS / File Server"

    if "openssh" in banners_lower and role == "Device":
        return "Managed Linux Device"

    if (
        "80(HTTP)" in ports
        or "443(HTTPS)" in ports
        or "8080(HTTP-Alt)" in ports
    ) and role == "Device":
        return "Web Server / Admin Interface"

    if "nest" in vendor_lower:
        return "IoT Device"

    if "apple" in vendor_lower and "macOS / iOS" in os_guess:
        return "Apple Device"

    if device_type == "Computer / Laptop" and os_guess in ["Linux", "Windows", "macOS / iOS"]:
        return "Workstation"

    if device_type == "Unknown Device" and open_ports == "None":
        return "Unknown Device"

    return device_type


# ==============================
# Security risk detection
# ==============================

def assess_security_risk(device_type, open_ports, role, banners):
    flags = []
    score = 0
    banners_lower = banners.lower() if banners != "None" else ""

    if device_type == "IoT Device":
        flags.append("Possible insecure IoT device")
        score += 2

    if device_type == "IP Camera":
        flags.append("Possible exposed camera device")
        score += 3

    if device_type == "IP Camera / Web Admin":
        flags.append("Possible exposed camera admin interface")
        score += 4

    if device_type == "Smart / Connected Device":
        flags.append("Smart device needs review")
        score += 1

    if device_type == "Unknown Device":
        flags.append("Unknown device detected")
        score += 2

    if device_type == "Web Server / Admin Interface" and role == "Device":
        flags.append("Web interface exposed on device")
        score += 1

    if "21(FTP)" in open_ports:
        flags.append("Insecure FTP service exposed")
        score += 3

    if "23(TELNET)" in open_ports:
        flags.append("Telnet is insecure and should not be exposed")
        score += 4

    if "445(SMB)" in open_ports and role != "Local Host":
        flags.append("SMB exposed to network")
        score += 3

    if "445(SMB)" in open_ports and role == "Local Host":
        flags.append("SMB exposed")
        score += 2

    if "3389(RDP)" in open_ports:
        flags.append("RDP exposed - potential brute force target")
        score += 3

    if "22(SSH)" in open_ports and role != "Local Host":
        flags.append("SSH open on network device")
        score += 1

    if "554(RTSP)" in open_ports:
        flags.append("Camera or video stream service exposed")
        score += 2

    if (
        "554(RTSP)" in open_ports
        and ("80(HTTP)" in open_ports or "8080(HTTP-Alt)" in open_ports or "443(HTTPS)" in open_ports)
    ):
        flags.append("Camera stream and web admin interface both exposed")
        score += 2

    if "goahead" in banners_lower or "hikvision" in banners_lower or "dahua" in banners_lower:
        flags.append("Possible embedded camera web interface detected")
        score += 2

    if "apache" in banners_lower or "nginx" in banners_lower or "lighttpd" in banners_lower:
        flags.append("Web server banner detected")
        score += 1

    if open_ports != "None" and role == "Device":
        flags.append("Open ports require review")
        score += 1

    if score >= 5:
        risk_level = "High"
    elif score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not flags:
        flags = ["No obvious issues"]

    return risk_level, "; ".join(flags)


# ==============================
# Scan history loading
# ==============================

def load_previous_scan():
    try:
        with open("previous_scan.json", "r") as file:
            return json.load(file)
    except Exception:
        return []


# ==============================
# Scan history saving
# ==============================

def save_current_scan(devices):
    with open("previous_scan.json", "w") as file:
        json.dump(devices, file, indent=4)


# ==============================
# Device change detection
# ==============================

def detect_network_changes(previous_devices, current_devices):
    previous_ips = {device["ip"] for device in previous_devices}
    current_ips = {device["ip"] for device in current_devices}

    new_ips = current_ips - previous_ips
    missing_ips = previous_ips - current_ips

    if new_ips:
        print("\nNEW DEVICES DETECTED:")
        for ip in sorted(new_ips, key=ipaddress.ip_address):
            print(f" + {ip}")

    if missing_ips:
        print("\nDEVICES NO LONGER PRESENT:")
        for ip in sorted(missing_ips, key=ipaddress.ip_address):
            print(f" - {ip}")

    if not new_ips and not missing_ips:
        print("\nNo device-level network changes detected since the previous scan.")


# ==============================
# Service change detection
# ==============================

def detect_service_changes(previous_devices, current_devices):
    previous_map = {device["ip"]: device for device in previous_devices}
    current_map = {device["ip"]: device for device in current_devices}

    shared_ips = sorted(
        set(previous_map.keys()) & set(current_map.keys()),
        key=ipaddress.ip_address
    )

    changes_found = False

    for ip in shared_ips:
        previous_ports_raw = previous_map[ip].get("open_ports", "None")
        current_ports_raw = current_map[ip].get("open_ports", "None")

        previous_ports = set() if previous_ports_raw == "None" else set(
            port.strip() for port in previous_ports_raw.split(",")
        )
        current_ports = set() if current_ports_raw == "None" else set(
            port.strip() for port in current_ports_raw.split(",")
        )

        new_ports = sorted(current_ports - previous_ports)
        closed_ports = sorted(previous_ports - current_ports)

        if new_ports or closed_ports:
            changes_found = True
            print(f"\nSERVICE CHANGE DETECTED: {ip}")

            if new_ports:
                print(" New open ports:")
                for port in new_ports:
                    print(f"  + {port}")

            if closed_ports:
                print(" Closed ports:")
                for port in closed_ports:
                    print(f"  - {port}")

    if not changes_found:
        print("\nNo service-level port changes detected since the previous scan.")


# ==============================
# Terminal output formatting
# ==============================

def print_table(devices):
    headers = [
        "IP",
        "ROLE",
        "DEVICE_TYPE",
        "OS_GUESS",
        "STATE",
        "OPEN_PORTS",
        "BANNERS",
        "RISK_LEVEL",
        "SECURITY_FLAGS"
    ]

    rows = []
    for device in devices:
        rows.append([
            device["ip"],
            device["role"],
            device["device_type"],
            device["os_guess"],
            device["state"],
            device["open_ports"],
            device["banners"],
            device["risk_level"],
            device["security_flags"]
        ])

    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(min(max_width, 65))

    header_line = "  ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )
    separator_line = "  ".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    print(header_line)
    print(separator_line)

    for row in rows:
        formatted_row = []
        for i in range(len(headers)):
            value = str(row[i])
            if len(value) > col_widths[i]:
                value = value[:col_widths[i] - 3] + "..."
            formatted_row.append(value.ljust(col_widths[i]))
        print("  ".join(formatted_row))


# ==============================
# Main program
# ==============================

def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )
    args = parser.parse_args()

    detected_network, gateway, local_ip = detect_network_gateway_and_local_ip()
    network = args.network if args.network else detected_network

    discovery_scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\nScanning network: {network}")
    print(f"Gateway detected: {gateway}")
    print(f"Local host IP: {local_ip}")
    print(f"Scan time: {timestamp}\n")

    discovery_scanner.scan(hosts=network, arguments="-sn")
    discovered_hosts = discovery_scanner.all_hosts()

    previous_scan = load_previous_scan()
    devices = []

    for host in discovered_hosts:
        host_data = discovery_scanner[host]
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        mac = addresses.get("mac", "N/A")
        vendor = vendor_info.get(mac, "N/A")
        hostname = host_data.hostname() or "N/A"
        role = determine_role(host, gateway, local_ip)

        basic_device_type = guess_device_type(role, hostname, vendor)
        open_ports = scan_common_ports(host)

        if should_run_os_detection(role, open_ports):
            raw_os_guess = detect_os_guess(host)
            os_guess = simplify_os_guess(raw_os_guess)
        else:
            os_guess = "Skipped"

        banners = detect_banners(host, open_ports)

        device_type = fingerprint_device(
            device_type=basic_device_type,
            open_ports=open_ports,
            vendor=vendor,
            hostname=hostname,
            os_guess=os_guess,
            role=role,
            banners=banners
        )

        risk_level, security_flags = assess_security_risk(
            device_type=device_type,
            open_ports=open_ports,
            role=role,
            banners=banners
        )

        device = {
            "ip": host,
            "role": role,
            "device_type": device_type,
            "os_guess": os_guess,
            "hostname": hostname,
            "state": host_data.state(),
            "open_ports": open_ports,
            "banners": banners,
            "mac": mac,
            "vendor": vendor,
            "risk_level": risk_level,
            "security_flags": security_flags,
            "scan_time": timestamp
        }

        devices.append(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    print("Devices discovered:\n")
    print_table(devices)

    detect_network_changes(previous_scan, devices)
    detect_service_changes(previous_scan, devices)

    save_current_scan(devices)

    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "ip",
                "role",
                "device_type",
                "os_guess",
                "hostname",
                "state",
                "open_ports",
                "banners",
                "mac",
                "vendor",
                "risk_level",
                "security_flags",
                "scan_time"
            ]
        )
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved to scan_results.json and scan_results.csv\n")


# ==============================
# Program entry point
# ==============================

if __name__ == "__main__":
    main()
