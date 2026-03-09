# ==============================
# Imports
# ==============================
# Estas librerías permiten:
# - ejecutar Nmap desde Python
# - guardar resultados en JSON y CSV
# - aceptar argumentos de terminal
# - ejecutar comandos de Linux
# - trabajar con redes/IPs
# - agregar fecha y hora al escaneo

import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
from datetime import datetime


# ==============================
# Network detection functions
# ==============================
# Esta función detecta automáticamente:
# - la red local
# - el gateway
# - la IP local del equipo actual

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
# Esta función clasifica el rol del dispositivo:
# - Gateway
# - Local Host
# - Device

def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    return "Device"


# ==============================
# Device type guessing
# ==============================
# Esta función intenta adivinar el tipo de dispositivo
# basándose en:
# - rol
# - hostname
# - vendor

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
# Port scanning
# ==============================
# Esta función revisa algunos puertos comunes para un host.
#
# IMPORTANTE:
# usamos un scanner separado del discovery scanner para no
# sobrescribir los resultados del escaneo principal.

def scan_common_ports(host):
    common_ports = "22,53,80,443,445,3389,554"
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
                        open_ports.append(str(port))

    except Exception:
        pass

    if not open_ports:
        return "None"

    return ", ".join(open_ports)


# ==============================
# Terminal output formatting
# ==============================
# Esta función imprime una tabla alineada en la terminal.

def print_table(devices):
    headers = [
        "IP",
        "ROLE",
        "DEVICE_TYPE",
        "HOSTNAME",
        "STATE",
        "OPEN_PORTS",
        "MAC",
        "VENDOR"
    ]

    rows = []
    for device in devices:
        rows.append([
            device["ip"],
            device["role"],
            device["device_type"],
            device["hostname"],
            device["state"],
            device["open_ports"],
            device["mac"],
            device["vendor"]
        ])

    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    header_line = "  ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )
    separator_line = "  ".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    print(header_line)
    print(separator_line)

    for row in rows:
        print("  ".join(
            str(row[i]).ljust(col_widths[i]) for i in range(len(headers))
        ))


# ==============================
# Main program
# ==============================
# Esta función:
# 1. lee argumentos
# 2. detecta red/gateway/IP local
# 3. ejecuta discovery
# 4. clasifica rol y tipo de dispositivo
# 5. escanea puertos comunes
# 6. imprime tabla
# 7. guarda JSON y CSV

def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )
    args = parser.parse_args()

    detected_network, gateway, local_ip = detect_network_gateway_and_local_ip()
    network = args.network if args.network else detected_network

    # Scanner principal solo para discovery
    discovery_scanner = nmap.PortScanner()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\nScanning network: {network}")
    print(f"Gateway detected: {gateway}")
    print(f"Local host IP: {local_ip}")
    print(f"Scan time: {timestamp}\n")

    # Fase 1: discovery de hosts activos
    discovery_scanner.scan(hosts=network, arguments="-sn")

    # Guardamos la lista de hosts ANTES de hacer otros escaneos
    discovered_hosts = discovery_scanner.all_hosts()

    devices = []

    for host in discovered_hosts:
        host_data = discovery_scanner[host]
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        mac = addresses.get("mac", "N/A")
        vendor = vendor_info.get(mac, "N/A")
        hostname = host_data.hostname() or "N/A"
        role = determine_role(host, gateway, local_ip)
        device_type = guess_device_type(role, hostname, vendor)

        # Fase 2: escaneo de puertos usando scanner separado
        open_ports = scan_common_ports(host)

        device = {
            "ip": host,
            "role": role,
            "device_type": device_type,
            "hostname": hostname,
            "state": host_data.state(),
            "open_ports": open_ports,
            "mac": mac,
            "vendor": vendor,
            "scan_time": timestamp
        }

        devices.append(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    print("Devices discovered:\n")
    print_table(devices)

    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "ip",
                "role",
                "device_type",
                "hostname",
                "state",
                "open_ports",
                "mac",
                "vendor",
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
