# LEARNING NOTES — Network Asset Discovery Tool

These notes explain how the `discovery.py` script works step by step.

The goal of this file is to make the code easier to understand when reviewing it later.

---

# 1. What this project does

This tool performs **basic network asset discovery**.

It scans a network and identifies active devices.

For each device it collects:

- IP address
- role
- device type guess
- hostname
- state
- MAC address
- vendor
- open service ports

It also exports the results to:
scan_results.json
scan_results.csv

---

# 2. High level workflow

The script works in two main phases:

### Phase 1 — Host discovery

Nmap is used to find active hosts in the network.

Command used internally:
nmap -sn

This performs a **ping scan** without scanning ports.

---

### Phase 2 — Port scanning

For each discovered host, the script scans a small set of common ports:
22
53
80
443
445
3389
554

These ports represent common services such as:

- SSH
- DNS
- Web servers
- File sharing
- Remote desktop
- IP cameras

---

# 3. Main sections of discovery.py

The script is organized into several sections.

### Imports

Libraries used:

- `nmap`
- `json`
- `csv`
- `argparse`
- `subprocess`
- `ipaddress`
- `datetime`

These support:

- network scanning
- exporting results
- parsing command arguments
- detecting network configuration

---

### Network detection

Function:
detect_network_gateway_and_local_ip()

This function determines:

- the local network
- the gateway IP
- the local machine IP

It uses Linux commands like:
ip route
ip addr

---

### Role classification

Function:
determine_role()

This determines whether the device is:

- Gateway
- Local Host
- Device

---

### Device type guessing

Function:
guess_device_type()

This attempts to infer the device type using:

- hostname
- vendor
- device role

Examples:
Nest → IoT Device
Intel → Computer
HP → Printer

---

### Port scanning

Function:
scan_common_ports()

This scans common ports using Nmap.

Example scan:
nmap -Pn -p 22,53,80,443,445,3389,554


Open ports are stored and formatted.

---

### Service name mapping

Function:
get_service_name()

This converts port numbers into known services.

Example:
22 → SSH
53 → DNS
80 → HTTP
443 → HTTPS

Output example:
443(HTTPS)

---

### Table formatting

Function:
print_table()

This prints results in a clean aligned table.

It dynamically calculates column widths.

---

### Data export

Results are saved as:
scan_results.json
scan_results.csv

These can be used for:

- automation
- asset inventories
- reporting
- data analysis

---

# 4. Why this project is useful

This project demonstrates skills in:

- Python scripting
- Linux networking
- Nmap automation
- device discovery
- basic port scanning
- data processing

---

# 5. Possible improvements

Future ideas:

- OS detection
- deeper port scanning
- vulnerability checks
- HTML reports
- network visualization
