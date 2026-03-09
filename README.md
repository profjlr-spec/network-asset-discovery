# Network Asset Discovery Tool

A Python-based network scanning tool that discovers devices on a local network and collects basic asset information.

This project was built as part of a personal learning path in:

- Linux
- Networking
- Python scripting
- IT automation
- Cybersecurity fundamentals

The tool automatically scans a local network, identifies active hosts, detects device characteristics, and exports the results.

---

# Features

The tool currently performs two main phases:

### Phase 1 — Network Discovery

- Detects the **local network automatically**
- Detects the **default gateway**
- Detects the **local host IP**
- Uses **Nmap host discovery** to find active devices

### Phase 2 — Asset Identification

For each discovered host the tool collects:

- IP address
- Device role (Gateway / Local Host / Device)
- Guessed device type
- Hostname (when available)
- Host state
- MAC address
- Vendor (when available)

### Phase 3 — Basic Port Scanning

The tool scans a small set of **common service ports**:

| Port | Service |
|-----|------|
22 | SSH
53 | DNS
80 | HTTP
443 | HTTPS
445 | SMB
3389 | RDP
554 | RTSP

Detected ports are displayed with their **service name**.

Example:

---

# Example Output

Below is an example scan of the tool running on a local network.

![Example Scan](example_scan.png)

Example terminal output:

---

# Output Files

The tool automatically exports scan results to:

### JSON


Useful for:

- automation
- scripting
- integrations

### CSV

Useful for:

- spreadsheets
- reporting
- asset inventory tracking

---

# Requirements

The following tools must be installed:

### Python

Python 3.10+

### Nmap

Install with:

### Python library

---

# Installation

Clone the repository:
git clone https://github.com/profjlr-spec/network-asset-discovery.git

Enter the project directory:
cd network-asset-discovery

Create a virtual environment:
python3 -m venv venv

Activate the virtual environment:
source venv/bin/activate

Install requirements:
pip install -r requirements.txt

---

# Running the Tool

Basic scan:
sudo ./venv/bin/python discovery.py

Or scan a specific network:
sudo ./venv/bin/python discovery.py --network 10.0.0.0/24

---

# Project Structure
network-asset-discovery
│
├── discovery.py
├── README.md
├── LEARNING_NOTES.md
├── requirements.txt
├── example_scan.png
├── scan_results.json
├── scan_results.csv
└── venv/

---

# Learning Goals of This Project

This project was created to practice:

- Python scripting
- Network discovery
- Nmap automation
- Device fingerprinting
- Port scanning basics
- Data export automation

---

# Future Improvements

Planned improvements include:

- OS detection
- HTML reporting
- better device fingerprinting
- larger port scanning options
- network topology mapping

---

# License

This project is for educational purposes.
