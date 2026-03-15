# Network Asset Monitor

A Python-based network discovery and security monitoring tool designed to identify devices on a network and detect changes over time.

This project simulates capabilities commonly found in cybersecurity tools used by SOC teams, network administrators, and security analysts to maintain visibility over network assets.

---

## Screenshot

Example terminal output:

![Example Scan](screenshots/example_scan.png)

---

## Project Overview

Network Asset Monitor scans a network to discover connected devices and analyze their characteristics.

The tool builds a basic network asset inventory and detects security-relevant changes between scans.

It helps identify:

• Unknown devices connected to the network
• IoT and smart devices
• Exposed services
• Insecure legacy protocols
• Device type using fingerprinting
• Service banners for better identification
• Network changes over time

---

## Key Features

### Network Asset Discovery

Detects active devices on the network using Nmap host discovery.

### Device Enumeration

Collects information about discovered hosts including:

• IP address
• MAC address (when available)
• Open ports
• Service names
• Service banners
• Device role classification
• Device type fingerprinting

### Security Monitoring

Identifies potential security risks such as:

• FTP services running without encryption
• TELNET services exposed on the network
• IP cameras or IoT devices with potential security risks
• Services exposed on unusual ports

### Change Detection

Detects network changes between scans including:

• New devices appearing on the network
• Devices disappearing from the network
• Changes in open ports
• Changes in service banners
• Changes in calculated risk levels

### Monitoring Mode

Supports continuous monitoring of the network.

When monitoring mode is enabled the tool:

• Runs scans periodically
• Compares results against a baseline
• Logs detected changes
• Generates structured monitoring events

---

## Example Output

```
Scanning network: 10.0.0.0/24
Scan time: 2026-03-14T18:37:03

Devices discovered:

IP            DEVICE_TYPE     STATE   OPEN_PORTS    RISK_LEVEL
--------------------------------------------------------------
10.0.0.1      Router          up      53,80,443     Medium
10.0.0.220    Device          up      None          Low
10.0.0.221    Workstation     up      22            Low
```

---

## Project Structure

```
network-asset-monitor
│
├── discovery.py
├── requirements.txt
├── README.md
│
├── docs
│   └── ARCHITECTURE.md
│
├── screenshots
│   └── example_scan.png
│
├── snapshots
│   ├── scan_results.json
│   └── scan_results.csv
│
├── baseline.json
├── pending_changes.json
├── events.jsonl
└── monitor.log
```

---

## Installation

Clone the repository:

```
git clone https://github.com/profjlr-spec/network-asset-monitor.git
cd network-asset-monitor
```

Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

Install Nmap if not already installed.

Ubuntu / Debian:

```
sudo apt install nmap
```

---

## Usage

Run a single network scan:

```
python3 discovery.py --network 10.0.0.0/24
```

Run continuous monitoring mode:

```
python3 discovery.py --network 10.0.0.0/24 --monitor --interval 60
```

This will:

• Perform periodic network scans
• Compare results with the baseline
• Detect changes
• Log events

---

## Monitoring Files

The tool generates several monitoring artifacts.

### baseline.json

Stores the baseline network state used for comparison.

### pending_changes.json

Tracks devices that require confirmation across multiple scans.

### events.jsonl

Stores structured monitoring events such as:

• new_device
• device_disappeared
• open_ports_changed
• banner_changed
• risk_changed

### monitor.log

Human-readable monitoring log.

---

## Architecture

The project follows a simple monitoring pipeline:

```
Network Scan (Nmap)
        ↓
Device Enumeration
        ↓
Fingerprinting
        ↓
Risk Analysis
        ↓
Baseline Comparison
        ↓
Event Generation
        ↓
Monitoring Logs
```

Detailed architecture documentation is available in:

```
docs/ARCHITECTURE.md
```

---

## Technologies Used

• Python
• Nmap
• JSON / CSV data export
• Git & GitHub

---

## Learning Objectives

This project was built to better understand:

• Network discovery techniques
• Service enumeration
• Device fingerprinting
• Security risk detection
• Change monitoring across network scans
• Basic network asset inventory concepts

---

## Future Improvements

Planned improvements include:

• HTML reporting dashboard
• Improved device fingerprinting
• Visualization of network assets
• CLI installation as a system tool
• Integration with monitoring systems

---

## License

This project is intended for educational and research purposes.
