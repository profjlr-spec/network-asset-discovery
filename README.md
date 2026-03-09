# Network Asset Discovery Tool

A simple Python tool that scans a local network and discovers active devices using **Nmap**.

This tool is designed as a **learning project for IT, networking, and cybersecurity**. It automatically detects the local network, identifies active hosts, and collects useful asset information such as IP address, hostname, MAC address, and vendor.

The results are displayed in a clean terminal table and exported to **JSON** and **CSV** formats.

---

# Project Goals

This project was built to practice and demonstrate skills in:

- Linux
- Networking
- Python scripting
- Nmap usage
- IT automation
- basic asset discovery

---

# Features

The tool automatically:

- Detects the **local network range**
- Detects the **default gateway**
- Detects the **local host IP**
- Scans for active hosts using **Nmap**

For each discovered device it attempts to identify:

- IP address
- device role (Gateway / Local Host / Device)
- hostname
- device state
- MAC address
- vendor (when available)

Output includes:

- formatted terminal table
- JSON export
- CSV export

The tool also supports manually specifying a network range.

---

# Requirements

- Python 3
- Nmap
- python-nmap library

---

# Installation

Clone the repository:

```bash
git clone https://github.com/profjlr-spec/network-asset-discovery.git
cd network-asset-discovery
