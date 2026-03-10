# Network Asset Discovery Tool

A Python-based network discovery and asset inventory tool built for learning Linux networking, Python automation, and cybersecurity fundamentals.

The tool scans a local network and builds an inventory of active devices including:

- IP address
- device role
- device type guess
- hostname
- device state
- open ports
- MAC address
- vendor
- operating system guess

The results are displayed in a formatted terminal table and exported to JSON and CSV files.

--------------------------------------------------

FEATURES

Network Discovery

The tool automatically detects:

- local network range
- default gateway
- local host IP

It uses Nmap host discovery to find active devices.

--------------------------------------------------

Device Classification

Each discovered host is classified by role:

- Gateway
- Local Host
- Device

The script also attempts to guess the device type using:

- hostname
- vendor
- device role

Example device types:

- Gateway / Router
- Computer / Laptop
- IoT Device
- Printer
- Smart TV
- Camera
- Smart / Connected Device
- Unknown Device

--------------------------------------------------

Port Scanning

The tool scans common ports:

22 (SSH)  
53 (DNS)  
80 (HTTP)  
443 (HTTPS)  
445 (SMB)  
3389 (RDP)  
554 (RTSP)

Ports are displayed with service names.

Example:

80(HTTP), 443(HTTPS)

--------------------------------------------------

OS Detection

The tool attempts operating system detection using Nmap fingerprinting.

To keep the scan fast, OS detection only runs when:

- the device is the gateway
- the device is the local host
- the device has open ports

If OS detection is skipped the output shows:

Skipped

Example OS results:

Linux  
Windows  
macOS / iOS  
Router / Network OS  
Unknown

--------------------------------------------------

Example Output

Example terminal output:

IP          ROLE        DEVICE_TYPE               OS_GUESS  HOSTNAME  STATE  OPEN_PORTS
10.0.0.1    Gateway     Gateway / Router          Linux     _gateway  up     53(DNS),80(HTTP),443(HTTPS)
10.0.0.57   Device      Computer / Laptop         Skipped   N/A       up     None
10.0.0.221  Local Host  Local Computer            Linux     Friday    up     None

--------------------------------------------------

Output Files

After each scan the tool exports:

scan_results.json  
scan_results.csv

These files can be used for:

- asset inventory
- reporting
- automation
- analysis

--------------------------------------------------

Requirements

Python 3  
Nmap  

Python library:

python-nmap

--------------------------------------------------

Installation

Clone repository

git clone https://github.com/profjlr-spec/network-asset-discovery.git

Enter project directory

cd network-asset-discovery

Create virtual environment

python3 -m venv venv

Activate virtual environment

source venv/bin/activate

Install dependencies

pip install -r requirements.txt

Install Nmap if needed

sudo apt install nmap

--------------------------------------------------

Usage

Run automatic network scan

sudo ./venv/bin/python discovery.py

Scan a specific network

sudo ./venv/bin/python discovery.py --network 192.168.1.0/24

--------------------------------------------------

Project Purpose

This project was created to practice:

- Python scripting
- Linux networking
- network discovery
- IT automation
- cybersecurity fundamentals

--------------------------------------------------

Learning Goals

The project demonstrates:

- Nmap automation with Python
- host discovery
- port scanning
- OS fingerprinting
- structured data export

--------------------------------------------------

Future Improvements

Possible future improvements include:

- deeper service detection
- improved device fingerprinting
- vulnerability scanning
- web dashboard
- network topology visualization
- automated asset inventory

--------------------------------------------------

Author

Juan Ramos

IT Support | Linux | Networking | Cybersecurity Learning Project
