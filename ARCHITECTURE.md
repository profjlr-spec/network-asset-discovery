# Network Asset Discovery Tool — Architecture

This document explains the architecture and internal workflow of the Network Asset Discovery & Security Monitoring Tool.

The tool is written in Python and designed to discover, analyze, and monitor devices connected to a network.

--------------------------------------------------

HIGH LEVEL ARCHITECTURE

The program performs the following main phases:

1. Network discovery
2. Device enumeration
3. Service detection
4. Banner detection
5. Device fingerprinting
6. Security risk analysis
7. Change detection
8. Result export

Each phase builds on the previous one.

--------------------------------------------------

WORKFLOW OVERVIEW

The execution flow of the tool is:

START

↓ Detect local IP and network range

↓ Identify gateway

↓ Perform network scan using Nmap

↓ Enumerate discovered devices

↓ Detect open ports on each host

↓ Attempt banner grabbing

↓ Perform device fingerprinting

↓ Evaluate security risks

↓ Compare results with previous scan

↓ Detect network or service changes

↓ Export results

END

--------------------------------------------------

NETWORK DISCOVERY MODULE

The tool begins by identifying the local network.

Steps:

1. Detect local host IP address
2. Identify the network gateway
3. Determine network range (example: 10.0.0.0/24)

The tool then performs host discovery using:

Nmap host discovery (-sn)

This identifies active devices on the network.

--------------------------------------------------

DEVICE ENUMERATION

For each discovered host the tool collects:

- IP address
- hostname
- MAC address
- vendor (if available)
- device state

This provides the base inventory of the network.

--------------------------------------------------

PORT SCANNING

The tool scans a set of common ports including:

21   FTP
22   SSH
23   TELNET
53   DNS
80   HTTP
443  HTTPS
445  SMB
554  RTSP
3389 RDP
8080 HTTP alternative

These ports were selected because they commonly reveal useful information about devices.

--------------------------------------------------

BANNER DETECTION

For services running on open ports, the tool attempts to retrieve banners.

Banner grabbing uses Python socket connections to read responses from services.

Examples of possible banners:

SSH-2.0-OpenSSH_9.6
Server: nginx
Server: Apache
Server: lighttpd

Banners help identify:

- service type
- software versions
- device categories

--------------------------------------------------

DEVICE FINGERPRINTING

Device fingerprinting uses multiple indicators:

- open ports
- MAC vendor
- hostname
- service banners
- operating system guesses

Examples of device classifications:

IP Camera
Printer
NAS
Workstation
IoT Device
Web Server
Unknown Device

--------------------------------------------------

SECURITY ANALYSIS ENGINE

The tool evaluates potential risks based on detected services.

Risk examples:

FTP (21) → insecure file transfer
TELNET (23) → unencrypted remote access
SMB (445) → possible lateral movement risk
RDP (3389) → remote desktop exposure

Each device receives:

Risk level:
Low
Medium
High

Security flags explaining potential issues.

--------------------------------------------------

NETWORK CHANGE DETECTION

The tool compares current scan results with the previous scan.

This allows detection of:

New devices

Example:

NEW DEVICES DETECTED:
+ 10.0.0.215

Missing devices

Example:

DEVICES NO LONGER PRESENT:
- 10.0.0.103

--------------------------------------------------

SERVICE CHANGE DETECTION

The tool also detects changes in open ports.

Example:

SERVICE CHANGE DETECTED: 10.0.0.221

New ports:
+ 23(TELNET)

Closed ports:
- 22(SSH)

This helps identify configuration changes or suspicious activity.

--------------------------------------------------

DATA STORAGE

Results are saved into two formats:

JSON  
CSV

Files generated:

scan_results.json
scan_results.csv

These files allow further analysis or integration with other tools.

--------------------------------------------------

PROGRAM STRUCTURE

The main components of the script include functions for:

Network detection  
Host discovery  
Port scanning  
Banner detection  
Device fingerprinting  
Risk analysis  
Change detection  
Result export

The program is executed through the main() function.

--------------------------------------------------

SECURITY LAB PURPOSE

This project was designed for:

- cybersecurity learning
- network enumeration practice
- Python security tool development
- understanding asset visibility challenges

It simulates simplified capabilities of professional tools such as:

Nmap
Nessus
Armis
Lansweeper

--------------------------------------------------

FUTURE ARCHITECTURE IMPROVEMENTS

Future enhancements could include:

Real-time monitoring
Alerting system
Web dashboard
Integration with vulnerability databases
Machine learning device classification

