# Network Asset Discovery Tool – Architecture

This document describes the architecture and workflow of the Network Asset Discovery Tool.

The tool is designed to automatically discover devices on a network, identify services, and highlight potential security risks.

---

# High Level Workflow

The scanning pipeline works in the following order:

Network  
↓  
Host Discovery (ARP / Network Scan)  
↓  
Device Identification  
↓  
Port Scanning  
↓  
Service Detection  
↓  
Banner Detection  
↓  
Device Fingerprinting  
↓  
Risk Analysis  
↓  
Change Detection  
↓  
Report Generation (JSON / CSV)

---

# Architecture Components

## Network Discovery

Responsible for identifying active devices on the network.

The tool scans the local subnet (example: 10.0.0.0/24) and identifies responding hosts.

Outputs:
- Active IP addresses
- Gateway identification
- Local host detection

---

## Device Identification

Once hosts are discovered, the tool attempts to classify devices.

Possible classifications:

Gateway / Router  
Local Host  
Computer / Laptop  
Smart Device  
IoT Device  
Unknown Device

This classification is based on:

- network role
- observed behavior
- service exposure
- known patterns

---

## Port Scanning

The scanner checks common service ports on each discovered device.

Example ports scanned:

22   SSH  
23   TELNET  
53   DNS  
80   HTTP  
443  HTTPS  
445  SMB  
3389 RDP  

Detected open ports are recorded and later analyzed for risk.

---

## Banner Detection

For supported services, the scanner attempts to retrieve service banners.

Example:

Server: Xfinity Broadband Router Server

This helps identify:

- device vendors
- service software
- router firmware
- exposed web servers

---

## Device Fingerprinting

Using information gathered from:

- open ports
- service banners
- behavior patterns

The tool attempts to infer the type of device.

Example fingerprints:

Workstation  
Gateway / Router  
IoT Device  
Smart Device  
Unknown Device

---

## Risk Analysis

The scanner evaluates each device and flags potential security risks.

Examples of high-risk services:

TELNET (23)  
FTP (21)  
SMB (445)  
RDP (3389)

Example output:

RISK_LEVEL: High  
SECURITY_FLAGS: Telnet is insecure and should not be exposed

---

## Change Detection

The scanner compares the current scan with the previous scan.

This allows detection of:

New devices joining the network

Devices disappearing from the network

Service level changes such as newly opened ports

Example detection:

NEW DEVICES DETECTED

SERVICE CHANGE DETECTED

DEVICES NO LONGER PRESENT

---

## Report Generation

Results are exported for analysis and automation.

Outputs include:

data/scan_results.json  
data/scan_results.csv

These files allow:

security review  
asset inventory tracking  
network monitoring automation

---

# Summary

This tool provides a lightweight network discovery and security analysis capability.

Key capabilities include:

Network asset discovery

Port and service detection

Banner grabbing

Device fingerprinting

Security risk identification

Network change detection

Structured reporting
