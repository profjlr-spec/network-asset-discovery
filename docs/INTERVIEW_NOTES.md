# Interview Notes – Network Asset Discovery Tool

This document summarizes how to explain this project in technical interviews.

---

# Project Summary

This project is a Python-based Network Asset Discovery and Security Monitoring tool.

The tool scans a local network, identifies connected devices, detects exposed services, and highlights potential security risks.

It also compares current scan results with previous scans to detect network changes.

---

# Problem the Tool Solves

Many small networks do not have visibility into:

- what devices are connected
- what services are exposed
- whether insecure protocols are present
- when new devices appear on the network

This tool provides a lightweight way to monitor network assets and detect potential risks.

---

# Key Features

The tool includes the following capabilities:

Network host discovery

Device classification (gateway, workstation, IoT devices)

Port scanning of common services

Service banner detection

Device fingerprinting

Security risk identification

Network change detection

JSON and CSV report generation

---

# Security Detection

The scanner identifies potentially insecure services such as:

FTP (21)

TELNET (23)

SMB (445)

RDP (3389)

If detected, the tool marks the device with a higher risk level and generates a security flag.

Example:

RISK_LEVEL: High  
SECURITY_FLAGS: Telnet is insecure and should not be exposed

---

# Network Change Detection

One of the main features is the ability to detect network changes.

The tool compares the current scan with the previous scan and identifies:

New devices joining the network

Devices that disappeared

Newly opened ports

Closed ports

Example output:

NEW DEVICES DETECTED

DEVICES NO LONGER PRESENT

SERVICE CHANGE DETECTED

---

# Technologies Used

Python 3

Network scanning techniques

Socket connections for banner grabbing

JSON and CSV data processing

Basic security analysis logic

---

# What I Learned

Through this project I learned how to:

Perform network discovery and scanning

Identify open services on network devices

Extract service banners

Implement simple device fingerprinting

Detect network changes between scans

Generate structured security reports

Organize a technical project for documentation and reproducibility

---

# How I Would Improve the Tool

Future improvements could include:

Continuous network monitoring mode

Alerting when high-risk services appear

MAC address vendor identification

Integration with SIEM tools

Web dashboard for visualization

---

# One Sentence Explanation

"I built a Python-based network asset discovery tool that scans a network, identifies devices and services, detects insecure protocols, and tracks changes in the network over time."
