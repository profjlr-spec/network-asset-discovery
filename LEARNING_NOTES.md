# Network Asset Discovery Tool — Learning Notes

This document summarizes the key technical concepts and lessons learned while developing the Network Asset Discovery & Security Monitoring Tool.

--------------------------------------------------

PROJECT PURPOSE

The goal of this project was to build a practical cybersecurity learning tool capable of discovering devices on a network, analyzing exposed services, and detecting potential security risks.

The project helped reinforce important networking and security concepts through hands-on development.

--------------------------------------------------

NETWORK DISCOVERY

One of the first concepts explored was network discovery.

The tool uses Nmap host discovery to identify active devices on a network.

Key concepts learned:

- IP addressing
- Network ranges (CIDR notation)
- Host discovery techniques
- ARP and ICMP responses

Understanding how devices respond to discovery probes is fundamental for network enumeration.

--------------------------------------------------

PORT SCANNING

The project introduced the concept of port scanning.

Each device may expose services through open ports.

Common ports used in the tool include:

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

Scanning these ports allows identification of services running on a device.

--------------------------------------------------

DEVICE ENUMERATION

Device enumeration collects detailed information about each host.

Information gathered includes:

- IP address
- hostname
- MAC address
- vendor information
- open ports
- operating system guess

This creates a basic inventory of network assets.

--------------------------------------------------

DEVICE FINGERPRINTING

Device fingerprinting attempts to determine what type of device is present on the network.

The tool uses indicators such as:

- open ports
- vendor information
- service patterns
- OS guesses

Example device classifications:

Gateway / Router  
Workstation  
IoT Device  
Smart Device  
Unknown Device  

This technique is commonly used in network security monitoring.

--------------------------------------------------

SECURITY RISK IDENTIFICATION

The project introduced basic risk detection based on exposed services.

Some services are considered higher risk due to weak security or legacy protocols.

Examples:

TELNET (23)  
FTP (21)  
SMB (445)  
RDP (3389)

When these services are detected, the tool increases the risk level and adds security warnings.

--------------------------------------------------

NETWORK CHANGE DETECTION

The tool compares results between scans to detect changes.

This includes:

New devices appearing on the network

Example:

NEW DEVICES DETECTED:
+ 10.0.0.215

Devices disappearing from the network

Example:

DEVICES NO LONGER PRESENT:
- 10.0.0.103

This concept is important for network monitoring and intrusion detection.

--------------------------------------------------

SERVICE CHANGE DETECTION

The tool also monitors changes in open ports.

Example:

SERVICE CHANGE DETECTED: 10.0.0.221

New open ports:
+ 23(TELNET)

Closed ports:
- 22(SSH)

Monitoring service changes helps identify configuration changes or suspicious activity.

--------------------------------------------------

WORKING WITH NMAP IN PYTHON

The project used the python-nmap library to integrate Nmap scanning into Python scripts.

This allowed automated scanning and parsing of scan results.

Key lesson:

Automation of security tools using Python is extremely powerful.

--------------------------------------------------

WORKING WITH SOCKETS

Basic socket communication was used for service interaction and banner detection.

Concepts explored:

- TCP connections
- service responses
- banner grabbing techniques

These techniques are commonly used in penetration testing and service analysis.

--------------------------------------------------

DATA EXPORT AND REPORTING

Scan results are saved in two formats:

JSON  
CSV  

These formats allow easy integration with other tools or further analysis.

--------------------------------------------------

CYBERSECURITY SKILLS DEVELOPED

This project helped develop practical skills in:

Network enumeration  
Security monitoring  
Python scripting for security tools  
Understanding exposed services  
Analyzing network devices  

--------------------------------------------------

PERSONAL TAKEAWAY

Building this tool demonstrated how important network visibility is in cybersecurity.

Without knowing what devices exist on a network, it is difficult to properly secure it.

Hands-on projects like this help bridge the gap between theory and real-world security practices.

