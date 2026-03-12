# Network Asset Discovery & Security Monitoring Tool

A Python-based network discovery and security monitoring tool designed to identify devices on a network, analyze exposed services, and detect potential security risks.

This project simulates early-stage capabilities found in professional cybersecurity tools used by SOC teams and network administrators.

--------------------------------------------------

PROJECT OVERVIEW

The tool performs automated network scanning and device analysis to provide visibility into devices connected to a network.

It helps identify:

• Unknown devices  
• IoT devices  
• Exposed services  
• Insecure legacy protocols  
• Network changes between scans  

--------------------------------------------------

FEATURES

Network Asset Discovery

Detects active devices on a network using Nmap host discovery.

Device Enumeration

Identifies:

• IP address  
• Hostname  
• MAC address  
• Vendor information  

Device Fingerprinting

Classifies devices based on detected characteristics such as:

• Open ports  
• Vendor information  
• Service banners  
• OS detection  

Possible device classifications include:

• Gateway / Router  
• Workstation  
• IoT Device  
• Smart Device  
• Unknown Device  

--------------------------------------------------

PORT SCANNING

The tool scans commonly used ports including:

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

These ports help identify services running on discovered devices.

--------------------------------------------------

SECURITY RISK DETECTION

The tool flags insecure or risky services.

Examples include:

TELNET (23)  
FTP (21)  
SMB (445)  
RDP (3389)

Example output:

RISK_LEVEL: High  
SECURITY_FLAGS: Telnet is insecure and should not be exposed

--------------------------------------------------

NETWORK CHANGE DETECTION

The tool compares current scan results with previous scans.

It detects:

• New devices connected to the network  
• Devices that disappeared  

Example output:

NEW DEVICES DETECTED:
+ 10.0.0.215

DEVICES NO LONGER PRESENT:
- 10.0.0.103

--------------------------------------------------

SERVICE CHANGE DETECTION

The tool detects changes in exposed services.

Example:

SERVICE CHANGE DETECTED: 10.0.0.221

New open ports:
+ 23(TELNET)

Closed ports:
- 22(SSH)

This capability helps identify configuration changes or suspicious activity.

--------------------------------------------------

OUTPUT FILES

Scan results are exported to:

scan_results.json  
scan_results.csv  

These files allow additional analysis or integration with other tools.

--------------------------------------------------

TECHNOLOGIES USED

Python  
Linux  
Nmap  
TCP sockets  
JSON / CSV data processing  

Python Libraries

python-nmap  
socket  
ssl  
ipaddress  
datetime  

--------------------------------------------------

SECURITY USE CASES

Home network monitoring  
Small business asset visibility  
Cybersecurity lab experiments  
Learning network enumeration techniques  

The project demonstrates concepts used by tools such as:

Nmap  
Nessus  
Lansweeper  
Armis  

--------------------------------------------------

FUTURE IMPROVEMENTS

Possible enhancements include:

• Real-time monitoring  
• Banner detection improvements  
• IoT device identification  
• Web dashboard visualization  
• Security alerting system  

--------------------------------------------------

AUTHOR

Juan Ramos

Cybersecurity and network security learning project.

