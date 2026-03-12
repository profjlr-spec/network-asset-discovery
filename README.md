# Network Asset Discovery & Security Monitoring Tool

A Python-based network discovery and security monitoring tool designed to identify devices on a network, analyze exposed services, detect security risks, and monitor network changes over time.

This project simulates capabilities commonly found in cybersecurity tools used by SOC teams, network administrators, and security analysts.

--------------------------------------------------

PROJECT OVERVIEW

The tool scans a network to discover connected devices and analyze their characteristics.

It helps identify:

• Unknown devices connected to the network  
• IoT and smart devices  
• Exposed services  
• Insecure legacy protocols  
• Device type using fingerprinting  
• Service banners for better identification  
• Network and service changes between scans  

--------------------------------------------------

KEY FEATURES

Network Asset Discovery

Detects active devices on the network using Nmap host discovery.

Device Enumeration

Collects information about discovered hosts including:

• IP address  
• Hostname  
• MAC address  
• Vendor information  
• Device state  

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

These ports help identify services running on devices.

--------------------------------------------------

DEVICE FINGERPRINTING

The tool performs device fingerprinting using:

• Open ports  
• MAC vendor information  
• Hostnames  
• Service banners  
• OS detection  

Possible device classifications include:

Gateway / Router  
Workstation  
Computer / Laptop  
Printer  
NAS / File Server  
IP Camera  
IoT Device  
Smart Device  
Web Server / Admin Interface  
Unknown Device  

--------------------------------------------------

BANNER DETECTION

The tool attempts to retrieve service banners from open ports.

Banner grabbing helps identify:

• Server software  
• Service type  
• Device manufacturer  
• Embedded device interfaces  

Example banners:

Server: Xfinity Broadband Router Server  
Server: nginx  
Server: Apache  
SSH-2.0-OpenSSH  

This improves device identification and security analysis.

--------------------------------------------------

SECURITY RISK DETECTION

The tool evaluates potential security risks based on detected services and device types.

Examples of risky services:

TELNET (23)  
FTP (21)  
SMB (445)  
RDP (3389)

Example output:

RISK_LEVEL: High  
SECURITY_FLAGS: Telnet is insecure and should not be exposed

Devices are categorized into:

Low  
Medium  
High risk

--------------------------------------------------

IOT AND CAMERA DETECTION

The tool detects possible IoT and camera devices using port combinations and service patterns.

Examples:

RTSP (554) → camera stream  
HTTP / HTTPS admin interfaces  
Embedded web servers

Example detection:

DEVICE_TYPE: IP Camera  
SECURITY_FLAGS: Possible exposed camera admin interface

--------------------------------------------------

NETWORK CHANGE DETECTION

The tool compares the current scan with the previous scan to detect changes.

Example:

NEW DEVICES DETECTED:
+ 10.0.0.215

DEVICES NO LONGER PRESENT:
- 10.0.0.103

This helps identify new devices appearing on the network.

--------------------------------------------------

SERVICE CHANGE DETECTION

The tool also detects changes in exposed services.

Example:

SERVICE CHANGE DETECTED: 10.0.0.221

New open ports:
+ 23(TELNET)

Closed ports:
- 22(SSH)

This helps detect configuration changes or suspicious activity.

--------------------------------------------------

OUTPUT FILES

Scan results are exported to:

scan_results.json  
scan_results.csv  

These files allow further analysis or integration with other tools.

--------------------------------------------------

TECHNOLOGIES USED

Python  
Linux  
Nmap  
TCP sockets  
JSON / CSV processing  

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

EXAMPLE OUTPUT

IP          ROLE        DEVICE_TYPE               OS_GUESS  STATE  OPEN_PORTS                     RISK_LEVEL
10.0.0.1    Gateway     Gateway / Router          Linux     up     53(DNS),80(HTTP),443(HTTPS)   Low
10.0.0.221  Local Host  Workstation               Linux     up     None                           Low

--------------------------------------------------

FUTURE IMPROVEMENTS

Possible enhancements include:

• Real-time monitoring  
• Security alerting system  
• Web dashboard  
• Vulnerability database integration  
• Advanced IoT detection  

--------------------------------------------------

AUTHOR

Juan Ramos

Cybersecurity and network security learning project.

