# Learning Notes
Network Asset Discovery Tool

Author: Juan Ramos
Project: Network Asset Discovery Tool
Language: Python
Environment: Linux

--------------------------------------------------

PROJECT PURPOSE

The goal of this project is to build a practical network discovery tool
that scans a local network and identifies connected devices.

This project helps develop skills in:

- Linux networking
- Python scripting
- Network scanning
- IT automation
- Security reconnaissance

This type of tool is similar to the first step performed during a
network security assessment or penetration test.

--------------------------------------------------

WHAT THE TOOL DOES

The tool scans the local network and gathers information about devices.

The script performs the following tasks:

1. Detects the local network range
2. Identifies the gateway
3. Scans the network for active hosts
4. Attempts OS detection using nmap
5. Identifies open ports
6. Attempts to determine device type
7. Displays results in a table
8. Saves results to JSON and CSV files

Example output fields:

- IP address
- Device role
- Device type
- OS guess
- Hostname
- Device state
- Open ports
- MAC address
- Vendor

--------------------------------------------------

WHY THIS PROJECT IS IMPORTANT

This project simulates real tasks used by:

- Network engineers
- Cybersecurity analysts
- IT administrators
- Penetration testers

Before securing a network, professionals must first
discover what devices exist on the network.

This process is called:

Network Discovery
or
Network Enumeration

--------------------------------------------------

TECHNOLOGIES USED

Python
Linux
Nmap
ARP scanning
JSON data export
CSV reporting

Python libraries used:

python-nmap
socket
subprocess
datetime
csv
json

--------------------------------------------------

SKILLS PRACTICED

Linux command line usage
Python scripting
Network scanning techniques
Basic automation
Parsing command output
Data formatting
Writing structured output files

--------------------------------------------------

LESSONS LEARNED

Network scanning can take time depending on:

- network size
- scanning method
- OS detection
- number of hosts

OS detection using Nmap is powerful but slow.

For this reason the script was improved in Version 3
to limit OS detection to key devices such as:

- gateway
- local machine

This significantly improves scan speed.

--------------------------------------------------

REAL WORLD APPLICATION

Tools like this are commonly used in:

Network troubleshooting
Asset inventory
Security audits
Incident response
Penetration testing

Many enterprise tools perform similar functions:

Nmap
Nessus
OpenVAS
Qualys
Rapid7 InsightVM

--------------------------------------------------

FUTURE IMPROVEMENTS

Possible improvements for this tool include:

- threaded scanning for faster results
- service detection
- web interface
- network topology visualization
- scheduled automated scans
- alerting when new devices appear

--------------------------------------------------

INTERVIEW TALKING POINT

If asked about this project in an interview:

"I built a Python-based network discovery tool that scans
a local network, identifies devices, performs OS detection,
and generates structured reports in JSON and CSV format.
The goal of the project was to practice Linux networking,
automation, and security reconnaissance techniques."

--------------------------------------------------

END OF FILE
