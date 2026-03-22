# Network-Security-Sniffer 🛡️

A Python-based network analysis tool for educational purposes. Performs ARP spoofing, DNS logging, and HTTP credential sniffing using the Scapy library.

## ⚠️ LEGAL DISCLAIMER
**THIS TOOL IS FOR EDUCATIONAL AND ETHICAL TESTING PURPOSES ONLY.**
- **Authorization:** Only use this script on networks and devices you own or have explicit written permission to test.
- **Liability:** The author is not responsible for any misuse, damage, or legal consequences caused by this program.
- **Risk:** ARP spoofing can cause network instability. Use with caution.

## Features
- **ARP Spoofing**: Man-in-the-Middle (MITM) attack to redirect traffic.
- **DNS Logging**: Intercepts and displays all domain name requests.
- **HTTP Sniffing**: Extracts URLs and potential login credentials from unencrypted traffic.
- **Auto-Restore**: Automatically repairs ARP tables upon exit.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yassir030/Network-Security-Sniffer
2. go in to files
   ```bash
   cd Network-Security-Sniffer
3. install requirements
   ```bash
   sudo pip3 install -r requirements.txt
4. IP Forwarding
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
5. run the script
   ```bash
   sudo python3 network_sniffer.py

