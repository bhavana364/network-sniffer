# Network Sniffer

A basic network sniffer using python and scapy .
** this project is intended for educational and ethical purposes only **
//capture packets only on network you own or have explicit permission to monitor.//


A lightweight Python-based network packet sniffer built using [Scapy](https://scapy.net/).  
This tool captures live network traffic, processes packets, and optionally saves them to a `.pcap` file for further analysis.

---

## ✨ Features
- Capture IPv4 and IPv6 packets
- Identify network protocols like TCP, UDP, and ICMP protocols
- Extract and display packet metadata (source, destination, TTL, etc.)
- Safe payload formatting into human-readable ASCII
- Optional saving of captured traffic to a `.pcap` file
- Timestamped logging of packet activity

---

## 📦 Requirements
- Python 3.7+
- [Scapy](https://scapy.net/) library
-npcap 

Install dependencies:
```bash
pip install scapy
