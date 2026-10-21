from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap


captured_packets = []
SAVE_TO_PCAP = False  
PCAP_FILENAME = "captured_traffic.pcap"


def format_payload(packet, max_bytes=48):
    """Safely formats the payload into readable ASCII representation."""
    if Raw in packet:
        raw_data = bytes(packet[Raw].load)
        
        readable = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_data[:max_bytes])
        if len(raw_data) > max_bytes:
            readable += "..."
        return readable
    return "No Payload"


def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        version = "IPv4"
        ttl = packet[IP].ttl
    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        version = "IPv6"
        ttl = packet[IPv6].hlim
    else:
        
        return

    
    if TCP in packet:
        protocol = "TCP"
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
    elif UDP in packet:
        protocol = "UDP"
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif ICMP in packet or packet.haslayer("ICMPv6"):
        protocol = "ICMP / ICMPv6"
        ports = "N/A"
    else:
        protocol = "Other"
        ports = "N/A"

    
    print("=" * 60)
    print(f"Timestamp:    {timestamp}")
    print(f"IP Version:   {version} (TTL/Hop Limit: {ttl})")
    print(f"Protocol:     {protocol}")
    print(f"Source:       {source}")
    print(f"Destination:  {destination}")
    print(f"Ports:        {ports}")
    print(f"Packet Size:  {len(packet)} bytes")
    print(f"Payload Data: {format_payload(packet)}")

    if SAVE_TO_PCAP:
        captured_packets.append(packet)


def main():
    print("=== BASIC NETWORK SNIFFER ===")
    print("Capturing packets. Press Ctrl+C to stop.")
    
    
    packet_filter = ""

    try:
        
        sniff(filter=packet_filter, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user.")
        if SAVE_TO_PCAP and captured_packets:
            print(f"[+] Saving {len(captured_packets)} packets to {PCAP_FILENAME}...")
            wrpcap(PCAP_FILENAME, captured_packets)
            print("[+] Done.")
    except PermissionError:
        print("\n[-] Error: Root/Administrator privileges are required to sniff packets.")
    except Exception as error:
        print(f"\n[-] Error: {error}")


if __name__ == "__main__":
    main()