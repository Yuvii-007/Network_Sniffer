
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        proto_name = {
            6: 'TCP',
            17: 'UDP',
            1: 'ICMP'
        }.get(protocol, f'Other ({protocol})')

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto_name}")

        # Display payload if exists
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                try:
                    print(f"    Payload        : {payload.decode('utf-8', errors='replace')}")
                except:
                    print("    Payload        : <Non-text data>")
        elif packet.haslayer(ICMP):
            print("    ICMP packet received.")

# Start sniffing (interface can be specified, e.g., iface='eth0')
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
