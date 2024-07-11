from scapy.all import sniff, IP

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
            payload = packet.getlayer('TCP').payload
        elif proto == 17:
            protocol = "UDP"
            payload = packet.getlayer('UDP').payload
        else:
            protocol = "Other"
            payload = None

        print(f"Source: {src_ip}")
        print(f"Destination: {dst_ip}")
        print(f"Protocol: {protocol}")
        if payload:
            print(f"Payload: {payload}")
        print("=" * 40)

print("Packet sniffer started...")
sniff(prn=analyze_packet, store=False)
