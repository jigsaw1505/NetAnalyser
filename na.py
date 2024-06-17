from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        print(f"IP Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        if protocol == 6:  # TCP Protocol
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
        elif protocol == 17:  # UDP Protocol
            udp_layer = packet[UDP]
            print(f"UDP Packet: {src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}")

        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")
        print("\n")

def start_sniffing(interface):
    print(f"[*] Starting packet sniffer on {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    interface = input("Enter the interface you want to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)
