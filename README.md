# prodigy_cs_05
import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"Payload: {payload}")

# Take user input for the network interface
network_interface = input("Enter the network interface (e.g., eth0): ")
sniff(network_interface)