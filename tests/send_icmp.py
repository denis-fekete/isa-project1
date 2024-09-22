from scapy.all import IP, ICMP, send

def send_icmp():
    # Craft an ICMP Echo Request packet with destination IP 127.0.0.1
    icmp_packet = IP(dst="127.0.0.1") / ICMP()

    # Send the packet
    send(icmp_packet)

if __name__ == "__main__":
    send_icmp()