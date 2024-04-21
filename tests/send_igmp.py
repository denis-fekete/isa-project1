from scapy.all import IP, send
from scapy.contrib.igmp import *

def send_igmp():
    # Craft an IGMP packet
    igmp_packet = IP(dst="127.0.0.1")/IGMP(type=0x16, gaddr="152.30.62.5")

    # Send the packet on the loopback interface
    send(igmp_packet, iface="lo")

if __name__ == "__main__":
    send_igmp()