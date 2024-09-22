import scapy.all as scapy
import time

def send_arp_inarp():
    # Craft an ARP request packet
    arp_packet_req =  scapy.ARP(op = 8, pdst = "127.0.0.1")
    arp_packet_rep =  scapy.ARP(op = 9, pdst = "127.0.0.1")

    # Send the packet   
    scapy.send(arp_packet_req, iface="lo")
    time.sleep(2)
    scapy.send(arp_packet_rep, iface="lo")

if __name__ == "__main__":
    send_arp_inarp()

