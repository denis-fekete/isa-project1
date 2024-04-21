import socket
import struct
import time

# Define constants
LOOPBACK_IPv4 = '127.0.0.1'
LOOPBACK_IPv6 = '::1'
LOOPBACK_INTERFACE = 'lo'

def send_arp_packet():
    arp_packet = b'\xff\xff\xff\xff\xff\xff'  # Destination MAC address (broadcast)
    arp_packet += b'\x00\x00\x00\x00\x00\x00'  # Source MAC address
    arp_packet += b'\x08\x06'  # EtherType (ARP)
    arp_packet += b'\x00\x01'  # Hardware Type (Ethernet)
    arp_packet += b'\x08\x00'  # Protocol Type (IPv4)
    arp_packet += b'\x06\x04'  # Hardware Size (Ethernet MAC - 6 bytes), Protocol Size (IPv4 - 4 bytes)
    arp_packet += b'\x00\x01'  # Opcode (Request)
    arp_packet += b'\x00\x00\x00\x00\x00\x00'  # Sender MAC address
    arp_packet += socket.inet_aton('192.168.1.1')  # Sender IP address
    arp_packet += b'\x00\x00\x00\x00\x00\x00'  # Target MAC address (ignored in ARP request)
    arp_packet += socket.inet_aton('192.168.1.2')  # Target IP address

    send_packet(arp_packet, socket.AF_PACKET)

def send_icmp_packet(version):
    if version == 4:
        ip_dest = LOOPBACK_IPv4
    elif version == 6:
        ip_dest = LOOPBACK_IPv6

    icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0)  # ICMP Echo Request
    icmp_packet += b'Hello, World!'  # Payload

    send_packet(icmp_packet, socket.AF_INET if version == 4 else socket.AF_INET6, ip_dest)

def send_igmp_packet():
    igmp_packet = b'\x11\x22\x33\x44'  # Type (Membership Query)
    igmp_packet += b'\x00\x00'  # Max Response Time
    igmp_packet += b'\xe0\x00\x00\x01'  # Group Address

    send_packet(igmp_packet, socket.AF_INET)

def send_mld_packet():
    mld_packet = b'\x8f'  # Type (Multicast Listener Query)
    mld_packet += b'\x00'  # Maximum Response Code
    mld_packet += b'\x00\x00'  # Checksum
    mld_packet += b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'  # Multicast Address

    send_packet(mld_packet, socket.AF_INET6)

def send_ndp_packet():
    ndp_packet = b'\x86\xdd'  # Next Header (ICMPv6)
    ndp_packet += b'\x60'  # Hop Limit (64)
    ndp_packet += b'\x00\x24'  # ICMPv6 Length
    ndp_packet += b'\x87'  # Type (Neighbor Solicitation)
    ndp_packet += b'\x00'  # Code
    ndp_packet += b'\x00\x00'  # Checksum
    ndp_packet += b'\x00\x01\x00\x00\x00\x00\x00\x00'  # Target Address

    send_packet(ndp_packet, socket.AF_INET6)

def send_packet(packet, address_family, dest_ip=None):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as s:
        s.bind((LOOPBACK_INTERFACE, 0))

        if dest_ip:
            s.sendto(packet, (dest_ip, 0))
        else:
            s.send(packet)


if __name__ == "__main__":
    send_arp_packet()
    send_icmp_packet(4)
    send_icmp_packet(6)
    send_igmp_packet()
    send_mld_packet()
    send_ndp_packet()