from scapy.all import IPv6, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6MLDone, send
import time

def send_mld_packets():
    # Create an IPv6 ICMP MLD Query packet
    query_packet = IPv6(dst="::1") / ICMPv6MLQuery()

    # Create an IPv6 ICMP MLD Report packet
    report_packet = IPv6(dst="::1") / ICMPv6MLReport()

    # Create an IPv6 ICMP MLD Done packet
    done_packet = IPv6(dst="::1") / ICMPv6MLDone()

    # Send the packets over the loopback interface
    send(query_packet, iface="lo")
    send(report_packet, iface="lo")
    send(done_packet, iface="lo")

if __name__ == "__main__":
    send_mld_packets()
