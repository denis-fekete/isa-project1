from scapy.all import IPv6, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, send

def send_ndp_packets():
    # Create an IPv6 NDP Router Solicitation packet
    rs_packet = IPv6(dst="::1") / ICMPv6ND_RS()

    # Create an IPv6 NDP Router Advertisement packet
    ra_packet = IPv6(dst="::1") / ICMPv6ND_RA(routerlifetime=1800)

    # Create an IPv6 NDP Neighbor Solicitation packet
    ns_packet = IPv6(dst="::1") / ICMPv6ND_NS()

    # Create an IPv6 NDP Neighbor Advertisement packet
    na_packet = IPv6(dst="::1") / ICMPv6ND_NA()

    # Create an IPv6 NDP Redirect packet
    redirect_packet = IPv6(dst="::1") / ICMPv6ND_Redirect()

    # Send the packets over the loopback interface
    send(rs_packet, iface="lo")
    send(ra_packet, iface="lo")
    send(ns_packet, iface="lo")
    send(na_packet, iface="lo")
    send(redirect_packet, iface="lo")

if __name__ == "__main__":
    send_ndp_packets()
