from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, send

def send_icmpv6_packets():
    # Create an IPv6 ICMPv6 Echo Request packet
    echo_request_packet = IPv6(dst="::1", src="1234:5678:9abc:deff:1234:5678:9abc:deff") / ICMPv6EchoRequest()

    # Create an IPv6 ICMPv6 Echo Reply packet
    echo_reply_packet = IPv6(dst="::1", src="1234:5678:9abc:deff:1234:5678:9abc:deff") / ICMPv6EchoReply()

    # Send the packets over the loopback interface
    send(echo_request_packet, iface="lo")
    send(echo_reply_packet, iface="lo")

if __name__ == "__main__":
    send_icmpv6_packets()
