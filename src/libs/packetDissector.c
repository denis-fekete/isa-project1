/**
 * @file frameDissector.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "packetDissector.h"

// ----------------------------------------------------------------------------
// Ethernet frame
// ----------------------------------------------------------------------------

FrameSections frameDissector(const unsigned char* packet, size_t length)
{     
    EthernetHeader* eth;
    FrameSections frameS;

    eth = (EthernetHeader *) packet;
    printf("Ethernet: \n");
    printf("\tsrc MAC: ");
    printBytes(eth->dst, ETHERNET_ADDR_LEN, ':');
    printf("\n");
    printf("\tdst MAC: ");
    printBytes(eth->src, ETHERNET_ADDR_LEN, ':');
    printf("\n");
    printf("\tframe length: %li bytes\n", length);

    unsigned char protocol;
    switch( uchars2uint16(&(eth->etherType[0])) )
    {
        case ETH_TYPE_IPV4:
            protocol = ipv4Dissector(packet + sizeof(EthernetHeader));

            ipv4ProtocolDissector(protocol, 
                    packet + sizeof(EthernetHeader) + sizeof(struct iphdr), 
                    length - sizeof(EthernetHeader) - sizeof(struct iphdr)
                    );
            
            frameS.dataLen = sizeof(EthernetHeader);
            frameS.networkLen = sizeof(struct iphdr);
            frameS.transportLen = length - frameS.dataLen - frameS.networkLen;
            break;
        case ETH_TYPE_IPV6:
            protocol = ipv6Dissector(packet + sizeof(EthernetHeader));
            ipv6ProtocolDissector(protocol, 
                    packet + sizeof(EthernetHeader) + sizeof(struct ip6_hdr), 
                    length - sizeof(EthernetHeader) - sizeof(struct ip6_hdr)
                    );

            frameS.dataLen = sizeof(EthernetHeader);
            frameS.networkLen = sizeof(struct ip6_hdr);
            frameS.transportLen = length - frameS.dataLen - frameS.networkLen;
            break;
        case ETH_TYPE_ARP:
            arpDissector(packet + sizeof(EthernetHeader));
            frameS.dataLen = sizeof(EthernetHeader);
            frameS.networkLen = length - frameS.dataLen;
            frameS.transportLen = 0;
            break;
        default:
            printf("EtherType: (%hhx %hhx)\n", eth->etherType[0], eth->etherType[1]);
            errHandling("Unknown ether type", 9/*TODO:*/);
            break;
    }

    return frameS;
}

/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
u_int16_t uchars2uint16(unsigned char* value)
{
    //                  LOW         HIGH
    return (u_int16_t) (value[1] +  (value[0] << 8)); 
}

// ----------------------------------------------------------------------------
// Internet Protocol version 4
// ----------------------------------------------------------------------------

unsigned char ipv4Dissector(const unsigned char* packet)
{
    struct iphdr* ipv4 = (struct iphdr*) packet;
    printf("IPv4 Packet:\n");

    printf("\tsrc IP: ");
    printIPv4(ipv4->saddr);

    printf("\tdst IP: ");
    printIPv4(ipv4->daddr);

    return ipv4->protocol;
}

/**
 * @brief Dissector of IPv4 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv4ProtocolDissector(unsigned char protocol, const unsigned char* packet, size_t length)
{
    if(length){}
    printf("\tProtocol: ");
    switch (protocol)
    {
    case IPv4_PROTOCOL_UDP:;
        printf("udp\n");
        struct udphdr* udp = (struct udphdr*) packet;
        printf("\t\tsrc port: %u\n", ntohs(udp->uh_sport)); 
        printf("\t\tdst port: %u\n", ntohs(udp->uh_dport)); 
        break;
    case IPv4_PROTOCOL_TCP:;
        printf("tcp\n");
        struct tcphdr* tcp = (struct tcphdr*) packet;
        printf("\t\tsrc port: %u\n", ntohs(tcp->th_sport)); 
        printf("\t\tdst port: %u\n", ntohs(tcp->th_dport)); 
        break;
    case IPv4_PROTOCOL_ICMP:;
        printf("icmp\n");
        struct icmphdr* icmp = (struct icmphdr*) packet;
        printf("\t\ttype: %u (0x%hhx)\n", icmp->type, icmp->type);
        printf("\t\tcode: %u (0x%hhx)\n", icmp->code, icmp->code);
        break;
    case IPv4_PROTOCOL_IGMP:;
        printf("igmp\n");
        struct igmp* igmp = (struct igmp*) packet;
        printf("\t\ttype: %u (0x%hhx)\n", igmp->igmp_type, igmp->igmp_type);
        printf("\t\tcode: %u (0x%hhx)\n", igmp->igmp_code, igmp->igmp_code);
        printf("\t\tgroup address:\t");
        printIPv4(igmp->igmp_group.s_addr);
        break;
    
    default:
        errHandling("Unknown transport layer protocol", 9/*TODO:*/);
        break;
    }
}

/**
 * @brief Prints IPv4 address in correct endian
 * 
 * @param address IPv4 address
 */
void printIPv4(u_int32_t address)
{
    u_int32_t addressCorrected = ntohl(address);

    for(short i = 24 ; i >= 0 ; i -= 8)
    {
        printf("%hu", (addressCorrected >> i) & 0xFF);
            
        if(i != 0)
        {
            printf(".");
        }
    }

    printf("\n");
}

// ----------------------------------------------------------------------------
// Internet Protocol version 6
// ----------------------------------------------------------------------------

/**
 * @brief Dissects IPv6 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
unsigned char ipv6Dissector(const unsigned char* packet)
{
    struct ip6_hdr* ipv6 = (struct ip6_hdr*) packet;
    printf("IPv6 Packet:\n");

    printf("\tsrc IP: ");
    printIPv6(ipv6->ip6_src.__in6_u.__u6_addr32);

    printf("\tdst IP: ");
    printIPv6(ipv6->ip6_dst.__in6_u.__u6_addr32);

    
    return (unsigned char) packet[sizeof(struct ip6_hdr)];
}

/**
 * @brief Dissector of IPv6 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv6ProtocolDissector(unsigned char protocol, const unsigned char* packet, size_t length)
{
    struct icmp6_hdr* icmp6 = (struct icmp6_hdr*) packet;

    printf("\tProtocol: ");
    if(protocol == IPv6_ICMP_REQUEST || protocol == IPv6_ICMP_REPLY)
    {
        printf("Internet Control Message Protocol version 6 (ICMPv6)\n");
    }
    else if(protocol == IPv6_MLD_QUERY || protocol == IPv6_MLD_REPORT || protocol == IPv6_MLD_DONE)
    {
        printf("Multicast Listener Discovery (MLD)\n");
    }
    else if(protocol == IPv6_NDP_ROUTER_SOLICITATION || 
            protocol == IPv6_NDP_ROUTER_ADVERTISEMENT || 
            protocol == IPv6_NDP_NEIGHBOR_SOLICITATION ||
            protocol == IPv6_NDP_NEIGHBOR_ADVERTISEMENT ||
            protocol == IPv6_NDP_REDIRECT_MESSAGE)
    {
        printf("Neighbor Discovery Protocol (NDP)\n");
    }

    printf("\t\ttype: %u (0x%hhx) ", icmp6->icmp6_type, icmp6->icmp6_type);
    switch(protocol)
    {
        case IPv6_ICMP_REQUEST :;
            printf("(Echo Request)\n");
            break;
        case IPv6_ICMP_REPLY :;
            printf("(Echo Reply)\n");
            break;
        // --------------------------------------------------------------------
        case IPv6_MLD_QUERY :;
            printf("(Multicast Listener Query)\n");
            break;
        case IPv6_MLD_REPORT :;
            printf("(Multicast Listener Report)\n");
            break;
        case IPv6_MLD_DONE :;
            printf("(Multicast Listener Done)\n");
            break;
        // --------------------------------------------------------------------
        case IPv6_NDP_ROUTER_SOLICITATION :;
            printf("(Router Solicitation)\n");
            break;
        case IPv6_NDP_ROUTER_ADVERTISEMENT :;
            printf("(Router Advertisement)\n");
            break;
        case IPv6_NDP_NEIGHBOR_SOLICITATION :;
            printf("(Neighbor Solicitation)\n");
            break;
        case IPv6_NDP_NEIGHBOR_ADVERTISEMENT :;
            printf("(Neighbor Advertisement)\n");
            break;
        // --------------------------------------------------------------------
        case IPv6_NDP_REDIRECT_MESSAGE :;
            printf("(Redirect Message)\n");
            break;
        // --------------------------------------------------------------------
        default:         
            debugPrint(stdout, "\nDEBUG: Unknown protocol: %u\n", protocol);
            errHandling("\nUnknown transport layer protocol", 9/*TODO:*/);
            break;
    }
    printf("\t\tcode: %u (0x%hhx)\n", icmp6->icmp6_code, icmp6->icmp6_type);

    if(length){}
}

/**
 * @brief Prints IPv6 address in correct system endian
 * 
 * @param address pointer to u_int32_t[4]   
 */
void printIPv6(u_int32_t* address)
{
    char buffer[40];
    inet_ntop(AF_INET6, address, buffer, 40);
    
    printf("%s\n", buffer);
}

// ----------------------------------------------------------------------------
// Address Resolution Protocol
// ----------------------------------------------------------------------------

unsigned char arpDissector(const unsigned char* packet)
{
    struct arphdr* arp = (struct arphdr*) packet;
    switch (ntohs(arp->ar_op))
    {
        case ARPOP_REQUEST  :		/* ARP request.  */
            printf("opcode: arp request\n");
            // TODO:
            break;
        case ARPOP_REPLY    :		/* ARP reply.  */
            printf("opcode: arp reply\n");
            // TODO:
            break;
        case ARPOP_RREQUEST :		/* RARP request.  */
            printf("opcode: rarp request\n");
            // TODO:
            break;
        case ARPOP_RREPLY   :		/* RARP reply.  */
            printf("opcode: rarp reply\n");
            // TODO:
            break;
        case ARPOP_InREQUEST:		/* InARP request.  */
            printf("opcode: inarp request\n");
            // TODO:
            break;
        case ARPOP_InREPLY  :		/* InARP reply.  */
            printf("opcode: inarp reply\n");
            // TODO:
            break;
        case ARPOP_NAK      :		/* (ATM)ARP NAK.  */
            printf("opcode: (atm) arp nak\n");
            // TODO:
            break;
    default:
        break;
    }

    return 0;
}