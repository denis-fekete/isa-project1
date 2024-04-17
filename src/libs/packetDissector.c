/**
 * @file frameDissector.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "packetDissector.h"


void frameDissector(const unsigned char* packet, size_t length)
{     
    EthernetHeader* eth;

    eth = (EthernetHeader *) packet;
    printf("src MAC: ");
    printBytes(eth->dst, ETHERNET_ADDR_LEN, ':');
    printf("\n");
    printf("dst MAC: ");
    printBytes(eth->src, ETHERNET_ADDR_LEN, ':');
    printf("\n");
    printf("frame length: %li bytes\n", length);

    unsigned char protocol;
    switch( uchars2uint16(&(eth->etherType[0])) )
    {
        case ETH_TYPE_IPV4:
            protocol = ipv4Dissector(packet + sizeof(EthernetHeader));

            ipv4ProtocolDissector(protocol, packet + sizeof(EthernetHeader) + sizeof(struct iphdr));
            break;
        case ETH_TYPE_IPV6:
            ipv6Dissector(packet + sizeof(EthernetHeader));
            break;
        case ETH_TYPE_ARP:
            arpDissector(packet + sizeof(EthernetHeader));
            break;
        default:
            printf("EtherType: (%hhx %hhx)\n", eth->etherType[0], eth->etherType[1]);
            errHandling("Unknown ether type", 9/*TODO:*/);
            break;
    }

    if(length) {}
}

u_int16_t uchars2uint16(unsigned char* value)
{
    //                  LOW         HIGH
    return (u_int16_t) (value[1] +  (value[0] << 8)); 
}


void printIPV4(u_int32_t address)
{
    printf("%hu", (address >> 24) & 0xFF);
    printf(".");
    printf("%hu", (address >> 16) & 0xFF);
    printf(".");
    printf("%hu", (address >> 8) & 0xFF);
    printf(".");
    printf("%hu", (address >> 0) & 0xFF);
    printf("\n");
}

void ipv4ProtocolDissector(unsigned char protocol, const unsigned char* packet)
{
    switch (protocol)
    {
    case PROTOCOL_UDP:;
        printf("protocol: udp\n");
        struct udphdr* udp = (struct udphdr*) packet;
        printf("src port: %u\n", ntohs(udp->uh_sport)); 
        printf("dst port: %u\n", ntohs(udp->uh_dport)); 
        break;
    case PROTOCOL_TCP:;
        printf("protocol: tcp\n");
        struct tcphdr* tcp = (struct tcphdr*) packet;
        printf("src port: %u\n", ntohs(tcp->th_sport)); 
        printf("dst port: %u\n", ntohs(tcp->th_dport)); 
        break;
    case PROTOCOL_ICMP:;
        printf("protocol: icmp\n");
        struct icmphdr* icmp = (struct icmphdr*) packet;
        printf("type: %u (0x%hhx)\n", icmp->type, icmp->type);
        printf("code: %u (0x%hhx)\n", icmp->code, icmp->code);
        break;
    case PROTOCOL_IGMP:;
        printf("protocol: igmp\n");
        struct igmp* igmp = (struct igmp*) packet;
        printf("type: %u (0x%hhx)\n", igmp->igmp_type, igmp->igmp_type);
        printf("code: %u (0x%hhx)\n", igmp->igmp_code, igmp->igmp_code);
        printf("group address: ");
        printIPV4( ntohl(igmp->igmp_group.s_addr) );
        break;
    
    default:
        errHandling("Unknown transport layer protocol", 9/*TODO:*/);
        break;
    }
}

unsigned char ipv4Dissector(const unsigned char* packet)
{
    struct iphdr* ipv4 = (struct iphdr*) packet;

    printf("src IP: ");
    // print ipv4 address by bytes, need to convert it into system endian
    printIPV4(ntohl(ipv4->saddr));
    printf("dst IP: ");
    // print ipv4 address by bytes, need to convert it into system endian
    printIPV4(ntohl(ipv4->daddr));

    return ipv4->protocol;
}

unsigned char ipv6Dissector(const unsigned char* packet)
{
    if(packet ) {}
    return 0;
}

unsigned char arpDissector(const unsigned char* packet)
{
    struct arphdr* arp = (struct arphdr*) packet;
    switch (ntohs(arp->ar_op))
    {
        case ARPOP_REQUEST  :		/* ARP request.  */
            printf("opcode: arp request\n");
            break;
        case ARPOP_REPLY    :		/* ARP reply.  */
            printf("opcode: arp reply\n");
            break;
        case ARPOP_RREQUEST :		/* RARP request.  */
            printf("opcode: rarp request\n");
            break;
        case ARPOP_RREPLY   :		/* RARP reply.  */
            printf("opcode: rarp reply\n");
            break;
        case ARPOP_InREQUEST:		/* InARP request.  */
            printf("opcode: inarp request\n");
            break;
        case ARPOP_InREPLY  :		/* InARP reply.  */
            printf("opcode: inarp reply\n");
            break;
        case ARPOP_NAK      :		/* (ATM)ARP NAK.  */
            printf("opcode: (atm) arp nak\n");
            break;
    default:
        break;
    }

    return 0;
}


// void icmpPrint()
// {
    // switch(icmp->type)
    // {
    //     case 3:
    //         switch(icmp->code)
    //         {
    //             case 0: printf("net unreachable"); break;
    //             case 1: printf("host unreachable"); break;
    //             case 2: printf("protocol unreachable"); break;
    //             case 3: printf("port unreachable"); break;
    //             case 4: printf("fragmentation needed by DF set"); break;
    //             case 5: printf("source route failed"); break;
    //         }
    //         break;
    //     case 11:
    //         switch(icmp->code)
    //         {
    //             case 0: printf("time to live exceeded in transit"); break;
    //             case 1: printf("fragment reassembly time exceeded"); break;
    //         }
    //         break;
    //     case 12:;
    //         // error detected, print error message contained in protocol
    //         const unsigned char* pointer_pos = &packet[31];
    //         const unsigned char pointer = ntohs(((unsigned char)*pointer_pos));
    //         printf("%s", &(originalPacket[packet[pointer]]));
    //         break;
    // }
// }