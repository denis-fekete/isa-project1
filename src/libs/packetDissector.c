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

            transportLayerDissector(protocol, packet + sizeof(EthernetHeader) + sizeof(struct iphdr));
            break;
        case ETH_TYPE_IPV6:
            ipv6Dissector(packet + sizeof(EthernetHeader) + sizeof(struct ip6_hdr));
            break;
        case ETH_TYPE_ARP:
            arpDissector(packet + sizeof(EthernetHeader) + sizeof(struct arphdr));
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
    printf("%02hu", (address >> 24) & 0xFF);
    printf(".");
    printf("%02hu", (address >> 16) & 0xFF);
    printf(".");
    printf("%02hu", (address >> 8) & 0xFF);
    printf(".");
    printf("%02hu", (address >> 0) & 0xFF);
    printf("\n");
}

void transportLayerDissector(unsigned char protocol, const unsigned char* packet)
{
    switch (protocol)
    {
    case PROTOCOL_UDP:;
        struct udphdr* udp = (struct udphdr*) packet;
        printf("src port: %u\n", ntohs(udp->uh_sport)); 
        printf("dst port: %u\n", ntohs(udp->uh_dport)); 
        break;
    case PROTOCOL_TCP:;
        struct tcphdr* tcp = (struct tcphdr*) packet;
        printf("src port: %u\n", ntohs(tcp->th_sport)); 
        printf("dst port: %u\n", ntohs(tcp->th_dport)); 
        break;
    case PROTOCOL_ICMP:;
        /* do not print anything*/
        break;
    case PROTOCOL_IGMP:;
        /* do not print anything*/
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
    if(packet ) {}
    return 0;
}