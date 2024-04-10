/**
 * @file packetDissector.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "packetDissector.h"


void packetDissector(const unsigned char* packet, size_t length)
{     
    EthernetHeader* eth;

    eth = (EthernetHeader *) packet;
    printf("src MAC: ");
    printBytes(eth->dst, ETHERNET_ADDR_LEN);
    printf("\n");
    printf("dst MAC: ");
    printBytes(eth->src, ETHERNET_ADDR_LEN);
    printf("\n");
    printf("frame length: %li bytes\n", length);

    if(eth->etherType[0] == ETHERTYPE_IPV4_HIGH && eth->etherType[1] == ETHERTYPE_IPV4_LOW)
    {
        if(1) // TODO: differ icmp from ipv4
        {
            ipv4Dissector(packet + sizeof(EthernetHeader), length);
        }
        else
        {
            icmpDissector(packet + sizeof(EthernetHeader), length);
        }
    }
    else if (eth->etherType[0] == ETHERTYPE_IPV6_HIGH && eth->etherType[1] == ETHERTYPE_IPV6_LOW)
    {
        ipv6Dissector(packet + sizeof(EthernetHeader), length);
    }
    else if (eth->etherType[0] == ETHERTYPE_ARP_HIGH && eth->etherType[1] == ETHERTYPE_ARP_LOW)
    {
        arpDissector(packet + sizeof(EthernetHeader), length);
    }
    else
    {
        printf("EtherType: (%hhx %hhx)\n", eth->etherType[0], eth->etherType[1]);
        errHandling("Unknown ether type", 9/*TODO:*/);
    }

    if(length) {}
}

u_int8_t uchars2uint8(unsigned char* value)
{
    //                  LOW         HIGH
    return (u_int8_t) (value[1] +  (value[0] << 8)); 
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

void transportLayerDissector(unsigned char protocol, const unsigned char* packet, size_t length)
{
    switch (protocol)
    {
    case PROTOCOL_UDP:
        break;
    case PROTOCOL_TCP:
        break;
    case PROTOCOL_ICMP:
        break;
    case PROTOCOL_IGMP:
        break;
    default:
        errHandling("Unknown transport layer protocol", 9/*TODO:*/);
        break;
    }
}

void ipv4Dissector(const unsigned char* packet, size_t length)
{
    struct iphdr* ipv4 = (struct iphdr*) packet;

    printf("src IP: ");
    // print ipv4 address by bytes, need to convert it into system endian
    printIPV4(ntohl(ipv4->saddr));
    printf("dst IP: ");
    // print ipv4 address by bytes, need to convert it into system endian
    printIPV4(ntohl(ipv4->daddr));

    transportLayerDissector(ipv4->protocol, packet + sizeof(struct iphdr), length);

    if(packet && length && ipv4) {}
}

void icmpDissector(const unsigned char* packet, size_t length)
{
    struct icmphdr* icmp = (struct icmphdr*) packet;
    
    if(packet && length && icmp) {}
}

void ipv6Dissector(const unsigned char* packet, size_t length)
{

    if(packet && length) {}
}

void arpDissector(const unsigned char* packet, size_t length)
{
    if(packet && length) {}
}