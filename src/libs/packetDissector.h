/**
 * @file packetDissector.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief //TODO:
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef PACKET_DISSECTOR_H
#define PACKET_DISSECTOR_H


// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------


#include "utils.h"
#include "netinet/ether.h"
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/tcp.h"
#include "netinet/ip_icmp.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ethernet header lenght
#define ETHERNET_ADDR_LEN 6
// // size of ethernet head
#define ETHERTYPE_IPV6_LOW 0xDD
#define ETHERTYPE_IPV6_HIGH 0x86
#define ETHERTYPE_ARP_LOW 0x06
#define ETHERTYPE_ARP_HIGH 0x08
#define ETHERTYPE_IPV4_LOW 0x00
#define ETHERTYPE_IPV4_HIGH 0x08

typedef struct EthernetHeader
{
    // destination address
    unsigned char dst[ETHERNET_ADDR_LEN];
    // source address
    unsigned char src[ETHERNET_ADDR_LEN];
    // ether type
    unsigned char etherType[2];
} EthernetHeader; 

// // typedef struct ipHeader
// // {

// // } ipHeader;

#define PROTOCOL_ICMP 0x01
#define PROTOCOL_IGMP 0x02
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11

// typedef struct tcpHeader
// {

// } tcpHeader;

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

void packetDissector(const unsigned char* packet, size_t length);

void ipv4Dissector(const unsigned char* packet, size_t length);
void icmpDissector(const unsigned char* packet, size_t length);
void ipv6Dissector(const unsigned char* packet, size_t length);
void arpDissector(const unsigned char* packet, size_t length);

#endif /*PACKET_DISSECTOR_H*/