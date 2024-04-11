/**
 * @file frameDissector.h
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
#include "netinet/udp.h"
#include "netinet/ip_icmp.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ethernet header lenght
#define ETHERNET_ADDR_LEN 6
// // size of ethernet head
#define ETH_TYPE_IPV6_LOW 0xDD
#define ETH_TYPE_IPV6_HIGH 0x86
#define ETH_TYPE_IPV6 0x86DD

#define ETH_TYPE_ARP_LOW 0x06
#define ETH_TYPE_ARP_HIGH 0x08
#define ETH_TYPE_ARP 0x0806

#define ETH_TYPE_IPV4_LOW 0x00
#define ETH_TYPE_IPV4_HIGH 0x08
#define ETH_TYPE_IPV4 0x0800

typedef struct EthernetHeader
{
    // destination address
    unsigned char dst[ETHERNET_ADDR_LEN];
    // source address
    unsigned char src[ETHERNET_ADDR_LEN];
    // ether type
    unsigned char etherType[2];
} EthernetHeader; 

#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11
#define PROTOCOL_ICMP 0x01
#define PROTOCOL_IGMP 0x02

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

void frameDissector(const unsigned char* packet, size_t length);
void printIPV4(u_int32_t address);
u_int16_t uchars2uint16(unsigned char* value);
void transportLayerDissector(unsigned char protocol, const unsigned char* packet);

unsigned char ipv4Dissector(const unsigned char* packet);
unsigned char ipv6Dissector(const unsigned char* packet);
unsigned char arpDissector(const unsigned char* packet);

#endif /*PACKET_DISSECTOR_H*/