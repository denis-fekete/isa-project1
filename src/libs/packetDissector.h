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
#include "netinet/icmp6.h"
#include "arpa/inet.h"

#include "netinet/igmp.h"


// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ethernet header length
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

typedef struct FrameSections
{
    unsigned int dataLen;
    unsigned int networkLen;
    unsigned int transportLen;
} FrameSections;

typedef struct EthernetHeader
{
    // destination address
    unsigned char dst[ETHERNET_ADDR_LEN];
    // source address
    unsigned char src[ETHERNET_ADDR_LEN];
    // ether type
    unsigned char etherType[2];
} EthernetHeader; 

#define IPv4_PROTOCOL_TCP 0x06
#define IPv4_PROTOCOL_UDP 0x11
#define IPv4_PROTOCOL_ICMP 0x01
#define IPv4_PROTOCOL_IGMP 0x02

#define IPv6_ICMP_REQUEST 0x80 /*128*/
#define IPv6_ICMP_REPLY 0x81 /*129*/

#define IPv6_MLD_QUERY 0x82 /*130*/
#define IPv6_MLD_REPORT 0x83 /*131*/
#define IPv6_MLD_DONE 0x84 /*132*/

#define IPv6_NDP_ROUTER_SOLICITATION 0x85 /*133*/
#define IPv6_NDP_ROUTER_ADVERTISEMENT 0x86 /*134*/
#define IPv6_NDP_NEIGHBOR_SOLICITATION 0x87 /*135*/
#define IPv6_NDP_NEIGHBOR_ADVERTISEMENT 0x88 /*136*/
#define IPv6_NDP_REDIRECT_MESSAGE 0x89 /*137*/



#define IP_VER_4 0
#define IP_VER_6 1

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

u_int16_t uchars2uint16(unsigned char* value);

// ----------------------------------------------------------------------------
// Ethernet frame
// ----------------------------------------------------------------------------

FrameSections frameDissector(const unsigned char* packet, size_t length);

// ----------------------------------------------------------------------------
// Internet Protocol version 4
// ----------------------------------------------------------------------------

/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
unsigned char ipv4Dissector(const unsigned char* packet);

/**
 * @brief Dissector of IPv4 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv4ProtocolDissector(unsigned char protocol, const unsigned char* packet, size_t length);

/**
 * @brief Prints IPv4 address in correct endian
 * 
 * @param address IPv4 address
 */
void printIPv4(u_int32_t address);

// ----------------------------------------------------------------------------
// Internet Protocol version 6
// ----------------------------------------------------------------------------

/**
 * @brief Dissects IPv6 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
unsigned char ipv6Dissector(const unsigned char* packet);

/**
 * @brief Dissector of IPv6 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv6ProtocolDissector(unsigned char protocol, const unsigned char* packet, size_t length);

/**
 * @brief Prints IPv6 address in correct system endian
 * 
 * @param address pointer to u_int32_t[4]   
 */
void printIPv6(u_int32_t* address);

// ----------------------------------------------------------------------------
// Address Resolution Protocol
// ----------------------------------------------------------------------------

unsigned char arpDissector(const unsigned char* packet);

#endif /*PACKET_DISSECTOR_H*/