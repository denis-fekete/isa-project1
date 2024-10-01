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
#include "netinet/udp.h"
#include "netinet/icmp6.h"
#include "arpa/inet.h"

#include "buffer.h"
#include "programConfig.h"
#include "outputHandler.h"

// ----------------------------------------------------------------------------
//  Structures, enums and defines
// ----------------------------------------------------------------------------

#define ETHERNET_ADDR_LEN 6
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_IPV4 0x0800

#define QR 0x8000       // 1000 0000 0000 0000
#define OPCODE 0x7800   // 0111 1000 0000 0000
#define AA 0x0400       // 0000 0100 0000 0000
#define TC 0x0200       // 0000 0010 0000 0000
#define RD 0x0100       // 0000 0001 0000 0000
#define RA 0x0080       // 0000 0000 1000 0000
#define _Z 0x0070       // 0000 0000 0111 0000
#define RCODE 0x000f    // 0000 0000 0000 1111

#define RRType_A 0x0001
#define RRType_AAAA 0x001c
#define RRType_NS 0x0002
#define RRType_MX 0x000f
#define RRType_SOA 0x0006
#define RRType_CNAME 0x0005
#define RRType_SRV 0x0021

typedef struct EthernetHeader
{
    // destination address
    unsigned char dst[ETHERNET_ADDR_LEN];
    // source address
    unsigned char src[ETHERNET_ADDR_LEN];
    // ether type
    unsigned char etherType[2];
} EthernetHeader; 

typedef struct DNSHeader
{
    unsigned short transactionID;
    unsigned short flags;
    unsigned short noQuestions;
    unsigned short noAnswers;
    unsigned short noAuthority;
    unsigned short noAdditional;
} DNSHeader;

#define IPv4_PROTOCOL_UDP 0x11

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

/**
 * @brief Dissects frame into correct segments and prints relevant info
 * 
 * @param packet Byte array containing raw packet data
 * @param length Length of the packet
 * @param config Pointer to the Config structure containing pointers to the 
 * "global" variables and program mode
 */
void frameDissector(const unsigned char* packet, size_t length, Config* config);


/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
u_int16_t uchars2uint16(unsigned char* value);


// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------

/**
 * @brief Prints DNS information, transaction id/identifier and flags
 * 
 * @param packet Byte array containing raw packet data
 */
void dnsDissector(const unsigned char* packet);

/**
 * @brief Prints DNS information 
 * 
 * @param packet Byte array containing raw packet, must start at RDATA
 */
void verboseDNSDissector(const unsigned char* packet);

/**
 * @brief Dissects DNS packet into parts and prints relevant information
 * 
 * @param packet Packet to be dissected, must be at a start of DNS part of the packet
 * @param config Pointer to configuration structure that holds information about what should be displayed
 */
void rrDissector(const unsigned char* packet, Config* config);

/**
 * @brief Stores correct domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param addr2Print Buffer to which characters will be stored into
 * @return int Return length of NAME segment
 */
unsigned printRRName(const unsigned char* data, const unsigned char* dataWOptr, Buffer* addr2Print);


/**
 * @brief Stores correct IP address or domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param isIp Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param addr2Print Buffer to which characters will be stored into
 * @return int Return length of RDATA segment
 */
int printRRRData(const unsigned char* data, unsigned isIp, const unsigned char* dataWOptr, Buffer* addr2Print);


/**
 * @brief Prints Time To Live onto standard output
 * 
 * @param data yte array containing raw packet starting at TTL position
 */
void printRRTTL(const unsigned char* data);

/**
 * @brief Prints Resource Record Type onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Type position
 * @return int Returns detected type
 */
int printRRType(const unsigned char* data);

/**
 * @brief Prints Resource Record Class onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Class position
 * @return int Returns detected class
 */
int printRRClass(const unsigned char* data);

/**
 * @brief Dissector of IPv4 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv4ProtocolDissector(unsigned char protocol, const unsigned char* packet, size_t length);

// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------

/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 */
void ipv4Dissector(const unsigned char* packet, bool verbose);

/**
 * @brief Prints IPv4 address in correct endian
 * 
 * @param address IPv4 address
 * @param addr2Print buffer to which will the IPv4 address stored, if NULL 
 * address will be printed onto stdout
 */
void printIPv4(u_int32_t address, Buffer* addr2Print);

/**
 * @brief Dissects IPv6 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 */
void ipv6Dissector(const unsigned char* packet, bool verbose);

/**
 * @brief Prints IPv6 address in correct system endian
 * 
 * @param address pointer to u_int32_t[4]   
 */
void printIPv6(u_int32_t* address, Buffer* addr2Print);

#endif /*PACKET_DISSECTOR_H*/