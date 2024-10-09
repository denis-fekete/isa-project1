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
#define RRType_UNKNOWN 0x0000

#define RRClass_IN 0x0001
#define RRClass_UNKNOWN 0x0000

#define TTL_LEN 4
#define CLASS_LEN 2
#define TYPE_LEN 2
#define MX_PREFERENCE_LEN 2
#define RDATALEN_LEN 2

typedef const unsigned char* packet_t;

#define IS_IP() (type == RRType_A || type == RRType_AAAA)

#define LEN_CHECK(var)                  \
    if(maxLen < ptr + var)              \
    {                                   \
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET); \
    }

#define VERBOSE(arg) if(config->verbose){arg;}

#define STORE_DOMAIN(arg) if(config->domainsFile->data != NULL && (type == RRType_A || type == RRType_AAAA || type == RRType_NS)) {arg;} 

#define STORE_TRANSLATIONS(arg) if(config->domainsFile->data != NULL && !((type == RRType_A || type == RRType_AAAA))) {arg;} 

#define PACKET_2_SHORT(packet) ((unsigned short*)(packet))[0]

#define PACKET_2_UINT(packet) ((unsigned*)(packet))[0]


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
void frameDissector(packet_t packet, size_t length, Config* config);


// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------

/**
 * @brief Prints DNS information, transaction id/identifier and flags
 * 
 * @param packet Byte array containing raw packet data
 */
void dnsDissector(packet_t packet);

/**
 * @brief Prints DNS information 
 * 
 * @param packet Byte array containing raw packet, must start at RDATA
 */
void verboseDNSDissector(packet_t packet);

/**
 * @brief Dissects DNS packet into parts and prints relevant information
 * 
 * @param packet Packet to be dissected, must be at a start of DNS part of the packet
 * @param config Pointer to configuration structure that holds information about what should be displayed
 * @param maxLen Maximum allowed length of packet
 */
void rrDissector(packet_t packet, Config* config, size_t maxLen);

/**
 * @brief Checks if new query contains supported type of class
 * 
 * @param data Byte array containing raw packet data starting at Type section 
 * DNS message
 * @return true Is valid/known message type/class
 * @return false Is not valid/known message type/class
 */
bool isValidTypeOrClass(packet_t data);

/**
 * @brief Stores correct domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param addr2Print Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 * @return int Return length of NAME segment
 */
unsigned handleRRName(packet_t data, packet_t dataWOptr, 
                        Buffer* addr2Print, size_t currLen, size_t maxLen);


/**
 * @brief Stores correct IP address or domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param isIp Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param addr2Print Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 * @return int Return length of RDATA segment
 */

int handleRRRData(packet_t data, unsigned isIp, 
                    packet_t dataWOptr, Buffer* addr2Print, 
                    size_t currLen, size_t maxLen);

/**
 * @brief Handles correct printing of SRV packets
 * @param data Byte array containing raw packet, must start at RDATA
 * @param type Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 */
void handleSRV(packet_t data, packet_t dataWOptr, Buffer* bufferPtr, size_t currLen, size_t maxLen);

/**
 * @brief Handles correct printing of SOA packets
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param type Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 */
void handleSOA(packet_t data, packet_t dataWOptr, Buffer* bufferPtr, size_t currLen, size_t maxLen);

/**
 * @brief Prints Time To Live onto standard output
 * 
 * @param data yte array containing raw packet starting at TTL position
 */
void handleRRTTL(packet_t data);

/**
 * @brief Prints Resource Record Type onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Type position
 * @return int Returns detected type
 */
int handleRRType(packet_t data);

/**
 * @brief Prints Resource Record Class onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Class position
 * @return int Returns detected class
 */
int handleRRClass(packet_t data);

/**
 * @brief Dissector of IPv4 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv4ProtocolDissector(unsigned char protocol, packet_t packet, size_t length);

// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------

/**
 * @brief Prints UDP information like src and dst port
 * 
 * @param packet Byte array containing raw packet data with offset to udp header 
 */
void udpDissector(packet_t packet);

/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 */
void ipv4Dissector(packet_t packet, bool verbose);

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
void ipv6Dissector(packet_t packet, bool verbose);

/**
 * @brief Prints IPv6 address in correct system endian
 * 
 * @param address pointer to u_int32_t[4]   
 */
void printIPv6(u_int32_t* address, Buffer* addr2Print);

#endif /*PACKET_DISSECTOR_H*/