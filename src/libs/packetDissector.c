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

void frameDissector(const unsigned char* packet, size_t length, int verbose)
{     
    EthernetHeader* eth;
    eth = (EthernetHeader *) packet;
    
    if(verbose) {} // DEBUG:

    unsigned char protocol;
    switch( uchars2uint16(&(eth->etherType[0])) )
    {
        case ETH_TYPE_IPV4:
            protocol = ipv4Dissector(packet + sizeof(EthernetHeader));

            ipv4ProtocolDissector(protocol, 
                    packet + sizeof(EthernetHeader) + sizeof(struct iphdr), 
                    length - sizeof(EthernetHeader) - sizeof(struct iphdr)
                    );
            
            dnsDissector(packet + sizeof(EthernetHeader) + sizeof(struct iphdr) + sizeof(struct udphdr));
            rrDissector(packet + sizeof(EthernetHeader) + sizeof(struct iphdr) + sizeof(struct udphdr));
            break;
        case ETH_TYPE_IPV6:
            protocol = ipv6Dissector(packet + sizeof(EthernetHeader));
            ipv6ProtocolDissector(protocol, 
                    packet + sizeof(EthernetHeader) + sizeof(struct ip6_hdr), 
                    length - sizeof(EthernetHeader) - sizeof(struct ip6_hdr)
                    );

            break;
        default:
            debugPrint(stdout, "DEBUG: Unknown EtherType: (%hhx %hhx)\n", eth->etherType[0], eth->etherType[1]);
            #ifdef DEBUG
                debugPrint(stdout, "Packet:\n");
                printBytes(packet, length, ' ');
                debugPrint(stdout, "\n");
            #endif
            errHandling("Unknown ether type", ERR_UNKNOWN_PROTOCOL);
            break;
    }
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

    printf("SrcIP: ");
    printIPv4(ipv4->saddr);

    printf("DstIP: ");
    printIPv4(ipv4->daddr);

    return ipv4->protocol;
}

void print_bits(unsigned short num) {
    // Loop through each bit from 15 down to 0
    for (int i = 15; i >= 0; i--) {
        if(i == 3 || i == 7 || i == 11)
        {
            printf(" ");
        }

        // Use bitwise AND to check if the bit at position i is set
        if (num & (1 << i))
        {
            printf("1"); // Print '1' if the bit is set
        }
        else
        {
            printf("0"); // Print '0' if the bit is not set
        }


    }
    putchar('\n'); // Print a newline at the end
}

void dnsDissector(const unsigned char* packet)
{
    DNSHeader* dns = (struct DNSHeader*) packet;
    unsigned short correctedFlags = ntohs(dns->flags);

    //print_bits(correctedFlags); // DEBUG:

    printf("Identifier: 0x%hhX%hhX\n", (ntohs(dns->transactionID) >> 8), ntohs(dns->transactionID));
    printf("Flags:");
    printf("QR=%c, ",        (correctedFlags & QR)? '1' : '0');
    printf("OPCODE=%u, ",    (correctedFlags & OPCODE) >> 11);
    printf("AA=%c, ",        (correctedFlags & AA)? '1' : '0');
    printf("TC=%c, ",        (correctedFlags & TC)? '1' : '0');
    printf("RD=%c, ",        (correctedFlags & RD)? '1' : '0');
    printf("RA=%c, ",        (correctedFlags & RA)? '1' : '0');
    printf("Z=%u, ",         (correctedFlags & _Z) >> 4);
    printf("RCODE=%u\n",     correctedFlags & RCODE);

    
}

unsigned printRRQName(const unsigned char* data, const unsigned char* dataWOptr)
{
    unsigned ptr = 0;
    for(;1;)
    {

        const unsigned char lengthOctet = (data)[ptr];
        if(lengthOctet == 0)
        {
            ptr++;
            return ptr;
        }
        else if((lengthOctet >> 6) & 0x3)
        {
            // const unsigned short jumpPtr = ntohs(((unsigned short*)(data))[0]) & 0x3fff;
            const unsigned short jumpPtr = ((data[ptr] << 8) | data[ptr + 1]) & 0x3fff;

            return printRRQName(dataWOptr + jumpPtr, dataWOptr) + 2;
        }

        ptr++; // increase pointer to current byte

        for(unsigned char i = 0; i < lengthOctet; i++, ptr++)
        {
            printf("%c", (data)[ptr]);
        }
        printf(".");
    }

    return 0;
}

void printRRName(const unsigned char* data, const unsigned char* dataWOptr)
{
    unsigned short dataPtr = ntohs(((unsigned short*)(data))[0]);
    dataPtr = dataPtr & 0x3fff;

    printRRQName(dataWOptr + dataPtr, dataWOptr);
}

void printRRTTL(const unsigned char* data)
{
    printf(" %u", ntohs(((unsigned short*)(data))[0]));
}

int printRRClass(const unsigned char* data)
{
    switch (ntohs(((unsigned short*)(data))[0]))
        {
        case RRType_A:      printf("A ");
            return RRType_A;
            break;
        case RRType_AAAA:   printf("AAAA ");
            return RRType_AAAA;
            break; 
        case RRType_NS:     printf("NS ");
            break; 
        case RRType_MX:     printf("MX ");
            break; 
        case RRType_SOA:    printf("SOA ");
            break; 
        case RRType_CNAME:  printf("CNAME ");
            break; 
        case RRType_SRV:    printf("SRV ");
            break; 
        default:
            break;
        }
    return 0;
}

int printRRType(const unsigned char* data)
{
    switch (ntohs(((unsigned short*)(data))[0]))
    {
        case 0x0001: printf(" IN ");
            return 1;
            break;
        default: printf("Unknown Resource Record Class (%u)\n", ntohs(((unsigned short*)(data))[0]));
            break;
    }

    return 0;
}

int printRRRData(const unsigned char* data, unsigned isIp, const unsigned char* dataWOptr)
{
    unsigned short dataLen = ntohs(((unsigned short*)(data))[0]);

    if(isIp)
    {
       if(isIp == RRType_A)
        {
            printIPv4(((uint32_t*) (data + 2))[0]);
        }
        else
        {
            printIPv6((uint32_t*) (data + 2));
        }
    }
    else
    {
        printRRQName(data + 2, dataWOptr);
    }

    // return i + 2; // +2 is for the two bytes of dataLen 
    return dataLen + 2; // +2 is for the two bytes of dataLen 
}

#define TYPE_offset 2
#define CLASS_offset TYPE_offset + 2
#define TTL_offset CLASS_offset + 2
#define RDLENGTH_offset TTL_offset + 4

void rrDissector(const unsigned char* packet)
{
    DNSHeader* dns = (struct DNSHeader*) packet;
    const unsigned char* resourceRecords = packet + sizeof(struct DNSHeader);
    
    unsigned ptr = 0;

    if(ntohs(dns->noQuestions) > 0)
    {
        printf("\n[Question Section]\n");

        ptr += printRRQName(resourceRecords, packet);        
        printRRType(resourceRecords + ptr);
        ptr += 2;
        printRRClass(resourceRecords + ptr);
        ptr += 2;
        printf("\n");
    }

    unsigned repeat = 0;
    for(unsigned i = 0; i < 3; i++)
    {
        switch(i)
        {
            case 0: repeat = ntohs(dns->noAnswers);
                break;
            case 1: repeat = ntohs(dns->noAuthority);
                break;
            case 2: repeat = ntohs(dns->noAdditional);
                break;
        }

        if(repeat > 0)
        {
            switch(i)
            {
                case 0: printf("\n[Answer Section]\n"); break;
                case 1: printf("\n[Authority Section]\n"); break;
                case 2: printf("\n[Additional Section]\n"); break;
            }
        }

        for(unsigned i = 0; i < repeat; i++)
        {
            printRRName(resourceRecords+ptr, packet);
            ptr += 2;
            printRRTTL(resourceRecords + ptr + 6);
            unsigned isIp = printRRType(resourceRecords + ptr + 2);
            isIp = (isIp)? printRRClass(resourceRecords + ptr) : 0;
            ptr += 8; // apply correct offset after TYPE,CLASS and TTL
            const unsigned a = printRRRData(resourceRecords + ptr, isIp, packet);
            ptr += a;
            printf("\n");
        }
        printf("\n");
    }

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
    switch (protocol)
    {
    case IPv4_PROTOCOL_UDP:;
        struct udphdr* udp = (struct udphdr*) packet;
        printf("SrcPort: UDP/%u\n", ntohs(udp->uh_sport)); 
        printf("DstPort: UDP/%u\n", ntohs(udp->uh_dport)); 
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

    printf("SrcIP: ");
    printIPv6(ipv6->ip6_src.__in6_u.__u6_addr32);

    printf("DstIP: ");
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
    if(packet[0]) {} // TODO: delete
    switch(protocol)
    {
        // --------------------------------------------------------------------
        default:         
            debugPrint(stdout, "\nDEBUG: Unknown protocol: %u\n", protocol);
            errHandling("\nUnknown transport layer protocol", 9/*TODO:*/);
            break;
    }

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
    
    printf("%s", buffer);
}
