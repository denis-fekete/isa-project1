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

void frameDissector(const unsigned char* packet, size_t length, Config* config)
{     
    EthernetHeader* eth;
    eth = (EthernetHeader *) packet;
    
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
            rrDissector(packet + sizeof(EthernetHeader) + sizeof(struct iphdr) + sizeof(struct udphdr), config);
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
    printIPv4(ipv4->saddr, NULL);
    printf("\n");

    printf("DstIP: ");
    printIPv4(ipv4->daddr, NULL);
    printf("\n");

    return ipv4->protocol;
}

void dnsDissector(const unsigned char* packet)
{
    DNSHeader* dns = (struct DNSHeader*) packet;
    unsigned short correctedFlags = ntohs(dns->flags);

    printf("Identifier: 0x%hhX%hhX\n", 
        ((unsigned char) (ntohs(dns->transactionID) >> 8)),
        ((unsigned char) ntohs(dns->transactionID)));
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


typedef struct 
{
    unsigned value;
    char jumped; 
} nameReturnType;

unsigned printRRName(const unsigned char* data, const unsigned char* dataWOptr, Buffer* addr2Print)
{
    unsigned ptr = 0;
    for(;1;)
    {
        const unsigned char lengthOctet = (data)[ptr];
        if(lengthOctet == 0)
        {
            bufferSetUsed(addr2Print, addr2Print->used - 1);
            ptr++;
            return ptr;
        }
        else if((lengthOctet >> 6) & 0x3)
        {
            const unsigned short jumpPtr = ((data[ptr] << 8) | data[ptr + 1]) & 0x3fff;
            
            printRRName(dataWOptr + jumpPtr, dataWOptr, addr2Print);

            // return ptr + 2 for the jump pointer
            return ptr + 2;
        }

        ptr++; // increase pointer to go from length octet to data

        for(unsigned char i = 0; i < lengthOctet; i++, ptr++)
        {
            bufferAddChar(addr2Print, (data)[ptr]);
        }
        bufferAddChar(addr2Print, '.');
    }
    
    return 0;
}

void printRRTTL(const unsigned char* data)
{
    printf(" %lu", (unsigned long)ntohl(((unsigned long*)(data))[0]));
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

int printRRRData(const unsigned char* data, unsigned isIp, const unsigned char* dataWOptr, Buffer* addr2Print)
{
    unsigned short dataLen = ntohs(((unsigned short*)(data))[0]);

    if(isIp)
    {
       if(isIp == RRType_A)
            printIPv4(((uint32_t*) (data + 2))[0], addr2Print);
        else
            printIPv6((uint32_t*) (data + 2), addr2Print);
    }
    else
        printRRName(data + 2, dataWOptr, addr2Print);

    return dataLen + 2; // +2 is for the two bytes of dataLen 
}

/**
 * @brief Dissects DNS packet into parts and prints relevant information
 * 
 * @param packet Packet to be dissected, must be at a start of DNS part of the packet
 * @param config Pointer to configuration structure that holds information about what should be displayed
 */
void rrDissector(const unsigned char* packet, Config* config)
{
    Buffer* addr2Print = config->addressToPrint;

    DNSHeader* dns = (struct DNSHeader*) packet;
    const unsigned char* resourceRecords = packet + sizeof(struct DNSHeader);
    
    unsigned ptr = 0;

    if(ntohs(dns->noQuestions) > 0)
    {
        printf("\n[Question Section]\n");

        ptr += printRRName(resourceRecords, packet, addr2Print);      
        bufferPrint(addr2Print, 1);
        bufferClear(addr2Print);

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
            ptr += printRRName(resourceRecords+ptr, packet, addr2Print);
            bufferPrint(addr2Print, 1); 

            printRRTTL(resourceRecords + ptr + 4);

            unsigned isIp = printRRType(resourceRecords + ptr + 2);

            isIp = (isIp)? printRRClass(resourceRecords + ptr) : 0;
            ptr += 8; // apply correct offset after TYPE,CLASS and TTL
            
            if(config->domainsfile != NULL)
                domainNameHandler(addr2Print, config->domainList);
            
            if(isIp && config->translationsfile != NULL)
                translationNameHandler(addr2Print, config->translationsList, 0);

            bufferClear(addr2Print);

            ptr += printRRRData(resourceRecords + ptr, isIp, packet, addr2Print);
            bufferPrint(addr2Print, 1);

            if(isIp && config->translationsfile != NULL)
                translationNameHandler(addr2Print, config->translationsList, 1);

            bufferClear(addr2Print);
            printf("\n");
        }
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
 * @param addr2Print buffer to which will the IPv4 address stored, if NULL 
 * address will be printed onto stdout
 */
void printIPv4(u_int32_t address, Buffer* addr2Print)
{
    u_int32_t addressCorrected = ntohl(address);


    if(addr2Print == NULL)
    {
        for(short i = 24 ; i >= 0 ; i -= 8)
        {
            printf("%hu", ((unsigned short)((addressCorrected >> i) & 0xFF)));

            if(i != 0)
            {
                printf(".");
            }
        }

        return;
    }

    unsigned char number = 0;
    short unsigned int hundreds = 0;
    short unsigned int tens = 0;
    short unsigned int ones = 0;

    char tmp[4] = {0};
    for(short i = 24 ; i >= 0 ; i -= 8)
    {
        
        number = (addressCorrected >> i) & 0xFF;
        hundreds = (int) number/100;
        tens = (int) (number%100) / 10;
        ones = (int) ((number%100) % 10);

        number = 0; // reuse number for digit counting
        if(hundreds > 0)
        {
            tmp[number] = '0' + hundreds;
            number++;
        }

        if(tens > 0 || number > 0)
        {
            tmp[number] = '0' + tens;
            number++;
        }
            
        tmp[number] = '0' + ones;
        number++;
        
        tmp[number] = 0;

        bufferAddString(addr2Print, tmp);

        if(i != 0)
        {
            bufferAddChar(addr2Print, '.');
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
    printIPv6(ipv6->ip6_src.__in6_u.__u6_addr32, NULL);

    printf("DstIP: ");
    printIPv6(ipv6->ip6_dst.__in6_u.__u6_addr32, NULL);
    
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
void printIPv6(u_int32_t* address, Buffer* addr2Print)
{
    char buffer[40];
    inet_ntop(AF_INET6, address, buffer, 40);
    
    if(addr2Print == NULL)
    {
        printf("%s", buffer);
    }
    else
    {
        bufferAddString(addr2Print, buffer);
    }
}
