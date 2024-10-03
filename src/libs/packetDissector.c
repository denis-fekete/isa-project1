/**
 * @file frameDissector.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "packetDissector.h"

/**
 * @brief Dissects frame into correct segments and prints relevant info
 * 
 * @param packet Byte array containing raw packet data
 * @param length Length of the packet
 * @param config Pointer to the Config structure containing pointers to the 
 * "global" variables and program mode
 */
void frameDissector(const unsigned char* packet, size_t length, Config* config)
{     
    EthernetHeader* eth;
    eth = (EthernetHeader *) packet;

    unsigned offset = sizeof(EthernetHeader);

    if(length < offset)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);


    unsigned short etherType = ntohs(((unsigned short*) (eth->etherType))[0]);
    if(etherType != uchars2uint16(&(eth->etherType[0])))
        debugPrint(stdout, "\n\nZLE!!\n\n");
    switch( etherType )
    {
        case ETH_TYPE_IPV4:
            if(length < offset + sizeof(struct iphdr))
                errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);

            ipv4Dissector(packet + offset, config->verbose);
            offset += sizeof(struct iphdr);
            break;
        case ETH_TYPE_IPV6:
            if(length < offset + sizeof(struct ip6_hdr))
                errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);

            ipv6Dissector(packet + offset, config->verbose);
            offset += sizeof(struct ip6_hdr);
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

    if(length < offset + sizeof(struct udphdr))
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);

    if(config->verbose)
        udpDissector(packet + offset);
    offset += sizeof(struct udphdr);

    if(length < offset + sizeof(struct DNSHeader))
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);

    if(config->verbose)
        verboseDNSDissector(packet + offset);
    else
        dnsDissector(packet + offset);

    rrDissector(packet + offset, config, length - offset - sizeof(struct DNSHeader));
}


/**
 * @brief Breaks unsigned char into 16bit unsigned integer (unsigned short int)
 * 
 * @param value Input array containing value to be broken to unsigned integer
 * @return u_int16_t 
 */
u_int16_t uchars2uint16(unsigned char* value)
{
    //                  LOW         HIGH
    return (u_int16_t) (value[1] +  (value[0] << 8)); 
}


// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------


/**
 * @brief Prints DNS information in non-verbose mode
 * 
 * @param packet Byte array containing raw packet
 */
void dnsDissector(const unsigned char* packet)
{
    DNSHeader* dns = (struct DNSHeader*) packet;
    unsigned short correctedFlags = ntohs(dns->flags);

    printf("(%c ",      (correctedFlags & QR)? 'R' : 'Q');
    printf("%hu/",      ntohs(dns->noQuestions));
    printf("%hu/",      ntohs(dns->noAnswers));
    printf("%hu/",      ntohs(dns->noAuthority));
    printf("%hu)",    ntohs(dns->noAdditional));
}

/**
 * @brief Prints DNS information 
 * 
 * @param packet Byte array containing raw packet, must start at RDATA
 */
void verboseDNSDissector(const unsigned char* packet)
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

#define IS_IP() (type == RRType_A || type == RRType_AAAA)

#define LEN_CHECK(var)                  \
    if(maxLen < ptr + var)              \
    {                                   \
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET); \
    }


/**
 * @brief Dissects DNS packet into parts and prints relevant information
 * 
 * @param packet Packet to be dissected, must be at a start of DNS part of the packet
 * @param config Pointer to configuration structure that holds information about what should be displayed
 * @param maxLen Maximum allowed length of packet
 */
void rrDissector(const unsigned char* packet, Config* config, size_t maxLen)
{
    Buffer* addr2Print = config->addressToPrint;

    // dns header to know number of queries to be expected
    DNSHeader* dns = (struct DNSHeader*) packet;
    const unsigned char* resourceRecords = packet + sizeof(struct DNSHeader);
    
    // pointer in packet byte array, offset...
    unsigned ptr = 0;

    if(ntohs(dns->noQuestions) > 0)
    {
        if(config->verbose)
            printf("\n[Question Section]\n");

        ptr += printRRName(resourceRecords, packet, addr2Print, ptr, maxLen);     

        LEN_CHECK(0);

        if(config->domainsFile->data != NULL)
            domainNameHandler(addr2Print, config->domainList);

        if(config->verbose)
            bufferPrint(addr2Print, 1);
        bufferClear(addr2Print);

        if(config->verbose)
            // +2 for two zero bytes after name
            printRRClass(resourceRecords + ptr + 2);

        if(config->verbose)
            printRRType(resourceRecords + ptr);
        ptr += 4; // +2 for the type, +2 for the type

        if(config->verbose)
            printf("\n");
    }

    unsigned repeat = 0;
    unsigned short type;
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

        if(repeat > 0 && config->verbose)
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
            ptr += printRRName(resourceRecords+ptr, packet, addr2Print, ptr, maxLen);

            // +4 for ttl, +2 for class, +2 for type
            LEN_CHECK(8);

            if(config->verbose)
                bufferPrint(addr2Print, 1); 

            if(config->verbose)
                // +4 to get to the ttl
                printRRTTL(resourceRecords + ptr + 4);

            if(config->verbose)
                // +2 to get to the class
                printRRClass(resourceRecords + ptr + 2);

            if(config->verbose)
                type = printRRType(resourceRecords + ptr);

            ptr += 8; // +4 for ttl, +2 for class, +2 for type
            
            // check if capturing domain names is enabled, if yes capture them
            // first time for name
            if(config->domainsFile->data != NULL)
                domainNameHandler(addr2Print, config->domainList);
            
            // check if capturing translation is enabled, if yes capture them
            // first store domain name
            if(config->translationsFile->data != NULL && IS_IP())
                translationNameHandler(addr2Print, config->translationsList, 0);

            bufferClear(addr2Print);

            ptr += printRRRData(resourceRecords + ptr, type, packet, addr2Print, ptr, maxLen);

            // check if capturing domain names is enabled, if yes capture them
            // second time for rdata
            if(config->domainsFile->data != NULL && !(IS_IP()))
                domainNameHandler(addr2Print, config->domainList);

            if(config->verbose)
                bufferPrint(addr2Print, 1);

            // check if capturing translation is enabled, if yes capture them
            // second store translated ip
            if(config->translationsFile->data != NULL && IS_IP())
                translationNameHandler(addr2Print, config->translationsList, 1);

            bufferClear(addr2Print);
            
            if(config->verbose)
                printf("\n");
        }
    }

}

#undef IS_IP

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
unsigned printRRName(const unsigned char* data, const unsigned char* dataWOptr, 
                        Buffer* addr2Print, size_t currLen, size_t maxLen)
{
    unsigned ptr = 0;
    for(;1;)
    {
        if(ptr + currLen > maxLen)
            errHandling("Received packet is not long enough, probably malfunctioned packet (in printRRName)", ERR_BAD_PACKET);            

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
            
            printRRName(dataWOptr + jumpPtr, dataWOptr, addr2Print, currLen + ptr, maxLen);

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

int printRRRData(const unsigned char* data, unsigned isIp, 
                    const unsigned char* dataWOptr, Buffer* addr2Print, 
                    size_t currLen, size_t maxLen)
{
    if(currLen + 2 > maxLen)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);            

    unsigned short dataLen = ntohs(((unsigned short*)(data))[0]);

    if(currLen + dataLen + 2 > maxLen)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);    

    if(isIp)
    {
        // +2 is offset after datalen
       if(isIp == RRType_A)
        {
            printIPv4(((uint32_t*) (data + 2))[0], addr2Print);
        }
        else
        {
            printIPv6((uint32_t*) (data + 2), addr2Print);
        }
    }
    else
        printRRName(data + 2, dataWOptr, addr2Print, currLen, maxLen);

    return dataLen + 2; // +2 is for the two bytes of dataLen 
}


/**
 * @brief Prints Time To Live onto standard output
 * 
 * @param data Byte array containing raw packet starting at TTL position
 */
void printRRTTL(const unsigned char* data)
{
    printf(" %lu", (unsigned long)ntohl(((unsigned long*)(data))[0]));
}


/**
 * @brief Prints Resource Record Type onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Type position
 * @return int Returns detected type
 */
int printRRType(const unsigned char* data)
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
            debugPrint(stdout, "Bad RR Type: %u \n", ntohs(((unsigned short*)(data))[0]));
            errHandling("Unknown Resource Record Type", ERR_UNKNOWN_PROTOCOL);
            break;
        }
    return 0;
}


/**
 * @brief Prints Resource Record Class onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Class position
 * @return int Returns detected class
 */
int printRRClass(const unsigned char* data)
{
    switch (ntohs(((unsigned short*)(data))[0]))
    {
        case 0x0001: printf(" IN ");
            return 1;
            break;
        default:
            debugPrint(stdout, "Bad RR Class: %u \n", ntohs(((unsigned short*)(data))[0]));
            errHandling("Unknown Resource Record Class", ERR_UNKNOWN_PROTOCOL);
            break;
    }

    return 0;
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


// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------

/**
 * @brief Prints UDP information like src and dst port
 * 
 * @param packet Byte array containing raw packet data with offset to udp header 
 */
void udpDissector(const unsigned char* packet)
{
    struct udphdr* udp = (struct udphdr*) packet; 

    printf("SrcPort: %hu\n", ntohs(udp->source));
    printf("DstPort: %hu\n", ntohs(udp->dest));
}


/**
 * @brief Dissects IPv4 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @param verbose Setting if information display is should be detailed or not
 */
void ipv4Dissector(const unsigned char* packet, bool verbose)
{
    struct iphdr* ipv4 = (struct iphdr*) packet;

    if(verbose)
    {
        printf("SrcIP: ");
        printIPv4(ipv4->saddr, NULL);
        printf("\n");

        printf("DstIP: ");
        printIPv4(ipv4->daddr, NULL);
        printf("\n");
    }
    else
    {
        printf(" ");
        printIPv4(ipv4->saddr, NULL);
        printf(" -> ");
        printIPv4(ipv4->daddr, NULL);
        printf(" ");
    }
}


/**
 * @brief Prints IPv4 address in correct endian
 * 
 * @param address IPv4 address
 * @param addr2Print Buffer to which will the IPv4 address stored, if NULL 
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
        // break numerical value into printable chars
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


/**
 * @brief Dissects IPv6 protocol 
 * 
 * @param packet Pointer to the packet, must start at Internet Protocol
 * @param verbose Setting if information display is should be detailed or not
 * @return unsigned char Pointer where IP protocol ends, and protocol stars
 */
void ipv6Dissector(const unsigned char* packet, bool verbose)
{
    struct ip6_hdr* ipv6 = (struct ip6_hdr*) packet;

    if(verbose)
    {
        printf("SrcIP: ");
        printIPv6(ipv6->ip6_src.__in6_u.__u6_addr32, NULL);

        printf("DstIP: ");
        printIPv6(ipv6->ip6_dst.__in6_u.__u6_addr32, NULL);
    }
    else
    {
        printf(" ");
        printIPv6(ipv6->ip6_src.__in6_u.__u6_addr32, NULL);
        printf(" -> ");
        printIPv6(ipv6->ip6_dst.__in6_u.__u6_addr32, NULL);
        printf(" ");
    }
}

/**
 * @brief Prints IPv6 address in correct system endian
 * 
 * @param address Pointer to u_int32_t[4] containing IPv6 address
 * @param addr2Print Pointer to Buffer where IPv6 will be stored, if NULL
 * stdout will be used instead
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
