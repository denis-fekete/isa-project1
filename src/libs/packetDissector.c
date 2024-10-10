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
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void frameDissector(packet_t packet, size_t length, Config* config)
{     
    EthernetHeader* eth;
    eth = (EthernetHeader *) packet;

    unsigned offset = sizeof(EthernetHeader);

    if(length < offset)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);


    // unsigned short etherType = ntohs(((unsigned short*) (eth->etherType))[0]);
    unsigned short etherType = ntohs( PACKET_2_SHORT(eth->etherType) );
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

// ----------------------------------------------------------------------------
// IPv4 and IPv6
// ----------------------------------------------------------------------------


/**
 * @brief Prints DNS information in non-verbose mode
 * 
 * @param packet Byte array containing raw packet
 */
void dnsDissector(packet_t packet)
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
void verboseDNSDissector(packet_t packet)
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

void handleMXPreference(packet_t packet)
{
    // +2 is because first is data rdatalen (2 bytes) and then is rdata 
    // containing mx preference 
    printf("%hu ", ntohs(PACKET_2_SHORT(packet + 2) ));
}

#include <signal.h>
#include <unistd.h>

unsigned handleOtherSections(packet_t resourceRecords, packet_t packet, Config* config, unsigned ptr, size_t maxLen)
{
    Buffer* bufferPtr = config->addressToPrint;
    unsigned type;
    unsigned ptrOld = ptr;

    // bufferPtr already contains correct NAME, print it
    VERBOSE(
        bufferPrint(bufferPtr, 1);
        );

    VERBOSE(
        handleRRTTL(resourceRecords + ptr + TTL_LEN);
        );
    VERBOSE(
        handleRRClass(resourceRecords + ptr + CLASS_LEN);
        );
    VERBOSE(
        type = handleRRType(resourceRecords + ptr);
        );

    ptr += TTL_LEN + CLASS_LEN + TYPE_LEN;
    
    STORE_DOMAIN(
        domainNameHandler(bufferPtr, config->domainList);
        );
    STORE_TRANSLATIONS(
        translationNameHandler(bufferPtr, config->translationsList, 0);
        );

    if(type == RRType_MX) {
        VERBOSE(
            handleMXPreference(resourceRecords + ptr);
        );
    }
    bufferClear(bufferPtr);
    ptr += handleRRRData(resourceRecords + ptr, type, packet, bufferPtr, ptr, maxLen);

    STORE_TRANSLATIONS(
        translationNameHandler(bufferPtr, config->translationsList, 0);
        );
    VERBOSE(
        bufferPrint(bufferPtr, 1);
        );
    STORE_TRANSLATIONS(
        translationNameHandler(bufferPtr, config->translationsList, 0);
        );
    
    bufferClear(bufferPtr);
    VERBOSE(printf("\n"));

    return ptr - ptrOld;
}

/**
 * @brief Dissects DNS packet into parts and prints relevant information
 * 
 * @param packet Packet to be dissected, must be at a start of DNS part of the packet
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 * @param maxLen Maximum allowed length of packet
 */
void rrDissector(packet_t packet, Config* config, size_t maxLen)
{
    Buffer* bufferPtr = config->addressToPrint;

    // dns header to know number of queries to be expected
    DNSHeader* dns = (struct DNSHeader*) packet;
    packet_t resourceRecords = packet + sizeof(struct DNSHeader);
    
    // pointer in packet byte array, offset...
    unsigned ptr = 0;

    if(ntohs(dns->noQuestions) > 0)
    {
        if(config->verbose)
            printf("\n[Question Section]\n");

        ptr += handleRRName(resourceRecords, packet, bufferPtr, ptr, maxLen);     

        LEN_CHECK(0);

        if(config->domainsFile->data != NULL)
            domainNameHandler(bufferPtr, config->domainList);

        if(config->verbose)
            bufferPrint(bufferPtr, 1);
        bufferClear(bufferPtr);

        if(config->verbose)
            // +2 for two zero bytes after name
            handleRRClass(resourceRecords + ptr + 2);

        if(config->verbose)
            handleRRType(resourceRecords + ptr);
        ptr += 4; // +2 for the type, +2 for the type

        if(config->verbose)
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
            ptr += handleRRName(resourceRecords+ptr, packet, bufferPtr, ptr, maxLen);

            // +4 for ttl, +2 for class, +2 for type
            LEN_CHECK(8);

            // ignore unknown resource record types
            if(!isValidTypeOrClass(resourceRecords + ptr))
                continue;

            ptr += handleOtherSections(resourceRecords, packet, config, ptr, maxLen);
        }
    }

}


/**
 * @brief Checks if new query contains supported type of class
 * 
 * @param data Byte array containing raw packet data starting at Type section 
 * DNS message
 * @return true Is valid/known message type/class
 * @return false Is not valid/known message type/class
 */
bool isValidTypeOrClass(packet_t data)
{
    bool valid = false;
    // no need for offset
    switch (ntohs( PACKET_2_SHORT(data) ))
    // switch (ntohs(((unsigned short*)(data))[0]))
    {
        case RRType_A:
        case RRType_AAAA:
        case RRType_NS:
        case RRType_MX:
        case RRType_SOA:
        case RRType_CNAME:
        case RRType_SRV:
            valid = true;
            break;
    }

    if(valid == false)
        return false;

    // +2 is offset after name to the class
    switch (ntohs( PACKET_2_SHORT(data + 2) ))
    // switch (ntohs(((unsigned short*)(data + 2))[0]))
    {
        case RRClass_IN:
            valid = true;
            break;
        default:
            valid = false;            
    }

    return valid;
}

/**
 * @brief Stores correct domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 * @return int Return length of NAME segment
 */
unsigned handleRRName(packet_t data, packet_t dataWOptr, 
                        Buffer* bufferPtr, size_t currLen, size_t maxLen)
{
    unsigned ptr = 0;
    for(;1;)
    {
        if(ptr + currLen > maxLen)
            errHandling("Received packet is not long enough, probably malfunctioned packet (in handleRRName)", ERR_BAD_PACKET);            

        const unsigned char lengthOctet = (data)[ptr];
        if(lengthOctet == 0)
        {
            if(bufferPtr->used > 0)
                bufferSetUsed(bufferPtr, bufferPtr->used - 1);

            ptr++;
            return ptr;
        }
        else if((lengthOctet >> 6) & 0x3)
        {
            const unsigned short jumpPtr = ((data[ptr] << 8) | data[ptr + 1]) & 0x3fff;
            
            handleRRName(dataWOptr + jumpPtr, dataWOptr, bufferPtr, currLen + ptr, maxLen);

            // return ptr + 2 for the jump pointer
            return ptr + 2;
        }

        ptr++; // increase pointer to go from length octet to data

        for(unsigned char i = 0; i < lengthOctet; i++, ptr++)
        {
            bufferAddChar(bufferPtr, (data)[ptr]);
        }
        bufferAddChar(bufferPtr, '.');
    }
    
    return 0;
}


/**
 * @brief Stores correct IP address or domain name into Buffer
 * 
 * @param data Byte array containing raw packet, must start at RDATA
 * @param type Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 * @return int Return length of RDATA segment
 */
int handleRRRData(packet_t data, unsigned type, 
                    packet_t dataWOptr, Buffer* bufferPtr, 
                    size_t currLen, size_t maxLen)
{
    if(currLen + 2 > maxLen)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);            

    // unsigned short dataLen = ntohs(((unsigned short*)(data))[0]);
    unsigned short dataLen = ntohs( PACKET_2_SHORT(data) );

    if(currLen + dataLen + 2 > maxLen)
        errHandling("Received packet is not long enough, probably malfunctioned packet", ERR_BAD_PACKET);    

    switch (type)
    {
    case RRType_A:
            printIPv4(((uint32_t*) (data + 2))[0], bufferPtr);
        break;
    case RRType_AAAA:
            printIPv6((uint32_t*) (data + 2), bufferPtr);
        break;
    case RRType_MX:
        handleRRName(data + RDATALEN_LEN + MX_PREFERENCE_LEN, dataWOptr, bufferPtr, currLen, maxLen);
        break;
    case RRType_SOA:;
        handleSOA(data, dataWOptr, bufferPtr, currLen, maxLen);
        break;
    case RRType_SRV:;
        handleSRV(data, dataWOptr, bufferPtr, currLen, maxLen);
        break;
    default:
        handleRRName(data + RDATALEN_LEN, dataWOptr, bufferPtr, currLen, maxLen);
        break;
    }

    return dataLen + RDATALEN_LEN; // +2 is for the two bytes of dataLen 
}

/**
 * @brief Handles correct printing of SRV packets
 * @param data Byte array containing raw packet, must start at RDATA
 * @param type Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 */
void handleSRV(packet_t data, packet_t dataWOptr, Buffer* bufferPtr, size_t currLen, size_t maxLen)
{
        unsigned ptr = RDATALEN_LEN;
        // priority (length 2 octets unsigned short)
        printf("%u ", ntohs( PACKET_2_SHORT(data + ptr) ));
        ptr += 2;

        // weight (length 2 octets unsigned short)
        printf("%u ", ntohs( PACKET_2_SHORT(data + ptr) ));
        ptr += 2;

        // port (length 2 octets unsigned short)
        printf("%u ", ntohs( PACKET_2_SHORT(data + ptr) ));
        ptr += 2;

        handleRRName(data + ptr, dataWOptr, bufferPtr, currLen, maxLen);
}

/**
 * @brief Handles correct printing of SOA packets
 * @param data Byte array containing raw packet, must start at RDATA
 * @param type Sign if A or AAAA type is detected (this will be IP address)
 * @param dataWOptr Byte array that starts at DNS part of packet (without offset to RDATA)
 * @param bufferPtr Buffer to which characters will be stored into
 * @param currLen Current length of packet
 * @param maxLen Maximum allowed length of packet
 */
void handleSOA(packet_t data, packet_t dataWOptr, Buffer* bufferPtr, size_t currLen, size_t maxLen)
{
    // primary name server
    unsigned ptr = RDATALEN_LEN; 
    ptr += handleRRName(data + ptr, dataWOptr, bufferPtr, currLen, maxLen);
    // responsible authority mailbox
    ptr += handleRRName(data + ptr, dataWOptr, bufferPtr, currLen, maxLen);

    // serial number (length 4 octets = unsigned int)
    printf("%u ", ntohl( PACKET_2_UINT(data + ptr) ));
    ptr += 4;

    // refresh interval (length 4 octets = unsigned int)
    printf("%u ", ntohl( PACKET_2_UINT(data + ptr) ));
    ptr += 4;

    // retry interval (length 4 octets = unsigned int)
    printf("%u ", ntohl( PACKET_2_UINT(data + ptr) ));
    ptr += 4;

    // expire interval (length 4 octets = unsigned int)
    printf("%u ", ntohl( PACKET_2_UINT(data + ptr) ));
    ptr += 4;

    // minimum ttl (length 4 octets = unsigned int)
    printf("%u ", ntohl( PACKET_2_UINT(data + ptr) ));
    ptr += 4;
}

/**
 * @brief Prints Time To Live onto standard output
 * 
 * @param data Byte array containing raw packet starting at TTL position
 */
void handleRRTTL(packet_t data)
{
    printf(" %lu", (unsigned long)ntohl(((unsigned long*)(data))[0]));
}


/**
 * @brief Prints Resource Record Type onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Type position
 * @return int Returns detected type
 */
int handleRRType(packet_t data)
{
    // switch (ntohs(((unsigned short*)(data))[0]))
    switch (ntohs( PACKET_2_SHORT(data) ))
    {
        case RRType_A:      printf("A ");
            return RRType_A;
            break;
        case RRType_AAAA:   printf("AAAA ");
            return RRType_AAAA;
            break; 
        case RRType_NS:     printf("NS ");
            return RRType_NS;
            break; 
        case RRType_MX:     printf("MX ");
            return RRType_MX;
            break; 
        case RRType_SOA:    printf("SOA ");
            return RRType_SOA;
            break; 
        case RRType_CNAME:  printf("CNAME ");
            return RRType_CNAME;
            break; 
        case RRType_SRV:    printf("SRV ");
            return RRType_SRV;
            break; 
    }

    return RRType_UNKNOWN;
}


/**
 * @brief Prints Resource Record Class onto standard ouput 
 * 
 * @param data Byte array containing raw packet starting at Class position
 * @return int Returns detected class
 */
int handleRRClass(packet_t data)
{
    switch (ntohs( PACKET_2_SHORT(data) ))
    {
        case RRClass_IN: printf(" IN ");
            return RRClass_IN;
            break;
        default: return RRType_UNKNOWN;
    }
}


/**
 * @brief Dissector of IPv4 protocol
 * 
 * @param protocol Protocol to be dissected
 * @param packet Pointer to the packet
 * @param length Maximum length that you can read
 */
void ipv4ProtocolDissector(unsigned char protocol, packet_t packet, size_t length)
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
void udpDissector(packet_t packet)
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
void ipv4Dissector(packet_t packet, bool verbose)
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
 * @param bufferPtr Buffer to which will the IPv4 address stored, if NULL 
 * address will be printed onto stdout
 */
void printIPv4(u_int32_t address, Buffer* bufferPtr)
{
    u_int32_t addressCorrected = ntohl(address);


    if(bufferPtr == NULL)
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

        bufferAddString(bufferPtr, tmp);

        if(i != 0)
        {
            bufferAddChar(bufferPtr, '.');
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
void ipv6Dissector(packet_t packet, bool verbose)
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
 * @param bufferPtr Pointer to Buffer where IPv6 will be stored, if NULL
 * stdout will be used instead
 */
void printIPv6(u_int32_t* address, Buffer* bufferPtr)
{
    char buffer[40];
    inet_ntop(AF_INET6, address, buffer, 40);
    
    if(bufferPtr == NULL)
    {
        printf("%s", buffer);
    }
    else
    {
        bufferAddString(bufferPtr, buffer);
    }
}
