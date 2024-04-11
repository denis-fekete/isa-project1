/**
 * @file main.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

// #include <libnet.h>
#include "libs/utils.h"
#include "libs/buffer.h"
#include "libs/pcapHandler.h"
#include "libs/programConfig.h"
#include "libs/argumentHandler.h"
#include "libs/packetDissector.h"

#include "pcap/pcap.h"

void processArguments(int argc, char* argv[], Config* config);



void filterPackets()
{

}



int main(int argc, char* argv[])
{
    // ------------------------------------------------------------------------
    // Create and setup ProgramConfiguration
    // ------------------------------------------------------------------------
    
    struct ProgramConfiguration programConfig;
    Config* config = &programConfig;
    setupConfig(config);

    // ------------------------------------------------------------------------
    // Handle program arguments
    // ------------------------------------------------------------------------

    argumentHandler(argc, argv, config);
    #ifdef DEBUG
        printConfig(config);
        printf("\n");
    #endif
    // ------------------------------------------------------------------------
    // Setup pcap
    // ------------------------------------------------------------------------

    pcap_if_t* allDevices;
    pcap_t* handle;

    char* pcapErrbuf;
    // Setup pcap
    handle = pcapSetup(config, &allDevices, &pcapErrbuf);

    // ------------------------------------------------------------------------
    // Start getting packets
    // ------------------------------------------------------------------------

    // The header that pcap returns
    struct pcap_pkthdr header;
    // The actual packet in bytes
	const unsigned char* packet;


    unsigned int packetCounter = 0;
    while(packetCounter < config->numberOfPackets)
    {
        packet = pcap_next(handle, &header);
        filterPackets();
        // --------------------------------------------------------------------
        printf("timestamp: ");
        printf("%ld.%06ld\n", header.ts.tv_sec, header.ts.tv_usec);

        frameDissector(packet, header.len);

        // --------------------------------------------------------------------

        printf("\n");
        #define BYTES_PER_LINE 16
        long long int bytesToPrint = 0;
        short unsigned int tabs = 0;
        for(size_t i = 16; i < header.len; i += BYTES_PER_LINE)
        {
            // check if bytes to be printed on line is smaller number than header.len - i
            if(BYTES_PER_LINE < ((long long unsigned ) header.len) - i)
            {
                // if yes print BYTES_PER_LINE
                bytesToPrint = BYTES_PER_LINE;
            }   
            // if no calculate how many bytes needs to printed and correct tabulators
            else 
            {
                bytesToPrint = header.len - i; 
                tabs = (BYTES_PER_LINE * 2 + BYTES_PER_LINE) - ( bytesToPrint * 2 + bytesToPrint);
            }

            // print line number in hex
            printf("0x%04zx: ", i);
            // print hexedecimal values
            printBytes( packet + i, bytesToPrint, ' ');
            // separate
            printf(" ");
            // correct tabulation if last row is not full
            for(short unsigned int k = 0; k < tabs; k++)
            {
                printf(" ");
            }
            // print as printable characters
            printChars( packet + i, bytesToPrint);
            printf("\n");
        }

        packetCounter++;
        printf("\n");
    }

    
    // ------------------------------------------------------------------------
    // Close and cleanup
    // ------------------------------------------------------------------------
    free(pcapErrbuf);

    pcap_close(handle);
    pcap_freealldevs(allDevices);

    return 0;
}
