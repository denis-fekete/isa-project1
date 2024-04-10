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
    printConfig(config);

    // ------------------------------------------------------------------------
    // Setup pcap
    // ------------------------------------------------------------------------

    pcap_if_t* allDevices;
    pcap_t* handle;

    // Setup pcap
    handle = pcapSetup(config, &allDevices);

    // ------------------------------------------------------------------------
    // Start getting packets
    // ------------------------------------------------------------------------

    // The header that pcap returns
    struct pcap_pkthdr header;
    // The actual packet in bytes
	const unsigned char* packet;


    unsigned int packetCounter = 0;
    fprintf(stdout, "Capturing packets has begun.\n");
    while(packetCounter < config->numberOfPackets)
    {
        packet = pcap_next(handle, &header);
        filterPackets();
        // --------------------------------------------------------------------
        printf("timestamp:");
        printf("%ld.%06ld\n", header.ts.tv_sec, header.ts.tv_usec);
        
        packetDissector(packet, header.len);

        // --------------------------------------------------------------------

        printf("\nPacket:");
        printBytes(packet, header.len);
        printf("\n");

        packetCounter++;
    }

    
    // ------------------------------------------------------------------------
    // Close and cleanup
    // ------------------------------------------------------------------------

    pcap_close(handle);
    pcap_freealldevs(allDevices);

    return 0;
}
