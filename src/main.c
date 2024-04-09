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

#include "pcap/pcap.h"

void processArguments(int argc, char* argv[], Config* config);

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
    exit(0);
    // ------------------------------------------------------------------------
    // Setup pcap
    // ------------------------------------------------------------------------

    pcap_if_t* allDevices;
    pcap_t* handle;

    // Setup pcap
    errCodes_t result = pcapSetup(config, &allDevices, &handle);
    if(result != NO_ERR) { errHandling("", result); }

    // ------------------------------------------------------------------------
    // Start getting packets
    // ------------------------------------------------------------------------

    // The header that pcap returns
    struct pcap_pkthdr header;
    // The actual packet in bytes
	const unsigned char* packet;

    fprintf(stdout, "Capturing packets has begun.\n");
    while(1)
    {
        packet = pcap_next(handle, &header);

        printf("Yoinked a packed with length of [%d]\n", header.len);
        printf("Yoinked packet: %s\n", packet);

        if(packet){}
    }

    // ------------------------------------------------------------------------
    // Close and cleanup
    // ------------------------------------------------------------------------

    pcap_close(handle);
    pcap_freealldevs(allDevices);

    return 0;
}
