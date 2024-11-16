/**
 * @file main.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "libs/utils.h"
#include "libs/buffer.h"
#include "libs/pcapHandler.h"
#include "libs/programConfig.h"
#include "libs/argumentHandler.h"
#include "libs/packetDissector.h"

#include "pcap/pcap.h"

#include "time.h"
#include "signal.h"

/**
 * @brief Global Configuration structure that holds all dynamicly allocated data 
 * and variables that define program mode and behaviour.
 */
Config* globalConfig;

/**
 * @brief Function that loops and receives packets 
 * 
 * @param config Pointer to the Config structure
 */
void packetLooper(Config* config)
{
     // The header that pcap returns
    struct pcap_pkthdr* header;

    unsigned int packetCounter = 0;

    // variable holding raw packet data
    const unsigned char* packetData;

    bool loop = true;
    while(loop)
    {
        // short unsigned int tabsCorrected = 0;
        int res =  pcap_next_ex(config->cleanup.handle, &header, &packetData);

        switch(res)
        {
            case 1: // no problems
                break;
            case 0:
                // buffer timeout expired
                if(config->captureMode == ONLINE_MODE) {
                    // continue;
                }
                break;
            case PCAP_ERROR_BREAK:
                // if in offline mode file is at the end and no more records are left
                if(config->captureMode == OFFLINE_MODE) {
                    loop = false;
                    continue;
                }
                break;
            default:
                break;
        }
        
        if(config->verbose)
            printf("Timestamp: %s\n", getTimestamp(header->ts, config));
        else
            printf("%s", getTimestamp(header->ts, config));

        frameDissector(packetData, header->len, config);

        packetCounter++;
        printf("\n");
    }
}

/**
 * @brief Handle function for SIGINT signals, frees all memory and exits the 
 * program
 * 
 * @param num 
 */
void sigintHandler(int num)
{
    if(num) {}
    // set number of packets to capture to 0
    globalConfig->numberOfPackets = 0;

    destroyConfig(globalConfig);
    globalConfig = NULL;

    exit(0);
}

int main(int argc, char* argv[])
{
    // Create and setup ProgramConfiguration
    Config* config = (Config*) malloc(sizeof(Config));
    if(config == NULL)
    {
        errHandling("Memory allocation for ProgramConfiguration failed", ERR_MALLOC);
    }

    setupConfig(config);
    // set globalConfig to be same as local, global is for SIGINT handling
    globalConfig = config;

    // setup SIGINT handling
    signal(SIGINT, sigintHandler);
    signal(SIGTERM, sigintHandler);
    signal(SIGQUIT, sigintHandler);

    // Handle program arguments
    argumentHandler(argc, argv, config);

    if(config->displayDevices)
    {
        findDevices(config, &(config->cleanup.allDevices));
        destroyConfig(config);
        return 0;
    }

    // Setup pcap file/network interface and apply filters
    config->cleanup.handle = pcapSetup(config);

    // loop through received packet/packets that will be received
    packetLooper(config);

    // memory clean up
    destroyConfig(config);
    
    return 0;
}


