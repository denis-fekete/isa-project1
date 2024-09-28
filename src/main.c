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
#include "libs/outputHandler.h"

#include "pcap/pcap.h"

#include "time.h"
#include "signal.h"

Config* globalConfig;
bool sigintTriggered;

void* threadFunction(void* vargp)
{
    Config* config = (Config*)vargp;

     // The header that pcap returns
    struct pcap_pkthdr* header;

    unsigned int packetCounter = 0;
    const unsigned char* packetData;

    while(packetCounter < config->numberOfPackets)
    {
        // short unsigned int tabsCorrected = 0;
        int res =  pcap_next_ex(config->cleanup.handle, &header, &packetData);
        if(!res ) { errHandling("Capturing packet failed!", 99); }

        // Lock mutex to prevent segmentation fault if someone tried to destroy it

        if(config->verbose)
            printf("Timestamp: %s\n", getTimestamp(header->ts, config));
        else
            printf("%s", getTimestamp(header->ts, config));

        frameDissector(packetData, header->len, config);

        packetCounter++;
        printf("\n");
    }

    return NULL;
}

void sigintHandler(int num)
{
    if(num) {}
    sigintTriggered = true;

    // try to lock config, to prevent deleting data while functions are working with it
    // pthread_mutex_lock(globalConfig->cleanup.configMutex);
    // set number of packets to capture to 0
    globalConfig->numberOfPackets = 0;

    destroyConfig(globalConfig);
    globalConfig = NULL;
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
    sigintTriggered = false;

    // sets SIGINT handling
    signal(SIGINT, sigintHandler);

    // Handle program arguments
    argumentHandler(argc, argv, config);

    // Setup pcap
    config->cleanup.handle = pcapSetup(config, &(config->cleanup.allDevices));

    // Start getting packets in another thread
    pthread_t thread;
    pthread_create(&thread, NULL, threadFunction, config);
    pthread_join(thread, NULL);

    
    saveToFiles(config);

    // Close and cleanup
    if(!sigintTriggered)
    {    
        destroyConfig(config);
    }   
    return 0;
}


