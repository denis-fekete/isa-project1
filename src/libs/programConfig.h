/**
 * @file programConfig.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief //TODO:
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef PROGRAM_CONFIG_H
#define PROGRAM_CONFIG_H

// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------

#include "utils.h"
#include "buffer.h"

#include "pthread.h"

#include "pcap/pcap.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------
typedef struct CleanUp {
    char* timeptr; 
    pcap_t* handle;
    pcap_if_t* allDevices;
    char* pcapErrbuff;
    pthread_mutex_t* configMutex;
} CleanUp;


typedef struct ProgramConfiguration 
{
    union
    {
        Buffer* interface;
        // reuse interface as indication that program should
        void* exitOnNull;
    };
    Buffer* port;
    Buffer* portSrc;
    Buffer* portDst;
    unsigned int numberOfPackets;
    bool tcp;
    bool udp;
    bool icmp4;
    bool icmp6;
    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
    bool useFilter;
    bool wsHexdump;
    CleanUp cleanup;
    
} Config;

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

/**
 * @brief Sets default values to ProgramConfiguration(Config)
 * 
 * @param config Pointer to the program configurations. Must be allocated
 */
void setupConfig(Config* config);

/**
 * @brief Prints currect configuration to stdout
 * 
 * @param config 
 */
void printConfig(Config* config);

/**
 * @brief Destroys and frees all values inside Config
 * 
 * @param config pointer to Config to be destroyed
 */
void destroyConfig(Config* config);

#endif /*PROGRAM_CONFIG_H*/