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
#include "list.h"

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
    FILE* pcapFile;
} CleanUp;

#define NO_MODE 0
#define OFFLINE_MODE 1 
#define ONLINE_MODE 2

typedef struct ProgramConfiguration 
{
    union
    {
        Buffer* interface;
        Buffer* pcapFileName;
        void* exitOnNull;
    };

    unsigned numberOfPackets;
    char captureMode;
    bool verbose;

    Buffer* addressToPrint;

    BufferList* domainList;
    BufferList* translationsList;

    Buffer* domainsFile;
    Buffer* translationsFile;
    
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
 * @brief Prints current configuration to stdout
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