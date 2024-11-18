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
    char captureMode;
    bool verbose;
    bool displayDevices;

    union
    {
        Buffer* interface;
        Buffer* pcapFileName;
        Buffer* tmpListEntry;
    };
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
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables.
 * Must be allocated
 */
void setupConfig(Config* config);

/**
 * @brief Destroys and frees all values inside Config
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void destroyConfig(Config* config);

#endif /*PROGRAM_CONFIG_H*/