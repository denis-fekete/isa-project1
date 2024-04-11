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

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------
typedef struct CleanUp {
    char* timeptr; 
} CleanUp;

typedef struct ProgramConfiguration 
{
    Buffer* interface;
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

#endif /*PROGRAM_CONFIG_H*/