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

typedef enum DisplayOptions 
{
    dopt_ALL,
    dopt_ICMP4,
    dopt_ICMP6,
    dopt_ARP,
    dopt_NDP,
    dopt_IGMP,
    dopt_MLD,
} dopt_t; 

typedef struct ProgramConfiguration 
{
    Buffer* interface;
    Buffer* port;
    Buffer* portSrc;
    Buffer* portDst;
    bool enableTCP;
    bool enableUDP;
    enum DisplayOptions displayOptions;
    unsigned int numberOfPackets;
    

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

#endif /*PROGRAM_CONFIG_H*/