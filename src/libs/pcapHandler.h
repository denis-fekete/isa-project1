/**
 * @file pcapHandler.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef PCAP_HANDLER_H
#define PCAP_HANDLER_H

// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------

#include "unistd.h"
#include "string.h"
#include "sys/types.h"
#include "pcap/pcap.h"
#include "arpa/inet.h"

#include "utils.h"
#include "programConfig.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

pcap_t* pcapSetup(Config* config, pcap_if_t** allDevices, char** errorbuf);

#endif /*PCAP_HANDLER_H*/