/**
 * @file pcapHandler.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Is a header file containing function definition for setting up a 
 * network capturing mechanism using libpcap library.
 * 
 * Main source of information: www.tcpdump.org
 * 
 * @copyright BSD 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. The names of the authors may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * License from: https://github.com/the-tcpdump-group/libpcap
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
/**
 * @brief Opens offline file from which a data traffic will be read
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 * @return pcap_t* Returns handle to which is applied filter and then used for
 * reading captured data
 * 
 * @author Tim Carstens
 * Source: https://www.tcpdump.org/pcap.html
 */
pcap_t* pcapOfflineSetup(Config* config);

/**
 * @brief Opens online network interface from which a data traffic will be read
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 * @return pcap_t* Returns handle to which is applied filter and then used for
 * reading captured data
 * 
 * @author Tim Carstens
 * Source: https://www.tcpdump.org/pcap.html
 */
pcap_t* pcapOnlineSetup(Config* config, pcap_if_t** allDevices, pcap_if_t** device);

/**
 * @brief Setups PCAP library to correctly capture traffic and set filters to 
 * accept only relevant internet traffic. 
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 * @param allDevices Pointer to the pointer containing all devices
 * @return pcap_t* PCAP handle for further working with/reading captured data
 * 
 * @author Tim Carstens
 * Source: https://www.tcpdump.org/pcap.html
 */
pcap_t* pcapSetup(Config* config, pcap_if_t** allDevices);

#endif /*PCAP_HANDLER_H*/