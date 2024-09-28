/**
 * @file outputHandler.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#ifndef OUTPUT_HANDLER
#define OUTPUT_HANDLER

// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------

#include "utils.h"
#include "buffer.h"
#include "list.h"
#include "programConfig.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

/**
 * @brief Returns array of characters with correct timestamp in RFC 3339 format
 * 
 * @param tv timestamp
 * @param config pointer to global configuration where string pointer is stored
 * @return char* 
 */
char* getTimestamp(struct timeval tv, Config* config);

/**
 * @brief Checks is domain name exists in list of domain names, if not adds 
 * it to the list 
 * 
 * @param newEntry Possible new entry to the list 
 * @param list Pointer to the list
 */
void domainNameHandler(Buffer* newEntry, BufferList* list);

/**
 * @brief Saves ipaddress and domain translation into a list
 * 
 * @param newEntry Possible new entry to the list
 * @param list Pointer to the list
 * @param secondPart On false (if first part) will create a new entry, on 
 * true (second part) will add IP address to it
 */
void translationNameHandler(Buffer* newEntry, BufferList* list, bool secondPart);

#endif /*OUTPUT_HANDLER*/