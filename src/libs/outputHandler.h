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
#include "pcapHandler.h"
#include "programConfig.h"
#include "packetDissector.h"

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
 * @brief Print hexdump-like to standard output
 * 
 * @param maxLen length of the array
 * @param packetData pointer to array of bytes
 */
void printHexDump(size_t maxLen, const unsigned char* packetData);

/**
 * @brief Print hexdump-like to standard output
 * 
 * @param maxLen length of the array
 * @param packetData pointer to array of bytes
 * @param frameS FrameSelections structure holding length of headers
 */
void printBetterHexDump(size_t maxLen, const unsigned char* packetData, FrameSections frameS);

/**
 * @brief Helping function for printing characters at end of line 
 * (after hexdump) with correct indentation
 * 
 * @param actualVPos actual vertical position
 * @param bytesPrinted how many bytes are going to be printed on this line
 * @param vPos vertical postion
 * @param skipped how many bytes were skipped do to indentation
 * @param packetData array of data
 */
void printCharsAtEnd(size_t* actualVPos, size_t bytesPrinted, size_t vPos, size_t skipped, const unsigned char* packetData);
#endif /*OUTPUT_HANDLER*/