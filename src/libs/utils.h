/**
 * @file utils.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef UTILS_H
#define UTILS_H

// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------

#include "stdio.h"
#include "stdlib.h"
#include "stdbool.h"

#include "netinet/ether.h"
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netinet/ip_icmp.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

#define RFC3339_TIME_LEN 30 // Length of RFC3339 timestamp including '\0'

typedef enum ErrorCodes
{
    NO_ERR,
    ERR_INTERNAL,
    ERR_MALLOC,
    ERR_LIBPCAP,
    ERR_UNKNOWN_ARG,
    ERR_BAD_ARGS,
    ERR_FILE,
    ERR_UNKNOWN_PROTOCOL,
    ERR_NONEXISTING_FILE,
    ERR_BAD_PACKET
} errCodes_t;

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

/**
 * @brief Prints error message to the standard error ouput (stderr) and exits 
 * program with errorCode
 * 
 * @param errMessage Message to be printed to the stderr
 * @param errorCode Error code that program will exit with
 */
void errHandling(const char* errMessage, int errorCode);

/**
 * @brief Replaces bytes in dst with bytes from src up to len length
 * 
 * @param dst Destination byte array
 * @param src Source byte array
 * @param len Number of bytes to replace
 */
void stringReplace(char* dst, char* src, size_t len);

/**
 * @brief Checks if string contains only valid characters that can be in 
 * unsigned integer (no : '+', '-', '.', ',')
 * 
 * @param string Pointer to the string
 * @return true If string can be converted to valid number
 * @return false If string can not be converted to valid number
 */
bool stringIsValidUInt(char* string);

#ifdef DEBUG

/**
 * @brief Prints hexadecimal values of byte array
 * 
 * @param byteArr pointer to the byte arrays
 * @param len maximum length of the array
 * @param separator character to be put between characters of byte array
 */
void printBytes(const unsigned char* byteArr, size_t len, char separator);

#endif

#ifdef DEBUG
    #define debugPrint(...) \
        fprintf(__VA_ARGS__);
        
    #define debugPrintSeparator(fs) \
        fprintf(fs, "----------------------------------------\n");
#else
    #define debugPrint(...) ;
    #define debugPrintSeparator(fs) ;
#endif


#endif /*UTILS_H*/