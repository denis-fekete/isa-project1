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

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

typedef enum ErrorCodes
{
    NO_ERR,
    ERR_INTERNAL,
    ERR_MALOC,
    ERR_LIBPCAP,
    ERR_UNKNOWN_ARG,
    ERR_BAD_ARGS
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
 * @brief Replaces bytes in dst with bytes from src up to len lenght
 * 
 * @param dst Destinatin byte array
 * @param src Source byte arry
 * @param len Number of bytes to replace
 */
void stringReplace(char* dst, char* src, size_t len);

/**
 * @brief Checks if string conteins only valid characters that can be in 
 * usigned integer (no : '+', '-', '.', ',')
 * 
 * @param string Pointer to the string
 * @return true If string can be converted to valid number
 * @return false If string can not be converted to valid number
 */
bool stringIsValidUInt(char* string);

/**
 * @brief Prints hexadecimal values of byte array
 * 
 * @param packet 
 * @param len 
 */
void printBytes(const unsigned char* byteArr, size_t len);

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