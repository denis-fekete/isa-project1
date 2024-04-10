/**
 * @file utils.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "string.h"
#include "utils.h"

/**
 * @brief Prints error message to the standard error ouput (stderr) and exits 
 * program with errorCode
 * 
 * @param errMessage Message to be printed to the stderr
 * @param errorCode Error code that program will exit with
 */
void errHandling(const char* errMessage, int errorCode)
{
    if(errorCode != NO_ERR)
    {
        // filter out empty messages
        if(strcmp(errMessage, "") != 0)
        {
            fprintf(stderr, "ERR: %s\n", errMessage);
        }
    }

    exit(errorCode);
}

/**
 * @brief Replaces bytes in dst with bytes from src up to len lenght
 * 
 * @param dst Destinatin byte array
 * @param src Source byte arry
 * @param len Number of bytes to replace
 */
void stringReplace(char* dst, char* src, size_t len)
{
    if(dst != NULL && src != NULL)
    {
        for(size_t i = 0; i < len; i++)
        {
            dst[i] = src[i];
        }
        return;
    }

    #ifdef DEBUG
        fprintf(stderr, "Error: stringReplace() received bad pointer or "
        "invalid length (dst:%p, src:%p, len:%ld\n", dst, src, len);
    #endif
}

/**
 * @brief Checks if string conteins only valid characters that can be in 
 * usigned integer (no : '+', '-', '.', ',')
 * 
 * @param string Pointer to the string
 * @return true If string can be converted to valid number
 * @return false If string can not be converted to valid number
 */
bool stringIsValidUInt(char* string)
{
    for (size_t i = 0; string[i] != '\0'; i++)
    {
        if(string[i] < '0' || string[i] > '9')
            return false; 
    }
    
    return true;
}

/**
 * @brief Prints hexadecimal values of byte array
 * 
 * @param packet 
 * @param len 
 */
void printBytes(const unsigned char* byteArr, size_t len)
{
    for(size_t i = 0; i < len; i++)
    {
        printf("%hhx ", (unsigned char) byteArr[i]);
    }
}