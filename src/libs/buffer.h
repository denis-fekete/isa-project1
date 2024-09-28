/**
 * @file buffer.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Structures and declaration of functions for Buffer
 * 
 * Buffer is an structure for defining byte arrays (char arrays / string)
 * with information about how many bytes has been allocated and how many 
 * has been used.
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#ifndef BUFFER_H
#define BUFFER_H 1

#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "utils.h"

#define INITIAL_BUFFER_SIZE 256

/**
 * @brief Buffer is an structure for defining byte arrays (char arrays / string)
 * with information about how many bytes has been allocated and how many 
 * has been used.
 */
typedef struct Buffer
{
    char* data;
    size_t allocated ;
    size_t used;
} Buffer;


/**
 * @brief Sets default values to the buffer
 * 
 * @warning Do not use on buffer that already has allocated memory
 * 
 * @param buffer Buffer to be initiated
 */
void bufferInit(Buffer* buffer);

/**
 * @brief Resizes buffer to new size, if buffer is not
 * initialized (NULL) default value (INITIAL_BUFFER_SIZE) will
 * be used instead to prevent allocation of small buffers
 * 
 * @param buffer Buffer to be resized
 * @param newSize New size
 */
void bufferResize(Buffer* buffer, size_t newSize);

/**
 * @brief Copies contents from src buffer to dst
 * 
 * @param dst Buffer to which data will be copied
 * @param src Buffer from which data will be copied
 */
void bufferCopy(Buffer* dst, Buffer* src);

/**
 * @brief Fills buffer with characters from stdin.
 * 
 * Fills buffer character by character until EOF is found.
 * If buffer is running out of space, it will be resized
 * 
 * @param buffer Pointer to the buffer. Can be inputted as NULL, however correct buffer size
 * is required
 * @param bufferSize Pointer size of provided buffer
 */
size_t loadBufferFromStdin(Buffer* buffer, bool* eofDetected);

/**
 * @brief Prints buffer characters byte by byte from start to used
 * 
 * @param buffer Input buffer
 * @param printHex prints characters that are non printable in () if set to true
 * as characters and other chars will be printed as hex codes
 */
void bufferPrint(Buffer* buffer, bool printHex);

/**
 * @brief Destroys Buffer and frees memory
 * 
 * @param buffer 
 */
void bufferDestroy(Buffer* buffer);

/**
 * @brief Adds string to the end of buffer
 * 
 * @warning String must be ended with "\0"
 * 
 * @param buffer pointer to initialized buffer 
 * @param string string that will be added 
 */
void bufferAddString(Buffer* buffer, char* string);

/**
 * @brief Adds character to the end of buffer
 * 
 * @warning String must be ended with "\0"
 * 
 * @param buffer pointer to initialized buffer 
 * @param ch character that will be added 
 */
void bufferAddChar(Buffer* buffer, char ch);

/**
 * @brief Sets buffer used size to 0 and sets first byte to '\0'
 * 
 * @param buffer pointer to Buffer to be cleared
 */
void bufferClear(Buffer* buffer);

/**
 * @brief Compares contents of two buffers until first '\0' is found or until 
 * used limit was reached. Returns TRUE if buffer data are same
 * 
 * @param first First buffer
 * @param second Second buffer
 * @return true Buffer data until first '\0' are same
 * @return false Buffer data until first '\0' are not same
 */
bool bufferCompare(Buffer* first, Buffer* second);

/**
 * @brief Appends src Buffer at the end of the dst Buffer 
 * 
 * @param dst Pointer to the destination Buffer
 * @param src Pointer to the source Buffer
 */
void bufferAppend(Buffer* dst, Buffer* src);

/**
 * @brief Sets new value to buffer parameter used
 * 
 * @param buffer Pointer to the buffer
 * @param used New value of used parameter
 */
void bufferSetUsed(Buffer* buffer, size_t used);

#endif /*BUFFER_H*/