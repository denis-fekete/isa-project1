/**
 * @file buffer.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Implementation of Buffer functions
 * 
 * Buffer is an structure for defining byte arrays (char arrays / string)
 * with information about how many bytes has been allocated and how many 
 * has been used.
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "buffer.h"

/**
 * @brief Sets default values to the buffer
 * 
 * @warning Do not use on buffer that already has allocated memory
 * 
 * @param buffer Buffer to be reseted
 */
void bufferInit(Buffer* buffer)
{
    buffer->data = NULL;
    buffer->allocated = 0;
    buffer->used = 0;
}


/**
 * @brief Resizes buffer to new size, if buffer is not
 * iniatilized (NULL) default value (INITIAL_BUFFER_SIZE) will
 * be used instead to prevent allocation of small buffers
 * 
 * @param buffer Buffer to be resized
 * @param newSize New size
 */
void bufferResize(Buffer* buffer, size_t newSize)
{
    if(newSize <= buffer->allocated)
    {
        return;
    }

    // Realloc buffer
    char* tmp = (char*) realloc(buffer->data, newSize);
    // Check for failed memory reallocation
    if(tmp == NULL)
    {
        errHandling("Failed to reallocate memory for buffer in bufferResize()", ERR_MALLOC);
    }
    // Save new value to buffer and bufferSize
    buffer->data = tmp;
    buffer->allocated = newSize;
}

/**
 * @brief Copies contents from src buffer to dst
 * 
 * @param dst Buffer to which data will be copied
 * @param src Buffer from which data will be copied
 */
void bufferCopy(Buffer* dst, Buffer* src)
{
    if(dst == NULL || src == NULL)
    {
        errHandling("In bufferCopy() src or dst pointers are null", ERR_INTERNAL);
    }

    // If dst is smaller than src, resize it
    if(dst->allocated < src->used)
    {
        bufferResize(dst, src->used);
    }

    for (size_t i = 0; i < src->used; i++)
    {
        dst->data[i] = src->data[i];
    }

    dst->used = src->used;
}

/**
 * @brief Prints buffer characters byte by byte from start to used
 * 
 * @param buffer Input buffer
 * @param hex If not 0 (false) prints hex values with white spaces between
 * @param smartfilter If not 0 (false) only alphanumeric chacters will be prited
 * as chracaters and other chars will be printed as hex codes
 */
void bufferPrint(Buffer* buffer, int useDebugPrint)
{
    if(buffer->data == NULL || buffer->used == 0) { return; }

    for(size_t i = 0; i < buffer->used; i++)
    {
        char c = buffer->data[i];
        // if( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        if( (c >= 0x20 && c <= 0x7e))
        {
            if(useDebugPrint) { debugPrint(stdout, "%c", c); }
            else { printf("%c", c); }
        }
        else
        {
            if(useDebugPrint) { debugPrint(stdout, "(%hhx)", (unsigned char)c); }
            else { printf("(%hhx)", (unsigned char)c); }
        }
    }

    if(useDebugPrint) { debugPrint(stdout, "\n"); }
    else { printf("\n"); }
}

/**
 * @brief Adds string to the end of buffer
 * 
 * @warning String must be ended with "\0"
 * 
 * @param buffer pointer to initialized buffer 
 * @param string string that will be added 
 */
void bufferAddString(Buffer* buffer, char* string)
{
    int stringLen = strlen(string);
    
    int currentBufferLen = buffer->used;
    // check if buffer has any data in it
    if(buffer->data != NULL)
    {
        // get current length of buffer, if '\0' is last character dont count it
        if(buffer->data[buffer->used - 1] == '\0')
        {
            currentBufferLen--;
        }
    }

    // change size of buffer to new value, +1 is for '\0'
    bufferResize(buffer, currentBufferLen + stringLen + 1);

    // "old buffer string" + "new string"
    // add input string to the end of buffer
    stringReplace(&(buffer->data[currentBufferLen]), string, stringLen);

    // add end '\0' to the buffer
    buffer->data[currentBufferLen + stringLen] = '\0';
    buffer->used = currentBufferLen + stringLen + 1;
}


/**
 * @brief Destroys Buffer and frees memory
 * 
 * @param buffer 
 */
void bufferDestroy(Buffer* buffer)
{
    if(buffer->data != NULL)
    {
        free(buffer->data);
    }   
}