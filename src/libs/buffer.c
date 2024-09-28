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
 * @param buffer Buffer to be initiated
 */
void bufferInit(Buffer* buffer)
{
    buffer->data = NULL;
    buffer->allocated = 0;
    buffer->used = 0;
}


/**
 * @brief Resizes buffer to new size, if buffer is not
 * initalized (NULL) default value (INITIAL_BUFFER_SIZE) will
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
 * @param printHex prints characters that are non printable in () if set to true
 * as characters and other chars will be printed as hex codes
 */
void bufferPrint(Buffer* buffer, bool printHex)
{
    if(buffer->data == NULL || buffer->used == 0) { return; }

    for(size_t i = 0; i < buffer->used; i++)
    {
        char c = buffer->data[i];
        // if( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        if( (c >= 0x20 && c <= 0x7e) )
        {
            printf("%c", c);
        }
        else
        {
            if(printHex)
                printf("(%hhx)", (unsigned char)c);
        }
    }
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

    bufferResize(buffer, buffer->used + stringLen);

    // add input string to the end of buffer
    stringReplace(&(buffer->data[buffer->used]), string, stringLen);

    buffer->used = buffer->used + stringLen;
}

/**
 * @brief Adds character to the end of buffer
 * 
 * @warning String must be ended with "\0"
 * 
 * @param buffer pointer to initialized buffer 
 * @param ch character that will be added 
 */
void bufferAddChar(Buffer* buffer, char ch)
{
    // change size of buffer to new value
    bufferResize(buffer, buffer->used + 1);

    buffer->data[buffer->used] = ch;

    buffer->used = buffer->used + 1;
}

/**
 * @brief Sets buffer used size to 0 and sets first byte to '\0'
 * 
 * @param buffer pointer to Buffer to be cleared
 */
void bufferClear(Buffer* buffer)
{
    buffer->used = 0;
    if(buffer->data != NULL)
    {
        buffer->data[0] = 0;
    }
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

/**
 * @brief Compares contents of two buffers until first '\0' is found or until 
 * used limit was reached. Returns TRUE if buffer data are same
 * 
 * @param first First buffer
 * @param second Second buffer
 * @return true Buffer data until first '\0' are same
 * @return false Buffer data until first '\0' are not same
 */
bool bufferCompare(Buffer* first, Buffer* second)
{
    unsigned smaller = (first->used < second->used)? first->used : second->used;
    // compare only contents of buffer, used is position where buffer end
    // (not  part of used section), therefore check only used-1
    smaller--;

    for(unsigned i = 0; 1 ; i++)
    {
        if(first->data[i] != second->data[i])
            return false;

        if(i >= smaller)
            break;
    }

    return true;
}

/**
 * @brief Appends src Buffer at the end of the dst Buffer 
 * 
 * @param dst Pointer to the destination Buffer
 * @param src Pointer to the source Buffer
 */
void bufferAppend(Buffer* dst, Buffer* src)
{
    if(dst == NULL || src == NULL)
    {
        errHandling("In bufferAppend() src or dst pointers are null", ERR_INTERNAL);
    }

    // If dst is smaller than src, resize it
    if(dst->allocated < dst->used + src->used)
    {
        bufferResize(dst, dst->used + src->used);
    }

    for (size_t i = dst->used, k = 0; i < dst->used + src->used; i++, k++)
    {
        dst->data[i] = src->data[k];
    }

    dst->used = dst->used + src->used;
}

/**
 * @brief Sets new value to buffer parameter used
 * 
 * @param buffer Pointer to the buffer
 * @param used New value of used parameter
 */
void bufferSetUsed(Buffer* buffer, size_t used)
{
    if(buffer != NULL)
        buffer->used = used;
}