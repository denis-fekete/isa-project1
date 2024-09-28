/**
 * @file msgQueue.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Declaration of functions and structures of MessageQueue for storing 
 * and correctly working with multiple buffers.
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#ifndef LIST_H
#define LIST_H

#include "pthread.h"
#include "utils.h"
#include "buffer.h"

// ----------------------------------------------------------------------------
// Defines, typedefs and structures
// ----------------------------------------------------------------------------


/**
 * @brief Record in queue containing Buffer with message contents,
 *  type of message, flag and pointer to the message behind this message
 */
typedef struct Record {
    Buffer* data;
    struct Record* next;
    struct Record* previous;
} Record;

/**
 * @brief MessageQueue is priority FIFO (first in first out) queue contains
 * Record structures and mutex lock for protecting data from being access 
 * at multiple points in same time.
 */
typedef struct BufferList {
    Record* first; // Pointer to the first message
    Record* last; // Pointer to the last message
    size_t len; // length of queue
} BufferList;

// ----------------------------------------------------------------------------
// Functions
// ----------------------------------------------------------------------------
/**
 * @file msgQueue.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Implementation of BufferList for storing and correctly working 
 * with multiple messages.
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "list.h"

#define HIGHER_MSGID_BYTE_POSTION 2
#define LOWER_MSGID_BYTE_POSTION 1

#define IS_INITIALIZED                                              \
    if(list == NULL) {                                              \
        errHandling("Uninitialized list was passed as argument",    \
            ERR_INTERNAL);                                          \
    }                                                               \

/**
 * @brief Initializes BufferList with default size (DEFAULT_MESSAGE_QUEUE_SIZE)
 * 
 * @param list BufferList to be initalized
 */
void listInit(BufferList* list);

/**
 * @brief Destroys BufferList
 * 
 * @param list list to be destroyed
 */
void listDestroy(BufferList* list);

/**
 * @brief Deletes all records in list
 * 
 * @param list List that will be cleared
 */
void listClear(BufferList* list);

/**
 * @brief Creates and initializes message and returns pointer to it
 * 
 * @param buffer Contents of buffer that will be copied into message
 * @param msgFlags Flags that will be set
 * @return Record* Pointer to new allocated message
 */
Record* createRecord(Buffer* buffer);

/**
 * @brief Adds new message to the list at the end
 * 
 * @param list BufferList to which will the new message be added
 * @param buffer is and input buffer from which the new message will be created
 * @param cmdType type of message to be set to the message
 */
void listAddRecord(BufferList* list, Buffer* buffer);

/**
 * @brief Search for element in list, returns TRUE if element with same value 
 * in Buffer->data was found
 * 
 * @param list List to be searched in 
 * @param searched Element that we are searching for
 * @param type Type of the element to speed up proccess (must be same in both types)
 * @return true Element was found in List
 * @return false Element was not found
 */
bool listSearch(BufferList* list, Buffer* searched);

/**
 * @brief Check if BufferList is empty
 * 
 * @param list Queue to be checked
 * @return true if list is empty
 * @return false if list is not empty
 */
bool listIsEmpty(BufferList* list);

/**
 * @brief Prints Records in list
 * 
 * @param list Pointer to the list
 */
void listPrintContents(BufferList* list);

#endif /*LIST_H*/
