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
void listInit(BufferList* list)
{
    list->first = NULL;
    list->last = NULL;
    list->len = 0;
}

/**
 * @brief Destroys BufferList
 * 
 * @param list list to be destroyed
 */
void listDestroy(BufferList* list)
{
    IS_INITIALIZED;

    listClear(list);

    free(list);
}

/**
 * @brief Deletes all records in list
 * 
 * @param list List that will be cleared
 */
void listClear(BufferList* list)
{
    IS_INITIALIZED;
    
    if(list->first == NULL)
    {
        return;
    }

    Record* deleteNext = list->first;
    Record* tmp = NULL;

    while(deleteNext != NULL)
    {
        tmp = deleteNext;
        bufferDestroy(tmp->data);
        free(tmp->data);
        
        deleteNext = tmp->next;
        free(tmp);
    }

    list->first = NULL;
    list->last = NULL;
    list->last = 0;
}


/**
 * @brief Creates and initializes message and returns pointer to it
 * 
 * @param buffer Contents of buffer that will be copied into message
 * @param msgFlags Flags that will be set
 * @return Record* Pointer to new allocated message
 */
Record* createRecord(Buffer* buffer)
{
    Record* tmpRecord = (Record*) malloc(sizeof(Record));

    if(tmpRecord == NULL)
    {
        errHandling("Malloc failed in listAddRecord() for Record", 
            ERR_INTERNAL);
    }

    Buffer* tmpBuffer = (Buffer*) malloc(sizeof(Buffer));
    if(tmpRecord == NULL)
    {
        errHandling("Malloc failed in listAddRecord() for Buffer", 
            ERR_INTERNAL);
    }
    /* set default values to the message attributes*/
    bufferInit(tmpBuffer);

    /* Copies input buffer to the new message*/
    bufferCopy(tmpBuffer, buffer);

    tmpRecord->data = tmpBuffer;
    tmpRecord->next = NULL;
    tmpRecord->previous = NULL;

    return tmpRecord;
}

/**
 * @brief Adds new message to the list at the end
 * 
 * @param list BufferList to which will the new message be added
 * @param buffer is and input buffer from which the new message will be created
 * @param cmdType type of message to be set to the message
 */
void listAddRecord(BufferList* list, Buffer* buffer)
{
    IS_INITIALIZED;

    Record* newRecord = createRecord(buffer);

    // if list doesn't have first, set this msg as first
    if(list->first == NULL)
    {
        list->first = newRecord;
    }

    Record* oldLast = list->last; 

    if(list->last == NULL)
    {
        list->last = newRecord;
    }
    else
    {
        list->last->next = newRecord;
    }

    list->last = newRecord;
    list->last->previous = oldLast;
    
    // set new record's previous value to NULL
    list->last->next = NULL;

    // increase list size
    list->len += 1;
}

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
bool listSearch(BufferList* list, Buffer* searched)
{
    Record* elem = list->last;
    while(elem != NULL)
    {
        if(bufferCompare(elem->data, searched))
        {
            return true;
        }

        
        elem = elem->previous;
    }

    return false;
}

/**
 * @brief Check if BufferList is empty
 * 
 * @param list Queue to be checked
 * @return true if list is empty
 * @return false if list is not empty
 */
bool listIsEmpty(BufferList* list)
{
    IS_INITIALIZED;
    
    if(list->len == 0){
        return true;
    }

    return false;
}

/**
 * @brief Prints Records in list
 * 
 * @param list Pointer to the list
 */
void listPrintContents(BufferList* list)
{
    Record* elem = list->first;

    for(unsigned i = 1; elem != NULL; i++)
    {
        printf("%u.", i);
        bufferPrint(elem->data, 0);
        printf("\n");

        elem = elem->next;
    }
}

#undef HIGHER_BYTE_POSITION
#undef LOWER_BYTE_POSITION
#undef IS_INITIALIZED