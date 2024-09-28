
#include "outputHandler.h"

#define TIMEZONE_LEN sizeof("+00:00")

/**
 * @brief Returns array of characters with correct timestamp in RFC 3339 format
 * 
 * @param tv timestamp
 * @param config pointer to global configuration where string pointer is stored
 * @return char* 
 */
char* getTimestamp(struct timeval tv, Config* config)
{
    char* rtcTime = config->cleanup.timeptr;

    time_t time = tv.tv_sec;

    struct tm *tm_info = localtime(&time);
    if (tm_info == NULL)
    {
        errHandling("Failed to convert time to UTC", ERR_INTERNAL);
    }

    // add year, month, hour and seconds
    if (strftime(rtcTime, RFC3339_TIME_LEN, "%Y-%m-%d %T", tm_info) == 0)
     {
        errHandling("Failed to format time as RFC3339", ERR_INTERNAL);
    }

    return rtcTime;
}

#undef TIMEZONE_LEN

/**
 * @brief Checks is domain name exists in list of domain names, if not adds 
 * it to the list 
 * 
 * @param newEntry Possible new entry to the list 
 * @param list Pointer to the list
 */
void domainNameHandler(Buffer* newEntry, BufferList* list)
{
    if(listSearch(list, newEntry) == false)
    {
        listAddRecord(list, newEntry);
    }
}

/**
 * @brief Saves ipaddress and domain translation into a list
 * 
 * @param newEntry Possible new entry to the list
 * @param list Pointer to the list
 * @param secondPart On false (if first part) will create a new entry, on 
 * true (second part) will add IP address to it
 */
void translationNameHandler(Buffer* newEntry, BufferList* list, bool secondPart)
{
    if(!secondPart)
    {
        listAddRecord(list, newEntry);
    }
    else if(secondPart)
    {
        bufferAddChar(list->last->data, ' ');
        bufferAppend(list->last->data, newEntry);
    }
}
