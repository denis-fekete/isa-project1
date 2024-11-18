
#include "outputHandler.h"

#define TIMEZONE_LEN sizeof("+00:00")

/**
 * @brief Returns array of characters with correct timestamp in RFC 3339 format
 * 
 * @param tv timestamp
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
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
        // delete last .
        bufferSetUsed(newEntry, newEntry->used - 1);

        listAddRecord(list, newEntry);

        bufferSetUsed(newEntry, newEntry->used + 1);
    }
}

/**
 * @brief Saves ipaddress and domain translation into a list
 * 
 * @param newEntry Possible new entry to the list
 * @param tmp Temporary buffer containing first and second parts joined
 * @param list Pointer to the list
 * @param secondPart On false (if first part) will create a new entry, on 
 * true (second part) will add IP address to it
 */
void translationNameHandler(Buffer* newEntry, Buffer* tmp, BufferList* list, bool secondPart)
{
    if(!secondPart)
    {
        // delete last .
        bufferSetUsed(newEntry, newEntry->used - 1);
        bufferCopy(tmp, newEntry);
    }
    else if(secondPart)
    {
        bufferAddChar(tmp, ' ');
        bufferAppend(tmp, newEntry);
        if(listSearch(list, tmp) == false) 
        {
            listAddRecord(list, tmp);
        }
    }
}



/**
 * @brief Save domain names and translated ip addresses to the user provided files
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void saveToFiles(Config* config)
{
    if(config->domainsFile->data != NULL)
    {
        FILE* domFile = fopen(config->domainsFile->data, "w");
        if(domFile == NULL)
            errHandling("Failed to open file for domain names", ERR_NONEXISTING_FILE);

        Record* elem = config->domainList->first;
        while(elem != NULL)
        {
            if(elem->next != NULL)
            {
                bufferAddChar(elem->data, '\n');
            }
            bufferAddChar(elem->data, '\0');
            fprintf(domFile, "%s", elem->data->data);

            elem = elem->next;
        }

        fclose(domFile);
    }


    if(config->translationsFile->data != NULL)
    {
        FILE* tranFile = fopen(config->translationsFile->data, "w");
        if(tranFile == NULL)
            errHandling("Failed to open file for translated addresses", ERR_NONEXISTING_FILE);

        Record* elem = config->translationsList->first;
        while(elem != NULL)
        {
            if(elem->next != NULL)
            {
                bufferAddChar(elem->data, '\n');
            }
            bufferAddChar(elem->data, '\0');
            fprintf(tranFile, "%s", elem->data->data);
            
            elem = elem->next;
        }

        fclose(tranFile);
    }
}