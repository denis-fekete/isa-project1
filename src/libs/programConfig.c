#include "programConfig.h"

#define FREE_BUFFERS \
    bufferDestroy(config->interface);           \
    free(config->interface);                    \
    bufferDestroy(config->domainsFile);         \
    free(config->domainsFile);                  \
    bufferDestroy(config->translationsFile);    \
    free(config->translationsFile);             \
    bufferDestroy(config->addressToPrint);      \
    free(config->addressToPrint);

#define FREE_LISTS                              \
    listDestroy(config->domainList);            \
    listDestroy(config->translationsList);

/**
 * @brief Sets default values to ProgramConfiguration(Config)
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables.
 * Must be allocated
 */
void setupConfig(Config* config)
{
    config->captureMode = NO_MODE;
    config->verbose = 0;
    // ------------------------------------------------------------------------
    config->interface = malloc(sizeof(Buffer));
    if(config->interface == NULL)
    {
        free(config);
        errHandling("Failed to allocate memory for config->interface", ERR_MALLOC);
        return;
    }
    config->domainsFile = malloc(sizeof(Buffer));
    if(config->domainsFile == NULL)
    {
        free(config->interface);
        free(config);
        errHandling("Failed to allocate memory for config->domainsFile", ERR_MALLOC);
        return;
    }
    config->translationsFile = malloc(sizeof(Buffer));
    if(config->translationsFile == NULL)
    {
        free(config->interface);
        free(config->domainsFile);
        free(config);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALLOC);
        return;
    }

    config->addressToPrint = malloc(sizeof(Buffer));
    if(config->addressToPrint == NULL)
    {
        free(config->interface);
        free(config->domainsFile);
        free(config->translationsFile);
        free(config);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALLOC);
        return;
    }

    bufferInit(config->interface);
    bufferInit(config->domainsFile);
    bufferInit(config->translationsFile);
    bufferInit(config->addressToPrint);

    config->domainList = (BufferList*) malloc(sizeof(BufferList));
    if(config->domainList == NULL)
    {
        FREE_BUFFERS;
        free(config);
        errHandling("Failed to allocate memory for config->domainList", ERR_MALLOC);
    }

    config->translationsList = (BufferList*) malloc(sizeof(BufferList));
    if(config->translationsList == NULL)
    {
        FREE_BUFFERS;
        free(config->domainList);
        free(config);
        errHandling("Failed to allocate memory for config->domainList", ERR_MALLOC);
    }

    listInit(config->domainList);
    listInit(config->translationsList);


    // ------------------------------------------------------------------------
    config->cleanup.timeptr = (char*)malloc(RFC3339_TIME_LEN);
    if (config->cleanup.timeptr == NULL) {
        FREE_BUFFERS;
        FREE_LISTS;
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
        return;
    }

    config->cleanup.pcapErrbuff = (char*)malloc(PCAP_ERRBUF_SIZE);
    if (config->cleanup.timeptr == NULL) {
        FREE_BUFFERS;
        FREE_LISTS;
        free(config->cleanup.timeptr);
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
        return;
    }

    config->cleanup.allDevices = NULL;
    config->cleanup.handle = NULL;
    config->cleanup.pcapFile = NULL;
}

#include "outputHandler.h"

/**
 * @brief Destroys and frees all values inside Config
 * 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void destroyConfig(Config* config)
{
    // save results into a files
    saveToFiles(config);

    FREE_BUFFERS;
    FREE_LISTS;

    config->interface = NULL;
    config->pcapFileName = NULL;
    config->domainsFile = NULL;
    config->translationsFile = NULL;

    free(config->cleanup.timeptr);
    config->cleanup.timeptr = NULL;

    free(config->cleanup.pcapErrbuff);
    config->cleanup.pcapErrbuff = NULL;

    if(config->cleanup.handle != NULL)
        pcap_close(config->cleanup.handle);
        
    pcap_freealldevs(config->cleanup.allDevices);

    free(config);
}