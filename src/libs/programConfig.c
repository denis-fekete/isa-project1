#include "programConfig.h"

#define FREE_BUFFERS \
    bufferDestroy(config->interface);           \
    free(config->interface);                    \
    bufferDestroy(config->domainsfile);         \
    free(config->domainsfile);                  \
    bufferDestroy(config->translationsfile);    \
    free(config->translationsfile);             \
    bufferDestroy(config->addressToPrint);      \
    free(config->addressToPrint);               \

/**
 * @brief Sets default values to ProgramConfiguration(Config)
 * 
 * @param config Pointer to the program configurations. Must be allocated
 */
void setupConfig(Config* config)
{
    config->numberOfPackets = 1;
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
    config->domainsfile = malloc(sizeof(Buffer));
    if(config->domainsfile == NULL)
    {
        free(config->interface);
        free(config);
        errHandling("Failed to allocate memory for config->domainsfile", ERR_MALLOC);
        return;
    }
    config->translationsfile = malloc(sizeof(Buffer));
    if(config->translationsfile == NULL)
    {
        free(config->interface);
        free(config->domainsfile);
        free(config);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALLOC);
        return;
    }

    config->addressToPrint = malloc(sizeof(Buffer));
    if(config->addressToPrint == NULL)
    {
        free(config->interface);
        free(config->domainsfile);
        free(config->translationsfile);
        free(config);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALLOC);
        return;
    }

    bufferInit(config->interface);
    bufferInit(config->domainsfile);
    bufferInit(config->translationsfile);
    bufferInit(config->addressToPrint);

    // ------------------------------------------------------------------------
    config->cleanup.timeptr = (char*)malloc(RFC3339_TIME_LEN);
    if (config->cleanup.timeptr == NULL) {
        FREE_BUFFERS;
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
        return;
    }

    config->cleanup.pcapErrbuff = (char*)malloc(PCAP_ERRBUF_SIZE);
    if (config->cleanup.timeptr == NULL) {
        FREE_BUFFERS;
        free(config->cleanup.timeptr);
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
        return;
    }

    config->cleanup.allDevices = NULL;
    config->cleanup.handle = NULL;

    config->cleanup.configMutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
    if (config->cleanup.configMutex == NULL) {
        FREE_BUFFERS;
        free(config->cleanup.timeptr);
        free(config->cleanup.pcapErrbuff);
        free(config);
        errHandling("Failed to allocate memory for config->configMutex", ERR_MALLOC);
        return;
    }

    pthread_mutex_init(config->cleanup.configMutex, NULL);
}

/**
 * @brief Destroys and frees all values inside Config
 * 
 * @param config pointer to Config to be destroyed
 */
void destroyConfig(Config* config)
{
    FREE_BUFFERS;

    config->interface = NULL;
    config->pcapfile = NULL;
    config->domainsfile = NULL;
    config->translationsfile = NULL;

    free(config->cleanup.timeptr);
    config->cleanup.timeptr = NULL;

    free(config->cleanup.pcapErrbuff);
    config->cleanup.pcapErrbuff = NULL;

    // if ended before pcapSetup dont dont close it  
    pcap_close(config->cleanup.handle);
    pcap_freealldevs(config->cleanup.allDevices);

    pthread_mutex_destroy(config->cleanup.configMutex);
    free(config->cleanup.configMutex);
    free(config);
}


#define BOOL_TO_STR(boolVal) (boolVal)? "true" : "false"
/**
 * @brief Prints current configuration to stdout
 * 
 * @param config 
 */
void printConfig(Config* config)
{
    printf("Config options:\n");
    printf("\tInterface: %s\n", config->interface->data);
    printf("\tPCAP filename: %s\n", config->pcapfile->data);
    printf("\tDomains filename: %s\n", config->domainsfile->data);
    printf("\tTranslations filename: %s\n", config->translationsfile->data);
    printf("\tNO Packets: %u\n", config->numberOfPackets);
}