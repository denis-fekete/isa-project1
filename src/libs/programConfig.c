#include "programConfig.h"

/**
 * @brief Sets default values to ProgramConfiguration(Config)
 * 
 * @param config Pointer to the program configurations. Must be allocated
 */
void setupConfig(Config* config)
{
    config->tcp = false;
    config->udp = false;
    config->icmp4 = false;
    config->icmp6 = false;
    config->arp = false;
    config->ndp = false;
    config->igmp = false;
    config->mld = false;
    config->numberOfPackets = 1;
    config->useFilter = false;
    config->wsHexdump = false;
    // ------------------------------------------------------------------------
    config->interface = malloc(sizeof(Buffer));
    if(config->interface == NULL)
    {
        free(config);
        errHandling("Failed to allocate memory for config->interface", ERR_MALLOC);
    }
    config->port = malloc(sizeof(Buffer));
    if(config->port == NULL)
    {
        free(config->interface);
        free(config);
        errHandling("Failed to allocate memory for config->port", ERR_MALLOC);
    }
    config->portDst = malloc(sizeof(Buffer));
    if(config->portDst == NULL)
    {
        free(config->interface);
        free(config->port);
        free(config);
        errHandling("Failed to allocate memory for config->portDst", ERR_MALLOC);
    }
    config->portSrc = malloc(sizeof(Buffer));
    if(config->portSrc == NULL)
    {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        free(config);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALLOC);
    }

    bufferInit(config->interface);
    bufferInit(config->port);
    bufferInit(config->portDst);
    bufferInit(config->portSrc);
    // ------------------------------------------------------------------------
    config->cleanup.timeptr = (char*)malloc(RFC3339_TIME_LEN);
    if (config->cleanup.timeptr == NULL) {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        free(config->portSrc);
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
    }

    config->cleanup.pcapErrbuff = (char*)malloc(PCAP_ERRBUF_SIZE);
    if (config->cleanup.timeptr == NULL) {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        free(config->portSrc);
        free(config->cleanup.timeptr);
        free(config);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALLOC);
    }

    config->cleanup.allDevices = NULL;
    config->cleanup.handle = NULL;

    config->cleanup.configMutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
    if (config->cleanup.configMutex == NULL) {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        free(config->portSrc);
        free(config->cleanup.timeptr);
        free(config->cleanup.pcapErrbuff);
        free(config);
        errHandling("Failed to allocate memory for config->configMutex", ERR_MALLOC);
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
    bufferDestroy(config->interface);
    bufferDestroy(config->port);
    bufferDestroy(config->portDst);
    bufferDestroy(config->portSrc);

    free(config->interface);
    free(config->port);
    free(config->portDst);
    free(config->portSrc);

    config->interface = NULL;
    config->port = NULL;
    config->portDst = NULL;
    config->portSrc = NULL;

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
    printf("\tDst port: %s\n", config->portDst->data);
    printf("\tSrc port: %s\n", config->portSrc->data);
    printf("\ttcp: %s\n", BOOL_TO_STR(config->tcp));
    printf("\tudp: %s\n", BOOL_TO_STR(config->udp));
    printf("\tarp: %s\n", BOOL_TO_STR(config->arp));
    printf("\tndp: %s\n", BOOL_TO_STR(config->ndp));
    printf("\tigmp: %s\n", BOOL_TO_STR(config->igmp));
    printf("\tmld: %s\n", BOOL_TO_STR(config->mld));
    printf("\tNO Packets: %u\n", config->numberOfPackets);
}