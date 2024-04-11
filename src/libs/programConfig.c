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

    config->interface = malloc(sizeof(Buffer));
    if(config->interface == NULL)
    {
        errHandling("Failed to allocate memory for config->interface", ERR_MALOC);
    }
    config->port = malloc(sizeof(Buffer));
    if(config->port == NULL)
    {
        free(config->interface);
        errHandling("Failed to allocate memory for config->port", ERR_MALOC);
    }
    config->portDst = malloc(sizeof(Buffer));
    if(config->portDst == NULL)
    {
        free(config->interface);
        free(config->port);
        errHandling("Failed to allocate memory for config->portDst", ERR_MALOC);
    }
    config->portSrc = malloc(sizeof(Buffer));
    if(config->portSrc == NULL)
    {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        errHandling("Failed to allocate memory for config->portSrc", ERR_MALOC);
    }

    config->cleanup.timeptr = (char*)malloc(RFC3339_TIME_LEN * sizeof(char));
    if (config->cleanup.timeptr == NULL) {
        free(config->interface);
        free(config->port);
        free(config->portDst);
        free(config->portSrc);
        errHandling("Failed to allocate memory for config->cleanUp", ERR_MALOC);
    }


    bufferInit(config->interface);
    bufferInit(config->port);
    bufferInit(config->portDst);
    bufferInit(config->portSrc);
}

#define BOOL_TO_STR(boolVal) (boolVal)? "true" : "false"

/**
 * @brief Prints currect configuration to stdout
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