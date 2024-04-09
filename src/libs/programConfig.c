#include "programConfig.h"

/**
 * @brief Sets default values to ProgramConfiguration(Config)
 * 
 * @param config Pointer to the program configurations. Must be allocated
 */
void setupConfig(Config* config)
{
    config->enableTCP = false;
    config->enableUDP = false;
    config->displayOptions = dopt_ALL;
    config->numberOfPackets = 0;

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

    bufferInit(config->interface);
    bufferInit(config->port);
    bufferInit(config->portDst);
    bufferInit(config->portSrc);
}