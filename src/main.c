/**
 * @file main.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

// https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
// https://www.rfc-editor.org/rfc/rfc3339

#include "libs/utils.h"
#include "libs/buffer.h"
#include "libs/pcapHandler.h"
#include "libs/programConfig.h"
#include "libs/argumentHandler.h"
#include "libs/packetDissector.h"

#include "pcap/pcap.h"

#include "time.h"
#include "signal.h"

Config* globalConfig;


#define LOCK_CONFIG                 \
    pthread_mutex_lock(config->cleanup.configMutex);    \
    if(config->exitOnNull == NULL)  \
    {                               \
        pthread_mutex_unlock(config->cleanup.configMutex);\
        break;                      \
    }                               \

#define UNLOCK_AND_CHECK_CONFIG     \
    pthread_mutex_unlock(config->cleanup.configMutex);
    
#define TIMEZONE_LEN sizeof("+00:00")

char* timeval2rfc3339(struct timeval tv, Config* config) 
{
    char* rtcTime = config->cleanup.timeptr;

    time_t time = tv.tv_sec;
    // convert to correct UTC time format for strftime()
    struct tm *tm_info = gmtime(&time);
    if (tm_info == NULL) {
        errHandling("Failed to convert time to UTC", 9/*TODO:*/);
    }

    // add year, month, hour and seconds
    if (strftime(rtcTime, RFC3339_TIME_LEN, "%Y-%m-%dT%T%z", tm_info) == 0) {
        errHandling("Failed to format time as RFC3339", 9/*TODO:*/);
    }

    // add miliseconds
    sprintf(rtcTime + 19, ".%03d", (int)(tv.tv_usec / 1000));

    // store times zone to other variable
    char timezone[TIMEZONE_LEN];
    if (strftime(timezone, TIMEZONE_LEN, "%z", tm_info) == 0) {
        errHandling("Failed to format timezone", 9/*TODO:*/);
    }

    // modify timezone from +0000 to +00:00 format
    timezone[5] = timezone[4]; // move last two digits
    timezone[4] = timezone[3];
    timezone[3] = ':'; // add :
    timezone[TIMEZONE_LEN - 1] = '\0';

    // add timezone
    sprintf(rtcTime + 23, "%s", timezone);

    return rtcTime;
}

void sigintHandler(int num)
{
    if(num) {}
    // try to lock config, to prevent deleting data while functions are working with it
    pthread_mutex_lock(globalConfig->cleanup.configMutex);

    // destroy config but leave mutex and config
    destroyConfig(globalConfig, true);
    globalConfig->exitOnNull = NULL;

    // unlock for main to check that it should cease function
    pthread_mutex_unlock(globalConfig->cleanup.configMutex);
    // TODO: explore better option
    sleep(1);
    // lock again and wait for main to stop
    pthread_mutex_lock(globalConfig->cleanup.configMutex);
    pthread_mutex_unlock(globalConfig->cleanup.configMutex);

    // destroy mutex and global config
    pthread_mutex_destroy(globalConfig->cleanup.configMutex);
    free(globalConfig->cleanup.configMutex);
    free(globalConfig);
}


void* threadFunction(void* vargp)
{
    Config* config = (Config*)vargp;

     // The header that pcap returns
    struct pcap_pkthdr* header;
    // The actual packet in bytes
	// const unsigned char* packet;

    long long int bytesToPrint = 0;
    unsigned int packetCounter = 0;
    const unsigned char* packetData;
    while(packetCounter < config->numberOfPackets)
    {
        // Lock mutex to prevent segmentation fault if someone tried to destroy it
        LOCK_CONFIG;
        
        short unsigned int tabs = 0;
        // short unsigned int tabsCorrected = 0;
        int res =  pcap_next_ex(config->cleanup.handle, &header, &packetData);
        if(!res ) {continue;;}

        // for(size_t i = 0; i < header->len; i++)
        // {
        //     printf("%hhx ", (packetData[i]));
        // }

        // printf("\n\n");
        // for(size_t i = 0; i < header->len; i++)
        // {
        //     printf("%hhx ", (ntohs(packetData[i]) & 0x00FF) );
        // }

        // printf("\n\n");
        // for(size_t i = 0; i < header->len; i++)
        // {
        //     printf("%hhx ", (ntohs(packetData[i]) & 0xFF00) );
        // }

        // for(size_t i = 0; i < header->len; i++)
        // {
        //     printf("%hhx%hhx ", ntohs(packetData[i]) );
        // }

        // printf("\n\n");

        // UNLOCK_AND_CHECK_CONFIG;
        // packetCounter++;
        // continue;
        UNLOCK_AND_CHECK_CONFIG;
        LOCK_CONFIG;
        
        // --------------------------------------------------------------------
        printf("timestamp: ");
        printf("%s\n", timeval2rfc3339(header->ts, config));

        frameDissector(packetData, header->len);

        UNLOCK_AND_CHECK_CONFIG;
        LOCK_CONFIG;
        // --------------------------------------------------------------------
        printf("\n");
        #define BYTES_PER_LINE 16

        for(size_t i = 0; i < header->len; i += BYTES_PER_LINE)
        {
            // check if bytes to be printed on line is smaller number than header.len - i
            if(BYTES_PER_LINE < ((long long unsigned ) header->len) - i)
            {
                // if yes print BYTES_PER_LINE
                bytesToPrint = BYTES_PER_LINE;
            }   
            // if no calculate how many bytes needs to printed and correct tabulators
            else 
            {
                bytesToPrint = header->len - i; 
                tabs = (BYTES_PER_LINE * 2 + BYTES_PER_LINE) - ( bytesToPrint * 2 + bytesToPrint);
            }

            // print line number in hex
            printf("0x%04zx: ", i);
            // print hexadecimal values
            printBytes( packetData + i, bytesToPrint, ' ');
            // separate
            printf(" ");
            // correct tabulation if last row is not full
            for(short unsigned int k = 0; k < tabs; k++)
            {
                printf(" ");
            }
            // print as printable characters
            printChars( packetData + i, bytesToPrint);
            printf("\n");
        }

        packetCounter++;
        printf("\n");

        UNLOCK_AND_CHECK_CONFIG;
    }

    return NULL;
}


int main(int argc, char* argv[])
{
    // ------------------------------------------------------------------------
    // Create and setup ProgramConfiguration
    // ------------------------------------------------------------------------
    
    Config* config = (Config*) malloc(sizeof(Config));
    if(config == NULL)
    {
        errHandling("Memory allocation for ProgramConfiguration failed", ERR_MALLOC);
    }

    setupConfig(config);
    // set globalConfig to be same as local, global is for SIGINT handling
    globalConfig = config;

    signal(SIGINT, sigintHandler);

    // ------------------------------------------------------------------------
    // Handle program arguments
    // ------------------------------------------------------------------------

    argumentHandler(argc, argv, config);
    #ifdef DEBUG
        printConfig(config);
        printf("\n");
    #endif
    // ------------------------------------------------------------------------
    // Setup pcap
    // ------------------------------------------------------------------------

    // Setup pcap
    config->cleanup.handle = pcapSetup(config, &(config->cleanup.allDevices));

    // ------------------------------------------------------------------------
    // Start getting packets
    // ------------------------------------------------------------------------

    pthread_t thread;
    pthread_create(&thread, NULL, threadFunction, config);
    pthread_join(thread, NULL);

    // ------------------------------------------------------------------------
    // Close and cleanup
    // ------------------------------------------------------------------------
    // if(config != NULL)
    // {    
    //     destroyConfig(config, false);
    // }   
    return 0;
}
