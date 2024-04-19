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
    if (tm_info == NULL)
    {
        errHandling("Failed to convert time to UTC", 9/*TODO:*/);
    }

    // add year, month, hour and seconds
    if (strftime(rtcTime, RFC3339_TIME_LEN, "%Y-%m-%dT%T%z", tm_info) == 0)
     {
        errHandling("Failed to format time as RFC3339", 9/*TODO:*/);
    }

    // add miliseconds
    sprintf(rtcTime + 19, ".%03d", (int)(tv.tv_usec / 1000));

    // store times zone to other variable
    char timezone[TIMEZONE_LEN];
    if (strftime(timezone, TIMEZONE_LEN, "%z", tm_info) == 0)
    {
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

#undef TIMEZONE_LEN

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

#define BYTES_PER_LINE 16


void printHexDump(size_t maxLen, const unsigned char* packetData)
{
    long long int bytesToPrint = 0;
    short unsigned int tabs = 0;
    for(size_t i = 0; i < maxLen; i += BYTES_PER_LINE)
    {
        // check if bytes to be printed on line is smaller number than header.len - i
        if(BYTES_PER_LINE < ((long long unsigned ) maxLen) - i)
        {
            // if yes print BYTES_PER_LINE
            bytesToPrint = BYTES_PER_LINE;
        }   
        // if no calculate how many bytes needs to printed and correct tabulators
        else 
        {
            bytesToPrint = maxLen - i; 
            tabs = (BYTES_PER_LINE * 2 + BYTES_PER_LINE) - ( bytesToPrint * 2 + bytesToPrint);
        }

        // print line number in hex
        printf("\t0x%04zx: ", i);
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
}
#undef BYTES_PER_LINE


void printCharsAtEnd(size_t* actualVPos, size_t bytesPrinted, size_t vPos, size_t skipped, const unsigned char* packetData)
{
    const unsigned short VPOS_B_SIZE = sizeof("ff ") - 1;
    const unsigned short BYTES_PER_LINE = 16;
    const unsigned short CHAR_VPOS = BYTES_PER_LINE * VPOS_B_SIZE;
    const unsigned short CHAR_INDENT_VPOS = CHAR_VPOS + 7;

    // fix indentation
    for(; *actualVPos < CHAR_VPOS + skipped; (*actualVPos)++) { printf(" "); }
    
    const unsigned char* byte = packetData + bytesPrinted - vPos / VPOS_B_SIZE + skipped;
    // print bytes in as characters if printable
    for(size_t i = 0; i < vPos / VPOS_B_SIZE - skipped; i++)
    {
        if(byte[i] >= 0x20 && byte[i] <= 0x7e)
            printf("%c", (unsigned char) byte[i]);
        else
            printf(".");
        // add one extra in the middle
        if(*actualVPos == CHAR_INDENT_VPOS)
            printf(" ");

        (*actualVPos)++;
    }
    printf("\n");
}


void printBetterHexDump(size_t maxLen, const unsigned char* packetData, FrameSections frameS)
{
    size_t bytesPrinted = 0; 
    size_t vPos = 0;
    size_t actualVPos = 0;
    size_t hPos = 0;
    size_t skipped = 0; 

    const unsigned short VPOS_B_SIZE = sizeof("ff ") - 1;
    const unsigned short BYTES_PER_LINE = 16;

    for(; bytesPrinted < maxLen; bytesPrinted++)
    {
        unsigned char byte = *(packetData + bytesPrinted);

        if(bytesPrinted == 0)
        {
            printf("Data layer:\n");
            printf("\t0x%04zx: ", hPos);
            
            actualVPos = 0;
        }
        else if(bytesPrinted == frameS.dataLen)
        {
            // fix indentation at end of line
            printCharsAtEnd(&actualVPos, bytesPrinted, vPos, skipped, packetData);

            printf("Network layer:\n");
            printf("\t0x%04zx: ", hPos);
            actualVPos = 0;
        }
        else if(bytesPrinted == frameS.networkLen)
        {
            // fix indentation at end of line
            printCharsAtEnd(&actualVPos, bytesPrinted, vPos, skipped, packetData);

            printf("Transport layer:\n");
            printf("\t0x%04zx: ", hPos);
            actualVPos = 0;
        }

        // fix indentation if layer segment was changed
        for(; actualVPos < vPos; actualVPos++)
        {
            printf(" ");
            skipped++; // count skipped characters
        }

        // vertical position is over allowed bytes per line add new line
        if(vPos >= BYTES_PER_LINE * VPOS_B_SIZE)
        {
            skipped = skipped / VPOS_B_SIZE;
            // fix indentation at end of line
            printCharsAtEnd(&actualVPos, bytesPrinted, vPos, skipped, packetData);

            hPos++;
            printf("\t0x%04zx: ", hPos);
            vPos = 0;
            actualVPos = 0;
            skipped = 0;
        }

        // print byte and separator
        printf("%02hhx ", byte);

        vPos+= VPOS_B_SIZE;
        actualVPos += VPOS_B_SIZE;
    }

    printCharsAtEnd(&actualVPos, bytesPrinted, vPos, skipped, packetData);
}

void* threadFunction(void* vargp)
{
    Config* config = (Config*)vargp;

     // The header that pcap returns
    struct pcap_pkthdr* header;
    // The actual packet in bytes
	// const unsigned char* packet;

    const bool betterHexDump = true;

    unsigned int packetCounter = 0;
    const unsigned char* packetData;
    while(packetCounter < config->numberOfPackets)
    {
        // Lock mutex to prevent segmentation fault if someone tried to destroy it
        LOCK_CONFIG;

        // short unsigned int tabsCorrected = 0;
        int res =  pcap_next_ex(config->cleanup.handle, &header, &packetData);
        if(!res ) { errHandling("Capturing packet failed!", 99); }

        UNLOCK_AND_CHECK_CONFIG;
        LOCK_CONFIG;
        
        // --------------------------------------------------------------------
        printf("Number: %u\n", packetCounter);
        printf("\ttimestamp: %s\n", timeval2rfc3339(header->ts, config));

        FrameSections frameSelection =  frameDissector(packetData, header->len);

        UNLOCK_AND_CHECK_CONFIG;
        LOCK_CONFIG;
        
        // --------------------------------------------------------------------

        // if(betterHexDump)
        //     printBetterHexDump(header->len, packetData, frameSelection);
        // else
        //     printHexDump(header->len, packetData);

        if(betterHexDump) {}
        printBetterHexDump(header->len, packetData, frameSelection);
        printf("\n\n\n\n");
        printHexDump(header->len, packetData);

        packetCounter++;
        printf("\n");

        UNLOCK_AND_CHECK_CONFIG;
    }

    return NULL;
}


int main(int argc, char* argv[])
{
    // Create and setup ProgramConfiguration
    Config* config = (Config*) malloc(sizeof(Config));
    if(config == NULL)
    {
        errHandling("Memory allocation for ProgramConfiguration failed", ERR_MALLOC);
    }

    setupConfig(config);
    // set globalConfig to be same as local, global is for SIGINT handling
    globalConfig = config;

    signal(SIGINT, sigintHandler);

    // Handle program arguments
    argumentHandler(argc, argv, config);

    // Setup pcap
    config->cleanup.handle = pcapSetup(config, &(config->cleanup.allDevices));


    // Start getting packets in another thread
    pthread_t thread;
    pthread_create(&thread, NULL, threadFunction, config);
    pthread_join(thread, NULL);

    // Close and cleanup
    if(config != NULL)
    {    
        destroyConfig(config, false);
    }   
    return 0;
}


