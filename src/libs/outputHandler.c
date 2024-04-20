
#include "outputHandler.h"

#define TIMEZONE_LEN sizeof("+00:00")

/**
 * @brief Returns array of characters with correct timestamp in RFC 3339 format
 * 
 * @param tv timestamp
 * @param config pointer to global configuration where string pointer is stored
 * @return char* 
 */
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

#define BYTES_PER_LINE 16
/**
 * @brief Print hexdump-like to standard output
 * 
 * @param maxLen length of the array
 * @param packetData pointer to array of bytes
 */
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

/**
 * @brief Print hexdump-like to standard output
 * 
 * @param maxLen length of the array
 * @param packetData pointer to array of bytes
 * @param frameS FrameSelections structure holding length of headers
 */
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

/**
 * @brief Helping function for printing characters at end of line 
 * (after hexdump) with correct indentation
 * 
 * @param actualVPos actual vertical position
 * @param bytesPrinted how many bytes are going to be printed on this line
 * @param vPos vertical postion
 * @param skipped how many bytes were skipped do to indentation
 * @param packetData array of data
 */
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
