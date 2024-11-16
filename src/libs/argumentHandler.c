/**
 * @file argumentHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Source file containing argument handling functions
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "argumentHandler.h"

/*
Source: https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
*/

static struct option long_options[] =
{
    {"interface",               required_argument,  0, 'i'},
    {"display-interfaces",      no_argument,        0, 'o'},
    {"help",                    no_argument,        0, 'h'},
    {"pcapfile",                required_argument,  0, 'p'},
    {"verbose",                 no_argument,        0, 'v'},
    {"domainsFile",             no_argument,        0, 'd'},
    {"translationsFile",        no_argument,        0, 't'},
    {0, 0, 0, 0}
};

/**
 * @brief Copies argument from optarg into a Buffer structure
 * 
 * @param optarg Pointer to the source optarg
 * @param buffer Pointer to the destination buffer
 */
void copyArgToBuffer(char* optarg, Buffer* buffer)
{
    size_t optLen = strlen(optarg);
    bufferResize(buffer, optLen + 1);
    stringReplace(buffer->data, optarg, optLen);
    buffer->data[optLen] = '\0';
    buffer->used = optLen + 1;
}

/**
 * @brief Handles program arguments and sets correct 
 * ProgramConfiguration (Config)
 * 
 * @param argc 
 * @param argv 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void argumentHandler(int argc, char* argv[], Config* config)
{
    int opt;
    int options_index;

    // \0 == PORT_OPTIONS, \1 DISPLAY_OPTIONS
    while((opt = getopt_long(argc, argv, "ovht:i:n:p:d:t:", long_options, &options_index)) != -1)
    {
        switch (opt)
        {
            case 'o':
                config->displayDevices = true;
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'd':
                copyArgToBuffer(optarg, config->domainsFile);
                break;
            case 't':
                copyArgToBuffer(optarg, config->translationsFile);
                break;
            case 'p':
                if(config->captureMode != NO_MODE)
                    errHandling("Arguments -i and -p cannot be used together", ERR_BAD_ARGS);

                copyArgToBuffer(optarg, config->pcapFileName);
                config->captureMode = OFFLINE_MODE;
                break;
            // ----------------------------------------------------------------
            case 'i':
                if(config->captureMode != NO_MODE)
                    errHandling("Arguments -i and -p cannot be used together", ERR_BAD_ARGS);

                copyArgToBuffer(optarg, config->interface);
                config->captureMode = ONLINE_MODE;
                break;
            case 'h':
                printCliHelpMenu("dns-monitor"); //TODO:
                errHandling("", 0);
                break;
            case 'n':
                if(stringIsValidUInt(optarg))
                    config->numberOfPackets = atoi(optarg);
                else
                    errHandling("TODO:", 1);
                break;
            default:
                errHandling("Unknown option. Use -h for help", ERR_UNKNOWN_ARG);
                break;
        }
    }

    // Check mandatory arguments
    if( config->interface->data == NULL && 
        config->captureMode != OFFLINE_MODE && 
        !config->displayDevices)
    {
        errHandling("Interface not provided", ERR_BAD_ARGS);
    }
}

/**
 * @brief Prints help menu when user inputs /help command 
 */
void printCliHelpMenu(const char* executableName)
{
    printf(
        "Usage: ./%s (-i <interface> | -p <pcapfile> | -o) "
        "[-v] [-d <domainsfile>] "
        "[-t <translationsfile>]\n"
        "\n"
        "Mandatory options:\n"
        "\t-i | --interface                - Sets interface that program will\n" 
        "\t                                  monitor for DNS communication\n"
        "\t-p | --pcapfile <PATH_TO_FILE>  - Opens a .pcapng file from which \n"
        "\t                                  program will read captured DNS \n"
        "\t                                  communication\n"
        "\t-o | --display-interfaces        - Displays available interfaces on \n"
        "\t                                  device. Devices with '*' before them\n"
        "\t                                  are flagged as non applicable by \n"
        "\t                                  pcap library.\n"
        "Non-mandatory options:\n"
        "\t-v | --verbose                  - Prints full details about DNS \n"
        "\t                                  communication, otherwise a output\n"
        "\t                                  will be in compacted version\n"
        "\t-d | --domainsfile <PATH>       - All domain names will be stored in\n"
        "\t                                  specified <PATH> file\n"
        "\t-t | --translationsfile <PATH>  - All translations from domain name \n"
        "\t                                  to IP addresses will be stored in \n"
        "\t                                  <PATH> specified file\n"
        "\t-h | --help                     - Prints this help menu end exits \n"
        "\t                                  program with code 0\n"
        , executableName
    );
}