/**
 * @file argumentHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief //TODO:
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
    {"tcp",                     no_argument,        0, 't'},
    {"udp",                     no_argument,        0, 'u'},
    {"port-destination",        required_argument,  0, PORT_OPTIONS},
    {"port-source",             required_argument,  0, PORT_OPTIONS},
    {"icmp4",                   no_argument,        0, DISPLAY_OPTIONS},
    {"icmp6",                   no_argument,        0, DISPLAY_OPTIONS},
    {"arp",                     no_argument,        0, DISPLAY_OPTIONS},
    {"ndp",                     no_argument,        0, DISPLAY_OPTIONS},
    {"igmp",                    no_argument,        0, DISPLAY_OPTIONS},
    {"mld",                     no_argument,        0, DISPLAY_OPTIONS},
    {0, 0, 0, 0}
};

/**
 * @brief Handles program arguements and sets correct 
 * ProgramConfigaration (Config)
 * 
 * @param argc 
 * @param argv 
 * @param config pointer to ProgramConfigaration (Config)
 */
void argumentHandler(int argc, char* argv[], Config* config)
{
    debugPrint(stdout, "a\n");
    int opt;
    size_t optLen;
    int options_index;
    // \0 == PORT_OPTIONS, \1 DISPLAY_OPTIONS
    while((opt = getopt_long(argc, argv, "htui:p:\0\1", long_options, &options_index)) != -1)
    {
        switch (opt)
        {
            case PORT_OPTIONS:
                debugPrint(stdout, "1\n");
                break;
            case DISPLAY_OPTIONS:
                debugPrint(stdout, "2\n");
                break;
            case 'p':
                debugPrint(stdout, "3\n");
                break;
            case 't':
                debugPrint(stdout, "4\n");
                config->enableTCP = true;
                break;
            case 'u':
                debugPrint(stdout, "5\n");
                config->enableTCP = true;
                break;
            case 'i':
                debugPrint(stdout, "6\n");
                optLen = strlen(optarg);
                bufferResize(config->interface, optLen + 1);
                stringReplace(config->interface->data, optarg, optLen);
                config->interface->data[optLen] = '\0';
                config->interface->used = optLen + 1;
                break;
            case 'h':
                debugPrint(stdout, "7\n");
                printCliHelpMenu("ipk-sniffer");
                errHandling("", 0);
                break;
            default:
                errHandling("Unknown option. Use -h for help", ERR_UNKNOWN_ARG);
                break;
        }
    }
}

/**
 * @brief Prints help menu when user inputs /help command 
 */
void printCliHelpMenu(const char* executableName)
{
    printf(
        "Usage: %s [OPTION] [ARGUMENT] ...\n"
        "Starts client for communication with server at provided address "
        "(through -s OPTION) using IPK24-CHAT Protocol based on TCP or "
        "UDP (based on -t OPTION)\n"
        "\n"
        "Mandatory options:\n"
        "\t-s\t- "
        "Sets server IP address (can be in \"www.server.com\" format) "
        "to which client will try to connect\n"
        "\t-t\t- "
        "Sets between UDP or TCP protocol to be used for sending messages to server\n"
        "\nNon-mandatory options:\n"
        "\t-p\t- "
        "Specifies which port will client try to connect to at specified "
        "IP adress. Default value is 4567.\n"
        "\t-d\t- "
        "Sets UDP confirmation timeout in milliseconds\n"
        "\t-r\t- "
        "Sets maximum number of UDP retransmissions\n"
        "\t-h\t- "
        "Prints this help menu end exits program with code 0\n"

        , executableName
    );
}