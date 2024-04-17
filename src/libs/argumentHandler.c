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

#define DST_PORT_OPT 1000
#define SRC_PORT_OPT 1001

static struct option long_options[] =
{
    {"interface",               required_argument,  0, 'i'},
    {"tcp",                     no_argument,        0, 't'},
    {"udp",                     no_argument,        0, 'u'},
    {"help",                    no_argument,        0, 'h'},
    {"port-destination",        required_argument,  0, DST_PORT_OPT},
    {"port-source",             required_argument,  0, SRC_PORT_OPT},
    {"icmp4",                   no_argument,        0, dopt_ICMP4},
    {"icmp6",                   no_argument,        0, dopt_ICMP6},
    {"arp",                     no_argument,        0, dopt_ARP},
    {"ndp",                     no_argument,        0, dopt_NDP},
    {"igmp",                    no_argument,        0, dopt_IGMP},
    {"mld",                     no_argument,        0, dopt_MLD},
    {0, 0, 0, 0}
};


/**
 * @brief Handles program arguments and sets correct 
 * ProgramConfiguration (Config)
 * 
 * @param argc 
 * @param argv 
 * @param config pointer to ProgramConfiguration (Config)
 */
void argumentHandler(int argc, char* argv[], Config* config)
{
    int opt;
    size_t optLen;
    int options_index;

    int counter = 0; // counter for setting config->useFilter
    // \0 == PORT_OPTIONS, \1 DISPLAY_OPTIONS
    while((opt = getopt_long(argc, argv, "htui:n:p:", long_options, &options_index)) != -1)
    {
        counter++;
        switch (opt)
        {
            case DST_PORT_OPT:
                optLen = strlen(optarg);
                bufferResize(config->portDst, optLen + 1);
                stringReplace(config->portDst->data, optarg, optLen);
                config->portDst->data[optLen] = '\0';
                config->portDst->used = optLen + 1;
                config->useFilter = false;
                break;
            case SRC_PORT_OPT:
                optLen = strlen(optarg);
                bufferResize(config->portSrc, optLen + 1);
                stringReplace(config->portSrc->data, optarg, optLen);
                config->portSrc->data[optLen] = '\0';
                config->portSrc->used = optLen + 1;
                break;
            case 'p':
                optLen = strlen(optarg);
                bufferResize(config->port, optLen + 1);
                stringReplace(config->port->data, optarg, optLen);
                config->port->data[optLen] = '\0';
                config->port->used = optLen + 1;
                break;
            // ----------------------------------------------------------------
            case dopt_ICMP4: config->icmp4 = true; 
                break;
            case dopt_ICMP6: config->icmp6 = true;
                break;
            case dopt_ARP: config->arp = true;
                break;
            case dopt_NDP: config->ndp = true;
                break;
            case dopt_IGMP: config->igmp = true;
                break;
            case dopt_MLD: config->mld = true; 
                break;
            case 't':
                config->tcp = true;
                break;
            case 'u':
                config->udp = true;
                break;
            // ----------------------------------------------------------------
            case 'i':
                optLen = strlen(optarg);
                bufferResize(config->interface, optLen + 1);
                stringReplace(config->interface->data, optarg, optLen);
                config->interface->data[optLen] = '\0';
                config->interface->used = optLen + 1;
                counter--; // decrease counter because this doesn't count as no filter
                break;
            case 'h':
                printCliHelpMenu("ipk-sniffer");
                errHandling("", 0);
                counter--; // decrease counter because this doesn't count as no filter
                break;
            case 'n':
                // TODO: add some checking for valid numbers
                if(stringIsValidUInt(optarg))
                    config->numberOfPackets = atoi(optarg);
                else
                    errHandling("TODO:", 1);
                counter--; // decrease counter because this doesn't count as no filter
                break;
            default:
                errHandling("Unknown option. Use -h for help", ERR_UNKNOWN_ARG);
                break;
        }
    }

    // check if useFilter should be set based on arguments
    if(counter != 0)
    {
        config->useFilter = true;
    }

    // Check mandatory arguments
    if(config->interface->data == NULL)
    {
        errHandling("Interface not provided", ERR_BAD_ARGS);
    }
    else if(config->port->data != NULL && 
            (config->portSrc->data != NULL || config->portDst->data != NULL))
    {
        errHandling("Invalid combination of arguments: use only port or use src and dst port settings, but not the combination", ERR_BAD_ARGS);
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