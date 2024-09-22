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
    {"wslike",                  no_argument,        0, dopt_WSLIKE},
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
            case dopt_WSLIKE: config->wsHexdump = true; 
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
        "\t-i | --interface\t- "
        "Sets interface from which will program capture network traffic\n"
        "\nNon-mandatory options:\n"
        "\t--arp\t\t\t- "
        "Only ARP packets will be captured\n"
        "\t--icmp4\t\t\t- "
        "Only ICMP for IPv4 will be captured\n"
        "\t--icmp6\t\t\t- "
        "Only ICMP for IPv6 will be captured\n"
        "\t--igmp\t\t\t- "
        "Only IGMP will be captured\n"
        "\t-h | --help\t\t\t- "
        "Prints this help menu end exits program with code 0\n"
        "\t--ndp\t\t\t- "
        "Only NDP will be captured\n"
        "\t--MLD\t\t\t- "
        "Only MLD will be captured\n"
        "\t-p\t\t\t- "
        "Will display only traffic that has {PORT_NUMBER} as source or destination\n"
        "\t--port-destination {PORT_NUMBER}\t\t- "
        "Will display only traffic that has {PORT_NUMBER} destination port "
        "(can be combined with --port-source)\n"
        "\t--port-source {PORT_NUMBER}\t\t\t- "
        "Will display only traffic that has {PORT_NUMBER} source port "
        "(can be combined with --port-destination)\n"
        "\t--tcp\t\t\t- "
        "Only TCP packets will be captured (can be combined with --udp option)\n"
        "\t--udp\t\t\t- "
        "Only UDO packets will be captured (can be combined with --tcp option)\n"
        "\t--wslike\t\t\t- "
        "Printed hexdump will be formatted more like wireshark\n"
        , executableName
    );
}