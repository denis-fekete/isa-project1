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
    {"help",                    no_argument,        0, 'h'},
    {"pcapfile",                required_argument,  0, 'r'},
    {"verbose",                 no_argument,        0, 'v'},
    {"domainsfile",             no_argument,        0, 'd'},
    {"translationsfile",        no_argument,        0, 't'},
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
    while((opt = getopt_long(argc, argv, "htui:n:p:r:d:t:", long_options, &options_index)) != -1)
    {
        counter++;
        switch (opt)
        {
            case 'r':
                break;
            case 'v':
                break;
            case 'd':
                break;
            case 't':
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
                printCliHelpMenu("dns-monitor"); //TODO:
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

    // Check mandatory arguments
    if(config->interface->data == NULL)
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