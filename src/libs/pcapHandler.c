/**
 * @file pcapHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "pcapHandler.h"

errCodes_t pcapSetup(Config* config, pcap_if_t** allDevices, pcap_t** handle)
{
    // char errbuf[PCAP_ERRBUF_SIZE];
    char* errbuf = calloc(1, PCAP_ERRBUF_SIZE);
    if(errbuf == NULL)
    {
        fprintf(stderr, "Memory allocation for pcap error buffer failed\n");
        // errHandling("Memory allocation for pcap error buffer failed", ERR_MALOC);
        return ERR_MALOC;
    }

    // Get list of all devices
    int result = pcap_findalldevs( allDevices, errbuf);
    
    // Check for errors
    if(result == PCAP_ERROR)
    {
        fprintf(stderr, "Error: When looking for diveces\n");
        fprintf(stderr, "Error buffer:  %s\n", errbuf);
        return ERR_LIBPCAP;
    }

    if(allDevices == NULL)
    {
        fprintf(stderr, "Error: No devices found!\n");
        fprintf(stderr, "Error buffer:  %s\n", errbuf);
        return ERR_LIBPCAP;
    }
    
    // Looking for correct device
    pcap_if_t* device = *allDevices;

    // find correct device from list, based on its name, jump out of while if found match
    while(strcmp(device->name, config->interface->data) != 0)
    {
        if(device->next != NULL)
        {
            device = device->next;
        }
        else
        {
            pcap_freealldevs(*allDevices);

            // if end of list found, end with error
            fprintf(stderr, "%s was not found\n", config->interface->data);
            return ERR_LIBPCAP;
        }
    }

    // Open live sniffing of packets
    *handle = pcap_open_live(device->name, BUFSIZ, false, 250, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return ERR_LIBPCAP;
    }
    
    // Check handle can work with ethernet (DLT_EN10MB)
    if(pcap_datalink(*handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device->name);
        return ERR_LIBPCAP;
    }

    // Get IPv4 of device and its mask
    bpf_u_int32 mask; // The netmask of our sniffing device
    bpf_u_int32 net; // IP address of sniffing device
    if(pcap_lookupnet(device->name, &net, &mask, errbuf))
    {
        net = 0;
        mask = 0;
        fprintf(stderr, "Can't get netmask for device %s\n", device->name);
        return ERR_LIBPCAP;
    }

    // Creating a filter to only look for certain traffic
    const char filter_exp[] = "port 4567"; // Filter expression
    struct bpf_program fp; // Stuct that holds compiled filter expression
    if(pcap_compile(*handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(*handle));
        return ERR_LIBPCAP;
    }

    // Set the filter
    if(pcap_setfilter(*handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(*handle));
        return ERR_LIBPCAP;
    }

    return NO_ERR;
}