/**
 * @file pcapHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "pcapHandler.h"

pcap_t* pcapSetup(Config* config, pcap_if_t** allDevices, char** errorbuf)
{
    // char errbuf[PCAP_ERRBUF_SIZE];
    char* errbuf = calloc(1, PCAP_ERRBUF_SIZE);
    if(errbuf == NULL)
    {
        errHandling("Memory allocation for pcap error buffer failed\n", ERR_MALOC);
    }

    pcap_t* handle;

    // Get list of all devices
    int result = pcap_findalldevs( allDevices, errbuf);
    
    // Check for errors
    if(result == PCAP_ERROR)
    {
        fprintf(stderr, "Error buffer:  %s\n", errbuf);
        errHandling("When looking for diveces\n", ERR_LIBPCAP);
    }

    if(allDevices == NULL)
    {
        fprintf(stderr, "Error buffer:  %s\n", errbuf);
        errHandling("No devices found!\n", ERR_LIBPCAP);
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
            fprintf(stderr, "ERR: %s was not found\n", config->interface->data);
            errHandling("", ERR_LIBPCAP);
        }
    }

    // Open live sniffing of packets
    handle = pcap_open_live(device->name, BUFSIZ, true, 1000, errbuf);
    
    if(handle == NULL)
    {
        fprintf(stderr, "ERR: Couldn't open device %s: %s\n", device->name, errbuf);
        errHandling("", ERR_LIBPCAP);
    }
    
    // Check handle can work with ethernet (DLT_EN10MB)
    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERR: Device %s doesn't provide Ethernet headers - not supported\n", device->name);
        errHandling("", ERR_LIBPCAP);
    }

    // Get IPv4 of device and its mask
    bpf_u_int32 mask; // The netmask of our sniffing device
    bpf_u_int32 net; // IP address of sniffing device
    if(pcap_lookupnet(device->name, &net, &mask, errbuf))
    {
        net = 0;
        mask = 0;
        fprintf(stderr, "ERR: Can't get netmask for device %s\n", device->name);
        errHandling("", ERR_LIBPCAP);
    }

    if(config->useFilter)
    {
        // Creating a filter to only look for certain traffic
        const char filter_exp[] = ""; // Filter expression
        struct bpf_program fp; // Stuct that holds compiled filter expression
        if(pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR)
        {
            fprintf(stderr, "ERR: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            errHandling("", ERR_LIBPCAP);
        }

        // Set the filter
        if(pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "ERR: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            errHandling("", ERR_LIBPCAP);
        }

    }

    *errorbuf = errbuf;
    return handle;
}