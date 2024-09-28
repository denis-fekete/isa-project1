/**
 * @file pcapHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "pcapHandler.h"

pcap_t* pcapOfflineSetup(Config* config)
{
    config->cleanup.pcapFile = fopen(config->pcapFileName->data, "r");
    if(config->cleanup.pcapFile == NULL)
        errHandling("Couldn't open file for reading captured packets", ERR_FILE);

    return pcap_fopen_offline(config->cleanup.pcapFile, config->cleanup.pcapErrbuff);
}

pcap_t* pcapOnlineSetup(Config* config, pcap_if_t** allDevices, pcap_if_t** device)
{
    // Get list of all devices
    int result = pcap_findalldevs(allDevices, config->cleanup.pcapErrbuff);
    
    // Check for errors
    if(result == PCAP_ERROR)
    {
        fprintf(stderr, "Error buffer:  %s\n", config->cleanup.pcapErrbuff);
        errHandling("When looking for devices\n", ERR_LIBPCAP);
    }

    if(allDevices == NULL)
    {
        fprintf(stderr, "Error buffer:  %s\n", config->cleanup.pcapErrbuff);
        errHandling("No devices found!\n", ERR_LIBPCAP);
    }
    
    // Looking for correct device
    *device = *allDevices;

    // find correct device from list, based on its name, jump out of while if found match
    while(strcmp((*device)->name, config->interface->data) != 0)
    {
        if((*device)->next != NULL)
        {
            *device = (*device)->next;
        }
        else
        {
            pcap_freealldevs(*allDevices);

            // if end of list found, end with error
            fprintf(stderr, "ERR: %s was not found\n", config->interface->data);
            errHandling("", ERR_LIBPCAP);
        }
    }

    return pcap_open_live((*device)->name, BUFSIZ, true, 1000, config->cleanup.pcapErrbuff);
}



pcap_t* pcapSetup(Config* config, pcap_if_t** allDevices)
{
    pcap_t* handle;
    pcap_if_t* device = NULL;
 
    if(config->captureMode == OFFLINE_MODE)
        handle = pcapOfflineSetup(config);
    else
        handle = pcapOnlineSetup(config, allDevices, &device);

    
    if(handle == NULL)
    {
        fprintf(stderr, "ERR: Couldn't open device %s: %s\n", device->name, config->cleanup.pcapErrbuff);
        errHandling("", ERR_LIBPCAP);
    }
    
    // Check handle can work with ethernet (DLT_EN10MB)
    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERR: Device %s doesn't provide Ethernet headers - not supported\n", device->name);
        errHandling("", ERR_LIBPCAP);
    }

    bpf_u_int32 net = 0; // IP address of sniffing device, for offline can be set to zero
    if(config->captureMode == ONLINE_MODE)
    {
        // Get IPv4 of device and its mask
        bpf_u_int32 mask; // The netmask of our sniffing device
        if(pcap_lookupnet(device->name, &net, &mask, config->cleanup.pcapErrbuff))
        {
            net = 0;
            mask = 0;
            fprintf(stderr, "ERR: Can't get netmask for device %s\n", device->name);
            errHandling("", ERR_LIBPCAP);
        }
    }

    // Creating a filter to only look for certain traffic
    // Filter expression
    Buffer expr;
    bufferInit(&expr);
    bufferAddString(&expr, "port 53");
    bufferAddChar(&expr, 0);

    struct bpf_program fp; // Stuct that holds compiled filter expression
    if(pcap_compile(handle, &fp, expr.data, 0, net) == PCAP_ERROR)
    {
        fprintf(stderr, "ERR: Couldn't parse filter %s: %s\n", expr.data, pcap_geterr(handle));
        errHandling("", ERR_LIBPCAP);
    }

    // Set the filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "ERR: Couldn't install filter %s: %s\n", expr.data, pcap_geterr(handle));
        errHandling("", ERR_LIBPCAP);
    }
    
    free(fp.bf_insns);
    bufferDestroy(&expr);

    return handle;
}