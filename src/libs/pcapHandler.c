/**
 * @file pcapHandler.c
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief 
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "pcapHandler.h"

pcap_t* pcapSetup(Config* config, pcap_if_t** allDevices)
{
    pcap_t* handle;
    // Get list of all devices
    int result = pcap_findalldevs( allDevices, config->cleanup.pcapErrbuff);
    
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
    handle = pcap_open_live(device->name, BUFSIZ, true, 1000, config->cleanup.pcapErrbuff);
    
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

    // Get IPv4 of device and its mask
    bpf_u_int32 mask; // The netmask of our sniffing device
    bpf_u_int32 net; // IP address of sniffing device
    if(pcap_lookupnet(device->name, &net, &mask, config->cleanup.pcapErrbuff))
    {
        net = 0;
        mask = 0;
        fprintf(stderr, "ERR: Can't get netmask for device %s\n", device->name);
        errHandling("", ERR_LIBPCAP);
    }

    if(config->useFilter)
    {
        // Creating a filter to only look for certain traffic
        // Filter expression
        Buffer expr = createFilterExpression(config);
        debugPrint(stdout, "DEBUG: Final expression of filter: ");
        bufferPrint(&expr, 1);
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
    }

    return handle;
}

// add or to filter expression if needed
#define ADD_OR                                                                 \
    if(expr.data != NULL && expr.data[expr.used -2] != '(')                    \
    {                                                                          \
        bufferAddString(&expr, " or ");                                        \
    }                                   

/**
 * @brief Creates Buffer and fills it with PCAP filters
 * 
 * @param config 
 * @return Buffer 
 */
Buffer createFilterExpression(Config* config)
{
    Buffer expr;
    bufferInit(&expr);
    
    bool noPrevious = true;
    if(config->icmp4 || config->icmp6 || config->ndp || config->mld || config->arp || config->arp || config->igmp)
    {
        bufferAddString(&expr, "(");
        if(config->icmp4)
        {
            bufferAddString(&expr, "icmp");
        }
        
        // ndp and mld are subsets of ICMPv6 however pcap doesn't have build it 
        // function to filter them out, so filtering will be done in later steps
        if(config->icmp6 || config->ndp || config->mld)
        {
            ADD_OR;
            bufferAddString(&expr, "icmp6");
        }

        if(config->arp )
        {
            ADD_OR;
            bufferAddString(&expr, "arp");
        }

        if(config->igmp)
        {
            ADD_OR;
            bufferAddString(&expr, "igmp");
        }
        bufferAddString(&expr, ")");

        noPrevious = false;
    }

    if( config->port->data != NULL || 
        config->portDst->data != NULL || 
        config->portSrc->data != NULL)
    {
        if(!noPrevious)
        {
            bufferAddString(&expr, " and (");
        }

        if(config->port->data != NULL)
        {
            bufferAddString(&expr, "port ");
            bufferAddString(&expr, config->port->data);
        }
        
        if (config->portDst->data != NULL)
        {
            bufferAddString(&expr, "dst port ");
            bufferAddString(&expr, config->portDst->data);
            
        }
        if (config->portSrc->data != NULL)
        {
            if(config->portDst->data != NULL)
            {
                bufferAddString(&expr, " ");
            }

            bufferAddString(&expr, "src port ");
            bufferAddString(&expr, config->portSrc->data);
        }

        if(!noPrevious)
        {
            bufferAddString(&expr, ")");
        }
    }

    if(config->tcp || config->udp)
    {
        if(!noPrevious)
        {
            bufferAddString(&expr, " and (");
        }

        if(config->tcp)
        {
            bufferAddString(&expr, "tcp");
        }
        
        if(config->udp)
        {
            if(config->tcp)
            {
                bufferAddString(&expr, " or ");
            }

            bufferAddString(&expr, "udp");
        }

        if(!noPrevious)
        {
            bufferAddString(&expr, ")");
        }
    }

    return expr;
}