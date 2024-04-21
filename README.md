# IPK-Sniffer
**Author**
Denis Fekete Denis Fekete ([xfeket01@vutbr.cz](mailto:xfeket01@vutbr.cz))

**Git repository:**
https://git.fit.vutbr.cz/xfeket01/ipk-project2.git

## Description
IPK-Sniffer is a program written in C programming language and utilizes [libcap / pcap](https://www.tcpdump.org/) library for sniffing packets from the network. Program works in *promiscuous mode*[^1] and picks up network traffic from the connected network. Program can be set to accept only certain types of protocols (use --help when starting the program). Captured network traffic is then displayed to standard out (stdin).

[^1]: Promiscuous mode is a mode of operation for pcap-like libraries and it means that even packets that are meant for the client PC are captured. This however is only possible in non-switched networks that use only hubs for communication between computers. Promiscuous mode is also used by applications like Wireshark.

## Theory
For internet traffic to arrive at its destination there is a need for some kind of mechanism, in the modern world, the data that are sent over the internet are wrapped in **headers** at different levels of the **OSI** model. When the packet(data) is received by the program the first information given to it is data in raw format and length. From this point on some kind of unwrapping mechanism is needed to find what data the program just received.

### Unwrapping mechanism
For a normal human being to be able to understand what is the program displaying, some format changes need to be made. In order to format this raw data the program is given by pcap library, some form of formatting is needed, how is it done then?

Since the program is written in C, pointers are a valid option (maybe the only option). Pointer can be cast into another type of pointer, for example:

Raw data of packet (array of bytes in hexadecimal format separated by white spaces):
```
ff ff ff ff ff ff 00 00 00 00 00 00 08 00 45 00 00 1c 00 01 00 00 40 01 7c de 7f 00 00 01 7f 00 00 01 08 00 f7 ff 00 00 00 00
``` 
Structure of EthernetHeader 
```
typedef struct EthernetHeader
{
    // destination address
    unsigned char dst[ETHERNET_ADDR_LEN];
    // source address
    unsigned char src[ETHERNET_ADDR_LEN];
    // ether type
    unsigned char etherType[2];
} EthernetHeader; 
```
By casting an array of bytes pointer into a pointer of `struct EthernetHeader` a pointer with EthernetHeader type will be returned, then it is possible to simply address data types of this structure that contain values from the byte array. From this structure, it is possible to get values of the source MAC address, destination MAC address and type of protocol header that is in the Network layer of the OSI model.
```
    src MAC: ff:ff:ff:ff:ff:ff
    dst MAC: 00:00:00:00:00:00
```
*output from the program when the byte array from over example is passed to the program* <br>

The value of the *etherType* is *08 00* which is an IPv4 packet. Based on *Protocol* value it can be deduced that this packet is ICMPv4. Here is how IPv4 and ICMP packets look by an RFC standard.
```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*example of ICMP in IPv4 packet from RFC 792 and RFC 791,  sources: https://datatracker.ietf.org/doc/html/rfc792, https://datatracker.ietf.org/doc/html/rfc791* 


Here is the program output for the packet from the example
```
Number: 0
        timestamp: 2024-04-19T20:22:46.613+00:00
Ethernet:
        src MAC: ff:ff:ff:ff:ff:ff
        dst MAC: 00:00:00:00:00:00
        frame length: 42 bytes
IPv4 Packet:
        src IP: 127.0.0.1
        dst IP: 127.0.0.1
        Protocol: icmp
                type: 8 (0x8)
                code: 0 (0x0)
Data layer:
        0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00       ........ ......
Network layer:
        0x0000:                                           45 00               E.
        0x0001: 00 1c 00 01                                     ....
Transport layer:
        0x0001:             00 00 40 01 7c de 7f 00 00 01 7f 00     ..@. |.......
        0x0002: 00 01 08 00 f7 ff 00 00 00 00                   ........ ..
```
*output from the program, for anyone who ever saw how Wireshark's hexdump looks, this might be confusing but an explanation will be later in the text*

This can be done to all headers that are present in the packet.

## A quick explanation of program flow
The first step of the program is to allocate and initialize its ProgramConfiguration structure (from now on Config). This structure holds basic data for controlling the behavior of the program (for example which filters are enabled and which are not). It also holds pointers to dynamically allocated data from other parts of the program, reasoning for this is to make sure that if the program were to exit at the wrong time (due to *SIGINT* signal ), all memory that was allocated would also be freed. 

After Config has been initialized arguments given by the user are processed. Next step is setting up the pcap to capture network traffic. This was done by following the guide on [tcpdump.org](https://www.tcpdump.org/pcap.html) written by Tim Carstens. With few changes to the program all that is left is to set up filters for filtering captured network traffic (more information of filters can be found on [tcpdump.org](https://www.tcpdump.org/manpages/pcap-filter.7.html)). 

After filters have been set up, a new thread is created that will loop and capture network traffic (the number of captured traffic can be adjusted with command line arguments). The reason for creating a new thread and running the main loop of the program is because of *SIGINT* signal that can be received at any moment. 

In the main loop a desired number of network traffic is captured and displayed to the user. Byte array containing data is broken into parts and length of each part is stored in the **FrameSelections** structure. This structure is later used for the correct printing of hexdump-like representation of bytes.

## Output explanation
The program "hexdump" format is by default different then what Wireshark looks like, this makes it more user-friendly in finding bytes that the user might be interested in.

```
Number: 0
        timestamp: 2024-04-20T14:15:04.997+00:00
Ethernet:
        src MAC: ff:ff:ff:ff:ff:ff
        dst MAC: 00:00:00:00:00:00
        frame length: 42 bytes
IPv4 Packet:
        src IP: 127.0.0.1
        dst IP: 127.0.0.1
        Protocol: icmp
                type: 8 (0x8)
                code: 0 (0x0)
Data layer:
        0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00       ........ ......
Network layer:
        0x0000:                                           45 00               E.
        0x0001: 00 1c 00 01                                     ....
Transport layer:
        0x0001:             00 00 40 01 7c de 7f 00 00 01 7f 00     ..@. |.......
        0x0002: 00 01 08 00 f7 ff 00 00 00 00                   ........ ..
```
*Output of the program for captured ICMPv4 without any options disable/enabled.*

```
Number: 0
        timestamp: 2024-04-20T14:15:51.728+00:00
Ethernet:
        src MAC: ff:ff:ff:ff:ff:ff
        dst MAC: 00:00:00:00:00:00
        frame length: 42 bytes
IPv4 Packet:
        src IP: 127.0.0.1
        dst IP: 127.0.0.1
        Protocol: icmp
                type: 8 (0x8)
                code: 0 (0x0)
        0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00 45 00 ..............E.
        0x0010: 00 1c 00 01 00 00 40 01 7c de 7f 00 00 01 7f 00 ......@.|.......
        0x0020: 00 01 08 00 f7 ff 00 00 00 00                   ..........
```
*Output of the program for captured ICMPv4 with --wslike argument enabled.*

## Testing
Testing was done by comparing output from Wireshark application and ipk-sniffer while capturing traffic on network or by sending generated traffic by Python scripts in */tests* directory through *loopback* interface. 


### Bibliography
https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
https://www.tcpdump.org/pcap.html
https://www.tcpdump.org/manpages/pcap-filter.7.html
https://www.rfc-editor.org/rfc/rfc3339
https://datatracker.ietf.org/doc/html/rfc792
https://datatracker.ietf.org/doc/html/rfc791
https://datatracker.ietf.org/doc/html/rfc3376
https://datatracker.ietf.org/doc/html/rfc2236
https://datatracker.ietf.org/doc/html/rfc826