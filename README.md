# IPK-Sniffer
**Author**
Denis Fekete Denis Fekete ([xfeket01@vutbr.cz](mailto:xfeket01@vutbr.cz))

**Git repository:**
https://git.fit.vutbr.cz/xfeket01/ipk-project2.git

## Description
IPK-Sniffer is a program written in C programming language and utilizes [libcap / pcap](https://www.tcpdump.org/) library for sniffing packets from the network. Program works in *promiscuous mode*[^1] and picks up network traffic from the connected network. Program can be set to accept only certain types of protocols (see the section about commands or use --help when starting the program). Captured network traffic is then displayed to standard out (stdin).

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
*example of ICMP in IPv4 packet from RFC 792, source: https://datatracker.ietf.org/doc/html/rfc792* 


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
*output from program, for anyone who ever saw how Wireshark's hexdump looks this might be confusing but explanation will be later in text*

This can be done to all headers that are present in the packet.

## A quick explanation of program flow

## Output explanation

## Testing


[^1]: Promiscuous mode is a mode of operation for pcap-like libraries and it means that even packets that are meant for the client PC are captured. This however is only possible in non-switched networks that use only hubs for communication between computers. Promiscuous mode is also used by applications like Wireshark.