# DNS-Monitor - ISA Project 
**Author:**
Denis Fekete Denis Fekete ([xfeket01@vutbr.cz](mailto:xfeket01@vutbr.cz))

**Git repository:**
https://github.com/denis-fekete/isa-project1

**Date:**

## About
DNS-Monitor is a command line program for storing DNS communication from packets and displaying them in human readable form. Program uses system network interfaces for live capturing of packets or can open already stored communication from a file. Program is also capable of storing captured communication into files, more specifically it can store domain names, that were present in communication, and also translations from IP addresses to domain names.

## Using the program
In order to use the program we need its binary, which in this case we can build using Makefile.

*Note: it is required to have installed these dependencies on you machine: gcc compiler, libpcap library, and Makefile*

Run command in root directory of project (in this directory a README.md or Makefile should be present)<br>
`$ make`

After the program is run a binary file in root directory should be created named `dns-monitor`. In order to run and capture communication from live interface you will need to run program with privileged permissions (on unix based system it means to either run program as root or using sudo). If you are reading from file you do not need privileges.

On you user account you can run program like this, lets run it with `-h` or `--help` arguments:<br>
`$ sudo ./dns-monitor -h`

Program should print how to use it, let's review it quickly:
In order to run the program you need to specify either a interface or file from which file will be reading:

for reading from a file<br>
`$ ./dns-monitor -p {FILE}`<br>
or to read from live interface. For list the of available interfaces use program with `-o` option<br>
`$ sudo ./dns-monitor -i {INTERFACE}`

After this you should get your first captured packet. Next you can use `-v` option to get more detailed information about captured packets.

If you want to save all domain names that were captured by program you can use `-d` option and give it name of the file to store this information in.
You can also use `-t` option to capture all translated IP addresses to the domain names, you also need to specify the file:<br>
`$ sudo ./dns-monitor -i {INTERFACE} -d {FILE_WHERE_DOMAIN_NAMES_WILL_BE_STORED}`<br>
or<br>
`$ sudo ./dns-monitor -p {FILE} -t {FILE_WHERE_DOMAIN_NAME_TRANSLATIONS_WILL_BE_STORED}`<br>


### Bibliography
https://www.tcpdump.org/pcap.html
https://www.tcpdump.org/manpages/pcap-filter.7.html
https://datatracker.ietf.org/doc/html/rfc1035
https://datatracker.ietf.org/doc/html/rfc3596
https://www.tcpdump.org/manpages/pcap_open_offline.3pcap.html
https://www.tcpdump.org/pcap.html

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



## A quick explanation of program flow
The first step of the program is to allocate and initialize its ProgramConfiguration structure (from now on Config). This structure holds basic data for controlling the behavior of the program (for example which filters are enabled and which are not). It also holds pointers to dynamically allocated data from other parts of the program, reasoning for this is to make sure that if the program were to exit at the wrong time (due to *SIGINT* signal ), all memory that was allocated would also be freed. 

After Config has been initialized arguments given by the user are processed. Next step is setting up the pcap to capture network traffic. This was done by following the guide on [tcpdump.org](https://www.tcpdump.org/pcap.html) written by Tim Carstens. With few changes to the program all that is left is to set up filters for filtering captured network traffic (more information of filters can be found on [tcpdump.org](https://www.tcpdump.org/manpages/pcap-filter.7.html)). 

After filters have been set up, a new thread is created that will loop and capture network traffic (the number of captured traffic can be adjusted with command line arguments). The reason for creating a new thread and running the main loop of the program is because of *SIGINT* signal that can be received at any moment. 

In the main loop a desired number of network traffic is captured and displayed to the user. Byte array containing data is broken into parts and length of each part is stored in the **FrameSelections** structure. This structure is later used for the correct printing of hexdump-like representation of bytes.


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