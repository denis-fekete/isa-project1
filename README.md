# DNS-Monitor - ISA Project 
**Author:**
Denis Fekete ([xfeket01@vutbr.cz](mailto:xfeket01@vutbr.cz))

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

## Additional features (outside of assignment)
* Custom number of captured packets with `-n` argument
* Displaying all available device interfaces `-o` argument

## Files
List of files that were included with program/project
/
Makefile
README.md
src/
   main.c
   libs/
      argumentHandler.c
      argumentHandler.h
      buffer.c
      buffer.h
      list.c
      list.h
      outputHandler.c
      outputHandler.h
      packetDissector.c
      pcapHandler.c
      pcapHandler.h
      programConfig.c
      programConfig.h
      utils.c
      utils.h

## Bibliography
https://www.tcpdump.org/pcap.html
https://www.tcpdump.org/manpages/pcap-filter.7.html
https://datatracker.ietf.org/doc/html/rfc1035
https://datatracker.ietf.org/doc/html/rfc3596
https://www.tcpdump.org/manpages/pcap_open_offline.3pcap.html
https://www.tcpdump.org/pcap.html