from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

# Set the destination IP of the DNS server (e.g., Google's DNS server)
# dns_server = '127.0.0.1'
dns_server = '8.8.8.8'

# Set the domain you want to query
domain = 'example.com'

# Create a DNS request packet
dns_request = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype='MX'))

# Send the DNS packet and wait for the response
response = sr1(dns_request, verbose=0)

# Display the response
response.show()