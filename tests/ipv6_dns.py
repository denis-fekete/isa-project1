import socket

# Construct a DNS query (standard query for AAAA (IPv6) record for "example.com")
dns_query = bytes.fromhex("aaaa01000001000000000000076578616d706c6503636f6d00001c0001")

# Define the IPv6 DNS server and port (53)
dns_server = "::1"  # Use a local DNS server or a public IPv6 DNS server like '2001:4860:4860::8888'
dns_port = 53

# Create a socket for IPv6, UDP
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# Send the DNS query to the server
sock.sendto(dns_query, (dns_server, dns_port))

# Wait for the response (1024 bytes buffer)
response, addr = sock.recvfrom(1024)

# Print the raw DNS response in hexadecimal
print("DNS Response:", response.hex())
