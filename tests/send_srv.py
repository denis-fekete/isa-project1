import dns.resolver

# Define the SRV query (e.g., "_sip._tcp.example.com")
srv_query = '_sip._tcp.example.com'

# Send the SRV query
try:
    answers = dns.resolver.resolve(srv_query, 'SRV')
    
    # Loop through each answer in the response
    for srv in answers:
        print(f"Target: {srv.target}, Port: {srv.port}, Priority: {srv.priority}, Weight: {srv.weight}")
except dns.resolver.NoAnswer:
    print("No SRV record found.")
except dns.resolver.NXDOMAIN:
    print("Domain does not exist.")
except dns.resolver.Timeout:
    print("Query timed out.")
except dns.resolver.NoNameservers:
    print("No nameservers available.")
