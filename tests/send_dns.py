import dns.resolver

# Set the DNS resolver to use the loopback interface (127.0.0.1)
resolver = dns.resolver.Resolver()
resolver.nameservers = ['127.0.0.1']

# Domain you want to look up
domain = 'example.com'

try:
    # Perform DNS lookup
    answer = resolver.resolve(domain, 'A')
    for rdata in answer:
        print(f'The IP address of {domain} is {rdata}')
except dns.resolver.NXDOMAIN:
    print(f'{domain} does not exist.')
except dns.resolver.Timeout:
    print(f'Timeout while resolving {domain}.')
except dns.resolver.NoNameservers:
    print('No DNS servers responded.')
except Exception as e:
    print(f'An error occurred: {e}')
