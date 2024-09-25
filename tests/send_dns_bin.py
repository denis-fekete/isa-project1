import socket

# Define the bytes you want to send
data = bytes([0xff, 0xdd, 0xcc])

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send data to localhost on port 53
sock.sendto(data, ('127.0.0.1', 53))

# Close the socket
sock.close()
