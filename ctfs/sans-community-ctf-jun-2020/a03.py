import re
import socket


# Connect the socket to the port where the server is listening
server_address = ('A03-target.allyourbases.co', 8135)

# Connect to the challenge endpoint and read in the data
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
data = b''
chunk = "Not Empty"
while chunk != b'':
    chunk = sock.recv(1024)
    data += chunk
data: str = data.decode('utf-8')
sock.close()

# Extract the digits
pattern = r"^Server responds with:\n(.*)\nTerminating"
result = re.search(pattern, data)
blob: str = result.group(1).strip()
digits = [int(d) for d in blob.split(' ')]

# Convert positive digitals into ASCII characters
pos = [d for d in digits if d >= 0]
msg = "".join([chr(d) for d in pos])

# Extract the flag
pattern = r"Flag\[\w+\]"
result = re.search(pattern, msg)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
