import re
import socket


# Connect to the challenge endpoint and read in the data
server_address = ('A04-target.allyourbases.co', 8150)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
data = b''
chunk = "Not Empty"
while chunk != b'':
    chunk = sock.recv(1024)
    data += chunk
data: str = data.decode('utf-8')
sock.close()

# Extract the blob
pattern = r"^Server responds with:\n(.*)\nTerminating"
result = re.search(pattern, data)
blob: str = result.group(1).strip()

# Append all single hex digits with 0
pattern = r"\b[0-9a-fA-F]{1}\b"
subbed = re.sub(pattern, lambda l: f"0{l.group()}", blob)

# Remove padding characters
filtered = subbed.replace(';', '').replace('+', '')

# Group by two to get the ASCII hex digits and translate them into ASCII
ascii_chars = [
    chr(int(filtered[i:i+2], 16))
    for i in range(0, len(filtered), 2) if int(filtered[i:i+2], 16) <= 128
]
msg = "".join(ascii_chars)

# Extract the flag
pattern = r"Flag\[\w+\]"
result = re.search(pattern, msg)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
