import re
import socket
from typing import List


# Connect to the challenge endpoint and read in the data
server_address = ('A02-target.allyourbases.co', 8134)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
data = b''
chunk = "Not Empty"
while chunk != b'':
    chunk = sock.recv(1024)
    data += chunk
data: str = data.decode('utf-8')
sock.close()

# Extract the ASCII data
pattern = r"^Server responds with:\n(.*)\nTerminating"
result = re.search(pattern, data)
blob: str = result.group(1).strip()

# Translate the ASCII hex into characters
ascii_hex: List[str] = blob.split(' ')
ascii_chars: List[str] = [chr(int(char, 16)) for char in ascii_hex]
msg: str = "".join(ascii_chars)

# Extract the flag
pattern = r"Flag\[\w+\]"
result = re.search(pattern, msg)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
