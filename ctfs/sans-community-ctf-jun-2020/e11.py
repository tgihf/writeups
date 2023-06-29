import re
import requests
import socket
import sys


# Ensure user gives email address and acccess code to md5decrypt.net
if len(sys.argv) != 3:
    print("[!] Usage: python e10.py <email> <access code>")
    print("[!] You need an account on md5decrypt.net to proceed")
    email: str = input("[!] Email: ")
    code: str = input("[!] Access Code: ")
else:
    email: str = sys.argv[1]
    code: str = sys.argv[2]

# Connect to challenge endpoint and grab the banner
# The banner contains the MD5 hash of a valid password
server_address = ('E11-target.allyourbases.co', 8152)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
banner: bytes = sock.recv(1024)
banner: str = banner.decode('utf-8')

# Extract the MD5 hash from the password prompt
pattern = r"[0-9a-fA-F]{32}"
result = re.search(pattern, banner)
md5: str = result.group(0)

# Send the MD5 to md5decrypt.net to get the plaintext password
response = requests.get(
    "https://md5decrypt.net/en/Api/api.php",
    params={
        "hash": md5,
        "hash_type": "md5",
        "email": email,
        "code": code
    }
)

response_text: str = response.text.strip()
if "ERROR CODE : 002" in response_text:
    print("[!] Invalid credentials to md5decrypt.net. Exiting...")
    exit(1)
password: str = response_text
password = password.lower()

# Send the password to the challenge endpoint
sock.send(password.encode('utf-8') + b'\n')
data: bytes = sock.recv(1024)
data: str = data.decode('utf-8')

# Extract flag from response
pattern = r"Flag\[\w+\]"
result = re.search(pattern, data)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
