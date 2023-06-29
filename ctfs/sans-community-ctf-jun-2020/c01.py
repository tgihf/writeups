from bs4 import BeautifulSoup
import re
import requests
import socket


# Connect to the challenge endpoint and read in the data
server_address = ('C01-target.allyourbases.co', 8147)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
data: bytes = sock.recv(10000)
data: str = data.decode('utf-8')

# Extract the encrypted key
pattern = r"Protected credential: (.+)"
result = re.search(pattern, data)
key = result.group(1)

# Send Vigenere ciphered key to be auto solved
response = requests.get("https://www.guballa.de/vigenere-solver")
soup = BeautifulSoup(response.text, "html.parser")
form = soup.find("form")
url = form.get("action")
request_token = [
    inp for inp in form.find_all("input")
    if inp.get("name") == "REQUEST_TOKEN"
][0].get("value")
cookie = response.headers.get("Set-Cookie").split(' ')[0]

response = requests.post(
    url,
    data={
        "REQUEST_TOKEN": request_token,
        "cipher": key,
        "variant": "vigenere",
        "lang": "en",
        "key_len": "3-30",
        "break": "Break Cipher"
    },
    headers={"cookie": cookie}
)

# Parse response to retrieve solution
soup = BeautifulSoup(response.text, "html.parser")
div = soup.find(id="vig_clear")
protected_key: str = div.find("textarea").contents[0]
pattern = r"THEPROTECTEDKEYIS(.+)"
result = re.search(pattern, protected_key)
protected_key: str = result.group(1)

# Send plaintext key to challenge endpoint
sock.send(protected_key.encode("utf-8") + b"\n")
data: bytes = sock.recv(1024)
sock.send(b"\n")
data: bytes = sock.recv(1024)
data: str = data.decode("utf-8")

# Extract the flag
pattern = r"Flag\[\w+\]"
result = re.search(pattern, data)
flag = result.group(0)
print(f"[*] Got the flag: {flag}")
