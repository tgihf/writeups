from base64 import b64decode
import re

import requests


# Grab the ciphered text
url = "https://redpwn.storage.googleapis.com/uploads"
url += "/d2416e56cf33dfb504fa614285dfa9f9b2f9cba23e02e6bcd7e6e413e529b911/cipher.txt"
response = requests.get(url)
assert response.status_code == 200, "[!] Failed to download cipher.txt"
string = response.text

# Grab the code that ciphered the text to figure out how many iterations
url = "https://redpwn.storage.googleapis.com/uploads"
url += "/0be0e67b33d7df42a6524fa0bd48c74784d2375673039e210b864ac901f6573e/generate.js"
response = requests.get(url)
assert response.status_code == 200, "[!] Failed to download cipher.txt"
regex = r"for\(let i = 0; i < ([0-9]+); i\+\+\)"
result = re.search(regex, response.text)
assert result, "[!] Couldn't find the number of iterations"
iterations = int(result.group(1))

# Iteratively decode the cipher
for _ in range(iterations):
    string = b64decode(string)
flag: str = string.decode()
print(f"[*] Got the flag: {flag}")
