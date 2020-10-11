import re

import requests


# Grab the web page
response = requests.get("https://redpwn.net")
assert response.status_code == 200, "[!] Failed to grab web page"

# Extract the flag
regex = r"flag{(.+)}"
result = re.search(regex, response.text)
flag: str = result.group(0)
print(f"[*] Got the flag: {flag}")
