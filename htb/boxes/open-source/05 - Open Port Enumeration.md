## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.46.240 --rate=1000 -e tun0 --output-format grepable --output-filename scanning/open-source.masscan
$ cat scanning/open-source.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','                                              130 ⨯
22,80,                                                                                                                                                      
```

Only TCP ports 22 and 80 are open.

```bash
$ nmap -sC -sV -p22,80 10.129.46.240 -oA scanning/open-source-nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-17 14:01 EDT
Nmap scan report for 10.129.46.240
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 17 Oct 2022 18:02:03 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 17 Oct 2022 18:02:03 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     Connection: close
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=10/17%Time=634D989A%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1072,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20
SF:Python/3\.10\.3\r\nDate:\x20Mon,\x2017\x20Oct\x202022\x2018:02:03\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:05316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x2
SF:0\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name
SF:=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">
SF:\n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free
SF:!</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jqu
SF:ery-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/sta
SF:tic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<scrip
SF:t\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n
SF:\x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaroun
SF:d\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hre
SF:f=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<l
SF:ink\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/bo
SF:otstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x2
SF:0\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r
SF:\nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Mon,\x2017
SF:\x20Oct\x202022\x2018:02:03\x20GMT\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nContent-Length:\x2
SF:00\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HT
SF:ML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\
SF:x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x
SF:20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>
SF:Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20cod
SF:e:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20re
SF:quest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x2
SF:0Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x2
SF:0\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.02 seconds
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4ubuntu0.7), the SSH banner indicates the target's operating system is likely Ubuntu 18.04.

Port 80's title indicates it is running `upcloud`, which allows for free file uploads. Response headers indicate the application is written in Python, likely utilizing the [Flask](https://flask.palletsprojects.com/en/2.2.x/) framework.

### UDP

Nothing here.

```bash
$ sudo nmap -sU 10.129.46.240
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-17 14:07 EDT
Nmap scan report for 10.129.46.240
Host is up (0.024s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1015.22 seconds
```