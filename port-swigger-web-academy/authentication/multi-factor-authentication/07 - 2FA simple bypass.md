# [Lab 7: 2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

## Description

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

-   Your credentials: `wiener:peter`
-   Victim's credentials `carlos:montoya`

## Solution

After verifying the first authentication factor (username and password), the web application makes the mistake of issuing a full-blown cookie that grants full access, removing the need to enter the second authentication factor. In the browser, login as `carlos`.

![](images/Pasted%20image%2020210810184005.png)

When prompted for the second authentication factor, simply navigate to `/` and then `My Account` to solve the challenge.
