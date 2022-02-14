# [Lab 10: User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

---

## Description

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`.

---

## Solution

Login with the credential `wiener`:`peter`. Note `wiener`'s password prefilled in and masked on the `Update Password` form. This indicates that if it is possible to access `administrator`'s account page, their password can be retrieved and used to login as `administrator` and delete `carlos`.

![](images/Pasted%20image%2020220209155852.png)

Click on `My Account` and note the resulant URL path: `/my-account?id=wiener`. It appears the web application determines which user account to render based on the username in the `id` parameter.

Navigate to the URL path `/my-account?id=administrator` and retrieve `administrator`'s password from the HTML source: `ddje9gy3fl4z9ohk8bl4`.

![](images/Pasted%20image%2020220209160114.png)

Log out as `wiener` and use the credential `administrator`:`ddje9gy3fl4z9ohk8bl4` to login and navigate to the `Admin Panel`. Delete `carlos`'s account to complete the challenge.
