# [Lab 07: User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

---

## Description

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`.

---

## Solution

Login with the credential `wiener`:`peter`. Note the API key on the account page.

Click on `My Account` and note the resulant URL path: `/my-account?id=wiener`. It appears the web application determines which user account to render based on the username in the `id` parameter.

`carlos`' API key is most likely on his account page. To navigate to his account, navigate to the URL path `/my-account?id=carlos`.

![](images/Pasted%20image%2020220209150449.png)

Submit `carlos`' API key to solve the challenge.
