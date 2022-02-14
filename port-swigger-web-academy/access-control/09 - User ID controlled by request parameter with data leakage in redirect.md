# [Lab 09: User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

---

## Description

This lab contains an [access control](https://portswigger.net/web-security/access-control) vulnerability where sensitive information is leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`.

---

## Solution

Login with the credential `wiener`:`peter`. Note the API key on the account page.

Click on `My Account` and note the resulant URL path: `/my-account?id=wiener`. It appears the web application determines which user account to render based on the username in the `id` parameter.

`carlos`' API key is most likely on his account page. To navigate to his account, navigate to the URL path `/my-account?id=carlos`. This results in a 302 redirect to the login page. However, the body of the 302 response is actually the HTML source of `carlos`'s account page and contains his API key.

![](images/Pasted%20image%2020220209153440.png)

Submit this API key to complete the challenge.
