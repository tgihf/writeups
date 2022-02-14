# [Lab 08: User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

---

## Description

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

To solve the lab, find the GUID for `carlos`, then submit his API key as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

Login with the credential `wiener`:`peter`. Note the API key on the account page.

Click on `My Account` and note the resulant URL path: `/my-account?id=358988c3-d6b2-4426-a4d1-0492236ed4af`. The web application determines which user account to render based on the GUID in the `id` parameter.

`carlos`' API key is most likely on his account page. To reach his account page, his GUID must be found.

Each blog post on the web application has been written by a particular user. Each author's name is actually an anchor tag that reveals their GUID. The post `Look No Hands - The Game Plays Itself` was written by `carlos`. Its author anchor tag reveals his GUID as `c9845f7f-b16d-4390-b4eb-0bb9b49a3e53`.

![](images/Pasted%20image%2020220209152145.png)

Navigate to the URL path `/my-account?id=c9845f7f-b16d-4390-b4eb-0bb9b49a3e53` to access `carlos`' account. Submit his API key to complete the challenge.
