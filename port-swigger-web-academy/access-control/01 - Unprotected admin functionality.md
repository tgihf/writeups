# [Lab 1: Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

---

## Description

This lab has an unprotected admin panel.

Solve the lab by deleting the user `carlos`.

---

## Solution

Navigate to `/robots.txt`.

![](images/Pasted%20image%2020210921220609.png)

Note the path to the unprotected administrator panel: `/administrator-panel`.

Navigate to `/administrator-panel` and delete `carlos` to complete the challenge.
