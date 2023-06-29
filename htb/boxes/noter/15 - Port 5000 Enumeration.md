## Port 5000 Enumeration

The "Noter" note-taking web application.

![](images/Pasted%20image%2020220521140553.png)

### Content Discovery

```bash
$ feroxbuster -u http://10.129.104.50:5000 --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.104.50:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       67l      106w     1963c http://10.129.104.50:5000/login
302      GET        4l       24w      218c http://10.129.104.50:5000/logout => http://10.129.104.50:5000/login
200      GET       95l      152w     2642c http://10.129.104.50:5000/register
302      GET        4l       24w      218c http://10.129.104.50:5000/dashboard => http://10.129.104.50:5000/login
302      GET        4l       24w      218c http://10.129.104.50:5000/notes => http://10.129.104.50:5000/login
302      GET        4l       24w      218c http://10.129.104.50:5000/VIP => http://10.129.104.50:5000/login
[####################] - 1m     29999/29999   0s      found:6       errors:0
[####################] - 1m     29999/29999   421/s   http://10.129.104.50:5000
```

### Site Map

#### Doesn't Require Authentication

- [X] `/`
- [ ] `/register`
- [ ] `/login`

#### Requires Authentication

- [ ] `/notes`
- [ ] `/note/$ID`
	- Redirects to `/notes` if user is not authorized to view note with ID  `$ID`
- [ ] `/add_note`
- [ ] `/logout`
- [ ] `/dashboard`
- [ ] `/VIP`

### `/register`

```http
POST /register HTTP/1.1
Host: 10.129.104.50:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 76
Origin: http://10.129.104.50:5000
Connection: close
Referer: http://10.129.104.50:5000/register
Upgrade-Insecure-Requests: 1

name=tgihf&email=tgihf%40noter.htb&username=tgihf&password=blah&confirm=blah
```

```http
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 218
Location: http://10.129.104.50:5000/login
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIllvdSBhcmUgbm93IHJlZ2lzdGVyZWQgYW5kIGNhbiBsb2cgaW4iXX1dfQ.YokrpQ.T93TcqwpzrP5QZlbeE5XK77Ob5Y; HttpOnly; Path=/
Server: Werkzeug/2.0.2 Python/3.8.10
Date: Sat, 21 May 2022 18:12:53 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
```

### `/login`

Successful login redirects to `/dashboard`.

```http
POST /login HTTP/1.1
Host: 10.129.104.50:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://10.129.104.50:5000
Connection: close
Referer: http://10.129.104.50:5000/login
Upgrade-Insecure-Requests: 1

username=tgihf&password=blah
```

```http
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 226
Location: http://10.129.104.50:5000/dashboard
Vary: Cookie
Set-Cookie: session=.eJwlx8sJwCAQBcBWlne2AjsJIYiY9QNGwVVyEHuPkNMwE8ZnK5EF-pygvoEM51gECkcdZBtTqS_lGgLflAqudSn8Nbu6t8EKQ7gV-zA0ekjRY33Jtx_n.YoksDg.rfkyFKamOAHzCfozceeiVhQyOPQ; HttpOnly; Path=/
Server: Werkzeug/2.0.2 Python/3.8.10
Date: Sat, 21 May 2022 18:14:38 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/dashboard">/dashboard</a>. If not click the link.
```

## `/dashboard`

Lists notes. Contains links to add a note or "upgrade to VIP."

## `POST /add_note`

```http
POST /add_note HTTP/1.1
Host: 10.129.104.50:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Origin: http://10.129.104.50:5000
Connection: close
Referer: http://10.129.104.50:5000/add_note
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.YoksDg.0hI1UmSR2NxVANTNsMJmqF0zPlg
Upgrade-Insecure-Requests: 1

title=Hello%2C+World%21&body=%3Cp%3EHello%2C+World%21+This+is+it%21%3C%2Fp%3E
```

Likely backend behavior:

1. Receive form body with keys `title` and `body`
2. Validate input
3. Insert into database
	- Doesn't appear to be vulnerable to SQL injection

```sql
INSERT INTO notes (title, body) VALUES (?, ?)
```

## 	`GET /VIP`

"We are currently not able to provide new premium memberships due to some problems in our end. We will let you know once we are back on. Thank you!"

TODO: gotta be something here	

```http
GET /VIP HTTP/1.1
Host: 10.129.104.50:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.129.104.50:5000/dashboard
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.YoktdA.Y61uhlo7KsCEG3hZUXFLXrpZ4ak
Upgrade-Insecure-Requests: 1

```

## `GET /notes`

Retrieves all notes associated with the current user.

1. Get the current user's ID
2. Retrieve the notes corresponding to the current user's ID

```sql
SELECT title, body FROM notes WHERE user_id = ?
```

3. Return the notes

## `GET /note/$ID`

Retrieves note with ID `$ID`.

1. Get current user's ID
2. Retrieve the note corresponding to the note ID and user's ID
	- It appears that as long as `$ID` begins with the correct integer, it can contain any other characters (except for numbers). It seems the application achieves this by casting the input ID as an integer, like so:

```sql
SELECT title, body FROM notes WHERE id = CAST(?, AS UNSIGNED) AND user_id = ?
```

I attempted the following injections unsuccessfully:

```sql
SELECT title, body FROM notes WHERE id = CAST("3" AS UNSIGNED)--" AS UNSIGNED);
SELECT title, body FROM notes WHERE id = CAST('3' AS UNSIGNED)--' AS UNSIGNED);
```

3. Return the note


## CKEditor

The web application leverages CKEditor version 4.6.2 to create notes in the browser. All versions of CKEditor prior to version 4.18.0 contain a [JavaScript injection vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2022-24728).
