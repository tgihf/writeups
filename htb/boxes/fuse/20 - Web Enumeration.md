## Web Enumeration

The web application on port 80 appears to be `PaperCut Print Logger`, an application that logs print jobs to specified printers.

![](images/Pasted%20image%2020211206182402.png)

### Content Discovery

```bash
$ gobuster dir -u http://fuse.fabricorp.local -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://fuse.fabricorp.local
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/06 17:27:14 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 103]

===============================================================
2021/12/06 17:30:25 Finished
===============================================================
```

### Virtual Host Discovery

No virtual hosts.

```bash
$ gobuster vhost -u http://fabricorp.local -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://fabricorp.local
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/12/06 17:26:43 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/12/06 17:27:08 Finished
===============================================================
```

### Manual Enumeration

There are print logs for three different dates: 29 May, 30 May, and 10 June of 2020. Each print log indicates the user who initiated it, the client computer, and the printer (`HP-MFT01`).

The users:

```txt
pmerton
bnielson
tlavel
sthompson
bhult
```

The client computers:

```txt
JUMP01$
LONWK015$
LONWK019$
LAPTOP07$
FUSE$
HP-MFT01$
```

Attempting to brute force other dates yields nothing.

```bash
$ for i in {400..800}; do d=$(date --date="$i days ago" +"%Y-%m-%d"); echo $d >> dates.txt; done
$ patator http_fuzz url='http://fuse.fabricorp.local/papercut/logs/html/papercut-print-log-FILE0.htm' 0=dates.txt proxy=127.0.0.1:8080 -x ignore:code=404
21:10:26 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2021-12-06 21:10 EST
21:10:26 patator    INFO -
21:10:26 patator    INFO - code size:clen       time | candidate                          |   num | mesg
21:10:26 patator    INFO - -----------------------------------------------------------------------------
21:10:28 patator    INFO - 200  3782:3537      0.117 | 2020-06-10                         |   145 | HTTP/1.1 200 OK
21:10:28 patator    INFO - 200  4012:3769      0.124 | 2020-05-30                         |   156 | HTTP/1.1 200 OK
21:10:28 patator    INFO - 200  3786:3541      0.121 | 2020-05-29                         |   157 | HTTP/1.1 200 OK
21:10:39 patator    INFO - Hits/Done/Skip/Fail/Size: 3/401/0/0/401, Avg: 32 r/s, Time: 0h 0m 12s
```