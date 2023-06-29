## Situational Awareness as `svc`

```bash
svc@noter:~$ uname -a
Linux noter 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
svc@noter:~$ cat /etc/issue
Ubuntu 20.04.3 LTS \n \l
```

```bash
svc@noter:~$ lscpu
Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   43 bits physical, 48 bits virtual
CPU(s):                          2
On-line CPU(s) list:             0,1
Thread(s) per core:              1
Core(s) per socket:              1
Socket(s):                       2
NUMA node(s):                    1
Vendor ID:                       GenuineIntel
CPU family:                      6
Model:                           85
Model name:                      Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz
Stepping:                        7
CPU MHz:                         2294.609
BogoMIPS:                        4589.21
Hypervisor vendor:               VMware
Virtualization type:             full
L1d cache:                       64 KiB
L1i cache:                       64 KiB
L2 cache:                        2 MiB
L3 cache:                        44 MiB
NUMA node0 CPU(s):               0,1
Vulnerability Itlb multihit:     KVM: Vulnerable
Vulnerability L1tf:              Not affected
Vulnerability Mds:               Not affected
Vulnerability Meltdown:          Not affected
Vulnerability Spec store bypass: Mitigation; Speculative Store Bypass disabled v
                                 ia prctl and seccomp
Vulnerability Spectre v1:        Mitigation; usercopy/swapgs barriers and __user
                                  pointer sanitization
Vulnerability Spectre v2:        Mitigation; Enhanced IBRS, IBPB conditional, RS
                                 B filling
Vulnerability Srbds:             Not affected
Vulnerability Tsx async abort:   Not affected
Flags:                           fpu vme de pse tsc msr pae mce cx8 apic sep mtr
                                 r pge mca cmov pat pse36 clflush mmx fxsr sse s
                                 se2 ss syscall nx pdpe1gb rdtscp lm constant_ts
                                 c arch_perfmon nopl xtopology tsc_reliable nons
                                 top_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid
                                  sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline
                                 _timer aes xsave avx f16c rdrand hypervisor lah
                                 f_lm abm 3dnowprefetch cpuid_fault invpcid_sing
                                 le ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase
                                 tsc_adjust bmi1 avx2 smep bmi2 invpcid avx512f
                                 avx512dq rdseed adx smap clflushopt clwb avx512
                                 cd avx512bw avx512vl xsaveopt xsavec xsaves ara
                                 t pku ospke md_clear flush_l1d arch_capabilitie
                                 s
```

Users with console:

- `svc`
- `blue`
- `ftp_admin`

```bash
svc@noter:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
svc:x:1001:1001:,,,:/home/svc:/bin/bash
ftp:x:113:118:ftp daemon,,,:/home/svc/ftp/:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
ftp_admin:x:1003:1003::/srv/ftp/ftp_admin:/sbin/nologin
blue:x:1002:1002::/srv/ftp/blue:/sbin/nologin
```

```bash
svc@noter:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:syslog
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
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
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
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
crontab:x:105:
messagebus:x:106:
input:x:107:
kvm:x:108:
render:x:109:
syslog:x:110:
tss:x:111:
uuidd:x:112:
tcpdump:x:113:
ssh:x:114:
landscape:x:115:
lxd:x:116:
systemd-coredump:x:999:
svc:x:1001:
ssl-cert:x:117:
ftp:x:118:
mysql:x:119:
ftp_admin:x:1003:
blue:x:1002:
netdev:x:120:
```

```bash
svc@noter:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:75:f3 brd ff:ff:ff:ff:ff:ff
    inet 10.129.101.16/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2243sec preferred_lft 2243sec
    inet6 dead:beef::250:56ff:feb9:75f3/64 scope global dynamic mngtmpaddr
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:75f3/64 scope link
       valid_lft forever preferred_lft forever
```

```bash
svc@noter:~$ ip route
default via 10.129.0.1 dev eth0
10.129.0.0/16 dev eth0 proto kernel scope link src 10.129.101.16
```

```bash
svc@noter:~$ ip neigh
10.129.0.1 dev eth0 lladdr 00:50:56:b9:2b:b5 REACHABLE
fe80::250:56ff:feb9:2bb5 dev eth0 lladdr 00:50:56:b9:2b:b5 router STALE
```

```bash
svc@noter:~$ ss -antl
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*
LISTEN  0        128              0.0.0.0:5000           0.0.0.0:*
LISTEN  0        80             127.0.0.1:3306           0.0.0.0:*
LISTEN  0        32                     *:21                   *:*
LISTEN  0        128                 [::]:22                [::]:*
LISTEN  0        511                    *:46689                *:*
LISTEN  0        511                    *:34723                *:*
LISTEN  0        511                    *:45769                *:*
LISTEN  0        511                    *:33801                *:*
```
