## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.2.5 --rate=1000 -e tun0 --output-format grepable --output-filename enum/fuse.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-06 22:02:31 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/fuse.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,49666,49667,49675,49676,49679,49692,53,593,636,80,88,9389,                                                                    
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,49666,49667,49675,49676,49679,49692,53,593,636,80,88,9389,65535 10.129.2.5 -oA enum/fuse
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-06 17:06 EST
Nmap scan report for 10.129.2.5
Host is up (0.051s latency).

PORT      STATE    SERVICE      VERSION
53/tcp    open     domain       Simple DNS Plus
80/tcp    open     http         Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open     kerberos-sec Microsoft Windows Kerberos (server time: 2021-12-06 22:19:17Z)
135/tcp   open     msrpc        Microsoft Windows RPC
139/tcp   open     netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open     ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
9389/tcp  open     mc-nmf       .NET Message Framing
49666/tcp open     msrpc        Microsoft Windows RPC
49667/tcp open     msrpc        Microsoft Windows RPC
49675/tcp open     ncacn_http   Microsoft Windows RPC over HTTP 1.0
49676/tcp open     msrpc        Microsoft Windows RPC
49679/tcp open     msrpc        Microsoft Windows RPC
49692/tcp open     msrpc        Microsoft Windows RPC
65535/tcp filtered unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h52m57s, deviation: 4h37m08s, median: 12m56s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2021-12-06T14:20:11-08:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2021-12-06T22:20:13
|_  start_date: 2021-12-06T22:14:03
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.28 seconds
```

The target is serving ports 53, 88, 389, and 636, indicating that it is most likely an Active Directory domain controller. The banner from the LDAP ports indicate the domain name is `fabricorp.local`. The machine's FQDN is `fuse.fabricorp.local`. There is also a Microsoft IIS web server on port 80. The absence of remote access ports 5985 and 3389 indicate that some sort of remote code execution vulnerability or administrative credentials will be required to have command interaction with the target.

### UDP

```bash
$ nmap -sU 10.129.2.5

```
