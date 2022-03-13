## SMB Enumeration

Neither anonymous nor guest access are allowed.

```bash
$ crackmapexec smb 10.129.2.5 --shares
SMB         10.129.2.5      445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.129.2.5      445    FUSE             [-] Error enumerating shares: SMB SessionError: 0x5b
```

```bash
$ smbmap -P 445 -H 10.129.2.5
[+] IP: 10.129.2.5:445  Name: 10.129.2.5
```

```bash
$ crackmapexec smb 10.129.2.5 -d fabricorp.local -u guest --shares SMB         10.129.2.5      445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:FUSE) (signing:True) (SMBv1:True)
SMB         10.129.2.5      445    FUSE             [-] Error enumerating shares: SMB SessionError: 0x5b
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.2.5
[!] Authentication error on 10.129.2.5
```