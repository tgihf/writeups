## Open Port Enumeration

### TCP

The target's TCP ports 21, 22, and 5000 are open.

```bash
$ sudo masscan -p1-65535 10.129.171.154 --rate=1000 -e tun0 --output-format grepable --output-filename noter.masscan                                  1 ⨯
$ cat noter.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,22,5000,
```

According to [launchpad.net], the OpenSSH banner indicates the target's operating system is likely Ubuntu 20.04 (Focal).

Port 5000 appears to be running a Python 3.8 web application that leverages the Werkzeug WSGI library. This is likely a Flask application.

```bash
$ nmap -sC -sV -p21,22,5000 10.129.171.154 -oA noter
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-07 20:39 EDT
Nmap scan report for 10.129.171.154
Host is up (0.061s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title: Noter
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.91 seconds
```

### UDP

```bash
$ sudo nmap -sU 10.129.104.50
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-21 12:03 EDT
Nmap scan report for 10.129.104.50
Host is up (0.050s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1009.35 seconds
```
