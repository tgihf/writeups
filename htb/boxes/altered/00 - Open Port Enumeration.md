## Open Port Enumeration

### TCP

```bash
$ sudo masscan -p1-65535 10.129.227.109 --rate=1000 -e tun0 --output-format grepable --output-filename enum/altered.masscan
$ cat enum/altered.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to the OpenSSH banner, [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.4) indicates the target's operating system is Ubuntu 20.04.

Port 80 is running an Nginx 1.18.0 web server whose home page is titled `UHC March Finals`. The home page is redirected to `/login`.

```bash
$ nmap -sV -sC -p22,80 10.129.227.109 -oA enum/altered
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 12:06 EDT
Nmap scan report for 10.129.227.109
Host is up (0.026s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-title: UHC March Finals
|_Requested resource was http://10.129.227.109/login
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.76 seconds
```

### UDP

```bash
$ sudo nmap -sU 10.129.227.109

```
