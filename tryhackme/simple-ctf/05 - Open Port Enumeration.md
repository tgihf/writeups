## Open Port Enumeration

### TCP

TCP ports 21 and 2222 are open.

```bash
$ sudo masscan -p1-65535 10.10.162.248 --rate=1000 -e tun0 --output-format grepable --output-filename enum/simple-ctf.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-19 20:50:30 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/simple-ctf.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
21,80,2222, 
```

The target is serving `vsftpd 3.0.3` on TCP port 21, an Apache web server on TCP port 80, and `OpenSSH 7.2p2` on port 2222.

```bash
$ sudo nmap -sC -sV -p21,2222,80 10.10.162.248 -oA enum/simple-ctf
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-19 21:15 UTC
Nmap scan report for ip-10-10-162-248.us-east-2.compute.internal (10.10.162.248)
Host is up (0.080s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.6.31.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries
|_/ /openemr-5_0_1_3
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.90 seconds
```

### UDP

```bash
$ sudo nmap -sU 10.10.162.248

```
