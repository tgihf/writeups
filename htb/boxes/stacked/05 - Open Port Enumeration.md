## Open Port Enumeration

The target's TCP ports 22, 80, and 2376 are open.

```bash
$ sudo masscan -p1-65535 10.129.140.39 --rate=1000 -e tun0 --output-format grepable --output-filename enum/stacked.masscan
$ cat enum/stacked.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,2376,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.3), the OpenSSH banner indicates the target's operating system is Ubutnu 20.04 (Focal).

Apache 2.4.41 is running on port 80, redirecting to `http://stacked.htb`. Add this hostname to the local DNS resolver.

Generally port 2376 hosts Docker's REST API over HTTPS. This is generally only considered secure if mutual TLS is used. If mutual TLS isn't used, this is a a potential finding (TODO: why?).

```bash
$ nmap -sC -sV -p22,2376,80 10.129.140.39 -oA enum/stacked
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-19 16:00 EDT
Nmap scan report for 10.129.140.39
Host is up (0.051s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 12:8f:2b:60:bc:21:bd:db:cb:13:02:03:ef:59:36:a5 (RSA)
|   256 af:f3:1a:6a:e7:13:a9:c0:25:32:d0:2c:be:59:33:e4 (ECDSA)
|_  256 39:50:d5:79:cd:0e:f0:24:d3:2c:f4:23:ce:d2:a6:f2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://stacked.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
2376/tcp open  ssl/docker?
| ssl-cert: Subject: commonName=0.0.0.0
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1
| Not valid before: 2021-07-17T15:37:02
|_Not valid after:  2022-07-17T15:37:02
Service Info: Host: stacked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.95 seconds
```
