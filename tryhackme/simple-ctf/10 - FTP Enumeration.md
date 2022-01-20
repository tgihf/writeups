## FTP Enumeration

The target is hosting `vsftpd 3.0.3`, which is a relatively recent version of `vsftpd`.

It allows anonymous access and contains a single directory, `pub`, which contains a single file, `ForMitch.txt`.

```bash
$ ftp
ftp> open 10.10.162.248
Connected to 10.10.162.248.
220 (vsFTPd 3.0.3)
Name (10.10.162.248:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
226 Transfer complete.
166 bytes received in 0.00 secs (3.2981 MB/s)
```

`ForMitch.txt` is a note that shames a developer (presumably Mitch) for setting an easily crackable password.

```bash
$ cat ForMitch.txt
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```