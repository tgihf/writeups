## FTP Session as `blue`

`blue`'s "Noter Premium Membership" note discloses the FTP credential `blue`:`blue@Noter!`. It also reveals the potential username `ftp_admin`.

![](images/Pasted%20image%2020220605095333.png)

`blue`'s "Before the weekend" note is a to-do list reminding `blue` to delete the "Noter Premium Membership" note and "ask the admin team to change the password."

![](images/Pasted%20image%2020220605095511.png)

```bash
$ ftp 10.129.101.16
Connected to 10.129.101.16.
220 (vsFTPd 3.0.3)
Name (10.129.101.16:tgihf): blue
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24 20:59 policy.pdf
226 Directory send OK.
```

The `files/` directory is empty. `policy.pdf` is Noter's password policy. It indicates that the default user-password's structure is `username@site_name!`.
