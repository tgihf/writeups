## SSH Access as `mitch`

Use the credential `mitch`:`secret` to access the target via SSH on port 2222 and grab the user flag from `/users/mitch/user.txt`.

```bash
$ ssh mitch@10.10.162.248 -p 2222
The authenticity of host '[10.10.162.248]:2222 ([10.10.162.248]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.162.248]:2222' (ECDSA) to the list of known hosts.
mitch@10.10.162.248's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
/usr/bin/xauth:  file /home/mitch/.Xauthority does not exist
$ id
uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)
$ cat user.txt
G00d j0b, keep up!
```
