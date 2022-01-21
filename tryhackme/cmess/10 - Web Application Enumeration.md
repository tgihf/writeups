## Web Application Enumeration

The web application being served by Apache 2.4.18 is `Gilma CMS`, which appears to be a custom CMS for the challenge. It is being used as a blog, with one post titled "Hello World."

![](images/Pasted%20image%2020220121174619.png)

### `/robots.txt`

There is a `/robots.txt` preventing crawler access to `/src/`, `/themes/`, and `/lib/`.

`/src/` redirects to `/src/url=src`, which returns a 403. Same with `/lib/` and `/themes/`

### Content Discovery

```bash
$ gobuster dir -u http://cmess.thm -w /usr/share/wordlists/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cmess.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/21 17:50:32 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/login                (Status: 200) [Size: 1580]
/admin                (Status: 200) [Size: 1580]
/themes               (Status: 301) [Size: 318] [--> http://cmess.thm/themes/?url=themes]
/index                (Status: 200) [Size: 3851]
/tmp                  (Status: 301) [Size: 312] [--> http://cmess.thm/tmp/?url=tmp]
/feed                 (Status: 200) [Size: 735]
/.htm                 (Status: 403) [Size: 274]
/category             (Status: 200) [Size: 3862]
/tag                  (Status: 200) [Size: 3874]
/blog                 (Status: 200) [Size: 3851]
/sites                (Status: 301) [Size: 316] [--> http://cmess.thm/sites/?url=sites]
/search               (Status: 200) [Size: 3851]
/lib                  (Status: 301) [Size: 312] [--> http://cmess.thm/lib/?url=lib]
/author               (Status: 200) [Size: 3590]
/api                  (Status: 200) [Size: 0]
/assets               (Status: 301) [Size: 318] [--> http://cmess.thm/assets/?url=assets]
/tags                 (Status: 200) [Size: 3139]
/about                (Status: 200) [Size: 3353]
/Search               (Status: 200) [Size: 3851]
/1                    (Status: 200) [Size: 4078]
/log                  (Status: 301) [Size: 312] [--> http://cmess.thm/log/?url=log]
/.                    (Status: 200) [Size: 3865]
/0                    (Status: 200) [Size: 3851]
/.htaccess            (Status: 403) [Size: 274]
/src                  (Status: 301) [Size: 312] [--> http://cmess.thm/src/?url=src]
/01                   (Status: 200) [Size: 4078]
/.php3                (Status: 403) [Size: 274]
/.phtml               (Status: 403) [Size: 274]
/fm                   (Status: 200) [Size: 0]
/cm                   (Status: 500) [Size: 0]
/About                (Status: 200) [Size: 3339]
/Index                (Status: 200) [Size: 3851]
/.htc                 (Status: 403) [Size: 274]
/.php5                (Status: 403) [Size: 274]
/Category             (Status: 200) [Size: 3862]
/.html_var_DE         (Status: 403) [Size: 274]
/.php4                (Status: 403) [Size: 274]
/Author               (Status: 200) [Size: 3590]
/server-status        (Status: 403) [Size: 274]
/001                  (Status: 200) [Size: 4078]
/Tags                 (Status: 200) [Size: 3139]
/.htpasswd            (Status: 403) [Size: 274]
/.html.               (Status: 403) [Size: 274]
/Feed                 (Status: 200) [Size: 735]
/.html.html           (Status: 403) [Size: 274]
/.htpasswds           (Status: 403) [Size: 274]
/Tag                  (Status: 200) [Size: 3874]
/.htm.                (Status: 403) [Size: 274]
/0001                 (Status: 200) [Size: 4078]
/.htmll               (Status: 403) [Size: 274]
/.phps                (Status: 403) [Size: 274]
/SEARCH               (Status: 200) [Size: 3851]
/.html.old            (Status: 403) [Size: 274]
/.ht                  (Status: 403) [Size: 274]
/.html.bak            (Status: 403) [Size: 274]
/.htm.htm             (Status: 403) [Size: 274]
/1index               (Status: 200) [Size: 4078]
/ABOUT                (Status: 200) [Size: 3339]
/.hta                 (Status: 403) [Size: 274]
/.htgroup             (Status: 403) [Size: 274]
/.html1               (Status: 403) [Size: 274]
/1c                   (Status: 200) [Size: 4078]
/.html.LCK            (Status: 403) [Size: 274]
/.html.printable      (Status: 403) [Size: 274]
/1b                   (Status: 200) [Size: 4078]
/.htm.LCK             (Status: 403) [Size: 274]
/.htaccess.bak        (Status: 403) [Size: 274]
/.html.php            (Status: 403) [Size: 274]
/.htmls               (Status: 403) [Size: 274]
/.htx                 (Status: 403) [Size: 274]
/1a                   (Status: 200) [Size: 4078]
/1checkout            (Status: 200) [Size: 4078]
/1images              (Status: 200) [Size: 4078]
/1ps                  (Status: 200) [Size: 4078]
/1qaz2wsx             (Status: 200) [Size: 4078]
/1st                  (Status: 200) [Size: 4078]
/1x1                  (Status: 200) [Size: 4078]
/INDEX                (Status: 200) [Size: 3851]
/.htlm                (Status: 403) [Size: 274]
/.htm2                (Status: 403) [Size: 274]
/.htuser              (Status: 403) [Size: 274]
/.html-               (Status: 403) [Size: 274]
/01_02                (Status: 200) [Size: 4078]
/1-1                  (Status: 200) [Size: 4078]
/1-3                  (Status: 200) [Size: 4078]
/1-delivery           (Status: 200) [Size: 4078]
/1-livraison          (Status: 200) [Size: 4078]
/1_0                  (Status: 200) [Size: 4078]
/1_files              (Status: 200) [Size: 4078]
/1_1                  (Status: 200) [Size: 4078]
/1temp                (Status: 200) [Size: 4078]

===============================================================
2022/01/21 17:56:39 Finished
===============================================================
```

### Virtual Host Discovery

All virtual hosts return a 200.

