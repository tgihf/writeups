## Web Application Enumeration

The target's TCP port 80 is running a web application served by `Apache httpd 2.4.18`.

There is a `/robots.txt` file that indicates the target is running a [CUPS server](http://www.cups.org/) and disallows access to `/openemr-5_0_1_3`. This path results in a 404.

```txt
#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```

### Content Discovery

`/simple` is the only non-standard path.

```bash
$ gobuster dir -u http://10.10.162.248 -w /usr/share/wordlists/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.248
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/01/19 21:23:29 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 292]
/.htm                 (Status: 403) [Size: 292]
/.htm.php             (Status: 403) [Size: 296]
/.html                (Status: 403) [Size: 293]
/.html.php            (Status: 403) [Size: 297]
/.                    (Status: 200) [Size: 11321]
/.htaccess            (Status: 403) [Size: 297]
/.htaccess.php        (Status: 403) [Size: 301]
/.phtml               (Status: 403) [Size: 294]
/.htc                 (Status: 403) [Size: 292]
/.htc.php             (Status: 403) [Size: 296]
/simple               (Status: 301) [Size: 315] [--> http://10.10.162.248/simple/]
/.html_var_DE         (Status: 403) [Size: 300]
/.html_var_DE.php     (Status: 403) [Size: 304]
/server-status        (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 297]
/.htpasswd.php        (Status: 403) [Size: 301]
/.html..php           (Status: 403) [Size: 298]
/.html.               (Status: 403) [Size: 294]
/.html.html           (Status: 403) [Size: 298]
/.html.html.php       (Status: 403) [Size: 302]
/.htpasswds           (Status: 403) [Size: 298]
/.htpasswds.php       (Status: 403) [Size: 302]
/.htm..php            (Status: 403) [Size: 297]
/.htm.                (Status: 403) [Size: 293]
/.htmll               (Status: 403) [Size: 294]
/.htmll.php           (Status: 403) [Size: 298]
/.phps                (Status: 403) [Size: 293]
/.html.old.php        (Status: 403) [Size: 301]
/.html.old            (Status: 403) [Size: 297]
/.ht                  (Status: 403) [Size: 291]
/.html.bak            (Status: 403) [Size: 297]
/.ht.php              (Status: 403) [Size: 295]
/.html.bak.php        (Status: 403) [Size: 301]
/.htm.htm             (Status: 403) [Size: 296]
/.htm.htm.php         (Status: 403) [Size: 300]
/.hta                 (Status: 403) [Size: 292]
/.htgroup             (Status: 403) [Size: 296]
/.html1               (Status: 403) [Size: 294]
/.hta.php             (Status: 403) [Size: 296]
/.html1.php           (Status: 403) [Size: 298]
/.htgroup.php         (Status: 403) [Size: 300]
/.html.LCK            (Status: 403) [Size: 297]
/.html.printable      (Status: 403) [Size: 303]
/.html.LCK.php        (Status: 403) [Size: 301]
/.html.printable.php  (Status: 403) [Size: 307]
/.htm.LCK             (Status: 403) [Size: 296]
/.htm.LCK.php         (Status: 403) [Size: 300]
/.htaccess.bak        (Status: 403) [Size: 301]
/.html.php            (Status: 403) [Size: 297]
/.htmls.php           (Status: 403) [Size: 298]
/.htx                 (Status: 403) [Size: 292]
/.html.php.php        (Status: 403) [Size: 301]
/.htaccess.bak.php    (Status: 403) [Size: 305]
/.htmls               (Status: 403) [Size: 294]
/.htx.php             (Status: 403) [Size: 296]
/.htlm                (Status: 403) [Size: 293]
/.htm2.php            (Status: 403) [Size: 297]
/.html-               (Status: 403) [Size: 294]
/.htuser              (Status: 403) [Size: 295]
/.htlm.php            (Status: 403) [Size: 297]
/.htm2                (Status: 403) [Size: 293]
/.html-.php           (Status: 403) [Size: 298]
/.htuser.php          (Status: 403) [Size: 299]

===============================================================
2022/01/19 21:35:05 Finished
===============================================================
```

### CMS Made Simple Enumeration

`/simple` is the home page of [CMS Made Simple](http://www.cmsmadesimple.org/), an open-source content management system.

![](images/Pasted%20image%2020220119214636.png)
