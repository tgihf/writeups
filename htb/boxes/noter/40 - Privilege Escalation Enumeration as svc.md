## Privilege Escalation Enumeration as `svc`

- [ ] Investigate MySQL

```sql
MariaDB [app]> select * from app.users;
+-------------+----------------+----------+-------------------------------------------------------------------------------+------+
| name        | email          | username | password                                                                      | role |
+-------------+----------------+----------+-------------------------------------------------------------------------------+------+
| Blue Wilson | blue@Noter.htb | blue     | $5$rounds=535000$76NyOgtW18b3wIqL$HZqlzNHs1SdzbAb2V6EyAnqYNskA3K.8e1iDesL5vI2 | VIP  |
+-------------+----------------+----------+-------------------------------------------------------------------------------+------+
1 row in set (0.001 sec)
```

- [ ] Attempt to crack `blue`'s sha512crypt hash
	- `blue` can't even login, try `root`

```bash
$ hashcat -m 7400 '$5$rounds=535000$76NyOgtW18b3wIqL$HZqlzNHs1SdzbAb2V6EyAnqYNskA3K.8e1iDesL5vI2' rockyou.txt

```

---

- [X] `mysqlcheck` service and timer?

---

- [ ] `sudo` version (1.8.31)

---

- [ ] `/opt/backup.sh`

Only executable by `root`. Readable by everyone else.

```bash
#!/bin/bash
zip -r `echo /home/svc/ftp/admin/app_backup_$(date +%s).zip` /home/svc/app/web/* -x /home/svc/app/web/misc/node_modules/**\*
```

TODO: is this getting executed? Was this just to set up the FTP portion of the box or is this the privilege escalation vector?
