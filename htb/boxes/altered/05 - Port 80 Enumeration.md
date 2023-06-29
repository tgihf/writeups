## Port 80 Enumeration

The web server offers `XSRF-Token` and `laravel_session` cookies, indicating it is likely a [Laravel](https://laravel.com/) web application.

The login page is for access to the UHC Player Dashboard.

Login form contains a CSRF token.

### Content Discovery
- `/` --> `/login`
- `/login`
- `/test`: 200
	- Returns the string `1       2       ippsec` as plain text
- `/reset`: 200
	- Allows a user to reset their password
	- Appears to make username enumeration possible

```bash
$ feroxbuster -u http://10.129.227.109 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -x php --filter-status 403 -n --json --output feroxbuster-root

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.109
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💢  Status Code Filters   │ [403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🧔  JSON Output           │ true
 💾  Output File           │ feroxbuster-root
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      178c http://10.129.227.109/js => http://10.129.227.109/js/
301      GET        7l       12w      178c http://10.129.227.109/css => http://10.129.227.109/css/
200      GET        1l        3w       11c http://10.129.227.109/test
200      GET      144l      321w        0c http://10.129.227.109/login
302      GET       12l       22w        0c http://10.129.227.109/index.php => http://10.129.227.109/index.php/login
301      GET        7l       12w      178c http://10.129.227.109/fonts => http://10.129.227.109/fonts/
302      GET       12l       22w        0c http://10.129.227.109/ => http://10.129.227.109/login
200      GET      137l      303w        0c http://10.129.227.109/reset
[####################] - 10m    86006/86006   0s      found:8       errors:1
[####################] - 10m    86006/86006   141/s   http://10.129.227.109
```

### Username Enumeration

Whenever an invalid username is submitted through the form at `/reset`, the web application responds with `Invalid Username`.

![](images/Pasted%20image%2020220907185958.png)

Assuming it doesn't respond this way to a valid username, it should be possible to enumerate valid usernames. Submitting `admin` indicates that `admin` is indeed a valid username.

![](images/Pasted%20image%2020220907190050.png)

Submitting a valid username results in the generation of a four-digit PIN that is apparently emailed to the target user. Four digits is easy enough to brute force.

