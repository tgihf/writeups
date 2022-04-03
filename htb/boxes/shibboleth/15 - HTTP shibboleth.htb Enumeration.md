## `http://shibboleth.htb`

An instance of the [FlexStart Bootstrap Template](https://bootstrapmade.com/flexstart-bootstrap-startup-template/). Seems completely static.

TODO: usernames on `/` for a potential brute force of `http://monitor.shibboleth.htb`.

### Content Discovery

The only paths discovered `/assets` and `/forms`.

```bash
$ feroxbuster -u http://shibboleth.htb --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shibboleth.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      317c http://shibboleth.htb/assets => http://shibboleth.htb/assets/
301      GET        9l       28w      316c http://shibboleth.htb/forms => http://shibboleth.htb/forms/
403      GET        9l       28w      279c http://shibboleth.htb/server-status
[####################] - 30s    29999/29999   0s      found:3       errors:7
[####################] - 30s    29999/29999   982/s   http://shibboleth.htb
```

Nothing discovered off `/forms`.

```bash
$ feroxbuster -u http://shibboleth.htb/forms --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shibboleth.htb/forms
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 30s    29999/29999   0s      found:0       errors:10
[####################] - 30s    29999/29999   989/s   http://shibboleth.htb/forms
```
