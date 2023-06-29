## Port 80 Enumeration

### `/`

The landing page at `/` indicates two things of interest about `upcloud`:

1. No authentication required to upload and download files
2. The product is open source

### `/download`

This path yields an archive which contains the `upcloud` Docker container, which contains the application's source code.

### `/upcloud`

The server's **upload** feature is found at this path.

### `/console`

The [Werkzeug Interactive Debugger](https://werkzeug.palletsprojects.com/en/2.2.x/debug/), protected by a PIN. This indicates the application is running in debug mode.

### Content Discovery

```bash
$ feroxbuster -u http://10.129.46.240

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.46.240
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET     9803l    56722w  2489147c http://10.129.46.240/download
200      GET       45l      144w     1563c http://10.129.46.240/console
[####################] - 1m     29999/29999   0s      found:2       errors:0
[####################] - 1m     29999/29999   345/s   http://10.129.46.240
```

### Virtual Host Discovery

TODO
