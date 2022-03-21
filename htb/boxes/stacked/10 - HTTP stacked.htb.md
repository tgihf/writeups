## `http://stacked.htb`

A countdown page for STACKED.HTB. There's a form for submitting an email address to be notified when "it's" ready, but it doesn't do anything. The website feels fairly static.

### Content Discovery

Nothing significant here.

```bash
$ feroxbuster -u http://stacked.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stacked.htb
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
301      GET        9l       28w      307c http://stacked.htb/js => http://stacked.htb/js/
301      GET        9l       28w      311c http://stacked.htb/images => http://stacked.htb/images/
301      GET        9l       28w      310c http://stacked.htb/fonts => http://stacked.htb/fonts/
301      GET        9l       28w      308c http://stacked.htb/css => http://stacked.htb/css/
403      GET        9l       28w      276c http://stacked.htb/server-status
[####################] - 1m    149995/149995  0s      found:5       errors:43
[####################] - 1m     29999/29999   412/s   http://stacked.htb
[####################] - 1m     29999/29999   418/s   http://stacked.htb/js
[####################] - 1m     29999/29999   427/s   http://stacked.htb/images
[####################] - 1m     29999/29999   437/s   http://stacked.htb/fonts
[####################] - 1m     29999/29999   448/s   http://stacked.htb/css
```

### Virtual Host Discovery

Almost all virtual hosts return a 302 redirect. Use [this gist](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) to convert the `gobuster vhost` output into a JSON list and filter away all virtual hosts that return 302s, leaving `portfolio.stacked.htb`. Add this hostname to the local DNS resolver.

```bash
$ gobuster vhost -u http://stacked.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt > vhosts.txt
$ python3 gobuster-vhost-to-json.py --file vhosts.txt | jq '.[] | select(.status != 302)'
{
  "hostname": "portfolio.stacked.htb",
  "status": 200,
  "size": 30268
}
```

