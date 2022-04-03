## Port 80 Enumeration

### Virtual Host Enumeration

The vast majority of virtual hosts return 302s. [Filtering those away](https://gist.github.com/tgihf/4c8f510ba18c392aa9a849549a048a8c) yields 200s with the same response size for `monitor`, `monitoring`, and `Monitor`. Add these to the local DNS resolver.

TODO: check these out. Are they the same? Does Apache just route anything with the case-insensitive prefix `monitor*` to this application? Yes, the all seem to be the same [Zabbix](https://www.zabbix.com/) login page.

```bash
$ gobuster vhost -u http://shibboleth.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt > vhosts.txt
$ gobuster-vhost-to-json --file vhosts.txt | jq '.[] | select(.status != 302)'
{
  "hostname": "monitor.shibboleth.htb",
  "status": 200,
  "size": 3689
}
{
  "hostname": "monitoring.shibboleth.htb",
  "status": 200,
  "size": 3689
}
{
  "hostname": "Monitor.shibboleth.htb",
  "status": 200,
  "size": 3689
}
```
