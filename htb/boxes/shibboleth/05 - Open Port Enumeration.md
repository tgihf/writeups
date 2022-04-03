## Open Port Enumeration

### TCP

The target's TCP port 80 is open.

```bash
$ sudo masscan -p1-65535 --rate=1000 -e tun0 --output-format grepable --output-filename enum/shibboleth.masscan 10.129.123.64
$ cat enum/shibboleth.masscan  | grep open | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ','
80,
```

Apache 2.4.41 is running on port 80. It redirects to `http://shibboleth.htb`. Add this hostname to the local DNS resolver.

```bash
$ nmap -sC -sV -p80 10.129.123.64 -oA enum/shibboleth
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-02 23:11 EDT
Nmap scan report for 10.129.123.64
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://shibboleth.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

### UDP

The target's UDP port 623 (MCP) is open.

```bash
$ sudo nmap -sU 10.129.123.122
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-03 15:41 EDT
Nmap scan report for shibboleth.htb (10.129.123.122)
Host is up (0.049s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp

Nmap done: 1 IP address (1 host up) scanned in 1004.35 seconds
```
