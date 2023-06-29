## Todos

- [x] Anoymous access
- [ ] Credentialed access

## Anonymous Access

```bash
$ smbmap -P 445 -H 10.129.251.212
[!] Authentication error on 10.129.251.212
```

```bash
$ smbmap -u "guest" -p "" -P 445 -H 10.129.251.212
[!] Authentication error on 10.129.251.212
```
