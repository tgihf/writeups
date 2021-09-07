# [Lab 2: Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page)

---

## Description

This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the `SECRET_KEY` environment variable.

---

## Solution

View the source of the home page and note the HTML comment containing a URL to `phpinfo.php`.

```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

Navigate to the `/cgi-bin/phpinfo.php` and note the `SECRET_KEY` environment variable.

![](images/Pasted%20image%2020210907155217.png)

Submit the value to complete the challenge.


