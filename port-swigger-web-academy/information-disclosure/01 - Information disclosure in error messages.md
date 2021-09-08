# [Lab 1: Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages)

---

## Description

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

---

## Solution

The objective of this lab is to induce an error state, causing the web application to render a verbose error message that will indicate the version number of the backend web application framework.

Note that the URL of the product page is `/product?productId=$PRODUCT_ID`, where `$PRODUCT_ID` is an integer. Attempt to navigate to a product page with a `productId` that is a string, such as `/product?productId=blah`.

![](images/Pasted%20image%2020210903201927.png)

This triggers a verbose error message that indicates the backend web application framework is `Apache Struts 2 2.3.31`.

Submit this string to complete the challenge.
