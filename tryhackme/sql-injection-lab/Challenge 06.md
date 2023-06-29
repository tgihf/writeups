# Challenge 6 - Vulnerable Startup: Broken Authentication

![Pasted image 20210804155310](Pasted%20image%2020210804155310.png)

The goal of this challenge is to find a way to bypass the authentication to retrieve the flag.

The challenge is a simple login form that takes in string parameters `username` and `password` and submits them in the body of an HTTP POST request to `/challenge1/login`, presumably with the following backend SQL query:

```sql
SELECT username FROM $USERS_TABLE WHERE username = '$USERNAME' AND password = '$PASSWORD_HASH'
```

If the above is the backend SQL query, the following injection should bypass the form and result in authentication:

```txt
' OR 1=1--
```