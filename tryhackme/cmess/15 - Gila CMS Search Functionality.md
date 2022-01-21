# Gila CMS Search Functionality

There is a search bar on the main page of the web application that appears to search through the existing blog entries. Searching for "hello" sends the following `GET` request.

```http
GET /?search=hello HTTP/1.1
Host: cmess.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://cmess.thm/?search=blah
Upgrade-Insecure-Requests: 1
```

This request returns the "Hello World" blog post.

![](images/Pasted%20image%2020220121175723.png)

However, submitting a request with a random query string returns nothing.

![](images/Pasted%20image%2020220121175806.png)

This indicates that the search functionality is likely interacting with a backend database to dynamically retrieve the blog post whose title contains the query string. If the database is a SQL database, perhaps it is using a query like the following:

```sql
SELECT * FROM posts WHERE name LIKE '%$QUERY%';
```

```sql
SELECT * FROM posts WHERE CONTAINS(name, '$QUERY');
```
