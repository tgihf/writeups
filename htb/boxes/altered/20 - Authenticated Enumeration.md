## Authenticated Enumeration

```bash
$ feroxbuster -u http://10.129.227.109 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -n -b 'laravel_session=' -b 'XSRF-TOKEN=' --json --output feroxbuster-root-authenticated

```

```bash
$ feroxbuster -u http://10.129.227.109 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -n -b 'laravel_session=eyJpdiI6IkYwTlFCUk5PWDJnMnE5QmFHNTU1NkE9PSIsInZhbHVlIjoiMjM0K3NpVWYzYTRVaWdXOGVIbzdVa2xyVWRKVi9yT1krayt3ZjJ0ZWgxejd4RDYyS1h5MFBiOWNrTlFSMUgvcTBxMnFGREp2UFZ3SlRWRlpzSjhWMitmV2JuUHVobkFaNzNjTG1iZWlyeTU0QlNTS3BkMm9jWGsrK0ZYM3k3TDciLCJtYWMiOiIxZDVjYjRkNDU4ZGM1ODZkYWNiZjNkOGU0ZWQxOTk5NjJiMjNjMDdlMDA3YWJmMDUwYzEyNTRhNWRhZTRkZWI5IiwidGFnIjoiIn0%3D' -b 'XSRF-TOKEN=eyJpdiI6Im9PM2M4anlKSVYrOWwzOXlwUWZjb3c9PSIsInZhbHVlIjoiYXAwUW1icmloWmdLVzl0M241Nkc3VzJqWGZNV1BEN1g3ZUFiWmIzamZJWmowWk9jaEZDNXFqandTZStHZWEwVlVmNk1SMnRkWVNwbFU4dXVTWElJWkJDWGtmRThIdjFsRWYxRnRDcXJ6a0JNY1VNTXdvTTUxclV1ZDlzUDFscXgiLCJtYWMiOiJlZDBlNDc3MzY3NGRlY2Y4YzRiZDg3MDQ4NGFiZmE4MjAxN2I1YzIxNjcxY2Y1MmY4YzU1MGI1Y2MwY2Q3MzlkIiwidGFnIjoiIn0%3D' --json --output feroxbuster-root-authenticated

```

`/` contains JavaScript that leaks the API endpoint `/api/getprofile`.

```javascript
function getBio(id,secret) {
        $.ajax({
            type: "GET",
            url: 'api/getprofile',
            data: {
                id: id,
                secret: secret
            },
            success: function(data)
            {
                document.getElementById('alert').style.visibility = 'visible';
                document.getElementById('alert').innerHTML = data;
            }

        });
    }

$(document).ready(function() {

    $('#GetBio').click(function(event){
        event.preventDefault();
        alert("tesT");
        $("#alert").html("data");
    });
  
  $('#loginform').submit(function() {

      $.ajax({
          type: "GET",
          url: 'api/getprofile',
          data: {
              password: $("#password").val()
          },
          success: function(data)
          {
            document.getElementById('alert').style.visibility = 'visible';
            document.getElementById('alert').innerHTML = data;
          }
      });     
      return false; 
  });
});
```
