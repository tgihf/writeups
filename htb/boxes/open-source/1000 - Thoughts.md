
- [X] How can you get access to `upcloud`'s source code?
	- `/download` yields an archive which contains a Docker container which contains the application's source code
- [x] Understand `get_file_name()`
	- What is this supposed to do?
		- Remove all instances of `"../"` by replacing them with `""`
	- What does it actually do?
		- It actually appears to do just that
		- [X] However, what about unicode alternatives to `.`, like `\u2024`?
			- `"\u2024\u2024/" != "../"` and appears to bypass `get_file_name()`
				- [X] Does it work with Flask's [send_file()](https://tedboy.github.io/flask/generated/flask.send_file.html)?
					- The documentation says it expects the parameter in `latin-1` encode, which I believe would rule out this possibility
- [ ] The application has the Werkzeug Interactive Debugger enabled, which would make it trivial to execute code. However, it's protected by a PIN that will reset the application (and the PIN) if guessed too many times. Why is this here?

```python
# This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        "root", # username
        "flask.app", # modname
        "Flask", # getattr(app, "__name__", type(app).__name__),
        "/usr/local/lib/python3.10/site-packages/flask/app.py" # getattr(mod, "__file__", None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [str(uuid.getnode()), get_machine_id()]
```