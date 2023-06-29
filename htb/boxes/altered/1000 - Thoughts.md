# Thoughts

- What's the purpose of `/test`? To indicate `ippsec` as a valid username?
- From `/test`, `ippsec` appears to be a valid username. However, submitting it to `/reset` indicates it is not a valid username.
- Can the password reset mechanism be used to enumerate users?
	- `admin` appears to be a valid user
- How does the password reset mechanism work?
	- "Emails" a four digit PIN to the user
	- Submission of the PIN results in a `POST` request to `/api/resettoken`
		- [ ] Brute force 4-digit PINs

