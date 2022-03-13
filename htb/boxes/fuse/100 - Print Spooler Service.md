## Print Spooler Service

The target is serving the Print Spooler service. TODO: if you get a credential, the printer bug or Print Nightmare might work.

```bash
$ impacket-rpcdump 10.129.2.5 | grep MS-RPRN -A 6
Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
          ncacn_ip_tcp:10.129.2.5[49679]
          ncalrpc:[LRPC-f95f1cbda631ee34e1]
```
