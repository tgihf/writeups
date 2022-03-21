## HTTPS Docker Endpoint

This is likely running the LocalStack Docker container.

Attempting to interact with the endpoint results in `curl` "bad certificate" errors. According to [this ServerFault post](https://serverfault.com/questions/806141/is-the-alert-ssl3-read-bytessslv3-alert-bad-certificate-indicating-that-the-s), this particular error indicates the server is requiring mutual authentication. Since a client certificate wasn't presented, the TLS handshake failed.

See [here](https://docs.docker.com/engine/security/protect-access/#use-tls-https-to-protect-the-docker-daemon-socket) for Docker's documentation on setting up mutual TLS.

```bash
$ curl --insecure https://stacked.htb:2376/containers/json -v
*   Trying 10.129.140.39:2376...
* Connected to stacked.htb (10.129.140.39) port 2376 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Certificate (11):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=0.0.0.0
*  start date: Jul 17 15:37:02 2021 GMT
*  expire date: Jul 17 15:37:02 2022 GMT
*  issuer: C=UK; ST=Some State; L=Some City; O=Stacked; OU=Some Section; CN=stacked; emailAddress=support@stacked.htb
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
> GET /containers/json HTTP/1.1
> Host: stacked.htb:2376
> User-Agent: curl/7.74.0
> Accept: */*
>
* TLSv1.3 (IN), TLS alert, bad certificate (554):
* OpenSSL SSL_read: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate, errno 0
* Closing connection 0
curl: (56) OpenSSL SSL_read: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate, errno 0
```
