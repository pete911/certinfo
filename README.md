# print x509 certificate info

[![pipeline](https://github.com/pete911/certinfo/actions/workflows/pipeline.yml/badge.svg)](https://github.com/pete911/certinfo/actions/workflows/pipeline.yml)

Similar to `openssl x509 -in <file> -text` command, but handles chains, multiple files and TCP addresses. TLS/SSL
version prints as well when using TCP address argument.

## usage

```shell script
certinfo [flags] [<file>|<host:port> ...]
```

**file** argument can be:
 - **local file path** `certinfo <filename>`
 - **TCP network address** `certinfo <host:port>` e.g. `certinfo google.com:443`
 - **stdin** `echo "<cert-content>" | certinfo`

```
+-------------------------------------------------------------------------------------------------------------------+
| optional flags                                                                                                    |
+---------------+---------------------------------------------------------------------------------------------------+
| -chains       | whether to print verified chains as well                                                          |
| -expiry       | print expiry of certificates                                                                      |
| -extensions   | whether to print extensions                                                                       |
| -insecure     | whether a client verifies the server's certificate chain and host name (only applicable for host) |
| -issuer-like  | print certificates with subject field containing supplied string                                  |
| -no-duplicate | do not print duplicate certificates                                                               |
| -no-expired   | do not print expired certificates                                                                 |
| -pem          | whether to print pem as well                                                                      |
| -pem-only     | whether to print only pem (useful for downloading certs from host)                                |
| -server-name  | verify the hostname on the returned certificates, useful for testing SNI                          |
| -sort-expiry  | sort certificates by expiration date                                                              |
| -subject-like | print certificates with issuer field containing supplied string                                   |
| -version      | certinfo version                                                                                  |
| -help         | help                                                                                              |
+---------------+---------------------------------------------------------------------------------------------------+
```

If you need to run against multiple hosts, it is faster to execute command with multiple arguments e.g.
`certinfo -insecure -expiry google.com:443 amazon.com:443 ...` rather than executing command multiple times. Args are
executed concurrently and much faster.

Flags can be set as env. variable as well (`CERTINFO_<FLAG>=true` e.g. `CERTINFO_INSECURE=true`) and can be then
overridden with a flag.

## download

 - [binary](https://github.com/pete911/certinfo/releases)

## build/install

### brew

- add tap `brew tap pete911/tap`
- install `brew install certinfo`

### go

[go](https://golang.org/dl/) has to be installed.
 - build `make build`
 - install `make install`

## release

Releases are published when the new tag is created e.g.
`git tag -m "add super cool feature" v1.0.0 && git push --follow-tags`

## examples

### remove expired and malformed certs

- `--pem-only` flag returns only pem blocks that can be parsed and are type of certificate
- `--no-expired` flag removes expired certificates

`certinfo --pem-only --no-expired <chain-file>.pem > <new-chain-file>.pem`

### info/verbose

`certinfo vault.com:443`
```
--- [vault.com:443 TLS 1.2] ---
Version: 3
Serial Number: 16280914906313700456
Signature Algorithm: SHA256-RSA
Type: end-entity
Issuer: CN=Go Daddy Secure Certificate Authority - G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
Validity
    Not Before: Mar 24 10:44:12 2022 UTC
    Not After : Mar 19 13:04:10 2023 UTC
Subject: CN=*.vault.com
DNS Names: *.vault.com, vault.com
IP Addresses:
Authority Key Id: 40c2bd278ecc348330a233d7fb6cb3f0b42c80ce
Subject Key Id  : 6b8c8d1da18cbb8cd64437ed0a9c8a0fef673821
Key Usage: Digital Signature, Key Encipherment
Ext Key Usage: Server Auth, Client Auth
CA: false

Version: 3
Serial Number: 7
Signature Algorithm: SHA256-RSA
Type: intermediate
Issuer: CN=Go Daddy Root Certificate Authority - G2,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
Validity
    Not Before: May  3 07:00:00 2011 UTC
    Not After : May  3 07:00:00 2031 UTC
Subject: CN=Go Daddy Secure Certificate Authority - G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
DNS Names:
IP Addresses:
Authority Key Id: 3a9a8507106728b6eff6bd05416e20c194da0fde
Subject Key Id  : 40c2bd278ecc348330a233d7fb6cb3f0b42c80ce
Key Usage: Cert Sign, CRL Sign
Ext Key Usage:
CA: true

Version: 3
Serial Number: 1828629
Signature Algorithm: SHA256-RSA
Type: intermediate
Issuer: OU=Go Daddy Class 2 Certification Authority,O=The Go Daddy Group\, Inc.,C=US
Validity
    Not Before: Jan  1 07:00:00 2014 UTC
    Not After : May 30 07:00:00 2031 UTC
Subject: CN=Go Daddy Root Certificate Authority - G2,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
DNS Names:
IP Addresses:
Authority Key Id: d2c4b0d291d44c1171b361cb3da1fedda86ad4e3
Subject Key Id  : 3a9a8507106728b6eff6bd05416e20c194da0fde
Key Usage: Cert Sign, CRL Sign
Ext Key Usage:
CA: true

--- 1 verified chains ---
```

### info/expiry

`certinfo -expiry google.com:443`
```
--- [google.com:443 TLS 1.3] ---
Subject: CN=*.google.com
Expiry: 2 months 4 days 14 hours 41 minutes

Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
Expiry: 4 years 6 months 19 days 5 hours 29 minutes

Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
Expiry: 4 years 10 months 17 days 4 hours 29 minutes
```

### show certificate with specific subject
This example shows AWS RDS certificates for specific region (we can also see AWS started using 100 years expiration)
- show only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certinfo -issuer-like eu-west-2`
- download only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certinfo -issuer-like eu-west-2 -pem-only > rds-eu-west-2.pem`

### verify SNI certificates
Specific host can be set by `server-name` flag. This is useful if we need to verify that load balancer is correctly
using certificates for different hosts: `certinfo -server-name <host> <load-balancer|proxy>` e.g.
`certinfo -server-name tabletmag.com  cname.vercel-dns.com:443` (tabletmag certificate behind vercel).

### local root certs

- linux `ls -d /etc/ssl/certs/* | grep '.pem' | xargs certinfo -expiry`
- mac `cat /etc/ssl/cert.pem | certinfo -expiry`
