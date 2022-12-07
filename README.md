# print x509 certificate info

Similar to `openssl x509 -in <file> -text` command, but handles chains, multiple files and TCP addresses. TLS/SSL
version prints as well when using TCP address argument.

If one (or more) of the supplied certificates are malformed, the rest is still parsed and printed. There is additional
log at the beginning of the output in this case, to show which block is malformed.

## usage

```shell script
certinfo [flags] [<file>|<host:port> ...]
```

**file** argument can be:
 - **local file path** `certinfo <filename>`
 - **TCP network address** `certinfo <host:port>` e.g. `certinfo google.com:443`
 - **stdin** `echo "<cert-content>" | certinfo`

```
+---------------------------------------------------------------------------------------------------------------+
| optional flags                                                                                                |
+-----------+---------------------------------------------------------------------------------------------------+
| -chains   | whether to print verified chains as well (only applicable for host)                               |
| -expiry   | print expiry of certificates                                                                      |
| -insecure | whether a client verifies the server's certificate chain and host name (only applicable for host) |
| -pem      | whether to print pem as well                                                                      |
| -pem-only | whether to print only pem (useful for downloading certs from host)                                |
| -version  | certinfo version                                                                                  |
| -help     | help                                                                                              |
+-----------+---------------------------------------------------------------------------------------------------+
```

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

### info/verbose

`certinfo vault.com:443`
```
--- [vault.com:443 TLS 1.2] ---
Version: 3
Serial Number: 15424177460318123999
Signature Algorithm: SHA256-RSA
Type: end-entity
Issuer: CN=Go Daddy Secure Certificate Authority - G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
Validity
    Not Before: Apr  8 05:28:12 2020 UTC
    Not After : Apr 17 02:03:38 2022 UTC
Subject: CN=*.vault.com,OU=Domain Control Validated
DNS Names: *.vault.com, vault.com
IP Addresses:
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
Key Usage: Cert Sign, CRL Sign
Ext Key Usage:
CA: true
```

### info/expiry

`certinfo -expiry google.com:443`
```
--- [google.com:443 TLS 1.3] ---
Subject: CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
Expiry: 2 months 5 days 6 hours 56 minutes

Subject: CN=GTS CA 1O1,O=Google Trust Services,C=US
Expiry: 1 years 1 months 7 days 12 hours 54 minutes
```

### local root certs

- linux `ls -d /etc/ssl/certs/* | grep '.pem' | xargs certinfo -expiry`
- mac `cat /etc/ssl/cert.pem | certinfo -expiry`
