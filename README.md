[![Build Status](https://travis-ci.com/pete911/certinfo.svg?branch=master)](https://travis-ci.com/pete911/certinfo)

# print x509 certificate info

Similar to `openssl x509 -in <file> -text` command, but handles chains, multiple files and TCP addresses. TLS/SSL
version prints as well when using TCP address argument.

## usage

**file** argument can be either **local file path** or **TCP network address**
(`<host:port>` e.g. `google.com:443`)

 - info verbose `certinfo <file|host:port> [file|host:port] [...]`
 - info expiry `certinfo -expiry <file|host:port> [file|host:port] [...]`

Expiry flag can be set as env. variable as well (`CERTINFO_EXPIRY=true`) and can be then overridden with
`-expiry=false` flag.

## download

 - [binary](https://github.com/pete911/certinfo/releases)
 - [docker](https://hub.docker.com/repository/docker/pete911/certinfo)

## build/install

## go

[go](https://golang.org/dl/) has to be installed.
 - build `make build`
 - install `make install`

## docker

[docker](https://www.docker.com/products/docker-desktop) has to be installed.
 - build `make image`
 - run `docker run -it --rm pete911/certinfo:dev <file|host:port>`

## examples

### info/verbose

`certinfo vault.com:443`
```
--- [vault.com:443 TLS 1.2] ---
Version: 3
Serial Number: 15424177460318123999
Signature Algorithm: SHA256-RSA
Issuer: O=GoDaddy.com, Inc. CN=Go Daddy Secure Certificate Authority - G2
Validity
    Not Before: Apr  8 05:28:12 2020 UTC
    Not After : Apr 17 02:03:38 2022 UTC
Subject: CN=*.vault.com
DNS Names: *.vault.com, vault.com
IP Addresses:

Version: 3
Serial Number: 7
Signature Algorithm: SHA256-RSA
Issuer: O=GoDaddy.com, Inc. CN=Go Daddy Root Certificate Authority - G2
Validity
    Not Before: May  3 07:00:00 2011 UTC
    Not After : May  3 07:00:00 2031 UTC
Subject: O=GoDaddy.com, Inc. CN=Go Daddy Secure Certificate Authority - G2
DNS Names:
IP Addresses:

Version: 3
Serial Number: 1828629
Signature Algorithm: SHA256-RSA
Issuer: O=The Go Daddy Group, Inc.
Validity
    Not Before: Jan  1 07:00:00 2014 UTC
    Not After : May 30 07:00:00 2031 UTC
Subject: O=GoDaddy.com, Inc. CN=Go Daddy Root Certificate Authority - G2
DNS Names:
IP Addresses:
```

### info/expiry

`certinfo -expiry google.com:443`
```
--- [google.com:443 TLS 1.3] ---
Subject: O=Google LLC CN=*.google.com
Expiry: 1 months 26 days 13 hours 14 minutes

Subject: O=Google Trust Services CN=GTS CA 1O1
Expiry: 1 years 6 months 13 days 3 hours 52 minutes
```