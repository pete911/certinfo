package cert

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

type Certificate struct {
	// position of certificate in the chain, starts with 0
	Index           int
	X509Certificate *x509.Certificate
}

func (c Certificate) IsExpired() bool {
	return time.Now().After(c.X509Certificate.NotAfter)
}

func (c Certificate) IsExpiredAt(t time.Time) bool {
	return t.After(c.X509Certificate.NotAfter)
}

func (c Certificate) String() string {

	dnsNames := strings.Join(c.X509Certificate.DNSNames, ", ")

	var ips []string
	for _, ip := range c.X509Certificate.IPAddresses {
		ips = append(ips, fmt.Sprintf("%s", ip))
	}
	ipAddresses := strings.Join(ips, ", ")

	keyUsage := KeyUsageToString(c.X509Certificate.KeyUsage)
	extKeyUsage := ExtKeyUsageToString(c.X509Certificate.ExtKeyUsage)

	return strings.Join([]string{
		fmt.Sprintf("Version: %d", c.X509Certificate.Version),
		fmt.Sprintf("Serial Number: %d", c.X509Certificate.SerialNumber),
		fmt.Sprintf("Signature Algorithm: %s", c.X509Certificate.SignatureAlgorithm),
		fmt.Sprintf("Type: %s", CertificateType(c.X509Certificate)),
		fmt.Sprintf("Issuer: %s", c.X509Certificate.Issuer),
		fmt.Sprintf("Validity\n    Not Before: %s\n    Not After : %s",
			ValidityFormat(c.X509Certificate.NotBefore),
			ValidityFormat(c.X509Certificate.NotAfter)),
		fmt.Sprintf("Subject: %s", c.X509Certificate.Subject),
		fmt.Sprintf("DNS Names: %s", dnsNames),
		fmt.Sprintf("IP Addresses: %s", ipAddresses),
		fmt.Sprintf("Key Usage: %s", strings.Join(keyUsage, ", ")),
		fmt.Sprintf("Ext Key Usage: %s", strings.Join(extKeyUsage, ", ")),
		fmt.Sprintf("CA: %t", c.X509Certificate.IsCA),
	}, "\n")
}
