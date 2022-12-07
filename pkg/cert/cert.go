package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const certificateBlockType = "CERTIFICATE"

type Certificates []Certificate

func (c Certificates) RemoveExpired() Certificates {
	var out Certificates
	for i := range c {
		if !c[i].IsExpired() {
			out = append(out, c[i])
		}
	}
	return out
}

type Certificate struct {
	// position of certificate in the chain, starts with 1
	Position        int
	X509Certificate *x509.Certificate
	Error           error
}

func FromX509Certificates(cs []*x509.Certificate) Certificates {

	var certificates Certificates
	for i, c := range cs {
		certificates = append(certificates, Certificate{Position: i, X509Certificate: c})
	}
	return certificates
}

// FromBytes converts raw certificate bytes to certificate, if the supplied data is cert bundle (or chain)
// all the certificates will be returned
func FromBytes(data []byte) (Certificates, error) {

	var block *pem.Block
	var certificates Certificates
	var i int
	for {
		i++
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("cannot find any PEM block")
		}
		certificates = append(certificates, fromPemBlock(i, block))
		if len(data) == 0 {
			break
		}
	}
	return certificates, nil
}

func fromPemBlock(position int, block *pem.Block) Certificate {

	if block.Type != certificateBlockType {
		return Certificate{Position: position, Error: fmt.Errorf("cannot parse %s block", block.Type)}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{Position: position, Error: err}
	}
	return Certificate{Position: position, X509Certificate: certificate}
}

func (c Certificate) IsExpired() bool {

	if c.Error != nil {
		return false
	}
	return time.Now().After(c.X509Certificate.NotAfter)
}

func (c Certificate) ToPEM() []byte {

	if c.Error != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  certificateBlockType,
		Bytes: c.X509Certificate.Raw,
	})
}

func (c Certificate) String() string {

	if c.Error != nil {
		return fmt.Sprintf("ERROR: block at position %d: %v", c.Position, c.Error)
	}

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
