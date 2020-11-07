package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const certificateType = "CERTIFICATE"

type Certificates []Certificate

type Certificate struct {
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

// converts raw certificate bytes to certificate, if the supplied data is cert bundle (or chain)
// all the certificates will be returned
func FromBytes(data []byte) (Certificates, error) {

	cs, err := DecodeCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	return FromX509Certificates(cs), nil
}

func FromX509Certificates(cs []*x509.Certificate) Certificates {

	var certificates Certificates
	for _, c := range cs {
		certificates = append(certificates, Certificate{X509Certificate: c})
	}
	return certificates
}

func IsCertificatePEM(data []byte) error {

	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type == certificateType {
			return nil
		}
		return fmt.Errorf("%s type", block.Type)
	}
	return errors.New("certificate does not have any block/preamble specified")
}

func DecodeCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var block *pem.Block
	var decodedCerts []byte
	for {
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("failed to parse certificate PEM")
		}
		// append only certificates
		if block.Type == certificateType {
			decodedCerts = append(decodedCerts, block.Bytes...)
		}
		if len(data) == 0 {
			break
		}
	}
	return x509.ParseCertificates(decodedCerts)
}

func EncodeCertificatesPEM(certificates []*x509.Certificate) []byte {

	var out []byte
	for _, certificate := range certificates {
		b := EncodeCertificatePEM(certificate)
		out = append(out, b...)
	}
	return out
}

func EncodeCertificatePEM(certificate *x509.Certificate) []byte {

	return pem.EncodeToMemory(&pem.Block{
		Type:  certificateType,
		Bytes: certificate.Raw,
	})
}
