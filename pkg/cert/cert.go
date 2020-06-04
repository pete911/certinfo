package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const certificateType = "CERTIFICATE"

// format for NotBefore and NotAfter fields to make output similar to openssl
var validityFormat = "Jan _2 15:04:05 2006 MST"

type Certificates []Certificate

type Certificate struct {
	Version            int
	SerialNumber       *big.Int
	SignatureAlgorithm string
	Issuer             DN
	NotBefore          time.Time
	NotAfter           time.Time
	Subject            DN
	DNSNames           []string
	IPAddresses        []net.IP
	PEMCertificate     []byte
}

func (c Certificate) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

func (c Certificate) IsExpiredAt(t time.Time) bool {
	return t.After(c.NotAfter)
}

func (c Certificate) String() string {

	dnsNames := strings.Join(c.DNSNames, ", ")

	var ips []string
	for _, ip := range c.IPAddresses {
		ips = append(ips, fmt.Sprintf("%s", ip))
	}
	ipAddresses := strings.Join(ips, ", ")

	return strings.Join([]string{
		fmt.Sprintf("Version: %d", c.Version),
		fmt.Sprintf("Serial Number: %d", c.SerialNumber),
		fmt.Sprintf("Signature Algorithm: %s", c.SignatureAlgorithm),
		fmt.Sprintf("Issuer: %s", c.Issuer),
		fmt.Sprintf("Validity\n    Not Before: %s\n    Not After : %s", ValidityFormat(c.NotBefore), ValidityFormat(c.NotAfter)),
		fmt.Sprintf("Subject: %s", c.Subject),
		fmt.Sprintf("DNS Names: %s", dnsNames),
		fmt.Sprintf("IP Addresses: %s", ipAddresses),
	}, "\n")
}

func ValidityFormat(t time.Time) string {
	return t.Format(validityFormat)
}

type DN struct {
	Organization []string
	CommonName   string
}

func (dn DN) String() string {

	var fields []string
	if len(dn.Organization) != 0 {
		fields = append(fields, fmt.Sprintf("O=%s", strings.Join(dn.Organization, ", ")))
	}
	if dn.CommonName != "" {
		fields = append(fields, fmt.Sprintf("CN=%s", dn.CommonName))
	}
	return strings.Join(fields, " ")
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
		certificates = append(
			certificates,
			Certificate{
				Version:            c.Version,
				SerialNumber:       c.SerialNumber,
				SignatureAlgorithm: c.SignatureAlgorithm.String(),
				Issuer: DN{
					Organization: c.Issuer.Organization,
					CommonName:   c.Issuer.CommonName,
				},
				NotAfter:  c.NotAfter,
				NotBefore: c.NotBefore,
				Subject: DN{
					Organization: c.Subject.Organization,
					CommonName:   c.Subject.CommonName,
				},
				DNSNames:       c.DNSNames,
				IPAddresses:    c.IPAddresses,
				PEMCertificate: EncodeCertificatePEM(c),
			},
		)
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
