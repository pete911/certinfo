package cert

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const tlsDialTimeout = 5 * time.Second

type CertificateLocations []CertificateLocation

func (c CertificateLocations) RemoveExpired() CertificateLocations {
	var out CertificateLocations
	for i := range c {
		out = append(out, c[i].RemoveExpired())
	}
	return out
}

type CertificateLocation struct {
	TLSVersion     uint16 // only applicable for network certificates
	Path           string
	Certificates   Certificates
	VerifiedChains []Certificates // only applicable for network certificates
}

func (c CertificateLocation) RemoveExpired() CertificateLocation {
	c.Certificates = c.Certificates.RemoveExpired()
	return c
}

func LoadCertificatesFromNetwork(addr string, tlsSkipVerify bool) (CertificateLocation, error) {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: tlsDialTimeout}, "tcp", addr, &tls.Config{InsecureSkipVerify: tlsSkipVerify})
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("tcp connection failed: %w", err)
	}

	connectionState := conn.ConnectionState()
	x509Certificates := connectionState.PeerCertificates

	var verifiedChains []Certificates
	for _, chain := range connectionState.VerifiedChains {
		verifiedChains = append(verifiedChains, FromX509Certificates(chain))
	}

	return CertificateLocation{
		TLSVersion:     conn.ConnectionState().Version,
		Path:           addr,
		Certificates:   FromX509Certificates(x509Certificates),
		VerifiedChains: verifiedChains,
	}, nil
}

func LoadCertificatesFromFile(fileName string) (CertificateLocation, error) {

	b, err := os.ReadFile(fileName)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("skipping %s file: %w", fileName, err)
	}
	return loadCertificate(fileName, b)
}

func LoadCertificateFromStdin() (CertificateLocation, error) {

	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("reading stdin: %w", err)
	}
	return loadCertificate("stdin", content)
}

func loadCertificate(fileName string, data []byte) (CertificateLocation, error) {

	certificates, err := FromBytes(data)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", fileName, err)
	}

	return CertificateLocation{
		Path:         fileName,
		Certificates: certificates,
	}, nil
}
