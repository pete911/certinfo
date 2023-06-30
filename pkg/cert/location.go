package cert

import (
	"bytes"
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

func (c CertificateLocations) RemoveDuplicates() CertificateLocations {
	var out CertificateLocations
	for i := range c {
		out = append(out, c[i].RemoveDuplicates())
	}
	return out
}

type CertificateLocation struct {
	TLSVersion     uint16 // only applicable for network certificates
	Path           string
	Certificates   Certificates
	VerifiedChains []Certificates // only applicable for network certificates
}

func (c CertificateLocation) Name() string {
	return nameFormat(c.Path, c.TLSVersion)
}

func (c CertificateLocation) RemoveExpired() CertificateLocation {
	c.Certificates = c.Certificates.RemoveExpired()
	return c
}

func (c CertificateLocation) RemoveDuplicates() CertificateLocation {
	c.Certificates = c.Certificates.RemoveDuplicates()
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

	certificates, err := FromBytes(bytes.TrimSpace(data))
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", fileName, err)
	}

	return CertificateLocation{
		Path:         fileName,
		Certificates: certificates,
	}, nil
}

func nameFormat(name string, tlsVersion uint16) string {

	if tlsVersion == 0 {
		return name
	}
	return fmt.Sprintf("%s %s", name, tlsFormat(tlsVersion))
}

func tlsFormat(tlsVersion uint16) string {

	switch tlsVersion {
	case 0:
		return ""
	case tls.VersionSSL30:
		return "SSLv3 - Deprecated!"
	case tls.VersionTLS10:
		return "TLS 1.0 - Deprecated!"
	case tls.VersionTLS11:
		return "TLS 1.1 - Deprecated!"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS Version %d (unknown)", tlsVersion)
	}
}
