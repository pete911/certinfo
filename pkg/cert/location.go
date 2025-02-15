package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
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

func (c CertificateLocations) SubjectLike(subject string) CertificateLocations {
	var out CertificateLocations
	for i := range c {
		out = append(out, c[i].SubjectLike(subject))
	}
	return out
}

func (c CertificateLocations) IssuerLike(issuer string) CertificateLocations {
	var out CertificateLocations
	for i := range c {
		out = append(out, c[i].IssuerLike(issuer))
	}
	return out
}

func (c CertificateLocations) SortByExpiry() CertificateLocations {
	var out CertificateLocations
	// sort certificates in every location
	for i := range c {
		out = append(out, c[i].SortByExpiry())
	}

	// sort locations by first certificate (they have been already sorted)
	slices.SortFunc(out, func(a, b CertificateLocation) int {
		if len(a.Certificates) == 0 && len(b.Certificates) == 0 {
			return 0
		}
		if len(a.Certificates) == 0 {
			return 1
		}
		if len(b.Certificates) == 0 {
			return -1
		}
		return a.Certificates[0].x509Certificate.NotAfter.Compare(b.Certificates[0].x509Certificate.NotAfter)
	})
	return out
}

type CertificateLocation struct {
	TLSVersion   uint16 // only applicable for network certificates
	Path         string
	Error        error
	Certificates Certificates
}

func (c CertificateLocation) Chains() ([]Certificates, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	// we are not verifying time and dns, because we want to work with -insecure flag as well
	// just to see what local chains are used for verification
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range c.Certificates {
		// do not just use index (index 0 leaf/end-entity, rest intermediate) like connection,
		// because we can deal with certs from a bundle file
		if cert.Type() == "intermediate" {
			opts.Intermediates.AddCert(cert.x509Certificate)
		}
	}

	var verifiedChains []Certificates
	for _, cert := range c.Certificates {
		if cert.Type() == "end-entity" {
			chains, err := cert.x509Certificate.Verify(opts)
			if err != nil {
				return nil, err
			}
			for _, chain := range chains {
				verifiedChains = append(verifiedChains, FromX509Certificates(chain))
			}
		}
	}
	return verifiedChains, nil
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

func (c CertificateLocation) SubjectLike(subject string) CertificateLocation {
	c.Certificates = c.Certificates.SubjectLike(subject)
	return c
}

func (c CertificateLocation) IssuerLike(issuer string) CertificateLocation {
	c.Certificates = c.Certificates.IssuerLike(issuer)
	return c
}

func (c CertificateLocation) SortByExpiry() CertificateLocation {
	c.Certificates = c.Certificates.SortByExpiry()
	return c
}

func LoadCertificatesFromNetwork(addr string, serverName string, tlsSkipVerify bool) CertificateLocation {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: tlsDialTimeout}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: tlsSkipVerify,
		ServerName:         serverName,
	})
	if err != nil {
		slog.Error(fmt.Sprintf("load certificate from network %s: %v", addr, err.Error()))
		return CertificateLocation{Path: addr, Error: err}
	}

	connectionState := conn.ConnectionState()
	x509Certificates := connectionState.PeerCertificates

	return CertificateLocation{
		TLSVersion:   conn.ConnectionState().Version,
		Path:         addr,
		Certificates: FromX509Certificates(x509Certificates),
	}
}

func LoadCertificatesFromFile(fileName string) CertificateLocation {

	b, err := os.ReadFile(fileName)
	if err != nil {
		slog.Error(fmt.Sprintf("load certificate from file %s: %v", fileName, err.Error()))
		return CertificateLocation{Path: fileName, Error: err}
	}
	return loadCertificate(fileName, b)
}

func LoadCertificateFromStdin() CertificateLocation {

	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		slog.Error(fmt.Sprintf("load certificate from stdin: %v", err.Error()))
		return CertificateLocation{Path: "stdin", Error: err}
	}
	return loadCertificate("stdin", content)
}

func loadCertificate(fileName string, data []byte) CertificateLocation {

	certificates, err := FromBytes(bytes.TrimSpace(data))
	if err != nil {
		slog.Error(fmt.Sprintf("parse certificate %s bytes: %v", fileName, err.Error()))
		return CertificateLocation{Path: fileName, Error: err}
	}

	return CertificateLocation{
		Path:         fileName,
		Certificates: certificates,
	}
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
