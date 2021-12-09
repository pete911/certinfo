package cert

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
)

const tlsDialTimeout = 5 * time.Second

type CertificateLocation struct {
	TLSVersion     uint16 // only applicable for network certificates
	Path           string
	Certificates   Certificates
	VerifiedChains []Certificates // only applicable for network certificates
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

	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("skipping %s file: %w", fileName, err)
	}
	return loadCertificate(fileName, b)
}

func LoadCertificateFromStdin() (CertificateLocation, error) {

	content, err := ioutil.ReadAll(os.Stdin)
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
