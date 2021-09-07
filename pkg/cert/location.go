package cert

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
)

type CertificateLocation struct {
	TLSVersion     uint16 // only applicable for network certificates
	Path           Path
	Certificates   Certificates
	VerifiedChains []Certificates // only applicable for network certificates
}

type Path struct {
	Name    string
	Content []byte
}

func LoadCertificatesFromNetwork(addr string, tlsSkipVerify bool) (CertificateLocation, error) {

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: tlsSkipVerify})
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
		Path:           Path{Name: addr, Content: EncodeCertificatesPEM(x509Certificates)},
		Certificates:   FromX509Certificates(x509Certificates),
		VerifiedChains: verifiedChains,
	}, nil
}

func LoadCertificatesFromFile(fileName string) (CertificateLocation, error) {

	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("skipping %s file: %w", fileName, err)
	}
	file := Path{Name: fileName, Content: b}
	return loadCertificate(file)
}

func LoadCertificateFromStdin() (CertificateLocation, error) {

	content, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("reading stdin: %w", err)
	}
	file := Path{Name: "stdin", Content: content}
	return loadCertificate(file)
}

func loadCertificate(file Path) (CertificateLocation, error) {

	if err := IsCertificatePEM(file.Content); err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", file.Name, err)
	}

	certificates, err := FromBytes(file.Content)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", file.Name, err)
	}
	return CertificateLocation{Path: file, Certificates: certificates}, nil
}
