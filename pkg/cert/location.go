package cert

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
)

type CertificateLocation struct {
	TLSVersion   uint16 // only applicable for network certificates
	Path         Path
	Certificates Certificates
}

type Path struct {
	Name    string
	Content []byte
}

func LoadCertificatesFromNetwork(addr string) (CertificateLocation, error) {

	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("tcp connection failed: %w", err)
	}

	x509Certificates := conn.ConnectionState().PeerCertificates
	certificates := FromX509Certificates(x509Certificates)
	return CertificateLocation{
		TLSVersion:   conn.ConnectionState().Version,
		Path:         Path{Name: addr, Content: EncodeCertificatesPEM(x509Certificates)},
		Certificates: certificates,
	}, nil
}

func LoadCertificatesFromFile(fileName string) (CertificateLocation, error) {

	file, err := loadFromFile(fileName)
	if err != nil {
		return CertificateLocation{}, err
	}

	if err := IsCertificatePEM(file.Content); err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", file.Name, err)
	}

	certificates, err := FromBytes(file.Content)
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("file %s: %w", file.Name, err)
	}
	return CertificateLocation{Path: file, Certificates: certificates}, nil
}

func loadFromFile(fileName string) (Path, error) {

	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return Path{}, fmt.Errorf("skipping %s file: %w", fileName, err)
	}
	return Path{Name: fileName, Content: b}, nil
}
