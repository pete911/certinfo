package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
)

const certificateBlockType = "CERTIFICATE"

type Certificates []Certificate

// FromBytes converts raw certificate bytes to certificate, if the supplied data is cert bundle (or chain)
// all the certificates will be returned
func FromBytes(data []byte) (Certificates, error) {

	cs, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	return FromX509Certificates(cs), nil
}

func FromX509Certificates(cs []*x509.Certificate) Certificates {

	var certificates Certificates
	for i, c := range cs {
		certificate := Certificate{
			Index:           i,
			X509Certificate: c,
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}

func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {

	var block *pem.Block
	var certificates []*x509.Certificate
	var i int
	for {
		i++
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("cannot find any PEM block")
		}

		// append only certificates
		if block.Type == certificateBlockType {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("block %d cannot be parsed: %v", i, err)
			} else {
				certificates = append(certificates, certificate)
			}
		} else {
			log.Printf("block %d is %s type, only %s can be parsed", i, block.Type, certificateBlockType)
		}

		if len(data) == 0 {
			break
		}
	}
	return certificates, nil
}
