package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const certificateBlockType = "CERTIFICATE"

type Certificates []Certificate

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
	for i, c := range cs {
		certificate := Certificate{
			Index:           i,
			X509Certificate: c,
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}

func IsCertificatePEM(data []byte) error {

	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type == certificateBlockType {
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
		if block.Type == certificateBlockType {
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
		Type:  certificateBlockType,
		Bytes: certificate.Raw,
	})
}
