package cert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

const certificateBlockType = "CERTIFICATE"

var (
	// order is important!
	keyUsages = []string{
		"Digital Signature",
		"Content Commitment",
		"Key Encipherment",
		"Data Encipherment",
		"Key Agreement",
		"Cert Sign",
		"CRL Sign",
		"Encipher Only",
		"Decipher Only",
	}
	// order is important!
	extKeyUsages = []string{
		"Any",
		"Server Auth",
		"Client Auth",
		"Code Signing",
		"Email Protection",
		"IPSEC End System",
		"IPSEC Tunnel",
		"IPSEC User",
		"Time Stamping",
		"OCSP Signing",
		"Microsoft Server Gated Crypto",
		"Netscape Server Gated Crypto",
		"Microsoft Commercial Code Signing",
		"Microsoft Kernel Code Signing",
	}
)

type Certificates []Certificate

func (c Certificates) RemoveExpired() Certificates {
	var out Certificates
	for i := range c {
		if !c[i].IsExpired() {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) RemoveDuplicates() Certificates {
	var out Certificates
	savedSet := map[string]struct{}{}
	for i := range c {
		stringPem := string(c[i].ToPEM())
		if _, ok := savedSet[stringPem]; !ok {
			savedSet[stringPem] = struct{}{}
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) SubjectLike(subject string) Certificates {
	var out Certificates
	for i := range c {
		if strings.Contains(c[i].SubjectString(), subject) {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) IssuerLike(issuer string) Certificates {
	var out Certificates
	for i := range c {
		if strings.Contains(c[i].x509Certificate.Issuer.String(), issuer) {
			out = append(out, c[i])
		}
	}
	return out
}

func (c Certificates) SortByExpiry() Certificates {
	slices.SortFunc(c, func(a, b Certificate) int {
		return a.x509Certificate.NotAfter.Compare(b.x509Certificate.NotAfter)
	})
	return c
}

type Certificate struct {
	// position of certificate in the chain, starts with 1
	position        int
	x509Certificate *x509.Certificate
	err             error
}

func FromX509Certificates(cs []*x509.Certificate) Certificates {

	var certificates Certificates
	for i, c := range cs {
		certificates = append(certificates, Certificate{position: i, x509Certificate: c})
	}
	return certificates
}

// FromBytes converts raw certificate bytes to certificate, if the supplied data is cert bundle (or chain)
// all the certificates will be returned
func FromBytes(data []byte) (Certificates, error) {

	var block *pem.Block
	var certificates Certificates
	var i int
	for {
		i++
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("cannot find any PEM block")
		}
		certificates = append(certificates, fromPemBlock(i, block))
		if len(data) == 0 {
			break
		}
	}
	return certificates, nil
}

func fromPemBlock(position int, block *pem.Block) Certificate {

	if block.Type != certificateBlockType {
		return Certificate{position: position, err: fmt.Errorf("cannot parse %s block", block.Type)}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{position: position, err: err}
	}
	return Certificate{position: position, x509Certificate: certificate}
}

func (c Certificate) IsExpired() bool {

	if c.err != nil {
		return false
	}
	return time.Now().After(c.x509Certificate.NotAfter)
}

func (c Certificate) ToPEM() []byte {

	if c.err != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  certificateBlockType,
		Bytes: c.x509Certificate.Raw,
	})
}

func (c Certificate) SubjectString() string {

	if c.err != nil {
		return fmt.Sprintf("ERROR: block at position %d: %v", c.position, c.err)
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.x509Certificate.RawSubject, &subject); err != nil {
		return fmt.Sprintf("ERROR: asn1 unmarshal subject: %v", err)
	}
	return subject.String()
}

func (c Certificate) Error() error {
	if c.err != nil {
		return fmt.Errorf("ERROR: block at position %d: %v", c.position, c.err)
	}
	return nil
}

func (c Certificate) DNSNames() []string {
	return c.x509Certificate.DNSNames
}

func (c Certificate) IPAddresses() []string {
	var ips []string
	for _, ip := range c.x509Certificate.IPAddresses {
		ips = append(ips, fmt.Sprintf("%s", ip))
	}
	return ips
}

func (c Certificate) Version() int {
	return c.x509Certificate.Version
}

func (c Certificate) SerialNumber() string {
	return formatHexArray(c.x509Certificate.SerialNumber.Bytes())
}

func (c Certificate) SignatureAlgorithm() string {
	return c.x509Certificate.SignatureAlgorithm.String()
}

func (c Certificate) Issuer() string {
	return c.x509Certificate.Issuer.String()
}

func (c Certificate) NotBefore() time.Time {
	return c.x509Certificate.NotBefore
}

func (c Certificate) NotAfter() time.Time {
	return c.x509Certificate.NotAfter
}

func (c Certificate) AuthorityKeyId() string {
	if c.x509Certificate.AuthorityKeyId != nil {
		return formatHexArray(c.x509Certificate.AuthorityKeyId)
	}
	return ""
}

func (c Certificate) SubjectKeyId() string {
	if c.x509Certificate.SubjectKeyId != nil {
		return formatHexArray(c.x509Certificate.SubjectKeyId)
	}
	return ""
}

func (c Certificate) IsCA() bool {
	return c.x509Certificate.IsCA
}

func (c Certificate) KeyUsage() []string {
	var out []string
	for i, v := range keyUsages {
		bitmask := 1 << i
		if (int(c.x509Certificate.KeyUsage) & bitmask) == 0 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// ExtKeyUsage extended key usage string representation
func (c Certificate) ExtKeyUsage() []string {

	var extendedKeyUsageString []string
	for _, v := range c.x509Certificate.ExtKeyUsage {
		extendedKeyUsageString = append(extendedKeyUsageString, extKeyUsages[v])
	}
	return extendedKeyUsageString
}

func (c Certificate) Type() string {
	if c.x509Certificate.AuthorityKeyId == nil || bytes.Equal(c.x509Certificate.AuthorityKeyId, c.x509Certificate.SubjectKeyId) {
		return "root"
	}

	if c.x509Certificate.IsCA {
		return "intermediate"
	}
	return "end-entity"
}
func (c Certificate) Extensions() []Extension {
	var out []Extension
	for _, v := range c.x509Certificate.Extensions {
		name, value, err := parseExtension(v)
		if err != nil {
			// log error and set error as value
			slog.Error(fmt.Sprintf("certificate at position %d: extension %s (%s): %v", c.position, name, v.Id.String(), err))
			value = []string{err.Error()}
		}
		out = append(out, Extension{
			Name:     name,
			Oid:      v.Id.String(),
			Critical: v.Critical,
			Values:   value,
		})
	}
	return out
}

func formatHexArray(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}
