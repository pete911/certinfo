package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/icza/gox/timex"
	"slices"
	"strings"
	"time"
)

const certificateBlockType = "CERTIFICATE"

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

func (c Certificate) ExpiryString() string {

	if c.err != nil {
		return "-"
	}
	expiry := formatExpiry(c.x509Certificate.NotAfter)
	if c.IsExpired() {
		return fmt.Sprintf("EXPIRED %s ago", expiry)
	}
	return expiry
}

func (c Certificate) String() string {

	if c.err != nil {
		return fmt.Sprintf("ERROR: block at position %d: %v", c.position, c.err)
	}

	dnsNames := strings.Join(c.x509Certificate.DNSNames, ", ")

	var ips []string
	for _, ip := range c.x509Certificate.IPAddresses {
		ips = append(ips, fmt.Sprintf("%s", ip))
	}
	ipAddresses := strings.Join(ips, ", ")

	keyUsage := KeyUsageToString(c.x509Certificate.KeyUsage)
	extKeyUsage := ExtKeyUsageToString(c.x509Certificate.ExtKeyUsage)
	var authorityKeyId string
	if c.x509Certificate.AuthorityKeyId != nil {
		authorityKeyId = formatHexArray(c.x509Certificate.AuthorityKeyId)
	}

	return strings.Join([]string{
		fmt.Sprintf("Version: %d", c.x509Certificate.Version),
		fmt.Sprintf("Serial Number: %s", formatHexArray(c.x509Certificate.SerialNumber.Bytes())),
		fmt.Sprintf("Signature Algorithm: %s", c.x509Certificate.SignatureAlgorithm),
		fmt.Sprintf("Type: %s", CertificateType(c.x509Certificate)),
		fmt.Sprintf("Issuer: %s", c.x509Certificate.Issuer),
		fmt.Sprintf("Validity\n    Not Before: %s\n    Not After : %s",
			ValidityFormat(c.x509Certificate.NotBefore),
			ValidityFormat(c.x509Certificate.NotAfter)),
		fmt.Sprintf("Subject: %s", c.SubjectString()),
		fmt.Sprintf("DNS Names: %s", dnsNames),
		fmt.Sprintf("IP Addresses: %s", ipAddresses),
		fmt.Sprintf("Authority Key Id: %s", authorityKeyId),
		fmt.Sprintf("Subject Key Id  : %s", formatHexArray(c.x509Certificate.SubjectKeyId)),
		fmt.Sprintf("Key Usage: %s", strings.Join(keyUsage, ", ")),
		fmt.Sprintf("Ext Key Usage: %s", strings.Join(extKeyUsage, ", ")),
		fmt.Sprintf("CA: %t", c.x509Certificate.IsCA),
	}, "\n")
}

func (c Certificate) Extensions() string {
	var lines []string
	for _, v := range ToExtensions(c.x509Certificate.Extensions) {
		name := fmt.Sprintf("%s (%s)", v.Name, v.Oid)
		if v.Critical {
			name = fmt.Sprintf("%s [critical]", name)
		}
		lines = append(lines, name)
		for _, line := range v.Values {
			lines = append(lines, fmt.Sprintf("  %s", line))
		}
	}
	return strings.Join(lines, "\n")
}

func formatExpiry(t time.Time) string {

	year, month, day, hour, minute, _ := timex.Diff(time.Now(), t)
	if year != 0 {
		return fmt.Sprintf("%d years %d months %d days %d hours %d minutes", year, month, day, hour, minute)
	}
	if month != 0 {
		return fmt.Sprintf("%d months %d days %d hours %d minutes", month, day, hour, minute)
	}
	if day != 0 {
		return fmt.Sprintf("%d days %d hours %d minutes", day, hour, minute)
	}
	if hour != 0 {
		return fmt.Sprintf("%d hours %d minutes", hour, minute)
	}
	return fmt.Sprintf("%d minutes", minute)
}

func formatHexArray(b []byte) string {

	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}
