package cert

import (
	"bytes"
	"crypto/x509"
	"time"
)

var (
	// format for NotBefore and NotAfter fields to make output similar to openssl
	validityFormat = "Jan _2 15:04:05 2006 MST"
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

func ValidityFormat(t time.Time) string {
	return t.Format(validityFormat)
}

func CertificateType(cert *x509.Certificate) string {

	if IsRoot(cert) {
		return "root"
	}
	if cert.IsCA {
		return "intermediate"
	}
	return "end-entity"
}

func IsRoot(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.IsCA
}

// converts extended key usage integer values to strings
func ExtKeyUsageToString(extKeyUsage []x509.ExtKeyUsage) []string {

	var extendedKeyUsageString []string
	for _, v := range extKeyUsage {
		extendedKeyUsageString = append(extendedKeyUsageString, extKeyUsages[v])
	}
	return extendedKeyUsageString
}

// converts key usage bit values to strings
func KeyUsageToString(keyUsage x509.KeyUsage) []string {

	var keyUsageString []string
	for i, v := range keyUsages {
		bitmask := 1 << i
		if (int(keyUsage) & bitmask) == 0 {
			continue
		}
		keyUsageString = append(keyUsageString, v)
	}
	return keyUsageString
}
