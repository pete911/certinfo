package main

import (
	"crypto/tls"
	"fmt"
	"github.com/icza/gox/timex"
	"github.com/pete911/certinfo/pkg/cert"
	"time"
)

func PrintCertificatesLocations(certificateLocations []cert.CertificateLocation) {

	for _, certificateLocation := range certificateLocations {
		fmt.Printf("--- [%s] ---\n", nameFormat(certificateLocation.Path.Name, certificateLocation.TLSVersion))
		for _, certificate := range certificateLocation.Certificates {
			fmt.Println(certificate)
			fmt.Println()
		}
	}
}

func PrintCertificatesExpiry(certificateLocations []cert.CertificateLocation) {

	for _, certificateLocation := range certificateLocations {
		fmt.Printf("--- [%s] ---\n", nameFormat(certificateLocation.Path.Name, certificateLocation.TLSVersion))
		for _, certificate := range certificateLocation.Certificates {

			expiry := expiryFormat(certificate.X509Certificate.NotAfter)
			if certificate.IsExpired() {
				expiry = fmt.Sprintf("EXPIRED %s ago", expiry)
			}

			fmt.Printf("Subject: %s\n", certificate.X509Certificate.Subject)
			fmt.Printf("Expiry: %s\n", expiry)
			fmt.Println()
		}
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
		return "TLS Version %d (unknown)"
	}
}

func expiryFormat(t time.Time) string {

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
