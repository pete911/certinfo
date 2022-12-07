package main

import (
	"crypto/tls"
	"fmt"
	"github.com/icza/gox/timex"
	"github.com/pete911/certinfo/pkg/cert"
	"time"
)

func PrintCertificatesLocations(certificateLocations []cert.CertificateLocation, printChains, printPem bool) {

	for _, certificateLocation := range certificateLocations {
		fmt.Printf("--- [%s] ---\n", nameFormat(certificateLocation.Path, certificateLocation.TLSVersion))
		printCertificates(certificateLocation.Certificates, printPem)

		if certificateLocation.VerifiedChains != nil {
			fmt.Printf("--- %d verified chains ---\n", len(certificateLocation.VerifiedChains))
		}

		if printChains {
			for i, chain := range certificateLocation.VerifiedChains {
				fmt.Printf("--- chain %d ---\n", i+1)
				printCertificates(chain, printPem)
			}
		}
	}
}

func printCertificates(certificates []cert.Certificate, printPem bool) {

	for _, certificate := range certificates {
		fmt.Println(certificate)
		fmt.Println()
		if printPem {
			fmt.Println(string(certificate.ToPEM()))
		}
	}
}

func PrintPemOnly(certificateLocations []cert.CertificateLocation, printChains bool) {

	for _, certificateLocation := range certificateLocations {
		for _, certificate := range certificateLocation.Certificates {
			fmt.Print(string(certificate.ToPEM()))
		}

		if printChains {
			for _, chains := range certificateLocation.VerifiedChains {
				fmt.Println()
				for _, chain := range chains {
					fmt.Print(string(chain.ToPEM()))
				}
			}
		}
	}
}

func PrintCertificatesExpiry(certificateLocations []cert.CertificateLocation) {

	for _, certificateLocation := range certificateLocations {
		fmt.Printf("--- [%s] ---\n", nameFormat(certificateLocation.Path, certificateLocation.TLSVersion))
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
		return fmt.Sprintf("TLS Version %d (unknown)", tlsVersion)
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
