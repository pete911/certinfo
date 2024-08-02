package main

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
)

func PrintCertificatesLocations(certificateLocations []cert.CertificateLocation, printChains, printPem bool) {

	for _, certificateLocation := range certificateLocations {
		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
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
		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		if len(certificateLocation.Certificates) == 0 {
			// in case of error (no certificates), print new line
			fmt.Println()
		}
		for _, certificate := range certificateLocation.Certificates {

			fmt.Printf("Subject: %s\n", certificate.SubjectString())
			fmt.Printf("Expiry: %s\n", certificate.ExpiryString())
			fmt.Println()
		}
	}
}
