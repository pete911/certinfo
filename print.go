package main

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
)

func PrintCertificatesLocations(certificateLocations []cert.CertificateLocation, printChains, printPem, printExtensions bool) {

	for _, certificateLocation := range certificateLocations {
		if certificateLocation.Error != nil {
			fmt.Printf("--- [%s: %v] ---\n", certificateLocation.Name(), certificateLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		printCertificates(certificateLocation, printPem, printChains, printExtensions)
	}
}

func printCertificates(certLocation cert.CertificateLocation, printPem, printChains, printExtensions bool) {

	var prt = func(certs []cert.Certificate, printPem, printExtensions bool) {
		for _, certificate := range certs {
			fmt.Println(certificate)
			if printExtensions {
				fmt.Println("--- extensions ---")
				fmt.Print(certificate.Extensions())
				fmt.Println()
			}
			fmt.Println()
			if printPem {
				fmt.Println(string(certificate.ToPEM()))
			}
		}
	}

	prt(certLocation.Certificates, printPem, printExtensions)
	if printChains {
		chains, err := certLocation.Chains()
		if err != nil {
			fmt.Printf("--- chains: %v ---\n", err)
			return
		}
		fmt.Printf("--- %d chains ---\n", len(chains))
		for i, chain := range chains {
			fmt.Printf("--- chain %d ---\n", i+1)
			prt(chain, printPem, printExtensions)
		}
	}
}

func PrintPemOnly(certificateLocations []cert.CertificateLocation, printChains bool) {

	for _, certificateLocation := range certificateLocations {
		for _, certificate := range certificateLocation.Certificates {
			fmt.Print(string(certificate.ToPEM()))
		}

		if printChains {
			chains, err := certificateLocation.Chains()
			if err != nil {
				fmt.Printf("--- chains: %v ---\n", err)
				continue
			}
			for _, chain := range chains {
				for _, c := range chain {
					fmt.Print(string(c.ToPEM()))
				}
			}
		}
	}
}

func PrintCertificatesExpiry(certificateLocations []cert.CertificateLocation) {

	for _, certificateLocation := range certificateLocations {
		if certificateLocation.Error != nil {
			fmt.Printf("--- [%s: %v] ---\n", certificateLocation.Name(), certificateLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		for _, certificate := range certificateLocation.Certificates {

			fmt.Printf("Subject: %s\n", certificate.SubjectString())
			fmt.Printf("Expiry: %s\n", certificate.ExpiryString())
			fmt.Println()
		}
	}
}
