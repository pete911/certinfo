package print

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
	"log/slog"
	"strings"
	"time"
)

func Locations(certificateLocations []cert.CertificateLocation, printChains, printPem, printExtensions bool) {

	for _, certificateLocation := range certificateLocations {
		if certificateLocation.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", certificateLocation.Name(), certificateLocation.Error))
			fmt.Printf("--- [%s: %v] ---\n", certificateLocation.Name(), certificateLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		printCertificates(certificateLocation.Certificates, printPem, printExtensions)

		if printChains {
			chains, err := certificateLocation.Chains()
			if err != nil {
				slog.Error(fmt.Sprintf("chains for %s: %v", certificateLocation.Name(), certificateLocation.Error))
				fmt.Printf("--- [chains for %s: %v] ---\n", certificateLocation.Name(), err)
				continue
			}

			if len(chains) == 1 {
				fmt.Printf("--- [%d chain for %s] ---\n", len(chains), certificateLocation.Name())
			} else {
				fmt.Printf("--- [%d chains for %s] ---\n", len(chains), certificateLocation.Name())
			}
			for i, chain := range chains {
				fmt.Printf(" -- [chain %d] -- \n", i+1)
				printCertificates(chain, printPem, printExtensions)
			}
		}
	}
}

func printCertificates(certs cert.Certificates, printPem, printExtensions bool) {

	for _, certificate := range certs {
		printCertificate(certificate, printExtensions)
		fmt.Println()
		if printPem {
			fmt.Println(string(certificate.ToPEM()))
		}
	}
}

func printCertificate(certificate cert.Certificate, printExtensions bool) {

	if certificate.Error() != nil {
		slog.Error(certificate.Error().Error())
		fmt.Println(certificate.Error())
		return
	}

	fmt.Printf("Version: %d\n", certificate.Version())
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber())
	fmt.Printf("Signature Algorithm: %s\n", certificate.SignatureAlgorithm())
	fmt.Printf("Type: %s\n", certificate.Type())
	fmt.Printf("Issuer: %s\n", certificate.Issuer())
	fmt.Println("Validity")
	fmt.Printf("    Not Before: %s\n", validityFormat(certificate.NotBefore()))
	fmt.Printf("    Not After : %s\n", validityFormat(certificate.NotAfter()))
	fmt.Printf("Subject: %s\n", certificate.SubjectString())
	fmt.Printf("DNS Names: %s\n", strings.Join(certificate.DNSNames(), ", "))
	fmt.Printf("IP Addresses: %s\n", strings.Join(certificate.IPAddresses(), ", "))
	fmt.Printf("Authority Key Id: %s\n", certificate.AuthorityKeyId())
	fmt.Printf("Subject Key Id  : %s\n", certificate.SubjectKeyId())
	fmt.Printf("Key Usage: %s\n", strings.Join(certificate.KeyUsage(), ", "))
	fmt.Printf("Ext Key Usage: %s\n", strings.Join(certificate.ExtKeyUsage(), ", "))
	fmt.Printf("CA: %t\n", certificate.IsCA())

	if !printExtensions {
		return
	}

	fmt.Println("Extensions:")
	for _, extension := range certificate.Extensions() {
		name := fmt.Sprintf("%s (%s)", extension.Name, extension.Oid)
		if extension.Critical {
			name = fmt.Sprintf("%s [critical]", name)
		}
		fmt.Printf("    %s\n", name)
		for _, line := range extension.Values {
			fmt.Printf("        %s\n", line)
		}
	}
}

func validityFormat(t time.Time) string {
	// format for NotBefore and NotAfter fields to make output similar to openssl
	return t.Format("Jan _2 15:04:05 2006 MST")
}
