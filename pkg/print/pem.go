package print

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
	"log/slog"
)

func Pem(certificateLocations []cert.CertificateLocation, printChains bool) {

	for _, certificateLocation := range certificateLocations {
		for _, certificate := range certificateLocation.Certificates {
			fmt.Print(string(certificate.ToPEM()))
		}

		if printChains {
			chains, err := certificateLocation.Chains()
			if err != nil {
				slog.Error(fmt.Sprintf("chains: %v", err))
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
