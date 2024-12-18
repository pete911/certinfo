package print

import (
	"fmt"
	"github.com/icza/gox/timex"
	"github.com/pete911/certinfo/pkg/cert"
	"time"
)

func Expiry(certificateLocations []cert.CertificateLocation) {

	for _, certificateLocation := range certificateLocations {
		if certificateLocation.Error != nil {
			fmt.Printf("--- [%s: %v] ---\n", certificateLocation.Name(), certificateLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		for _, certificate := range certificateLocation.Certificates {

			fmt.Printf("Subject: %s\n", certificate.SubjectString())
			fmt.Printf("Expiry: %s\n", expiryString(certificate))
			fmt.Println()
		}
	}
}

func expiryString(certificate cert.Certificate) string {

	if certificate.Error() != nil {
		return "-"
	}
	expiry := formatExpiry(certificate.NotAfter())
	if certificate.IsExpired() {
		return fmt.Sprintf("EXPIRED %s ago", expiry)
	}
	return expiry
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
