package print

import (
	"fmt"
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

	year, month, day, hour, minute, _ := timeDiff(time.Now(), t)
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

// copied from github.com/icza/gox/timex Diff function
func timeDiff(a, b time.Time) (year, month, day, hour, min, sec int) {

	if a.Location() != b.Location() {
		b = b.In(a.Location())
	}
	if a.After(b) {
		a, b = b, a
	}
	y1, M1, d1 := a.Date()
	y2, M2, d2 := b.Date()

	h1, m1, s1 := a.Clock()
	h2, m2, s2 := b.Clock()

	year = y2 - y1
	month = int(M2 - M1)
	day = d2 - d1
	hour = h2 - h1
	min = m2 - m1
	sec = s2 - s1

	// Normalize negative values
	if sec < 0 {
		sec += 60
		min--
	}
	if min < 0 {
		min += 60
		hour--
	}
	if hour < 0 {
		hour += 24
		day--
	}
	if day < 0 {
		// days in month:
		t := time.Date(y1, M1, 32, 0, 0, 0, 0, time.UTC)
		day += 32 - t.Day()
		month--
	}
	if month < 0 {
		month += 12
		year--
	}

	return
}
