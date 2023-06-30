package cert

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadTestCertificates(t *testing.T, files ...string) Certificates {
	var bundle [][]byte
	for _, f := range files {
		bundle = append(bundle, loadTestFile(t, f))
	}
	certificates, err := FromBytes(bytes.Join(bundle, []byte("\n")))
	require.NoError(t, err)
	return certificates
}

func loadTestFile(t *testing.T, file string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", file))
	require.NoError(t, err)
	return b
}

func getTime(years, months, days, hours, minutes int) time.Time {
	return time.Now().AddDate(years, months, days).
		Add(time.Hour*time.Duration(hours) + time.Minute*time.Duration(minutes))
}
