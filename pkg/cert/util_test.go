package cert

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
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
