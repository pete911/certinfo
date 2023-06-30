package cert

import (
	"bytes"
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_nameFormat(t *testing.T) {
	t.Run("given no tls version then name is returned", func(t *testing.T) {
		name := nameFormat("test name", 0)
		assert.Equal(t, "test name", name)
	})

	t.Run("given unknown tls version then name and 'unknown' version is returned", func(t *testing.T) {
		name := nameFormat("test name", 67)
		assert.Equal(t, "test name TLS Version 67 (unknown)", name)
	})

	t.Run("given TLS 1.2 tls version then name and 1.2 version is returned", func(t *testing.T) {
		name := nameFormat("test name", tls.VersionTLS12)
		assert.Equal(t, "test name TLS 1.2", name)
	})
}

func Test_loadCertificate(t *testing.T) {
	t.Run("given valid certificate then cert location is loaded", func(t *testing.T) {
		certificate := loadTestFile(t, "cert.pem")
		_, err := loadCertificate("test", certificate)
		require.NoError(t, err)
	})

	t.Run("given certificate with extra new lines then cert location is loaded", func(t *testing.T) {
		certificate := loadTestFile(t, "cert.pem")
		certificate = bytes.Join([][]byte{[]byte("\n\n"), certificate}, []byte("/"))
		_, err := loadCertificate("test", certificate)
		require.NoError(t, err)
	})
}
