package cert

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.design/x/clipboard"
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
		cert := loadCertificate("test", certificate)
		require.Equal(t, 1, len(cert.Certificates))
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", cert.Certificates[0].SubjectString())
	})

	t.Run("given certificate with extra spaces then cert location is loaded", func(t *testing.T) {
		certificate := loadTestFile(t, "cert.pem")
		certificate = bytes.Join([][]byte{[]byte("   "), certificate}, []byte(""))
		cert := loadCertificate("test", certificate)
		require.Equal(t, 1, len(cert.Certificates))
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", cert.Certificates[0].SubjectString())
	})
}

func Test_loadCertificateFromClipboard(t *testing.T) {
	if err := clipboard.Init(); err != nil {
		t.Skip("clipboard not supported in this environment")
	}

	t.Run("given valid certificate in clipboard then cert is loaded", func(t *testing.T) {
		certificate := loadTestFile(t, "cert.pem")
		clipboard.Write(clipboard.FmtText, certificate)

		cert := LoadCertificateFromClipboard()
		require.Equal(t, 1, len(cert.Certificates))
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", cert.Certificates[0].SubjectString())
	})
}
