package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCertificateLocation_SortByExpiry(t *testing.T) {
	t.Run("given valid certificate in clipboard then cert is loaded", func(t *testing.T) {
		locations := CertificateLocations{
			{
				Path: "three",
				Certificates: Certificates{
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(3, 2, 3)}},
				},
			},
			{
				Path: "one",
				Certificates: Certificates{
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 2)}},
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 21)}},
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(0, 6, 3)}},
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 3, 3)}},
				},
			},
			{
				Path: "four",
			},
			{
				Path: "two",
				Certificates: Certificates{
					{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(0, 7, 3)}},
				},
			},
		}

		sortedLocations := locations.SortByExpiry()
		require.Equal(t, 4, len(sortedLocations))
		assert.Equal(t, "one", sortedLocations[0].Path)
		assert.Equal(t, "two", sortedLocations[1].Path)
		assert.Equal(t, "three", sortedLocations[2].Path)
		assert.Equal(t, "four", sortedLocations[3].Path)
	})
}
