package cert

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFromBytes(t *testing.T) {
	t.Run("given valid PEM certificate, then certificate is loaded", func(t *testing.T) {
		certificates := loadTestCertificates(t, "cert.pem")
		require.Equal(t, 1, len(certificates))
		assert.Equal(t, 1, certificates[0].position)
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", certificates[0].SubjectString())
		assert.Nil(t, certificates[0].err)
	})

	t.Run("given valid PEM bundle, then all certificates are loaded", func(t *testing.T) {
		certificates := loadTestCertificates(t, "bundle.pem")
		require.Equal(t, 2, len(certificates))
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", certificates[0].SubjectString())
		assert.Equal(t, "CN=GTS Root R1,O=Google Trust Services LLC,C=US", certificates[1].SubjectString())
	})
}

func TestCertificates_RemoveDuplicates(t *testing.T) {
	t.Run("given duplicate PEM certificate, when remove duplicates is called, then they are removed", func(t *testing.T) {
		bundle := bytes.Join([][]byte{
			loadTestFile(t, "bundle.pem"),
			loadTestFile(t, "bundle.pem"),
		}, []byte("\n"))
		certificates, err := FromBytes(bundle)
		require.NoError(t, err)

		require.Equal(t, 4, len(certificates))
		noDuplicates := certificates.RemoveDuplicates()
		require.Equal(t, 2, len(noDuplicates))
	})
}

func Test_expiryFormat(t *testing.T) {
	t.Run("given certificate expiry is more than a year then year is returned as well", func(t *testing.T) {
		v := expiryFormat(getTime(3, 2, 7, 5, 25))
		assert.Equal(t, "3 years 2 months 7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a year then year is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 2, 7, 5, 25))
		assert.Equal(t, "2 months 7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a month then year and month is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 7, 5, 25))
		assert.Equal(t, "7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a day then year, month and day is not returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 0, 5, 25))
		assert.Equal(t, "5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than an hour then only minutes are returned", func(t *testing.T) {
		v := expiryFormat(getTime(0, 0, 0, 0, 25))
		assert.Equal(t, "25 minutes", v)
	})
}

func Test_rootIdentification(t *testing.T) {
	t.Run("given certificate issuer is identical to subject but authority key id is set then identify as root", func(t *testing.T) {
		certificate, err := FromBytes(loadTestFile(t, "root_with_authority_key_id.pem"))
		require.NoError(t, err)
		require.Len(t, certificate, 1)
		require.Equal(t, certificate[0].x509Certificate.RawSubject, certificate[0].x509Certificate.RawIssuer)
		require.NotEmpty(t, certificate[0].x509Certificate.AuthorityKeyId)
		require.Equal(t, "root", CertificateType(certificate[0].x509Certificate))
	})

	t.Run("given certificate authority key id is unset then identify as root", func(t *testing.T) {
		certificate, err := FromBytes(loadTestFile(t, "cert.pem"))
		require.NoError(t, err)
		require.Len(t, certificate, 1)
		assert.Len(t, certificate[0].x509Certificate.AuthorityKeyId, 0)
		assert.True(t, certificate[0].x509Certificate.IsCA)
		require.Equal(t, "root", CertificateType(certificate[0].x509Certificate))
	})
}

// --- helper functions ---

func loadTestCertificates(t *testing.T, file string) Certificates {
	certificates, err := FromBytes(loadTestFile(t, file))
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
