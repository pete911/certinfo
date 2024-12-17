package cert

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
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
		certificates := loadTestCertificates(t, "bundle.pem", "bundle.pem")

		require.Equal(t, 4, len(certificates))
		noDuplicates := certificates.RemoveDuplicates()
		require.Equal(t, 2, len(noDuplicates))
	})
}

func TestCertificates_SortByExpiry(t *testing.T) {
	t.Run("given multiple certificates, when they have different expiry, then they are sorted", func(t *testing.T) {
		certificates := Certificates{
			// using version to validate tests
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(0, 6, 3), Version: 1}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 2), Version: 3}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 21), Version: 4}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 3, 3), Version: 2}},
		}

		sortedCertificates := certificates.SortByExpiry()
		require.Equal(t, 4, len(sortedCertificates))
		assert.Equal(t, 1, sortedCertificates[0].x509Certificate.Version)
		assert.Equal(t, 2, sortedCertificates[1].x509Certificate.Version)
		assert.Equal(t, 3, sortedCertificates[2].x509Certificate.Version)
		assert.Equal(t, 4, sortedCertificates[3].x509Certificate.Version)
	})
}

func Test_expiryFormat(t *testing.T) {
	t.Run("given certificate expiry is more than a year then year is returned as well", func(t *testing.T) {
		v := formatExpiry(getTime(3, 2, 7, 5, 25))
		assert.True(t, strings.HasPrefix(v, "3 years 2 months "))
	})

	t.Run("given certificate expiry is less than a year then year is not returned", func(t *testing.T) {
		v := formatExpiry(getTime(0, 2, 7, 5, 25))
		assert.True(t, strings.HasPrefix(v, "2 months "))
	})

	t.Run("given certificate expiry is less than a month then year and month is not returned", func(t *testing.T) {
		v := formatExpiry(getTime(0, 0, 7, 5, 25))
		assert.Equal(t, "7 days 5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than a day then year, month and day is not returned", func(t *testing.T) {
		v := formatExpiry(getTime(0, 0, 0, 5, 25))
		assert.Equal(t, "5 hours 25 minutes", v)
	})

	t.Run("given certificate expiry is less than an hour then only minutes are returned", func(t *testing.T) {
		v := formatExpiry(getTime(0, 0, 0, 0, 25))
		assert.Equal(t, "25 minutes", v)
	})
}

func Test_rootIdentification(t *testing.T) {
	t.Run("given certificate issuer is identical to subject but authority key id is set then identify as root", func(t *testing.T) {
		certificate := loadTestCertificates(t, "root_with_authority_key_id.pem")
		require.Len(t, certificate, 1)
		require.Equal(t, certificate[0].x509Certificate.RawSubject, certificate[0].x509Certificate.RawIssuer)
		require.NotEmpty(t, certificate[0].x509Certificate.AuthorityKeyId)
		require.Equal(t, "root", certificate[0].Type())
	})

	t.Run("given certificate authority key id is unset then identify as root", func(t *testing.T) {
		certificate := loadTestCertificates(t, "cert.pem")
		require.Len(t, certificate, 1)
		assert.Len(t, certificate[0].x509Certificate.AuthorityKeyId, 0)
		assert.True(t, certificate[0].x509Certificate.IsCA)
		require.Equal(t, "root", certificate[0].Type())
	})
}

func Test_intermediateIdentification(t *testing.T) {
	t.Run("given intermediate certificate issuer is identical to subject but authority and subject keys are different then identify as intermediate", func(t *testing.T) {
		certificate := loadTestCertificates(t, "intermediate_same_issuer_and_subject.pem")
		require.Len(t, certificate, 1)
		require.Equal(t, certificate[0].x509Certificate.RawSubject, certificate[0].x509Certificate.RawIssuer)
		require.NotEmpty(t, certificate[0].x509Certificate.AuthorityKeyId)
		require.Equal(t, "intermediate", certificate[0].Type())
	})
}
