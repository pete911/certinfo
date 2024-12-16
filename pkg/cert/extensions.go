package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

type Extension struct {
	Name     string
	Critical bool
	Value    string
}

func ToExtensions(in []pkix.Extension) []Extension {
	var out []Extension
	for _, v := range in {
		name, value := parseExtension(v)
		out = append(out, Extension{
			Name:     name,
			Critical: v.Critical,
			Value:    value,
		})
	}
	return out
}

func parseExtension(in pkix.Extension) (string, string) {
	if fn, ok := extensionsByOid[in.Id.String()]; ok {
		return fn(in.Value)
	}
	return in.Id.String(), "-"
}

var extensionsByOid = map[string]func(in []byte) (string, string){
	"2.5.29.35": parseAuthorityKeyIdentifier, // parser.go 745
	"2.5.29.14": parseSubjectKeyIdentifier,   // parser.go 755
	"2.5.29.15": parseKeyUsage,               // parser.go 671
	//"2.5.29.32": parseCertificatePolicies, // parser.go 767
	//"2.5.29.33": parsePolicyMappings,
	//"2.5.29.17": parseSubjectAlternativeName, // parser.go 683
	//"2.5.29.18": parseIssuerAlternativeName,
	//"2.5.29.9": parseSubjectDirectoryAttributes,
	"2.5.29.19": parseBasicConstraints,
	//"2.5.29.30": parseNameConstraints, // parser.go 694
	//"2.5.29.36": parsePolicyConstraints,
	//"2.5.29.37": parseExtendedKeyUsage, // parser.go 750
	// TODO - structure error: sequence tag mismatch
	//"2.5.29.31": parseCRLDistributionPoints, // parser.go 700
	//"2.5.29.54": parseInhibitAnyPolicy,
	//"2.5.29.46": parseFreshestCRL,
	// private internet extensions
	//"1.3.6.1.5.5.7.1": parseAuthorityInformationAccess,
	//"1.3.6.1.5.5.7.11": parseSubjectInformationAccess,
}

// AuthorityKeyIdentifier ::= SEQUENCE {
// keyIdentifier             [0] KeyIdentifier            OPTIONAL,
// authorityCertIssuer       [1] GeneralNames             OPTIONAL,
// authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
// -- authorityCertIssuer and authorityCertSerialNumber MUST both
// -- be present or both be absent
func parseAuthorityKeyIdentifier(in []byte) (string, string) {
	name := "Authority Key Identifier"
	var out AuthorityKeyIdentifier
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}

	fields := []string{fmt.Sprintf("Key Identifier: %s", formatHexArray(out.KeyIdentifier.Bytes))}
	if out.AuthorityCertIssuer != nil {
		// TODO append to fields
	}
	if out.AuthorityCertSerialNumber != 0 {
		// TODO append to fields
	}
	return name, strings.Join(fields, ", ")
}

// SubjectKeyIdentifier ::= KeyIdentifier
func parseSubjectKeyIdentifier(in []byte) (string, string) {
	name := "Subject Key Identifier"
	out := asn1.RawValue{Tag: asn1.TagOctetString}
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}
	return name, formatHexArray(out.Bytes)
}

//	KeyUsage ::= BIT STRING {
//	   digitalSignature        (0),
//	   nonRepudiation          (1),  -- recent editions of X.509 have
//	                              -- renamed this bit to contentCommitment
//	   keyEncipherment         (2),
//	   dataEncipherment        (3),
//	   keyAgreement            (4),
//	   keyCertSign             (5),
//	   cRLSign                 (6),
//	   encipherOnly            (7),
//	   decipherOnly            (8) }
func parseKeyUsage(in []byte) (string, string) {
	name := "Key Usage"
	var out asn1.BitString
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}
	return name, strings.Join(toKeyUsage(out), ", ")
}

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//	DistributionPoint ::= SEQUENCE {
//	    distributionPoint       [0]     DistributionPointName OPTIONAL,
//	    reasons                 [1]     ReasonFlags OPTIONAL,
//	    cRLIssuer               [2]     GeneralNames OPTIONAL }
//
//	DistributionPointName ::= CHOICE {
//	    fullName                [0]     GeneralNames,
//	    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
func parseCRLDistributionPoints(in []byte) (string, string) {
	name := "CRL Distribution Points"
	var out CRLDistributionPoints
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}

	// TODO ...
	return name, fmt.Sprintf("%+v", out)
}

// BasicConstraints ::= SEQUENCE {
// cA                      BOOLEAN DEFAULT FALSE,
// pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
func parseBasicConstraints(in []byte) (string, string) {
	name := "Basic Constraints"
	var out BasicConstraints
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}

	fields := []string{fmt.Sprintf("CA: %t", out.CA)}
	if out.PathLenConstraint != 0 {
		fields = append(fields, fmt.Sprintf("PathLenConstraint: %d", out.PathLenConstraint))
	}
	return name, strings.Join(fields, ", ")
}
