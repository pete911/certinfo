package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

type Extension struct {
	Name     string
	Oid      string
	Critical bool
	Value    string
}

func ToExtensions(in []pkix.Extension) []Extension {
	var out []Extension
	for _, v := range in {
		name, value := parseExtension(v)
		out = append(out, Extension{
			Name:     name,
			Oid:      v.Id.String(),
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
	return "-", in.Id.String()
}

var extensionsByOid = map[string]func(in []byte) (string, string){
	"2.5.29.35": parseAuthorityKeyIdentifier,
	"2.5.29.14": parseSubjectKeyIdentifier,
	"2.5.29.15": parseKeyUsage,
	"2.5.29.32": parseCertificatePolicies,
	//"2.5.29.33": parsePolicyMappings,
	"2.5.29.17": parseSubjectAltName,
	//"2.5.29.18": parseIssuerAlternativeName,
	//"2.5.29.9": parseSubjectDirectoryAttributes,
	"2.5.29.19": parseBasicConstraints,
	//"2.5.29.30": parseNameConstraints,
	//"2.5.29.36": parsePolicyConstraints,
	"2.5.29.37": parseExtendedKeyUsage,
	"2.5.29.31": parseCRLDistributionPoints,
	//"2.5.29.54": parseInhibitAnyPolicy,
	//"2.5.29.46": parseFreshestCRL,
	// private internet extensions
	//"1.3.6.1.5.5.7.1": parseAuthorityInformationAccess,
	//"1.3.6.1.5.5.7.11": parseSubjectInformationAccess,
	// TODO
	//"1.3.6.1.5.5.7.1.1": parseAuthorityInfoAccessSyntax
	// "1.3.6.1.4.1.11129.2.4.2" parseOID ???
}

// AuthorityKeyIdentifier ::= SEQUENCE {
// keyIdentifier             [0] KeyIdentifier            OPTIONAL,
// authorityCertIssuer       [1] GeneralNames             OPTIONAL,
// authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
// -- authorityCertIssuer and authorityCertSerialNumber MUST both
// -- be present or both be absent
func parseAuthorityKeyIdentifier(in []byte) (string, string) {
	name := "Authority Key Identifier"
	out, err := ToAuthorityKeyIdentifier(in)
	if err != nil {
		return name, err.Error()
	}

	fields := []string{formatHexArray(out.KeyIdentifier)}
	if out.AuthorityCertIssuer != nil {
		v := strings.Join(out.AuthorityCertIssuer, ", ")
		fields = append(fields, fmt.Sprintf("Authority Cert. Issuer: %s", v))
	}
	if out.AuthorityCertSerialNumber != 0 {
		fields = append(fields, fmt.Sprintf("Authority Cert SN: %d", out.AuthorityCertSerialNumber))
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
	out, err := ToKeyUsage(in)
	if err != nil {
		return name, err.Error()
	}
	return name, strings.Join(out, ", ")
}

func parseCertificatePolicies(in []byte) (string, string) {
	name := "Certificate Policies"
	out, err := ToCertificatePolicies(in)
	if err != nil {
		return name, err.Error()
	}
	return name, strings.Join(out, ", ")
}

func parseSubjectAltName(in []byte) (string, string) {
	name := "Subject Alt. Name"
	out, err := ToGeneralNames(in)
	if err != nil {
		return name, err.Error()
	}
	return name, strings.Join(out, ", ")
}

func parseExtendedKeyUsage(in []byte) (string, string) {
	name := "Extended Key Usage"
	out, err := ToExtendedKeyUsage(in)
	if err != nil {
		return name, err.Error()
	}
	return name, strings.Join(out, ", ")
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
	out, err := ToCRLDistributionPoints(in)
	if err != nil {
		return name, err.Error()
	}
	var points []string
	for _, v := range out {
		var point []string
		if len(v.DistributionPoint) != 0 {
			point = append(point, fmt.Sprintf("Distribution Point: %s", strings.Join(v.DistributionPoint, ", ")))
		}
		if len(v.Reasons) != 0 {
			point = append(point, fmt.Sprintf("Reasons: %s", strings.Join(v.Reasons, ", ")))
		}
		if len(v.CRLIssuer) != 0 {
			point = append(point, fmt.Sprintf("CRL Issuer: %s", strings.Join(v.CRLIssuer, ", ")))
		}
		if len(point) != 0 {
			points = append(points, strings.Join(point, " "))
		}
	}
	return name, strings.Join(points, "; ")
}

// BasicConstraints ::= SEQUENCE {
// cA                      BOOLEAN DEFAULT FALSE,
// pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
func parseBasicConstraints(in []byte) (string, string) {
	name := "Basic Constraints"
	out, err := ToBasicConstraints(in)
	if err != nil {
		return name, err.Error()
	}

	fields := []string{fmt.Sprintf("CA: %t", out.CA)}
	if out.PathLenConstraint != 0 {
		fields = append(fields, fmt.Sprintf("PathLenConstraint: %d", out.PathLenConstraint))
	}
	return name, strings.Join(fields, ", ")
}
