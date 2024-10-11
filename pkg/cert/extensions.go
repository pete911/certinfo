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
	//"2.5.29.35": parseAuthorityKeyIdentifier,
	"2.5.29.14": parseSubjectKeyIdentifier,
	"2.5.29.15": parseKeyUsage,
	//"2.5.29.32": parseCertificatePolicies,
	//"2.5.29.": parsePolicyMappings,
	//"2.5.29.": parseSubjectAlternativeName,
	//"2.5.29.": parseIssuerAlternativeName,
	//"2.5.29.": parseSubjectDirectoryAttributes,
	"2.5.29.19": parseBasicConstraints,
	//"2.5.29.": parseNameConstraints,
	//"2.5.29.": parsePolicyConstraints,
	//"2.5.29.": parseExtendedKeyUsage,
	//"2.5.29.": parseCRLDistributionPoints,
	//"2.5.29.": parseInhibitAnyPolicy,
	//"2.5.29.": parseFreshestCRL,
	// private internet extensions
	//"": parseAuthorityInformationAccess,
	//"": parseSubjectInformationAccess,
}

func parseSubjectKeyIdentifier(in []byte) (string, string) {
	name := "Subject Key Identifier"
	out := asn1.RawValue{Tag: asn1.TagOctetString}
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}
	return name, formatHexArray(out.Bytes)
}

func parseKeyUsage(in []byte) (string, string) {
	name := "Key Usage"
	var out asn1.BitString
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}
	return name, strings.Join(toKeyUsage(out), ", ")
}

func parseBasicConstraints(in []byte) (string, string) {
	name := "Basic Constraints"
	out := struct {
		CA                bool `asn1:"optional"`
		PathLenConstraint int  `asn1:"optional"`
	}{}

	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return name, err.Error()
	}

	fields := []string{fmt.Sprintf("CA: %t", out.CA)}
	if out.PathLenConstraint != 0 {
		fields = append(fields, fmt.Sprintf("PathLenConstraint: %d", out.PathLenConstraint))
	}
	return name, strings.Join(fields, ", ")
}

// order is important!
var keyUsage = []string{
	"Digital Signature",
	"Content Commitment", // renamed from non repudiation
	"Key Encipherment",
	"Data Encipherment",
	"Key Agreement",
	"Key Cert Sign",
	"CRLs Sign",
	"Encipher Only",
	"Decipher Only",
}

func toKeyUsage(in asn1.BitString) []string {
	var out []string
	for i, v := range keyUsage {
		if in.At(i) != 0 {
			out = append(out, v)
		}
	}
	return out
}
