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
	//"2.5.29.35": parseAuthorityKeyIdentifier, // parser.go 745
	"2.5.29.14": parseSubjectKeyIdentifier, // parser.go 755
	"2.5.29.15": parseKeyUsage,             // parser.go 671
	//"2.5.29.32": parseCertificatePolicies, // parser.go 767
	//"2.5.29.33": parsePolicyMappings,
	//"2.5.29.17": parseSubjectAlternativeName, // parser.go 683
	//"2.5.29.18": parseIssuerAlternativeName,
	//"2.5.29.9": parseSubjectDirectoryAttributes,
	"2.5.29.19": parseBasicConstraints,
	//"2.5.29.30": parseNameConstraints, // parser.go 694
	//"2.5.29.36": parsePolicyConstraints,
	//"2.5.29.37": parseExtendedKeyUsage, // parser.go 750
	"2.5.29.31": parseCRLDistributionPoints, // parser.go 700
	//"2.5.29.54": parseInhibitAnyPolicy,
	//"2.5.29.46": parseFreshestCRL,
	// private internet extensions
	//"1.3.6.1.5.5.7.1": parseAuthorityInformationAccess,
	//"1.3.6.1.5.5.7.11": parseSubjectInformationAccess,
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

type GeneralNames []GeneralName

type OtherName struct {
	TypeId asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"optional"`
}

//	OtherName ::= SEQUENCE {
//	    type-id OBJECT IDENTIFIER,
//	    value   [0] EXPLICIT ANY DEFINED BY type-id }

//	GeneralName ::= CHOICE {
//	    otherName                 [0] OtherName,
//	    rfc822Name                [1] IA5String,
//	    dNSName                   [2] IA5String,
//	    x400Address               [3] ORAddress,
//	    directoryName             [4] Name,
//	    ediPartyName              [5] EDIPartyName,
//	    uniformResourceIdentifier [6] IA5String,
//	    iPAddress                 [7] OCTET STRING,
//	    registeredID              [8] OBJECT IDENTIFIER }
// TODO - decode raw values, switch on generalName.Tag - https://github.com/golang/go/issues/13999
// return string (key), string (values)
type GeneralName struct {
	OtherName                 asn1.RawValue `asn1:"tag:0,optional"`
	Rfc822Name                asn1.RawValue `asn1:"tag:1,optional"`
	DNSName                   asn1.RawValue `asn1:"tag:2,optional"`
	X400Address               asn1.RawValue `asn1:"tag:3,optional"`
	DirectoryName             asn1.RawValue `asn1:"tag:4,optional"`
	EdiPartyName              asn1.RawValue `asn1:"tag:5,optional"`
	UniformResourceIdentifier asn1.RawValue `asn1:"tag:6,optional"`
	IPAddress                 asn1.RawValue `asn1:"tag:7,optional"`
	RegisteredID              asn1.RawValue `asn1:"tag:8,optional"`
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
	out := struct {
		DistributionPoint []struct {
			DistributionPointName struct {
			}
		} `asn1:"optional"`
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
