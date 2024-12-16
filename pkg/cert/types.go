package cert

import "encoding/asn1"

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
//
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
type CRLDistributionPoints []DistributionPoint

// DistributionPoint ::= SEQUENCE {
// distributionPoint       [0]     DistributionPointName OPTIONAL,
// reasons                 [1]     ReasonFlags OPTIONAL,
// cRLIssuer               [2]     GeneralNames OPTIONAL }
type DistributionPoint struct {
	DistributionPoint DistributionPointName `asn1:"tag:0,optional"`
	Reasons           asn1.BitString        `asn1:"tag:1,optional"` // reasonFlags
	CRLIssuer         GeneralNames          `asn1:"tag:2,optional"`
}

// DistributionPointName ::= CHOICE {
// fullName                [0]     GeneralNames,
// nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
type DistributionPointName struct {
	FullName                GeneralNames  `asn1:"tag:0,optional"` // GeneralNames
	NameRelativeToCRLIssuer asn1.RawValue `asn1:"tag:1,optional"` // RelativeDistinguishedName
}

// AuthorityKeyIdentifier ::= SEQUENCE {
// keyIdentifier             [0] KeyIdentifier            OPTIONAL,
// authorityCertIssuer       [1] GeneralNames             OPTIONAL,
// authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
// -- authorityCertIssuer and authorityCertSerialNumber MUST both
// -- be present or both be absent
type AuthorityKeyIdentifier struct {
	KeyIdentifier             asn1.RawValue `asn1:"tag:0,optional"` // KeyIdentifier OCTET STRING
	AuthorityCertIssuer       GeneralNames  `asn1:"tag:1,optional"` // GeneralNames
	AuthorityCertSerialNumber int           `asn1:"tag:2,optional"` // CertificateSerialNumber
}

// BasicConstraints ::= SEQUENCE {
// cA                      BOOLEAN DEFAULT FALSE,
// pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
type BasicConstraints struct {
	CA                bool `asn1:"optional"`
	PathLenConstraint int  `asn1:"optional"`
}

// --- bit strings and conversions ---

var reasonFlags = []string{
	"unused",
	"keyCompromise",
	"cACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"privilegeWithdrawn",
	"aACompromise",
}

func toReasonFlag(in asn1.BitString) []string {
	var out []string
	for i, v := range reasonFlags {
		if in.At(i) != 0 {
			out = append(out, v)
		}
	}
	return out
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
