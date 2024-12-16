package cert

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

// AttributeTypeAndValue ::= SEQUENCE {
// type     AttributeType,
// value    AttributeValue }

// AttributeType ::= OBJECT IDENTIFIER
// AttributeValue ::= ANY -- DEFINED BY AttributeType

// ToRelativeDistinguishedName returns slice of "type: value" strings
func ToRelativeDistinguishedName(in []byte) ([]string, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	var typeValues []string
	for {
		var out struct {
			TypeId asn1.ObjectIdentifier
			Value  asn1.RawValue `asn1:"optional"`
		}
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}
		typeValues = append(typeValues, fmt.Sprintf("%s: %s", out.TypeId.String(), string(out.Value.Bytes)))
		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return typeValues, nil
}

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

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

// ToGeneralNames returns slice of "type: value1, value2, valueX" strings
func ToGeneralNames(in []byte) ([]string, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	names := make(map[string][]string)
	for {
		var out asn1.RawValue
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}

		name := toGeneralName(out)
		if _, ok := names[name.Type]; !ok {
			names[name.Type] = []string{}
		}
		names[name.Type] = append(names[name.Type], name.Value)

		if len(rest) == 0 {
			break
		}
		in = rest
	}

	var namesSlice []string
	for k, v := range names {
		namesSlice = append(namesSlice, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	return namesSlice, nil
}

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

// DistributionPoint ::= SEQUENCE {
// distributionPoint       [0]     DistributionPointName OPTIONAL,
// reasons                 [1]     ReasonFlags OPTIONAL,
// cRLIssuer               [2]     GeneralNames OPTIONAL }

// DistributionPointName ::= CHOICE {
// fullName                [0]     GeneralNames,
// nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

type DistributionPoint struct {
	DistributionPoint []string
	Reasons           []string
	CRLIssuer         []string
}

func ToCRLDistributionPoints(in []byte) ([]DistributionPoint, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	var points []DistributionPoint
	for {
		// DistributionPoint ::= SEQUENCE {
		// distributionPoint       [0]     DistributionPointName OPTIONAL,
		// reasons                 [1]     ReasonFlags OPTIONAL,
		// cRLIssuer               [2]     GeneralNames OPTIONAL }
		var out struct {
			DistributionPoint asn1.RawValue  `asn1:"tag:0,optional"`
			Reasons           asn1.BitString `asn1:"tag:1,optional"`
			CRLIssuer         asn1.RawValue  `asn1:"tag:2,optional"`
		}
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}

		// choice, either general names or relative distinguished name
		distPoint, err := toDistributionPoint(out.DistributionPoint)
		if err != nil {
			return nil, err
		}

		var crlIssuer []string
		if out.CRLIssuer.Bytes != nil {
			v, err := ToGeneralNames(out.CRLIssuer.Bytes)
			if err != nil {
				return nil, err
			}
			crlIssuer = v
		}

		points = append(points, DistributionPoint{
			DistributionPoint: distPoint,
			Reasons:           toReasonFlag(out.Reasons),
			CRLIssuer:         crlIssuer,
		})

		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return points, nil
}

func toDistributionPoint(in asn1.RawValue) ([]string, error) {
	if in.Bytes == nil {
		return nil, nil
	}

	// DistributionPointName ::= CHOICE {
	// fullName                [0]     GeneralNames,
	// nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

	// choice, either general names or relative distinguished name
	if in.Tag == 0 {
		return ToGeneralNames(in.Bytes)
	}
	if in.Tag == 1 {
		return ToRelativeDistinguishedName(in.Bytes)
	}
	return nil, fmt.Errorf("unsupported distribution point tag %d", in.Tag)
}

// AuthorityKeyIdentifier ::= SEQUENCE {
// keyIdentifier             [0] KeyIdentifier            OPTIONAL,
// authorityCertIssuer       [1] GeneralNames             OPTIONAL,
// authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
// -- authorityCertIssuer and authorityCertSerialNumber MUST both
// -- be present or both be absent
type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte
	AuthorityCertIssuer       []string
	AuthorityCertSerialNumber int
}

func ToAuthorityKeyIdentifier(in []byte) (AuthorityKeyIdentifier, error) {
	var out struct {
		KeyIdentifier             asn1.RawValue `asn1:"tag:0,optional"` // KeyIdentifier OCTET STRING
		AuthorityCertIssuer       asn1.RawValue `asn1:"tag:1,optional"` // GeneralNames
		AuthorityCertSerialNumber int           `asn1:"tag:2,optional"` // CertificateSerialNumber
	}
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return AuthorityKeyIdentifier{}, err
	}

	var names []string
	if out.AuthorityCertIssuer.Bytes != nil {
		v, err := ToGeneralNames(out.AuthorityCertIssuer.Bytes)
		if err != nil {
			return AuthorityKeyIdentifier{}, err
		}
		names = v
	}

	return AuthorityKeyIdentifier{
		KeyIdentifier:             out.KeyIdentifier.Bytes,
		AuthorityCertIssuer:       names,
		AuthorityCertSerialNumber: out.AuthorityCertSerialNumber,
	}, nil
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
func ToKeyUsage(in []byte) ([]string, error) {
	var out asn1.BitString
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return nil, err
	}
	return toKeyUsage(out), nil
}

// AuthorityInfoAccessSyntax  ::=
// SEQUENCE SIZE (1..MAX) OF AccessDescription
//
// AccessDescription  ::=  SEQUENCE {
// accessMethod          OBJECT IDENTIFIER,
// accessLocation        GeneralName  }

type AccessDescription struct {
	AccessMethod   string
	AccessLocation string
}

func ToAuthorityInformationAccess(in []byte) ([]AccessDescription, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	var accesses []AccessDescription
	for {
		var out struct {
			AccessMethod   asn1.ObjectIdentifier
			AccessLocation asn1.RawValue // TODO parse to general name
		}
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}
		name := toGeneralName(out.AccessLocation)
		oid := out.AccessMethod.String()
		accesses = append(accesses, AccessDescription{
			AccessMethod:   fmt.Sprintf("%s (%s)", accessDescriptorsOIDs[oid], oid),
			AccessLocation: fmt.Sprintf("%s: %s", name.Type, name.Value),
		})
		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return accesses, nil
}

func ToExtendedKeyUsage(in []byte) ([]string, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	var extKeyUsages []string
	for {
		var out asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}

		extKeyUsage := out.String()
		if v, ok := idKpOIDs[extKeyUsage]; ok {
			extKeyUsage = fmt.Sprintf("%s (%s)", v, extKeyUsage)
		}
		extKeyUsages = append(extKeyUsages, extKeyUsage)

		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return extKeyUsages, nil
}

// BasicConstraints ::= SEQUENCE {
// cA                      BOOLEAN DEFAULT FALSE,
// pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
type BasicConstraints struct {
	CA                bool `asn1:"optional"`
	PathLenConstraint int  `asn1:"optional"`
}

func ToBasicConstraints(in []byte) (BasicConstraints, error) {
	var out BasicConstraints
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return BasicConstraints{}, err
	}
	return out, nil
}

// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

// PolicyInformation ::= SEQUENCE {
// policyIdentifier   OBJECT IDENTIFIER,
// policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }

// PolicyQualifierInfo ::= SEQUENCE {
// policyQualifierId  OBJECT IDENTIFIER,
// qualifier          ANY DEFINED BY policyQualifierId }

// ToCertificatePolicies returns slice of "identifier: qualifier" values
func ToCertificatePolicies(in []byte) ([]string, error) {
	sequence := asn1.RawValue{Tag: asn1.TagSequence}
	if _, err := asn1.Unmarshal(in, &sequence); err != nil {
		return nil, err
	}
	in = sequence.Bytes

	var policies []string
	for {
		var out struct {
			PolicyIdentifier asn1.ObjectIdentifier
			PolicyQualifiers asn1.RawValue `asn1:"optional"`
		}
		rest, err := asn1.Unmarshal(in, &out)
		if err != nil {
			return nil, err
		}

		policy := out.PolicyIdentifier.String()
		if v, ok := certificatePoliciesOIDs[policy]; ok {
			// if we find correct oid, use that
			policy = fmt.Sprintf("%s (%s)", v, policy)
		}
		// TODO - policy qualifiers when I find appropriate cert to test

		policies = append(policies, policy)

		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return policies, nil
}

func ToSignedCertificateTimestampList(in []byte) ([]byte, error) {
	var out asn1.RawValue // OCTET STRING
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return nil, err
	}
	return out.Bytes, nil
}

// --- bit strings and conversions ---

// order is important, it matches either asn tag or bit string

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

var generalNames = []string{
	"Other Name",
	"Rfc822 Name",
	"DNS Name",
	"X400 Address",
	"Directory Name",
	"EdiParty Name",
	"URI",
	"IP Address",
	"Registered ID",
}

type GeneralName struct {
	Type  string // dns name, ip address, ...
	Value string
}

func toGeneralName(in asn1.RawValue) GeneralName {
	if len(generalNames) <= in.Tag {
		return GeneralName{}
	}
	value := string(in.Bytes)

	if in.Tag == 0 {
		//	OtherName ::= SEQUENCE {
		//	    type-id OBJECT IDENTIFIER,
		//	    value   [0] EXPLICIT ANY DEFINED BY type-id }
		var out struct {
			TypeId asn1.ObjectIdentifier
			Value  asn1.RawValue `asn1:"optional"`
		}
		// only if there is no error, otherwise continue and just use default value
		if _, err := asn1.Unmarshal(in.Bytes, &out); err == nil {
			value = fmt.Sprintf("%s: %s", out.TypeId.String(), string(out.Value.Bytes))
		}
	}

	return GeneralName{
		Type:  generalNames[in.Tag],
		Value: value,
	}
}

// --- OIDs ---

var certificatePoliciesOIDs = map[string]string{
	"2.5.29.32.0": "any policy",
	"2.5.29.32.2": "ldap",

	"2.23.140.1.1": "ev guidelines",

	// baseline requirements
	"2.23.140.1.2.1": "domain validated",
	"2.23.140.1.2.2": "organization validated",
	"2.23.140.1.2.3": "individual validated",

	"2.23.140.1.3": "extended-validation codesigning",

	// code-signing-requirements
	"2.23.140.1.4.1": "code signing",
	"2.23.140.1.4.2": "timestamping",

	// smime
	"2.23.140.1.5.1": "mailbox validated",
	"2.23.140.1.5.2": "organization validated",
	"2.23.140.1.5.3": "sponsor validated",
	"2.23.140.1.5.4": "individual validated",

	"2.23.140.31": "onion-ev",

	// google trust services, certificate policy
	"1.3.6.1.4.1.11129.2.5.3.1": "signed http exchanges",
	"1.3.6.1.4.1.11129.2.5.3.2": "client authentication",
	"1.3.6.1.4.1.11129.2.5.3.3": "document signing",
}

var idKpOIDs = map[string]string{
	"1.3.6.1.5.5.7.3.1": "server auth",
	"1.3.6.1.5.5.7.3.2": "client auth",
	"1.3.6.1.5.5.7.3.3": "code signing",
	"1.3.6.1.5.5.7.3.4": "email protection",
	"1.3.6.1.5.5.7.3.5": "ipsec end system",
	"1.3.6.1.5.5.7.3.6": "ipsec tunnel",
	"1.3.6.1.5.5.7.3.7": "ipsec user",
	"1.3.6.1.5.5.7.3.8": "time stamping",
	"1.3.6.1.5.5.7.3.9": "OCSP signing",
	// TODO add the rest
}

var accessDescriptorsOIDs = map[string]string{
	"1.3.6.1.5.5.7.48.1":  "ocsp",
	"1.3.6.1.5.5.7.48.2":  "ca issuers",
	"1.3.6.1.5.5.7.48.3":  "time stamping",
	"1.3.6.1.5.5.7.48.4":  "dvcs",
	"1.3.6.1.5.5.7.48.5":  "ca repository",
	"1.3.6.1.5.5.7.48.6":  "http certs",
	"1.3.6.1.5.5.7.48.7":  "http crls",
	"1.3.6.1.5.5.7.48.8":  "xkms",
	"1.3.6.1.5.5.7.48.9":  "signed object repository",
	"1.3.6.1.5.5.7.48.10": "rpki manifest",
	"1.3.6.1.5.5.7.48.11": "signed object",
	"1.3.6.1.5.5.7.48.12": "cmc",
	"1.3.6.1.5.5.7.48.13": "rpki notify",
	"1.3.6.1.5.5.7.48.14": "stir tn list",
}
