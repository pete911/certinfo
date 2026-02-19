package cert

import (
	"encoding/asn1"
	"fmt"
	"github.com/pete911/certinfo/pkg/cert/format"
	"math/big"
	"strings"
)

type RSAPublicKeyInfo struct {
	Modulus        *big.Int
	PublicExponent *big.Int
}

// RSAPublicKey ::= SEQUENCE {
// modulus            INTEGER,    -- n
// publicExponent     INTEGER  }  -- e

func toRSAPublicKeyInfo(in []byte) (RSAPublicKeyInfo, error) {
	var pk RSAPublicKeyInfo
	if _, err := asn1.Unmarshal(in, &pk); err != nil {
		return RSAPublicKeyInfo{}, err
	}
	return pk, nil
}

func (p RSAPublicKeyInfo) String() string {
	lines := []string{
		"Public Key Algorithm: RSA",
		fmt.Sprintf("    Public Key: (%d bit)", p.Modulus.BitLen()),
		"    Modulus",
	}
	lines = append(lines, format.SplitString(format.HexArray(p.Modulus.Bytes()), "        ", 45)...)
	lines = append(lines, fmt.Sprintf("    Exponent: %s", p.PublicExponent))
	return strings.Join(lines, "\n")
}

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
// algorithm            AlgorithmIdentifier,
// subjectPublicKey     BIT STRING  }

// AlgorithmIdentifier  ::=  SEQUENCE  {
// algorithm            OBJECT IDENTIFIER,
// parameters           ANY DEFINED BY algorithm OPTIONAL  }

func ToSubjectPublicKeyInfo(in []byte) (fmt.Stringer, error) {
	var out struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(in, &out); err != nil {
		return nil, err
	}

	algorithmOid := out.Algorithm.Algorithm.String()
	var algorithm string
	algorithm, ok := publicKeyAlgorithmOIDs[algorithmOid]
	if !ok {
		return nil, fmt.Errorf("unknown public key algorithm oid: %s", algorithm)
	}

	// RSA, DSA, ECDSA, X25519, Ed25519
	// https://datatracker.ietf.org/doc/html/rfc3279
	if algorithm == "RSA" {
		return toRSAPublicKeyInfo(out.SubjectPublicKey.Bytes)
	}
	if algorithm == "DSA" {
		// TODO
	}
	if algorithm == "ECDSA" {
		// TODO
	}
	if algorithm == "X25519" {
		// TODO
	}
	if algorithm == "Ed25519" {
		// TODO
	}
	return nil, nil
}

var publicKeyAlgorithmOIDs = map[string]string{
	"1.2.840.113549.1.1.1": "RSA",
	"1.2.840.10040.4.1":    "DSA",
	"1.2.840.10045.2.1":    "ECDSA",
	"1.3.101.110":          "X25519",
	"1.3.101.112":          "Ed25519",
}
