package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RFC 5280 §5.3.1 revocation reason codes.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

// revocationReasons maps each code to its RFC 5280 name.
var revocationReasons = map[int]string{
	ReasonUnspecified:          "unspecified",
	ReasonKeyCompromise:        "keyCompromise",
	ReasonCACompromise:         "cACompromise",
	ReasonAffiliationChanged:   "affiliationChanged",
	ReasonSuperseded:           "superseded",
	ReasonCessationOfOperation: "cessationOfOperation",
	ReasonCertificateHold:      "certificateHold",
	ReasonRemoveFromCRL:        "removeFromCRL",
	ReasonPrivilegeWithdrawn:   "privilegeWithdrawn",
	ReasonAACompromise:         "aACompromise",
}

// RevocationReasonName returns the RFC 5280 name for a reason code.
func RevocationReasonName(code int) string {
	if name, ok := revocationReasons[code]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", code)
}

// ValidateRevocationReason rejects codes RFC 5280 does not define. Value 7 is
// deliberately unassigned.
func ValidateRevocationReason(code int) error {
	if _, ok := revocationReasons[code]; !ok {
		return fmt.Errorf("pki: %d is not an RFC 5280 revocation reason code", code)
	}
	return nil
}

// RevokedCertificate is one entry of a CRL.
type RevokedCertificate struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	ReasonCode   int
}

// CRLRequest describes a certificate revocation list to generate.
type CRLRequest struct {
	// Number is the monotonically increasing CRL sequence number. Verifiers
	// use it to reject a replayed older list.
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    []RevokedCertificate
}

// GenerateCRL signs a CRL for the CA's issued certificates. An empty revoked
// list is valid and meaningful: it publishes "nothing is revoked".
func GenerateCRL(ca *CertificateAuthority, req CRLRequest) ([]byte, error) {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: an issuing CA with its private key is required")
	}
	if ca.Certificate.KeyUsage != 0 && ca.Certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("pki: CA %q lacks the cRLSign usage", ca.Certificate.Subject.CommonName)
	}

	thisUpdate := req.ThisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now()
	}
	nextUpdate := req.NextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = thisUpdate.Add(7 * 24 * time.Hour)
	}
	number := req.Number
	if number == nil {
		number = big.NewInt(1)
	}

	entries := make([]x509.RevocationListEntry, 0, len(req.Revoked))
	for _, r := range req.Revoked {
		if r.SerialNumber == nil {
			return nil, errors.New("pki: revocation entry has no serial number")
		}
		revokedAt := r.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = thisUpdate
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   r.SerialNumber,
			RevocationTime: revokedAt.UTC(),
			ReasonCode:     r.ReasonCode,
		})
	}

	template := &x509.RevocationList{
		SignatureAlgorithm:        signatureAlgorithmFor(ca.PrivateKey),
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                thisUpdate.UTC(),
		NextUpdate:                nextUpdate.UTC(),
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, ca.Certificate, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pki: create CRL: %w", err)
	}
	return der, nil
}

// EncodeCRLPEM wraps a DER CRL in a PEM block.
func EncodeCRLPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: BlockCRL, Bytes: der})
}

// ParseCRL decodes a PEM or DER revocation list.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil && block.Type == BlockCRL {
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CRL: %w", err)
	}
	return crl, nil
}
