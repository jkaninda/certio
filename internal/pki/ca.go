package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// serialBits is the width of generated serial numbers. RFC 5280 caps serials
// at 20 octets; 128 bits leaves room for the sign bit and is what public CAs
// use. Random serials also remove the need for the fragile .srl files the
// openssl workflow depends on.
const serialBits = 128

// clockSkew back-dates NotBefore so a certificate is usable on a peer whose
// clock is slightly behind.
const clockSkew = 5 * time.Minute

// Certificate aliases x509.Certificate so callers can work with the PKI
// package without importing crypto/x509 alongside it.
type Certificate = x509.Certificate

// CARequest describes a certificate authority to create.
type CARequest struct {
	Subject Subject
	KeySpec KeySpec

	// ValidityDays defaults to the profile value (10 years root, 5 years
	// intermediate) when zero.
	ValidityDays int

	// MaxPathLen limits how many CAs may appear below this one. Zero with
	// MaxPathLenZero set means "may only issue leaves".
	MaxPathLen     int
	MaxPathLenZero bool

	// CRLDistributionPoints and OCSPServer are baked into every certificate
	// this CA issues, not into the CA certificate itself.
	CRLDistributionPoints []string
	OCSPServer            []string

	// NameConstraints limits what this CA may certify. Empty means unlimited,
	// which is the historical default and the reason a stolen private root is
	// so much worse than it needs to be.
	NameConstraints NameConstraints

	// NotBefore overrides the start of the validity window. Zero means now.
	NotBefore time.Time
}

// CertificateAuthority is a created or loaded CA: its certificate, its private
// key and the chain up to the root.
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	// Chain holds the issuers above this CA, ordered from the immediate parent
	// to the root. Empty for a root CA.
	Chain []*x509.Certificate
}

// IsRoot reports whether the CA is self-signed.
func (ca *CertificateAuthority) IsRoot() bool {
	return len(ca.Chain) == 0 && isSelfSigned(ca.Certificate)
}

// CreateRootCA generates a key and a self-signed CA certificate.
func CreateRootCA(req CARequest) (*CertificateAuthority, error) {
	req.Subject = req.Subject.Normalize()
	if err := req.Subject.Validate(); err != nil {
		return nil, err
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = profiles[ProfileRoot].ValidityDays
	}

	key, err := GenerateKey(req.KeySpec)
	if err != nil {
		return nil, err
	}

	template, err := caTemplate(req)
	if err != nil {
		return nil, err
	}

	// Self-signed: the template is both subject and issuer.
	template.Issuer = template.Subject
	template.SignatureAlgorithm = signatureAlgorithmFor(key)
	template.AuthorityKeyId = nil // derived from SubjectKeyId by crypto/x509

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: create root CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse created root CA: %w", err)
	}
	return &CertificateAuthority{Certificate: cert, PrivateKey: key}, nil
}

// CreateIntermediateCA generates a key and has the parent CA sign the
// resulting CA certificate.
func CreateIntermediateCA(parent *CertificateAuthority, req CARequest) (*CertificateAuthority, error) {
	if parent == nil || parent.Certificate == nil || parent.PrivateKey == nil {
		return nil, errors.New("pki: an issuing CA with its private key is required")
	}
	req.Subject = req.Subject.Normalize()
	if err := req.Subject.Validate(); err != nil {
		return nil, err
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = profiles[ProfileIntermediate].ValidityDays
	}

	key, err := GenerateKey(req.KeySpec)
	if err != nil {
		return nil, err
	}

	template, err := caTemplate(req)
	if err != nil {
		return nil, err
	}
	if err := checkIssuerCanSign(parent.Certificate, template.NotAfter, true); err != nil {
		return nil, err
	}
	template.SignatureAlgorithm = signatureAlgorithmFor(parent.PrivateKey)

	der, err := x509.CreateCertificate(rand.Reader, template, parent.Certificate, key.Public(), parent.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pki: create intermediate CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse created intermediate CA: %w", err)
	}

	chain := append([]*x509.Certificate{parent.Certificate}, parent.Chain...)
	return &CertificateAuthority{Certificate: cert, PrivateKey: key, Chain: chain}, nil
}

// caTemplate builds the certificate template shared by root and intermediate
// creation.
func caTemplate(req CARequest) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-clockSkew)
	}

	profile := profiles[ProfileRoot]
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject.ToPKIX(),
		NotBefore:             notBefore.UTC(),
		NotAfter:              notBefore.AddDate(0, 0, req.ValidityDays).UTC(),
		KeyUsage:              profile.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            req.MaxPathLen,
		MaxPathLenZero:        req.MaxPathLenZero,
		CRLDistributionPoints: req.CRLDistributionPoints,
		OCSPServer:            req.OCSPServer,
	}

	constraints := req.NameConstraints.Normalize()
	if !constraints.IsZero() {
		if err := constraints.Validate(); err != nil {
			return nil, err
		}
		permittedIP, excludedIP, err := constraints.IPNets()
		if err != nil {
			return nil, err
		}
		// Marked critical, which is the whole point: a verifier that does not
		// understand the extension must reject the chain rather than ignore
		// the limit and trust the CA for everything.
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = constraints.PermittedDNS
		template.ExcludedDNSDomains = constraints.ExcludedDNS
		template.PermittedIPRanges = permittedIP
		template.ExcludedIPRanges = excludedIP
		template.PermittedEmailAddresses = constraints.PermittedEmail
		template.ExcludedEmailAddresses = constraints.ExcludedEmail
		template.PermittedURIDomains = constraints.PermittedURI
		template.ExcludedURIDomains = constraints.ExcludedURI
	}
	return template, nil
}

// ConstraintsOf reads the name constraints back off a CA certificate, so an
// imported CA reports the limits it already carries instead of appearing
// unconstrained.
func ConstraintsOf(cert *x509.Certificate) NameConstraints {
	if cert == nil {
		return NameConstraints{}
	}
	constraints := NameConstraints{
		PermittedDNS:   cert.PermittedDNSDomains,
		ExcludedDNS:    cert.ExcludedDNSDomains,
		PermittedEmail: cert.PermittedEmailAddresses,
		ExcludedEmail:  cert.ExcludedEmailAddresses,
		PermittedURI:   cert.PermittedURIDomains,
		ExcludedURI:    cert.ExcludedURIDomains,
	}
	for _, network := range cert.PermittedIPRanges {
		constraints.PermittedIP = append(constraints.PermittedIP, network.String())
	}
	for _, network := range cert.ExcludedIPRanges {
		constraints.ExcludedIP = append(constraints.ExcludedIP, network.String())
	}
	return constraints.Normalize()
}

// ImportCA adopts an existing CA from PEM certificate and key material — the
// path that lets this repo's jkantech-ca.crt/.key move into Certio unchanged.
func ImportCA(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	certs, err := ParseCertificatesPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no CERTIFICATE block found in the supplied PEM")
	}

	key, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	leaf := certs[0]
	if !leaf.IsCA {
		return nil, errors.New("pki: the supplied certificate is not a CA " +
			"(basicConstraints CA:TRUE is missing)")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("pki: the supplied CA certificate lacks the keyCertSign usage")
	}
	if !KeyMatchesCertificate(key, leaf) {
		return nil, errors.New("pki: the supplied private key does not match the certificate")
	}

	return &CertificateAuthority{Certificate: leaf, PrivateKey: key, Chain: certs[1:]}, nil
}

// GenerateSerial returns a positive cryptographically random serial number.
func GenerateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	for range 8 {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("pki: generate serial: %w", err)
		}
		// Zero is not a legal serial; anything else is fine.
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
	return nil, errors.New("pki: could not generate a non-zero serial number")
}

// FormatSerial renders a serial as lowercase hex, zero-padded to a byte
// boundary — the form openssl prints and the form Certio stores.
func FormatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	hexStr := fmt.Sprintf("%x", serial)
	if len(hexStr)%2 == 1 {
		hexStr = "0" + hexStr
	}
	return hexStr
}

// ParseSerial reads a hex serial back into a big.Int.
func ParseSerial(s string) (*big.Int, error) {
	serial, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("pki: %q is not a valid hexadecimal serial number", s)
	}
	return serial, nil
}

// checkIssuerCanSign verifies the issuer is a usable CA for a certificate
// expiring at notAfter. Signing something that outlives its issuer is the
// mistake this catches — the certificate would verify today and fail later.
func checkIssuerCanSign(issuer *x509.Certificate, notAfter time.Time, forCA bool) error {
	now := time.Now()
	if now.Before(issuer.NotBefore) {
		return fmt.Errorf("pki: issuing CA %q is not valid until %s",
			issuer.Subject.CommonName, issuer.NotBefore.Format(time.RFC3339))
	}
	if now.After(issuer.NotAfter) {
		return fmt.Errorf("pki: issuing CA %q expired on %s — renew the CA first",
			issuer.Subject.CommonName, issuer.NotAfter.Format(time.RFC3339))
	}
	if !issuer.IsCA {
		return fmt.Errorf("pki: %q is not a CA certificate", issuer.Subject.CommonName)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("pki: CA %q lacks the keyCertSign usage", issuer.Subject.CommonName)
	}
	if notAfter.After(issuer.NotAfter) {
		return fmt.Errorf("pki: requested expiry %s is after the issuing CA %q expires on %s — "+
			"shorten the validity or renew the CA first",
			notAfter.Format(time.RFC3339), issuer.Subject.CommonName, issuer.NotAfter.Format(time.RFC3339))
	}
	if forCA && issuer.MaxPathLenZero {
		return fmt.Errorf("pki: CA %q has pathLenConstraint 0 and may not issue intermediate CAs",
			issuer.Subject.CommonName)
	}
	if forCA && issuer.MaxPathLen > 0 {
		// MaxPathLen counts the intermediates allowed *below* this issuer.
		// One of them is the CA being created, which is legal; deeper nesting
		// is checked when that CA in turn signs.
		return nil
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// EncodeCertificatePEM wraps a parsed certificate back into PEM.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: BlockCertificate, Bytes: cert.Raw})
}

// ParseCertificateDER parses a raw DER certificate, which is how ACME carries
// one in a revocation request.
func ParseCertificateDER(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert, nil
}

// ParseCertificatePEM decodes the first certificate in a PEM document.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no CERTIFICATE block found in PEM input")
	}
	return certs[0], nil
}

// ParseCertificatesPEM decodes every certificate in a PEM document, in order.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != BlockCertificate {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no CERTIFICATE block found in PEM input")
	}
	return certs, nil
}
