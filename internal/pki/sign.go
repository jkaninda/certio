package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// IssueRequest describes a certificate to generate and sign. Certio creates
// the key, so the caller receives both halves.
type IssueRequest struct {
	Subject Subject
	SANs    SANSet
	KeySpec KeySpec
	Profile string

	// ValidityDays defaults to the profile value when zero.
	ValidityDays int
	// NotBefore overrides the start of the validity window. Zero means now.
	NotBefore time.Time

	// KeyUsage and ExtKeyUsage override the profile defaults when non-empty.
	KeyUsage    []string
	ExtKeyUsage []string

	CRLDistributionPoints []string
	OCSPServer            []string
}

// IssuedCertificate is a freshly signed certificate and its private key.
type IssuedCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	// Chain is the issuer chain, parent first, root last.
	Chain []*x509.Certificate
}

// Issue generates a key and signs a certificate for it with the given CA.
func Issue(ca *CertificateAuthority, req IssueRequest) (*IssuedCertificate, error) {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: an issuing CA with its private key is required")
	}

	key, err := GenerateKey(req.KeySpec)
	if err != nil {
		return nil, err
	}

	cert, err := SignPublicKey(ca, key.Public(), req)
	if err != nil {
		return nil, err
	}
	return &IssuedCertificate{
		Certificate: cert,
		PrivateKey:  key,
		Chain:       append([]*x509.Certificate{ca.Certificate}, ca.Chain...),
	}, nil
}

// SignCSR signs an externally supplied CSR. The subject and SANs come from the
// CSR unless the request overrides them, and the private key never exists on
// this side of the wire.
func SignCSR(ca *CertificateAuthority, csr *x509.CertificateRequest, req IssueRequest) (*x509.Certificate, error) {
	if err := ValidateCSRForSigning(csr); err != nil {
		return nil, err
	}

	if req.Subject.CommonName == "" {
		req.Subject = SubjectFromPKIX(csr.Subject)
	}
	if len(req.SANs) == 0 {
		req.SANs = SANsFromCertificateLike(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs)
	}

	// A CSR with SANs and no common name is not malformed — it is what modern
	// tooling produces, certbot included, because every client stopped reading
	// the CN years ago. Rejecting it would make Certio unable to sign for the
	// clients most likely to be automated, so the first SAN fills the field
	// the certificate still has to carry.
	if req.Subject.CommonName == "" {
		if name := req.SANs.PrimaryName(); name != "" {
			req.Subject.CommonName = name
		}
	}
	return SignPublicKey(ca, csr.PublicKey, req)
}

// SignPublicKey is the single code path every certificate goes through: it
// builds the template, applies the profile, checks the issuer, and signs.
func SignPublicKey(ca *CertificateAuthority, pub crypto.PublicKey, req IssueRequest) (*x509.Certificate, error) {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: an issuing CA with its private key is required")
	}

	profile, err := LookupProfile(req.Profile)
	if err != nil {
		return nil, err
	}

	req.Subject = req.Subject.Normalize()
	if err := req.Subject.Validate(); err != nil {
		return nil, err
	}

	// The CN is folded into the DNS SANs when it looks like a hostname:
	// every modern client ignores the CN outright.
	sans := req.SANs
	if !profile.IsCA {
		sans = sans.AddDNS(req.Subject.CommonName)
		if err := sans.Validate(); err != nil {
			return nil, err
		}
	}
	dnsNames, ips, emails, uris, err := sans.Split()
	if err != nil {
		return nil, err
	}

	keyUsage := profile.KeyUsage
	if len(req.KeyUsage) > 0 {
		if keyUsage, err = ParseKeyUsages(req.KeyUsage); err != nil {
			return nil, err
		}
	}
	extKeyUsage := profile.ExtKeyUsage
	if len(req.ExtKeyUsage) > 0 {
		if extKeyUsage, err = ParseExtKeyUsages(req.ExtKeyUsage); err != nil {
			return nil, err
		}
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = profile.ValidityDays
	}
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-clockSkew)
	}
	notAfter := notBefore.AddDate(0, 0, validityDays)

	if err := checkIssuerCanSign(ca.Certificate, notAfter, profile.IsCA); err != nil {
		return nil, err
	}

	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}
	skid, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          skid,
		Subject:               req.Subject.ToPKIX(),
		NotBefore:             notBefore.UTC(),
		NotAfter:              notAfter.UTC(),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  profile.IsCA,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		URIs:                  uris,
		CRLDistributionPoints: req.CRLDistributionPoints,
		OCSPServer:            req.OCSPServer,
		SignatureAlgorithm:    signatureAlgorithmFor(ca.PrivateKey),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, pub, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pki: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse signed certificate: %w", err)
	}
	return cert, nil
}

// RenewRequest describes a re-issue of an existing certificate.
type RenewRequest struct {
	// Rekey generates a fresh key pair. The default re-signs the same public
	// key, which preserves any pinning that depends on it.
	Rekey bool
	// KeySpec applies only when Rekey is set; zero reuses the current spec.
	KeySpec KeySpec
	// ValidityDays defaults to the profile value when zero.
	ValidityDays int
	// Subject and SANs override the originals when set.
	Subject *Subject
	SANs    SANSet
	Profile string

	CRLDistributionPoints []string
	OCSPServer            []string
}

// Renew re-issues a certificate from its current contents. The result is a new
// certificate with a new serial — never an in-place mutation — so the old one
// stays auditable and revocable.
func Renew(ca *CertificateAuthority, current *x509.Certificate, currentKey crypto.Signer, req RenewRequest) (*IssuedCertificate, error) {
	if current == nil {
		return nil, errors.New("pki: no certificate supplied to renew")
	}

	subject := SubjectFromPKIX(current.Subject)
	if req.Subject != nil {
		subject = *req.Subject
	}
	sans := req.SANs
	if len(sans) == 0 {
		sans = SANsFromCertificateLike(current.DNSNames, current.IPAddresses, current.EmailAddresses, current.URIs)
	}
	profile := req.Profile
	if profile == "" {
		profile = InferProfile(current)
	}

	issueReq := IssueRequest{
		Subject:               subject,
		SANs:                  sans,
		Profile:               profile,
		ValidityDays:          req.ValidityDays,
		CRLDistributionPoints: req.CRLDistributionPoints,
		OCSPServer:            req.OCSPServer,
	}

	if !req.Rekey {
		if currentKey == nil {
			return nil, errors.New("pki: the existing private key is required to renew without rekeying")
		}
		cert, err := SignPublicKey(ca, currentKey.Public(), issueReq)
		if err != nil {
			return nil, err
		}
		return &IssuedCertificate{
			Certificate: cert,
			PrivateKey:  currentKey,
			Chain:       append([]*x509.Certificate{ca.Certificate}, ca.Chain...),
		}, nil
	}

	spec := req.KeySpec
	if spec.Algorithm == "" {
		derived, err := SpecOf(current.PublicKey)
		if err != nil {
			return nil, err
		}
		spec = derived
	}
	issueReq.KeySpec = spec
	return Issue(ca, issueReq)
}

// InferProfile guesses which profile a parsed certificate was issued under,
// used when renewing a certificate Certio did not originally issue.
func InferProfile(cert *x509.Certificate) string {
	if cert.IsCA {
		if isSelfSigned(cert) {
			return ProfileRoot
		}
		return ProfileIntermediate
	}

	var server, client, codeSigning bool
	for _, u := range cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			server = true
		case x509.ExtKeyUsageClientAuth:
			client = true
		case x509.ExtKeyUsageCodeSigning:
			codeSigning = true
		}
	}
	switch {
	case server && client:
		return ProfilePeer
	case client:
		return ProfileClient
	case codeSigning:
		return ProfileCodeSigning
	default:
		return ProfileServer
	}
}
