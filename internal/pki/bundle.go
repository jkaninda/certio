package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Bundle is a certificate plus everything needed to serve or trust it.
type Bundle struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	// Chain is the issuer chain, immediate parent first, root last.
	Chain []*x509.Certificate
}

// CertPEM is the leaf certificate alone.
func (b Bundle) CertPEM() []byte { return EncodeCertificatePEM(b.Certificate) }

// ChainPEM is the issuer chain without the leaf — what nginx calls the
// intermediate bundle and what a client needs to build a path.
func (b Bundle) ChainPEM() []byte {
	var buf bytes.Buffer
	for _, c := range b.Chain {
		buf.Write(EncodeCertificatePEM(c))
	}
	return buf.Bytes()
}

// FullChainPEM is the leaf followed by its issuers — the file nginx's
// ssl_certificate and Traefik's certFile both expect.
func (b Bundle) FullChainPEM() []byte {
	var buf bytes.Buffer
	buf.Write(b.CertPEM())
	buf.Write(b.ChainPEM())
	return buf.Bytes()
}

// RootPEM is the trust anchor at the top of the chain, or the leaf itself when
// the bundle is a self-signed root.
func (b Bundle) RootPEM() []byte {
	if len(b.Chain) == 0 {
		return b.CertPEM()
	}
	return EncodeCertificatePEM(b.Chain[len(b.Chain)-1])
}

// KeyPEM encodes the private key as PKCS#8 PEM, optionally passphrase-
// protected in the legacy openssl format.
func (b Bundle) KeyPEM(passphrase string) ([]byte, error) {
	if b.PrivateKey == nil {
		return nil, errors.New("pki: no private key in this bundle")
	}
	if passphrase == "" {
		return MarshalPrivateKeyPEM(b.PrivateKey)
	}
	return EncryptPrivateKeyPEM(b.PrivateKey, passphrase)
}

// PKCS12 packages the leaf, its key and the chain into a .p12/.pfx file — the
// format Java keystores, Windows and many appliances import.
//
// The modern encoder (AES-256-CBC + SHA-256) is used because the legacy one
// relies on RC2/3DES, which current JDKs and OpenSSL 3 reject by default.
func (b Bundle) PKCS12(password string) ([]byte, error) {
	if b.PrivateKey == nil {
		return nil, errors.New("pki: PKCS#12 export requires the private key")
	}
	if password == "" {
		return nil, errors.New("pki: PKCS#12 export requires a password")
	}
	data, err := pkcs12.Modern.Encode(b.PrivateKey, b.Certificate, b.Chain, password)
	if err != nil {
		return nil, fmt.Errorf("pki: encode PKCS#12: %w", err)
	}
	return data, nil
}

// TrustStorePKCS12 packages CA certificates alone, for importing into a Java
// truststore.
func TrustStorePKCS12(certs []*x509.Certificate, password string) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("pki: no certificates to package")
	}
	entries := make([]pkcs12.TrustStoreEntry, 0, len(certs))
	for _, c := range certs {
		entries = append(entries, pkcs12.TrustStoreEntry{
			Cert:         c,
			FriendlyName: c.Subject.CommonName,
		})
	}
	data, err := pkcs12.Modern.EncodeTrustStoreEntries(entries, password)
	if err != nil {
		return nil, fmt.Errorf("pki: encode PKCS#12 trust store: %w", err)
	}
	return data, nil
}

// Verify builds a path from the leaf to the root of its own chain and checks
// it with crypto/x509 — the same code a client uses. This is what proves an
// issued certificate is actually usable, rather than merely well-formed.
func (b Bundle) Verify(at time.Time, keyUsages ...x509.ExtKeyUsage) error {
	if b.Certificate == nil {
		return errors.New("pki: nothing to verify")
	}
	if at.IsZero() {
		at = time.Now()
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	switch {
	case len(b.Chain) == 0:
		// Self-signed: it is its own trust anchor.
		roots.AddCert(b.Certificate)
	default:
		roots.AddCert(b.Chain[len(b.Chain)-1])
		for _, c := range b.Chain[:len(b.Chain)-1] {
			intermediates.AddCert(c)
		}
	}

	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	_, err := b.Certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     keyUsages,
	})
	if err != nil {
		return fmt.Errorf("pki: chain verification failed: %w", err)
	}
	return nil
}

// BuildChain orders a set of certificates into a path from leaf to root,
// following issuer links. Used when importing a CA whose PEM file lists the
// chain in an arbitrary order.
func BuildChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate
	current := leaf
	used := map[string]bool{Fingerprint(leaf): true}

	for range len(pool) {
		var issuer *x509.Certificate
		for _, candidate := range pool {
			if used[Fingerprint(candidate)] {
				continue
			}
			if err := current.CheckSignatureFrom(candidate); err == nil {
				issuer = candidate
				break
			}
		}
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		used[Fingerprint(issuer)] = true
		if isSelfSigned(issuer) {
			break
		}
		current = issuer
	}
	return chain
}

// ChainStatus reports the health of one link in the chain, for the UI's chain
// viewer.
type ChainStatus struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsCA          bool      `json:"is_ca"`
	SelfSigned    bool      `json:"self_signed"`
	Valid         bool      `json:"valid"`
	Problem       string    `json:"problem,omitempty"`
	DaysRemaining int       `json:"days_remaining"`
	PEM           string    `json:"pem"`
}

// DescribeChain walks leaf → root and reports each link's validity, so the UI
// can show which specific certificate broke the chain.
func (b Bundle) DescribeChain(at time.Time) []ChainStatus {
	if at.IsZero() {
		at = time.Now()
	}
	all := append([]*x509.Certificate{b.Certificate}, b.Chain...)
	out := make([]ChainStatus, 0, len(all))

	for i, cert := range all {
		status := ChainStatus{
			Subject:       cert.Subject.CommonName,
			Issuer:        cert.Issuer.CommonName,
			SerialNumber:  FormatSerial(cert.SerialNumber),
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			IsCA:          cert.IsCA,
			SelfSigned:    isSelfSigned(cert),
			DaysRemaining: int(cert.NotAfter.Sub(at).Hours() / 24),
			Valid:         true,
			PEM:           string(EncodeCertificatePEM(cert)),
		}

		switch {
		case at.Before(cert.NotBefore):
			status.Valid, status.Problem = false, "not valid yet"
		case at.After(cert.NotAfter):
			status.Valid, status.Problem = false, "expired"
		case i+1 < len(all):
			if err := cert.CheckSignatureFrom(all[i+1]); err != nil {
				status.Valid, status.Problem = false, "not signed by the next certificate in the chain"
			}
		case !status.SelfSigned:
			status.Problem = "chain is incomplete — the issuer of this certificate is missing"
		}
		out = append(out, status)
	}
	return out
}
