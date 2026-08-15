// Package pki is the X.509 engine behind Certio: key generation, CSRs,
// signing, SAN handling, CRLs and bundling. It is built entirely on the Go
// standard library — no openssl binary, no shelling out, no temp files.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 specifies SHA-1 for key identifiers
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Key algorithm families.
const (
	AlgoRSA     = "rsa"
	AlgoECDSA   = "ecdsa"
	AlgoEd25519 = "ed25519"
)

// ECDSA curve names, in the spelling X9.62 and every tool that prints a key
// uses — which is also what is stored and returned over the API.
const (
	CurveP256 = "P-256"
	CurveP384 = "P-384"
	CurveP521 = "P-521"
)

// PEM block types Certio reads and writes.
const (
	BlockPrivateKey     = "PRIVATE KEY"
	BlockRSAPrivateKey  = "RSA PRIVATE KEY"
	BlockECPrivateKey   = "EC PRIVATE KEY"
	BlockCertificate    = "CERTIFICATE"
	BlockCertificateReq = "CERTIFICATE REQUEST"
	BlockNewCertReq     = "NEW CERTIFICATE REQUEST"
	BlockCRL            = "X509 CRL"
)

// KeySpec identifies a key algorithm and its strength.
type KeySpec struct {
	Algorithm string // rsa | ecdsa | ed25519
	Size      int    // RSA modulus bits
	Curve     string // ECDSA curve: P-256 | P-384 | P-521
}

// SupportedKeySpecs lists every algorithm Certio will generate, in the order
// the UI presents them.
func SupportedKeySpecs() []string {
	return []string{
		"ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
		"rsa-2048", "rsa-3072", "rsa-4096",
		"ed25519",
	}
}

// String renders the spec in the canonical form ParseKeySpec accepts.
func (k KeySpec) String() string {
	switch k.Algorithm {
	case AlgoRSA:
		return fmt.Sprintf("rsa-%d", k.Size)
	case AlgoECDSA:
		return "ecdsa-" + strings.ToLower(strings.ReplaceAll(k.Curve, "-", ""))
	case AlgoEd25519:
		return AlgoEd25519
	}
	return k.Algorithm
}

// Display renders the spec for humans, e.g. "ECDSA P-256".
func (k KeySpec) Display() string {
	switch k.Algorithm {
	case AlgoRSA:
		return fmt.Sprintf("RSA %d", k.Size)
	case AlgoECDSA:
		return "ECDSA " + k.Curve
	case AlgoEd25519:
		return "Ed25519"
	}
	return k.Algorithm
}

// ParseKeySpec accepts "rsa-4096", "ecdsa-p256", "ecdsa-P-384", "ed25519" and
// the bare "rsa"/"ecdsa" forms, which take the recommended default strength.
func ParseKeySpec(s string) (KeySpec, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	switch normalized {
	case "", AlgoECDSA, "ecdsa-p256", "ecdsa-p-256", "p256", "prime256v1":
		return KeySpec{Algorithm: AlgoECDSA, Curve: CurveP256}, nil
	case "ecdsa-p384", "ecdsa-p-384", "p384", "secp384r1":
		return KeySpec{Algorithm: AlgoECDSA, Curve: CurveP384}, nil
	case "ecdsa-p521", "ecdsa-p-521", "p521", "secp521r1":
		return KeySpec{Algorithm: AlgoECDSA, Curve: CurveP521}, nil
	case AlgoEd25519, "ed-25519":
		return KeySpec{Algorithm: AlgoEd25519}, nil
	case AlgoRSA, "rsa-2048":
		return KeySpec{Algorithm: AlgoRSA, Size: 2048}, nil
	case "rsa-3072":
		return KeySpec{Algorithm: AlgoRSA, Size: 3072}, nil
	case "rsa-4096":
		return KeySpec{Algorithm: AlgoRSA, Size: 4096}, nil
	}
	return KeySpec{}, fmt.Errorf("pki: unsupported key algorithm %q (want one of %s)",
		s, strings.Join(SupportedKeySpecs(), ", "))
}

// Validate reports whether the spec is one Certio will generate. RSA below
// 2048 bits is rejected outright rather than warned about.
func (k KeySpec) Validate() error {
	switch k.Algorithm {
	case AlgoRSA:
		switch k.Size {
		case 2048, 3072, 4096:
			return nil
		default:
			return fmt.Errorf("pki: RSA key size %d not supported (want 2048, 3072 or 4096)", k.Size)
		}
	case AlgoECDSA:
		switch k.Curve {
		case CurveP256, CurveP384, CurveP521:
			return nil
		default:
			return fmt.Errorf("pki: ECDSA curve %q not supported (want P-256, P-384 or P-521)", k.Curve)
		}
	case AlgoEd25519:
		return nil
	default:
		return fmt.Errorf("pki: unknown key algorithm %q", k.Algorithm)
	}
}

// GenerateKey creates a private key matching the spec.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	switch spec.Algorithm {
	case AlgoRSA:
		return rsa.GenerateKey(rand.Reader, spec.Size)
	case AlgoECDSA:
		curve, err := curveFor(spec.Curve)
		if err != nil {
			return nil, err
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case AlgoEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("pki: unknown key algorithm %q", spec.Algorithm)
}

func curveFor(name string) (elliptic.Curve, error) {
	switch name {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("pki: unknown curve %q", name)
}

// SpecOf derives the KeySpec of an existing key or public key.
func SpecOf(key any) (KeySpec, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return KeySpec{Algorithm: AlgoRSA, Size: k.N.BitLen()}, nil
	case *rsa.PublicKey:
		return KeySpec{Algorithm: AlgoRSA, Size: k.N.BitLen()}, nil
	case *ecdsa.PrivateKey:
		return KeySpec{Algorithm: AlgoECDSA, Curve: k.Curve.Params().Name}, nil
	case *ecdsa.PublicKey:
		return KeySpec{Algorithm: AlgoECDSA, Curve: k.Curve.Params().Name}, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey, ed25519.PublicKey, *ed25519.PublicKey:
		return KeySpec{Algorithm: AlgoEd25519}, nil
	case crypto.Signer:
		return SpecOf(k.Public())
	}
	return KeySpec{}, fmt.Errorf("pki: unsupported key type %T", key)
}

// MarshalPrivateKeyPEM encodes a private key as unencrypted PKCS#8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: BlockPrivateKey, Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PEM private key in PKCS#8, PKCS#1 or SEC 1
// form. It walks every block so a combined key+cert file still works.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // legacy openssl compatibility
			return nil, errors.New("pki: private key is passphrase-encrypted; decrypt it first " +
				"(openssl pkey -in key.pem -out key-plain.pem)")
		}
		key, err := parsePrivateKeyDER(block.Type, block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, errors.New("pki: no PRIVATE KEY block found in PEM input")
}

func parsePrivateKeyDER(blockType string, der []byte) (crypto.Signer, error) {
	switch blockType {
	case BlockRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("pki: parse PKCS#1 key: %w", err)
		}
		return key, nil
	case BlockECPrivateKey:
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("pki: parse SEC 1 key: %w", err)
		}
		return key, nil
	}

	// PKCS#8, or an unlabeled block — try every parser before giving up.
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("pki: PKCS#8 key of type %T cannot sign", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("pki: unrecognised private key encoding")
}

// MarshalPublicKeyPEM encodes a public key as PKIX PEM.
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncryptPrivateKeyPEM produces a passphrase-protected PEM key.
//
// This uses the legacy DEK-Info encryption openssl has emitted for decades.
// It is weak by modern standards (MD5-based KDF) and Go marks it deprecated,
// but it is what every openssl-era tool can read back. Certio offers it only
// for downloads, never for storage — keys at rest use AES-256-GCM envelope
// encryption. PKCS#12 export is the better choice for portable secrets.
func EncryptPrivateKeyPEM(key crypto.Signer, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return MarshalPrivateKeyPEM(key)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal private key: %w", err)
	}
	block, err := x509.EncryptPEMBlock( //nolint:staticcheck // legacy openssl compatibility
		rand.Reader, BlockPrivateKey, der, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("pki: encrypt private key: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}

// PublicKeysEqual reports whether two public keys are the same, which is how
// Certio checks that a certificate and a key belong together.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if ea, ok := a.(equaler); ok {
		return ea.Equal(b)
	}
	return false
}

// KeyMatchesCertificate reports whether the private key corresponds to the
// certificate's public key.
func KeyMatchesCertificate(key crypto.Signer, cert *x509.Certificate) bool {
	return PublicKeysEqual(key.Public(), cert.PublicKey)
}

// subjectKeyID computes the RFC 5280 §4.2.1.2 method-1 key identifier: the
// SHA-1 digest of the subjectPublicKey BIT STRING.
//
// crypto/x509 fills this in automatically for CA certificates but leaves it
// empty on leaves. RFC 5280 recommends it on end-entity certificates too, and
// some path builders and appliances rely on it, so Certio always sets it.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal public key for key identifier: %w", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("pki: parse SubjectPublicKeyInfo: %w", err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec // RFC 5280 specifies SHA-1 here
	return sum[:], nil
}

// signatureAlgorithmFor picks a signature algorithm for an issuer key.
// Ed25519 has exactly one; for RSA and ECDSA the digest is scaled to the key
// so a P-521 CA does not sign with SHA-256.
func signatureAlgorithmFor(key crypto.Signer) x509.SignatureAlgorithm {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch {
		case k.N.BitLen() >= 4096:
			return x509.SHA512WithRSA
		case k.N.BitLen() >= 3072:
			return x509.SHA384WithRSA
		default:
			return x509.SHA256WithRSA
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		default:
			return x509.ECDSAWithSHA256
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519
	}
	return x509.UnknownSignatureAlgorithm
}
