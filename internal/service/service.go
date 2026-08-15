// Package service holds the application logic that sits between the PKI
// engine and the store. Both the HTTP handlers and the CLI drive these
// methods, so issuing a certificate behaves identically either way.
package service

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// Errors the API layer maps onto status codes.
var (
	// ErrValidation marks a bad request rather than a server fault.
	ErrValidation = errors.New("validation failed")
	// ErrNotFound mirrors store.ErrNotFound at the service boundary.
	ErrNotFound = store.ErrNotFound
	// ErrConflict marks a uniqueness or state conflict.
	ErrConflict = store.ErrConflict
	// ErrForbidden marks an operation the caller's role does not allow.
	ErrForbidden = errors.New("operation not permitted")
	// ErrPassphraseRequired means a CA key needs its passphrase.
	ErrPassphraseRequired = certiocrypto.ErrPassphraseRequired
	// ErrKeyUnavailable means Certio does not hold the private key.
	ErrKeyUnavailable = errors.New("the private key is not available for this certificate")
)

// Service bundles the collaborators every operation needs.
type Service struct {
	Store   *store.Store
	Keyring *certiocrypto.Keyring
	Config  *config.Config
	Audit   *audit.Logger
	Log     *slog.Logger
	// Metrics is where lifecycle events are counted. It is always non-nil, so
	// no call site has to guard an increment; a CLI process simply builds one
	// whose registry nobody scrapes.
	Metrics *metrics.Metrics
}

// New builds a Service.
func New(st *store.Store, keyring *certiocrypto.Keyring, cfg *config.Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	svc := &Service{
		Store:   st,
		Keyring: keyring,
		Config:  cfg,
		Audit:   audit.New(st.Audit, log),
		Log:     log,
	}
	// The collector reads through the service that owns it, so the snapshot
	// sees exactly the state every other operation does.
	svc.Metrics = metrics.New(svc.MetricsSnapshot, log)
	return svc
}

// validationError wraps a message as ErrValidation so handlers return 400.
func validationError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}

// sealKey encrypts private key material for storage.
func (s *Service) sealKey(key crypto.Signer, passphrase string) (ciphertext, nonce, salt []byte, err error) {
	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, nil, err
	}
	env, err := s.Keyring.Seal(keyPEM, passphrase)
	if err != nil {
		return nil, nil, nil, err
	}
	return env.Ciphertext, env.Nonce, env.Salt, nil
}

// openKey decrypts stored private key material.
func (s *Service) openKey(ciphertext, nonce, salt []byte, passphrase string) (crypto.Signer, error) {
	if len(ciphertext) == 0 {
		return nil, ErrKeyUnavailable
	}
	keyPEM, err := s.Keyring.Open(certiocrypto.Envelope{
		Ciphertext: ciphertext, Nonce: nonce, Salt: salt,
	}, passphrase)
	if err != nil {
		return nil, err
	}
	return pki.ParsePrivateKeyPEM(keyPEM)
}

// LoadCA rebuilds a usable pki.CertificateAuthority — certificate, decrypted
// key and full issuer chain — from a stored authority.
func (s *Service) LoadCA(a *store.Authority, passphrase string) (*pki.CertificateAuthority, error) {
	if a.PassphraseProtected && passphrase == "" {
		return nil, fmt.Errorf("%w: CA %q is passphrase-protected", ErrPassphraseRequired, a.Name)
	}

	cert, err := pki.ParseCertificatePEM([]byte(a.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("load CA %s: %w", a.Slug, err)
	}
	key, err := s.openKey(a.KeyEncrypted, a.KeyNonce, a.KeySalt, passphrase)
	if err != nil {
		return nil, err
	}

	chainRows, err := s.Store.Authorities.Chain(a)
	if err != nil {
		return nil, err
	}
	chain := make([]*pki.Certificate, 0, len(chainRows))
	for _, row := range chainRows {
		parent, err := pki.ParseCertificatePEM([]byte(row.CertPEM))
		if err != nil {
			return nil, fmt.Errorf("load CA chain for %s: %w", a.Slug, err)
		}
		chain = append(chain, parent)
	}

	return &pki.CertificateAuthority{Certificate: cert, PrivateKey: key, Chain: chain}, nil
}

// LoadCAPublic rebuilds a CA without its private key — enough to serve the
// root certificate, build a chain or describe an authority.
func (s *Service) LoadCAPublic(a *store.Authority) (*pki.CertificateAuthority, error) {
	cert, err := pki.ParseCertificatePEM([]byte(a.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("load CA %s: %w", a.Slug, err)
	}
	chainRows, err := s.Store.Authorities.Chain(a)
	if err != nil {
		return nil, err
	}
	chain := make([]*pki.Certificate, 0, len(chainRows))
	for _, row := range chainRows {
		parent, err := pki.ParseCertificatePEM([]byte(row.CertPEM))
		if err != nil {
			return nil, fmt.Errorf("load CA chain for %s: %w", a.Slug, err)
		}
		chain = append(chain, parent)
	}
	return &pki.CertificateAuthority{Certificate: cert, Chain: chain}, nil
}

// slugPattern matches everything that is not safe in a URL path segment.
var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a display name into a URL-safe identifier.
func Slugify(name string) string {
	slug := slugPattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "ca"
	}
	if len(slug) > 64 {
		slug = strings.Trim(slug[:64], "-")
	}
	return slug
}

// uniqueSlug appends a numeric suffix until the slug is free.
func (s *Service) uniqueSlug(base string) (string, error) {
	slug := Slugify(base)
	candidate := slug
	for i := 2; i < 100; i++ {
		taken, err := s.Store.Authorities.SlugExists(candidate)
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%d", slug, i)
	}
	return "", validationError("could not derive a free slug from %q", base)
}

// crlURL is the public distribution point baked into certificates a CA issues.
func (s *Service) crlURL(authorityID string) string {
	return s.publicCAURL(authorityID, "crl.pem")
}

// ocspURL is the responder address baked into the AIA extension of every
// certificate a CA issues.
func (s *Service) ocspURL(authorityID string) string {
	return s.publicCAURL(authorityID, "ocsp")
}

// publicCAURL builds a URL under the public trust-distribution prefix.
func (s *Service) publicCAURL(authorityID, suffix string) string {
	if s.Config == nil || s.Config.Server.BaseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/ca/%s/%s",
		strings.TrimRight(s.Config.Server.BaseURL, "/"), authorityID, suffix)
}
