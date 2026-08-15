package service

import (
	"fmt"
	"math/big"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// CreateAuthorityInput describes a CA to create.
type CreateAuthorityInput struct {
	Name        string
	Slug        string
	Description string
	Type        string // root | intermediate
	// ParentID is required for an intermediate and ignored for a root.
	ParentID string
	// ParentPassphrase unlocks the issuing CA when it is protected.
	ParentPassphrase string

	Subject      pki.Subject
	KeyAlgorithm string
	ValidityDays int

	MaxPathLen      *int
	Passphrase      string
	CRLDistribution []string
	OCSPServer      []string
	NameConstraints pki.NameConstraints
}

// CreateAuthority creates a root or intermediate CA, encrypts its key and
// stores it.
func (s *Service) CreateAuthority(actor audit.Actor, in CreateAuthorityInput) (*store.Authority, error) {
	if in.Type == "" {
		in.Type = store.AuthorityTypeRoot
	}
	if in.Type != store.AuthorityTypeRoot && in.Type != store.AuthorityTypeIntermediate {
		return nil, validationError("type must be %q or %q", store.AuthorityTypeRoot, store.AuthorityTypeIntermediate)
	}
	if in.Name == "" {
		in.Name = in.Subject.CommonName
	}
	if in.Name == "" {
		return nil, validationError("name is required")
	}

	spec, err := pki.ParseKeySpec(defaultString(in.KeyAlgorithm, s.Config.PKI.DefaultKeyAlgorithm))
	if err != nil {
		return nil, validationError("%s", err)
	}
	in.Subject = s.applySubjectDefaults(in.Subject)
	if err := in.Subject.Validate(); err != nil {
		return nil, validationError("%s", err)
	}
	// Refused here rather than at signing time: a CA whose constraints
	// crypto/x509 cannot parse is treated as untrusted by every verifier, and
	// that failure looks nothing like its cause.
	in.NameConstraints = in.NameConstraints.Normalize()
	if err := in.NameConstraints.Validate(); err != nil {
		return nil, validationError("%s", err)
	}

	slug := in.Slug
	if slug == "" {
		slug = in.Name
	}
	slug, err = s.uniqueSlug(slug)
	if err != nil {
		return nil, err
	}

	req := pki.CARequest{
		Subject:               in.Subject,
		KeySpec:               spec,
		ValidityDays:          in.ValidityDays,
		CRLDistributionPoints: in.CRLDistribution,
		OCSPServer:            in.OCSPServer,
		NameConstraints:       in.NameConstraints,
	}
	if in.MaxPathLen != nil {
		req.MaxPathLen = *in.MaxPathLen
		req.MaxPathLenZero = *in.MaxPathLen == 0
	}

	var (
		ca       *pki.CertificateAuthority
		parentID *string
	)
	if in.Type == store.AuthorityTypeRoot {
		if req.ValidityDays <= 0 {
			req.ValidityDays = s.Config.PKI.DefaultCAValidity
		}
		if ca, err = pki.CreateRootCA(req); err != nil {
			return nil, validationError("%s", err)
		}
	} else {
		if in.ParentID == "" {
			return nil, validationError("an intermediate CA needs a parent")
		}
		parentRow, err := s.Store.Authorities.Resolve(in.ParentID)
		if err != nil {
			return nil, err
		}
		parent, err := s.LoadCA(parentRow, in.ParentPassphrase)
		if err != nil {
			return nil, err
		}
		ca, err = pki.CreateIntermediateCA(parent, req)
		if err != nil {
			return nil, validationError("%s", err)
		}
		parentID = &parentRow.ID
	}

	row, err := s.persistAuthority(ca, in, slug, parentID, spec)
	if err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCACreate,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
		Metadata: map[string]any{
			"type": row.Type, "key_algorithm": spec.String(),
			"serial_number": row.SerialNumber, "not_after": row.NotAfter,
		},
	})
	return row, nil
}

// persistAuthority seals the key and writes the authority row.
func (s *Service) persistAuthority(
	ca *pki.CertificateAuthority, in CreateAuthorityInput,
	slug string, parentID *string, spec pki.KeySpec,
) (*store.Authority, error) {
	ciphertext, nonce, salt, err := s.sealKey(ca.PrivateKey, in.Passphrase)
	if err != nil {
		return nil, err
	}

	row := &store.Authority{
		Name:                in.Name,
		Slug:                slug,
		Type:                in.Type,
		ParentID:            parentID,
		Description:         in.Description,
		Subject:             store.JSON(pki.SubjectFromPKIX(ca.Certificate.Subject)),
		KeyAlgorithm:        spec.Algorithm,
		KeySize:             spec.Size,
		KeyCurve:            spec.Curve,
		SerialNumber:        pki.FormatSerial(ca.Certificate.SerialNumber),
		NotBefore:           ca.Certificate.NotBefore,
		NotAfter:            ca.Certificate.NotAfter,
		CertPEM:             string(pki.EncodeCertificatePEM(ca.Certificate)),
		KeyEncrypted:        ciphertext,
		KeyNonce:            nonce,
		KeySalt:             salt,
		PassphraseProtected: in.Passphrase != "",
		FingerprintSHA256:   pki.Fingerprint(ca.Certificate),
		Status:              store.StatusActive,
		CreatedBy:           in.Subject.CommonName,
		NameConstraints:     store.JSON(pki.ConstraintsOf(ca.Certificate)),
	}
	if ca.Certificate.MaxPathLenZero || ca.Certificate.MaxPathLen > 0 {
		pathLen := ca.Certificate.MaxPathLen
		row.PathLenConstraint = &pathLen
	}

	if err := s.Store.Authorities.Create(row); err != nil {
		return nil, err
	}

	// The distribution URLs embed the authority ID, so they can only be set
	// once the row exists. Certificates issued from here on carry them.
	row.CRLURL = s.crlURL(row.ID)
	// A passphrase-protected CA cannot sign an OCSP response unattended, so
	// advertising a responder for it would point clients at an endpoint that
	// can only ever answer "unauthorized".
	if !row.PassphraseProtected {
		row.OCSPURL = s.ocspURL(row.ID)
	}
	if row.CRLURL != "" || row.OCSPURL != "" {
		if err := s.Store.Authorities.Update(row); err != nil {
			return nil, err
		}
	}
	return row, nil
}

// ImportAuthorityInput describes an existing CA to adopt.
type ImportAuthorityInput struct {
	Name        string
	Slug        string
	Description string
	CertPEM     string
	KeyPEM      string
	Passphrase  string
}

// ImportAuthority adopts an existing CA from PEM material — the path that lets
// an openssl-managed CA move into Certio without re-issuing anything.
func (s *Service) ImportAuthority(actor audit.Actor, in ImportAuthorityInput) (*store.Authority, error) {
	if in.CertPEM == "" || in.KeyPEM == "" {
		return nil, validationError("both the certificate and the private key are required")
	}

	ca, err := pki.ImportCA([]byte(in.CertPEM), []byte(in.KeyPEM))
	if err != nil {
		return nil, validationError("%s", err)
	}

	spec, err := pki.SpecOf(ca.PrivateKey)
	if err != nil {
		return nil, validationError("%s", err)
	}

	name := in.Name
	if name == "" {
		name = ca.Certificate.Subject.CommonName
	}
	slugSource := in.Slug
	if slugSource == "" {
		slugSource = name
	}
	slug, err := s.uniqueSlug(slugSource)
	if err != nil {
		return nil, err
	}

	// A CA that already exists must not be imported twice: the fingerprint is
	// the identity, not the name.
	fingerprint := pki.Fingerprint(ca.Certificate)
	existing, err := s.Store.Authorities.All()
	if err != nil {
		return nil, err
	}
	for _, row := range existing {
		if row.FingerprintSHA256 == fingerprint {
			return nil, fmt.Errorf("%w: this CA is already imported as %q", ErrConflict, row.Name)
		}
	}

	authType := store.AuthorityTypeRoot
	if !ca.IsRoot() {
		authType = store.AuthorityTypeIntermediate
	}

	// If the issuer is already managed here, link the rows so the chain is
	// complete without re-importing the parent.
	var parentID *string
	for i := range existing {
		if existing[i].Subject.Data.CommonName == ca.Certificate.Issuer.CommonName &&
			existing[i].FingerprintSHA256 != fingerprint {
			parentID = &existing[i].ID
			authType = store.AuthorityTypeIntermediate
			break
		}
	}

	row, err := s.persistAuthority(ca, CreateAuthorityInput{
		Name: name, Description: in.Description, Type: authType,
		Passphrase: in.Passphrase,
		Subject:    pki.SubjectFromPKIX(ca.Certificate.Subject),
	}, slug, parentID, spec)
	if err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCAImport,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
		Metadata: map[string]any{
			"fingerprint_sha256": fingerprint, "type": authType,
			"serial_number": row.SerialNumber,
		},
	})
	return row, nil
}

// UpdateAuthorityInput carries the mutable fields of an authority.
type UpdateAuthorityInput struct {
	Name        *string
	Description *string
	CRLURL      *string
	OCSPURL     *string
}

// UpdateAuthority edits the metadata of a CA. Nothing here re-signs anything:
// the certificate itself is immutable once issued.
func (s *Service) UpdateAuthority(actor audit.Actor, id string, in UpdateAuthorityInput) (*store.Authority, error) {
	row, err := s.Store.Authorities.Resolve(id)
	if err != nil {
		return nil, err
	}

	if in.Name != nil {
		row.Name = *in.Name
	}
	if in.Description != nil {
		row.Description = *in.Description
	}
	if in.CRLURL != nil {
		row.CRLURL = *in.CRLURL
	}
	if in.OCSPURL != nil {
		row.OCSPURL = *in.OCSPURL
	}

	if err := s.Store.Authorities.Update(row); err != nil {
		return nil, err
	}
	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCAUpdate,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
	})
	return row, nil
}

// DeleteAuthority removes a CA. Without force it refuses while certificates or
// intermediates still depend on it; with force it cascades — and is audited
// either way.
func (s *Service) DeleteAuthority(actor audit.Actor, id string, force bool) error {
	row, err := s.Store.Authorities.Resolve(id)
	if err != nil {
		return err
	}

	if err := s.Store.Authorities.Delete(row.ID, force); err != nil {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action:       audit.ActionCADelete,
			ResourceType: audit.ResourceAuthority,
			ResourceID:   row.ID,
			ResourceName: row.Name,
		}, err)
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCADelete,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
		Metadata:     map[string]any{"force": force},
	})
	return nil
}

// RenewAuthorityInput describes a CA renewal.
type RenewAuthorityInput struct {
	ValidityDays int
	Rekey        bool
	// Passphrase unlocks this CA's key; ParentPassphrase unlocks its issuer.
	Passphrase       string
	ParentPassphrase string
}

// RenewAuthority re-issues a CA certificate. A root re-signs itself; an
// intermediate is re-signed by its parent. The key is preserved by default so
// every certificate already issued under it keeps verifying.
func (s *Service) RenewAuthority(actor audit.Actor, id string, in RenewAuthorityInput) (*store.Authority, error) {
	row, err := s.Store.Authorities.Resolve(id)
	if err != nil {
		return nil, err
	}
	if in.Rekey {
		return nil, validationError(
			"rekeying a CA invalidates every certificate it has issued; create a new CA instead")
	}

	ca, err := s.LoadCA(row, in.Passphrase)
	if err != nil {
		return nil, err
	}

	validity := in.ValidityDays
	if validity <= 0 {
		validity = int(row.NotAfter.Sub(row.NotBefore).Hours() / 24)
	}

	subject := pki.SubjectFromPKIX(ca.Certificate.Subject)
	req := pki.CARequest{
		Subject:      subject,
		KeySpec:      row.KeySpec(),
		ValidityDays: validity,
	}
	if row.PathLenConstraint != nil {
		req.MaxPathLen = *row.PathLenConstraint
		req.MaxPathLenZero = *row.PathLenConstraint == 0
	}

	var renewed *pki.Certificate
	if row.Type == store.AuthorityTypeRoot {
		renewed, err = pki.SignPublicKey(ca, ca.PrivateKey.Public(), pki.IssueRequest{
			Subject:      subject,
			Profile:      pki.ProfileRoot,
			ValidityDays: validity,
		})
	} else {
		if row.ParentID == nil {
			return nil, validationError("intermediate CA %q has no recorded parent", row.Name)
		}
		parentRow, perr := s.Store.Authorities.Get(*row.ParentID)
		if perr != nil {
			return nil, perr
		}
		parent, perr := s.LoadCA(parentRow, in.ParentPassphrase)
		if perr != nil {
			return nil, perr
		}
		renewed, err = pki.SignPublicKey(parent, ca.PrivateKey.Public(), pki.IssueRequest{
			Subject:      subject,
			Profile:      pki.ProfileIntermediate,
			ValidityDays: validity,
		})
	}
	if err != nil {
		return nil, validationError("%s", err)
	}

	row.CertPEM = string(pki.EncodeCertificatePEM(renewed))
	row.SerialNumber = pki.FormatSerial(renewed.SerialNumber)
	row.NotBefore = renewed.NotBefore
	row.NotAfter = renewed.NotAfter
	row.FingerprintSHA256 = pki.Fingerprint(renewed)
	row.Status = store.StatusActive

	if err := s.Store.Authorities.Update(row); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCARenew,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
		Metadata:     map[string]any{"not_after": row.NotAfter, "serial_number": row.SerialNumber},
	})
	return row, nil
}

// GenerateCRL rebuilds and stores the revocation list for a CA. It runs on
// every revocation and on the scheduler's interval.
func (s *Service) GenerateCRL(actor audit.Actor, authorityID, passphrase string) ([]byte, error) {
	row, err := s.Store.Authorities.Resolve(authorityID)
	if err != nil {
		return nil, err
	}
	ca, err := s.LoadCA(row, passphrase)
	if err != nil {
		return nil, err
	}

	revocations, err := s.Store.Revocations.ByAuthority(row.ID)
	if err != nil {
		return nil, err
	}

	entries := make([]pki.RevokedCertificate, 0, len(revocations))
	for _, rev := range revocations {
		serial, err := pki.ParseSerial(rev.SerialNumber)
		if err != nil {
			s.Log.Warn("skipping a revocation with an unparseable serial",
				"revocation_id", rev.ID, "serial", rev.SerialNumber)
			continue
		}
		entries = append(entries, pki.RevokedCertificate{
			SerialNumber: serial,
			RevokedAt:    rev.RevokedAt,
			ReasonCode:   rev.ReasonCode,
		})
	}

	now := time.Now()
	nextUpdate := now.Add(s.Config.PKI.CRLValidity)
	der, err := pki.GenerateCRL(ca, pki.CRLRequest{
		Number:     big.NewInt(row.CRLNumber + 1),
		ThisUpdate: now,
		NextUpdate: nextUpdate,
		Revoked:    entries,
	})
	if err != nil {
		return nil, err
	}

	row.CRLNumber++
	row.CRLPEM = string(pki.EncodeCRLPEM(der))
	row.NextCRLUpdate = &nextUpdate
	if err := s.Store.Authorities.Update(row); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCRLIssued,
		ResourceType: audit.ResourceAuthority,
		ResourceID:   row.ID,
		ResourceName: row.Name,
		Metadata:     map[string]any{"crl_number": row.CRLNumber, "revoked_count": len(entries)},
	})
	return der, nil
}

// CRLFor returns the stored CRL for a CA, generating one on first request so
// the public endpoint never 404s on a CA that has simply never revoked
// anything.
func (s *Service) CRLFor(authorityID string) ([]byte, error) {
	row, err := s.Store.Authorities.Resolve(authorityID)
	if err != nil {
		return nil, err
	}
	if row.CRLPEM != "" {
		return []byte(row.CRLPEM), nil
	}
	if row.PassphraseProtected {
		return nil, fmt.Errorf(
			"%w: CA %q is passphrase-protected and has no published CRL yet", ErrNotFound, row.Name)
	}
	der, err := s.GenerateCRL(audit.SystemActor(), row.ID, "")
	if err != nil {
		return nil, err
	}
	return pki.EncodeCRLPEM(der), nil
}

// RefreshAuthorityStatuses recomputes the status of every CA against the
// clock. The scheduler calls it; so does the dashboard on load.
func (s *Service) RefreshAuthorityStatuses() (int, error) {
	rows, err := s.Store.Authorities.All()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	changed := 0

	for i := range rows {
		row := &rows[i]
		if row.Status == store.StatusRevoked {
			continue
		}
		want := store.StatusActive
		switch {
		case now.After(row.NotAfter):
			want = store.StatusExpired
		case now.AddDate(0, 0, s.Config.Scheduler.ExpiryWarnDays).After(row.NotAfter):
			want = store.StatusExpiring
		}
		if row.Status != want {
			row.Status = want
			if err := s.Store.Authorities.Update(row); err != nil {
				return changed, err
			}
			changed++
		}
	}
	return changed, nil
}

// applySubjectDefaults fills organization and country from instance settings
// when the request left them blank.
func (s *Service) applySubjectDefaults(subject pki.Subject) pki.Subject {
	if s.Config == nil {
		return subject.Normalize()
	}
	if subject.Organization == "" {
		subject.Organization = s.Config.PKI.DefaultOrganization
	}
	if subject.Country == "" {
		subject.Country = s.Config.PKI.DefaultCountry
	}
	return subject.Normalize()
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
