package service

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// IssueInput describes a managed issuance: Certio generates the key.
type IssueInput struct {
	AuthorityID     string
	CAPassphrase    string
	Subject         pki.Subject
	SANs            pki.SANSet
	Profile         string
	KeyAlgorithm    string
	ValidityDays    int
	KeyUsage        []string
	ExtKeyUsage     []string
	AutoRenew       bool
	RenewBeforeDays int
	Labels          map[string]string
	Notes           string
	// Source names the flow that asked for this certificate — "api", "cli" or
	// "acme". It only ever reaches a metrics label, so a dashboard can tell
	// automated issuance from someone clicking a button.
	Source string
}

// IssueResult carries the stored row plus the material a caller may download
// exactly once — the private key is not persisted in plaintext anywhere.
type IssueResult struct {
	Certificate *store.Certificate
	Bundle      pki.Bundle
	// PrivateKeyPEM is present only for a managed issuance.
	PrivateKeyPEM []byte
}

// Issue generates a key pair, signs a certificate for it and stores both.
func (s *Service) Issue(actor audit.Actor, in IssueInput) (*IssueResult, error) {
	caRow, err := s.Store.Authorities.Resolve(in.AuthorityID)
	if err != nil {
		return nil, err
	}
	ca, err := s.LoadCA(caRow, in.CAPassphrase)
	if err != nil {
		return nil, err
	}

	spec, err := pki.ParseKeySpec(defaultString(in.KeyAlgorithm, s.Config.PKI.DefaultKeyAlgorithm))
	if err != nil {
		return nil, validationError("%s", err)
	}
	profile := defaultString(in.Profile, pki.ProfileServer)
	if _, err := pki.LookupProfile(profile); err != nil {
		return nil, validationError("%s", err)
	}

	in.Subject = s.applySubjectDefaults(in.Subject)
	if err := in.Subject.Validate(); err != nil {
		return nil, validationError("%s", err)
	}
	if err := s.checkNameConstraints(caRow, in.Subject.CommonName, in.SANs); err != nil {
		return nil, err
	}

	issued, err := pki.Issue(ca, pki.IssueRequest{
		Subject:               in.Subject,
		SANs:                  in.SANs,
		KeySpec:               spec,
		Profile:               profile,
		ValidityDays:          in.ValidityDays,
		KeyUsage:              in.KeyUsage,
		ExtKeyUsage:           in.ExtKeyUsage,
		CRLDistributionPoints: distributionPoints(caRow.CRLURL),
		OCSPServer:            distributionPoints(caRow.OCSPURL),
	})
	if err != nil {
		return nil, validationError("%s", err)
	}

	row, err := s.persistCertificate(caRow, issued.Certificate, issued.PrivateKey, "", in, nil)
	if err != nil {
		return nil, err
	}

	keyPEM, err := pki.MarshalPrivateKeyPEM(issued.PrivateKey)
	if err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertIssue,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   row.ID,
		ResourceName: row.CommonName,
		Metadata: map[string]any{
			"ca": caRow.Name, "profile": profile, "key_algorithm": spec.String(),
			"serial_number": row.SerialNumber, "not_after": row.NotAfter,
			"sans": row.SANs.Data.Strings(),
		},
	})

	return &IssueResult{
		Certificate:   row,
		Bundle:        pki.Bundle{Certificate: issued.Certificate, PrivateKey: issued.PrivateKey, Chain: issued.Chain},
		PrivateKeyPEM: keyPEM,
	}, nil
}

// SignCSRInput describes a BYO-CSR issuance: the requester keeps the key.
type SignCSRInput struct {
	AuthorityID  string
	CAPassphrase string
	CSRPEM       string
	// Profile, SANs and validity may override what the CSR asked for; an
	// empty value keeps the CSR's own.
	Profile      string
	SANs         pki.SANSet
	ValidityDays int
	KeyUsage     []string
	ExtKeyUsage  []string
	Labels       map[string]string
	Notes        string
}

// SignCSR signs an externally generated certificate signing request. Certio
// never sees the private key, so the result carries no key material.
func (s *Service) SignCSR(actor audit.Actor, in SignCSRInput) (*IssueResult, error) {
	caRow, err := s.Store.Authorities.Resolve(in.AuthorityID)
	if err != nil {
		return nil, err
	}
	ca, err := s.LoadCA(caRow, in.CAPassphrase)
	if err != nil {
		return nil, err
	}

	csr, err := pki.ParseCSR([]byte(in.CSRPEM))
	if err != nil {
		return nil, validationError("%s", err)
	}
	profile := defaultString(in.Profile, pki.ProfileServer)
	if _, err := pki.LookupProfile(profile); err != nil {
		return nil, validationError("%s", err)
	}

	// The names come from the CSR as well as from the request, and a CA with
	// name constraints must refuse both. Checking after parsing means the
	// error names the offending entry.
	if err := s.checkNameConstraints(caRow, csr.Subject.CommonName,
		append(pki.SANsFromCertificateLike(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs),
			in.SANs...)); err != nil {
		return nil, err
	}

	cert, err := pki.SignCSR(ca, csr, pki.IssueRequest{
		SANs:                  in.SANs,
		Profile:               profile,
		ValidityDays:          in.ValidityDays,
		KeyUsage:              in.KeyUsage,
		ExtKeyUsage:           in.ExtKeyUsage,
		CRLDistributionPoints: distributionPoints(caRow.CRLURL),
		OCSPServer:            distributionPoints(caRow.OCSPURL),
	})
	if err != nil {
		return nil, validationError("%s", err)
	}

	issueIn := IssueInput{
		AuthorityID: caRow.ID, Profile: profile,
		ValidityDays: in.ValidityDays, Labels: in.Labels, Notes: in.Notes,
	}
	row, err := s.persistCertificate(caRow, cert, nil, in.CSRPEM, issueIn, nil)
	if err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertSignCSR,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   row.ID,
		ResourceName: row.CommonName,
		Metadata: map[string]any{
			"ca": caRow.Name, "profile": profile,
			"serial_number": row.SerialNumber, "not_after": row.NotAfter,
		},
	})

	chain, err := s.chainFor(caRow)
	if err != nil {
		return nil, err
	}
	return &IssueResult{
		Certificate: row,
		Bundle:      pki.Bundle{Certificate: cert, Chain: chain},
	}, nil
}

// persistCertificate seals the key (when there is one) and writes the row.
func (s *Service) persistCertificate(
	caRow *store.Authority, cert *pki.Certificate, key crypto.Signer,
	csrPEM string, in IssueInput, renewedFrom *string,
) (*store.Certificate, error) {
	spec, err := pki.SpecOf(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	var ciphertext, nonce, salt []byte
	if key != nil {
		// The stored key is sealed with the master key alone: a per-certificate
		// passphrase would have to be supplied on every renewal, which defeats
		// unattended auto-renew. CA keys are the ones that take a passphrase.
		if ciphertext, nonce, salt, err = s.sealKey(key, ""); err != nil {
			return nil, err
		}
	}

	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)

	renewBefore := in.RenewBeforeDays
	if renewBefore <= 0 {
		renewBefore = 30
	}
	// A renewal window at least as long as the certificate's own lifetime would
	// make it due the moment it is issued, so auto-renew would loop forever.
	// Half the lifetime is the most that can still leave a usable margin.
	if in.AutoRenew && validityDays > 0 && renewBefore >= validityDays {
		capped := validityDays / 2
		if capped < 1 {
			capped = 1
		}
		s.Log.Warn("renewal window is not shorter than the certificate lifetime; capping it",
			"common_name", cert.Subject.CommonName,
			"requested_days", renewBefore, "validity_days", validityDays, "applied_days", capped)
		renewBefore = capped
	}

	row := &store.Certificate{
		AuthorityID:       caRow.ID,
		CommonName:        cert.Subject.CommonName,
		Subject:           store.JSON(pki.SubjectFromPKIX(cert.Subject)),
		Profile:           defaultString(in.Profile, pki.InferProfile(cert)),
		KeyAlgorithm:      spec.Algorithm,
		KeySize:           spec.Size,
		KeyCurve:          spec.Curve,
		SerialNumber:      pki.FormatSerial(cert.SerialNumber),
		SANs:              store.JSON(pki.SANsFromCertificateLike(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)),
		KeyUsage:          store.JSON(pki.KeyUsageStrings(cert.KeyUsage)),
		ExtKeyUsage:       store.JSON(pki.ExtKeyUsageStrings(cert.ExtKeyUsage)),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		ValidityDays:      validityDays,
		CertPEM:           string(pki.EncodeCertificatePEM(cert)),
		KeyEncrypted:      ciphertext,
		KeyNonce:          nonce,
		KeySalt:           salt,
		CSRPEM:            csrPEM,
		FingerprintSHA256: pki.Fingerprint(cert),
		Status:            store.StatusActive,
		AutoRenew:         in.AutoRenew,
		RenewBeforeDays:   renewBefore,
		RenewedFromID:     renewedFrom,
		Labels:            store.JSON(in.Labels),
		Notes:             in.Notes,
	}

	if err := s.Store.Certificates.Create(row); err != nil {
		return nil, err
	}

	s.Metrics.CertificatesIssued.
		WithLabelValues(caRow.Name, row.Profile, defaultString(in.Source, "api")).Inc()
	return row, nil
}

// checkNameConstraints refuses a name this CA is not allowed to certify.
//
// The constraint is already in the CA certificate and every verifier enforces
// it, so this check does not add security — it adds a legible failure. Without
// it the certificate is issued happily and only fails much later, in a browser,
// as "issuer is not permitted to issue certificates for this name".
func (s *Service) checkNameConstraints(caRow *store.Authority, commonName string, sans pki.SANSet) error {
	constraints := caRow.NameConstraints.Data
	if constraints.IsZero() {
		return nil
	}
	if err := constraints.PermitsSANs(sans); err != nil {
		return validationError("%s", err)
	}
	// A common name that looks like a hostname is treated as one. It is not a
	// SAN and browsers stopped reading it years ago, but plenty of non-browser
	// clients still do, and a constrained CA should not put one there either.
	if commonName != "" && strings.Contains(commonName, ".") && !strings.Contains(commonName, " ") {
		if !constraints.PermitsDNS(commonName) {
			return validationError(
				"the common name %q is outside this CA's name constraints", commonName)
		}
	}
	return nil
}

// RenewInput describes a certificate renewal.
type RenewInput struct {
	Rekey        bool
	KeyAlgorithm string
	ValidityDays int
	SANs         pki.SANSet
	CAPassphrase string
	// Trigger names what asked for the renewal — "manual", "scheduler" or
	// "acme" — so a dashboard can tell unattended renewal from a human one.
	// Metrics only.
	Trigger string
}

// Renew re-issues a certificate as a *new row*, linked to the old one through
// renewed_from_id. Nothing is mutated in place, so the previous certificate
// stays downloadable, auditable and revocable.
func (s *Service) Renew(actor audit.Actor, id string, in RenewInput) (_ *IssueResult, err error) {
	// Counted on every path, including the early returns: a renewal that keeps
	// failing for a passphrase-protected CA is exactly the thing an operator
	// needs to see, and it never reaches the success path to be counted there.
	trigger := defaultString(in.Trigger, "manual")
	defer func() { s.Metrics.Renewals.WithLabelValues(metrics.Result(err), trigger).Inc() }()

	current, caRow, err := s.Store.Certificates.GetWithAuthority(id)
	if err != nil {
		return nil, err
	}
	if current.Status == store.StatusRevoked {
		return nil, validationError("certificate %s is revoked and cannot be renewed", current.CommonName)
	}

	ca, err := s.LoadCA(caRow, in.CAPassphrase)
	if err != nil {
		return nil, err
	}
	currentCert, err := pki.ParseCertificatePEM([]byte(current.CertPEM))
	if err != nil {
		return nil, err
	}

	// Renewing without rekeying needs the original key. A BYO-CSR certificate
	// has none stored, so it can only be renewed by rekeying — or by signing a
	// fresh CSR, which is the honest answer to give the user.
	var currentKey crypto.Signer
	if !in.Rekey {
		if !current.HasPrivateKey() {
			return nil, fmt.Errorf(
				"%w: this certificate was signed from an external CSR, so Certio cannot re-sign the same key — "+
					"renew with rekey, or submit a new CSR", ErrKeyUnavailable)
		}
		if currentKey, err = s.openKey(current.KeyEncrypted, current.KeyNonce, current.KeySalt, ""); err != nil {
			return nil, err
		}
	}

	req := pki.RenewRequest{
		Rekey:                 in.Rekey,
		ValidityDays:          in.ValidityDays,
		SANs:                  in.SANs,
		Profile:               current.Profile,
		CRLDistributionPoints: distributionPoints(caRow.CRLURL),
		OCSPServer:            distributionPoints(caRow.OCSPURL),
	}
	if in.Rekey && in.KeyAlgorithm != "" {
		spec, err := pki.ParseKeySpec(in.KeyAlgorithm)
		if err != nil {
			return nil, validationError("%s", err)
		}
		req.KeySpec = spec
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = current.ValidityDays
	}

	renewed, err := pki.Renew(ca, currentCert, currentKey, req)
	if err != nil {
		return nil, validationError("%s", err)
	}

	issueIn := IssueInput{
		AuthorityID: caRow.ID, Profile: current.Profile,
		AutoRenew: current.AutoRenew, RenewBeforeDays: current.RenewBeforeDays,
		Labels: current.Labels.Data, Notes: current.Notes,
	}
	// A rekeyed renewal of a BYO-CSR certificate produces a key Certio holds;
	// otherwise the key situation is unchanged from the original.
	storeKey := renewed.PrivateKey
	if !in.Rekey && !current.HasPrivateKey() {
		storeKey = nil
	}

	row, err := s.persistCertificate(caRow, renewed.Certificate, storeKey, "", issueIn, &current.ID)
	if err != nil {
		return nil, err
	}

	// The old certificate has been superseded, so it must stop auto-renewing.
	// Left on, the scheduler would renew it again on the next tick — and the
	// certificate that renewal produced too — forking the chain and growing the
	// table without bound.
	if current.AutoRenew {
		if err := s.Store.Certificates.UpdateFields(current.ID, map[string]any{
			"auto_renew": false,
		}); err != nil {
			s.Log.Error("could not clear auto-renew on the superseded certificate",
				"error", err, "certificate", current.ID)
		}
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertRenew,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   row.ID,
		ResourceName: row.CommonName,
		Metadata: map[string]any{
			"renewed_from": current.ID, "rekey": in.Rekey,
			"serial_number": row.SerialNumber, "not_after": row.NotAfter,
		},
	})

	// Push the new certificate to wherever it is used, now rather than at the
	// next scheduler tick: a renewal made by hand is usually made because
	// something needs it soon.
	if results, deployErr := s.DeployCertificate(actor, row.ID, false); deployErr != nil {
		s.Log.Error("renewed but could not run the deployment targets",
			"error", deployErr, "certificate", row.ID)
	} else if len(results) > 0 {
		s.Log.Info("deployed the renewed certificate",
			"certificate", row.CommonName, "targets", len(results))
	}

	result := &IssueResult{
		Certificate: row,
		Bundle: pki.Bundle{
			Certificate: renewed.Certificate,
			PrivateKey:  renewed.PrivateKey,
			Chain:       renewed.Chain,
		},
	}
	if storeKey != nil {
		if result.PrivateKeyPEM, err = pki.MarshalPrivateKeyPEM(storeKey); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// RevokeInput describes a revocation.
type RevokeInput struct {
	ReasonCode   int
	CAPassphrase string
	// SkipCRL defers CRL regeneration to the scheduler, which is what bulk
	// revocation wants so the list is rebuilt once rather than per entry.
	SkipCRL bool
}

// Revoke marks a certificate revoked and republishes the CA's CRL.
func (s *Service) Revoke(actor audit.Actor, id string, in RevokeInput) (*store.Revocation, error) {
	if err := pki.ValidateRevocationReason(in.ReasonCode); err != nil {
		return nil, validationError("%s", err)
	}

	cert, caRow, err := s.Store.Certificates.GetWithAuthority(id)
	if err != nil {
		return nil, err
	}
	if cert.Status == store.StatusRevoked {
		return nil, fmt.Errorf("%w: certificate %s is already revoked", ErrConflict, cert.CommonName)
	}
	// A held certificate may be revoked outright — that is the decision the
	// hold was waiting on — so the old entry is replaced rather than duplicated.
	if cert.Status == store.StatusHeld {
		if existing, findErr := s.Store.Revocations.ByCertificate(cert.ID); findErr == nil && existing != nil {
			if err := s.Store.Revocations.Delete(existing.ID); err != nil {
				return nil, err
			}
		}
	}

	rev := &store.Revocation{
		CertificateID: cert.ID,
		AuthorityID:   cert.AuthorityID,
		SerialNumber:  cert.SerialNumber,
		ReasonCode:    in.ReasonCode,
		Reason:        pki.RevocationReasonName(in.ReasonCode),
		RevokedAt:     time.Now().UTC(),
		RevokedBy:     actor.ID,
	}
	if err := s.Store.Revocations.Create(rev); err != nil {
		return nil, err
	}

	cert.Status = store.StatusRevoked
	if in.ReasonCode == pki.ReasonCertificateHold {
		cert.Status = store.StatusHeld
	}
	if err := s.Store.Certificates.Update(cert); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertRevoke,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   cert.ID,
		ResourceName: cert.CommonName,
		Metadata: map[string]any{
			"reason": rev.Reason, "reason_code": in.ReasonCode,
			"serial_number": cert.SerialNumber, "ca": caRow.Name,
		},
	})

	s.Metrics.Revoked.WithLabelValues(rev.Reason).Inc()

	// A revocation nobody can see is not a revocation, so the CRL is
	// republished immediately — unless the CA needs a passphrase we were not
	// given, in which case the scheduler will pick it up.
	if !in.SkipCRL && (!caRow.PassphraseProtected || in.CAPassphrase != "") {
		if _, err := s.GenerateCRL(actor, caRow.ID, in.CAPassphrase); err != nil {
			s.Log.Error("certificate revoked but the CRL could not be republished",
				"error", err, "ca", caRow.Slug, "certificate", cert.ID)
		}
	}
	return rev, nil
}

// UpdateCertificateInput carries the mutable fields of a certificate.
type UpdateCertificateInput struct {
	Labels          *map[string]string
	Notes           *string
	AutoRenew       *bool
	RenewBeforeDays *int
}

// UpdateCertificate edits metadata only. The certificate itself is immutable.
func (s *Service) UpdateCertificate(actor audit.Actor, id string, in UpdateCertificateInput) (*store.Certificate, error) {
	row, err := s.Store.Certificates.Get(id)
	if err != nil {
		return nil, err
	}

	if in.Labels != nil {
		row.Labels = store.JSON(*in.Labels)
	}
	if in.Notes != nil {
		row.Notes = *in.Notes
	}
	if in.AutoRenew != nil {
		row.AutoRenew = *in.AutoRenew
	}
	if in.RenewBeforeDays != nil {
		if *in.RenewBeforeDays < 1 || *in.RenewBeforeDays > 365 {
			return nil, validationError("renew_before_days must be between 1 and 365")
		}
		row.RenewBeforeDays = *in.RenewBeforeDays
	}

	if err := s.Store.Certificates.Update(row); err != nil {
		return nil, err
	}
	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertUpdate,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   row.ID,
		ResourceName: row.CommonName,
	})
	return row, nil
}

// DeleteCertificate removes a certificate record. Deleting is not revoking:
// the warning matters because a deleted-but-unrevoked certificate stays valid
// to every client until it expires.
func (s *Service) DeleteCertificate(actor audit.Actor, id string) error {
	row, err := s.Store.Certificates.Get(id)
	if err != nil {
		return err
	}
	if err := s.Store.Certificates.Delete(id); err != nil {
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertDelete,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   row.ID,
		ResourceName: row.CommonName,
		Metadata: map[string]any{
			"serial_number": row.SerialNumber,
			"was_revoked":   row.Status == store.StatusRevoked,
		},
	})
	return nil
}

// LoadBundle rebuilds the exportable bundle for a stored certificate.
// withKey decrypts the private key, which the caller must be authorised for.
func (s *Service) LoadBundle(id string, withKey bool) (pki.Bundle, *store.Certificate, error) {
	cert, caRow, err := s.Store.Certificates.GetWithAuthority(id)
	if err != nil {
		return pki.Bundle{}, nil, err
	}

	leaf, err := pki.ParseCertificatePEM([]byte(cert.CertPEM))
	if err != nil {
		return pki.Bundle{}, nil, err
	}
	chain, err := s.chainFor(caRow)
	if err != nil {
		return pki.Bundle{}, nil, err
	}

	bundle := pki.Bundle{Certificate: leaf, Chain: chain}
	if withKey {
		if !cert.HasPrivateKey() {
			return pki.Bundle{}, nil, ErrKeyUnavailable
		}
		key, err := s.openKey(cert.KeyEncrypted, cert.KeyNonce, cert.KeySalt, "")
		if err != nil {
			return pki.Bundle{}, nil, err
		}
		bundle.PrivateKey = key
	}
	return bundle, cert, nil
}

// chainFor builds the issuer chain for a CA: the CA's own certificate first,
// then each ancestor up to the root.
func (s *Service) chainFor(caRow *store.Authority) ([]*pki.Certificate, error) {
	caCert, err := pki.ParseCertificatePEM([]byte(caRow.CertPEM))
	if err != nil {
		return nil, err
	}
	ancestors, err := s.Store.Authorities.Chain(caRow)
	if err != nil {
		return nil, err
	}

	chain := []*pki.Certificate{caCert}
	for _, row := range ancestors {
		cert, err := pki.ParseCertificatePEM([]byte(row.CertPEM))
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// AuthorizeKeyDownload enforces the key_download_policy and records the
// attempt either way — a denied download is exactly the event an operator
// wants to see in the audit log.
func (s *Service) AuthorizeKeyDownload(actor audit.Actor, cert *store.Certificate) error {
	policy := s.Config.Security.KeyDownloadPolicy

	deny := func(reason string) error {
		s.Audit.Record(actor, audit.Entry{
			Action:       audit.ActionKeyDownloadDenied,
			ResourceType: audit.ResourceCertificate,
			ResourceID:   cert.ID,
			ResourceName: cert.CommonName,
			Metadata:     map[string]any{"policy": policy, "reason": reason},
		})
		return fmt.Errorf("%w: %s", ErrForbidden, reason)
	}

	switch policy {
	case "never":
		return deny("private key downloads are disabled on this instance")
	case "once":
		if cert.KeyDownloadCount > 0 {
			return deny("this private key has already been downloaded once and the policy allows only one download")
		}
	}
	if !cert.HasPrivateKey() {
		return ErrKeyUnavailable
	}

	now := time.Now().UTC()
	cert.KeyDownloadCount++
	cert.LastDownloadedAt = &now
	if err := s.Store.Certificates.UpdateFields(cert.ID, map[string]any{
		"key_download_count": cert.KeyDownloadCount,
		"last_downloaded_at": now,
	}); err != nil {
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionKeyDownload,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   cert.ID,
		ResourceName: cert.CommonName,
		Metadata:     map[string]any{"policy": policy, "download_count": cert.KeyDownloadCount},
	})
	return nil
}

// RefreshCertificateStatuses recomputes every certificate's status against the
// clock and returns how many rows changed.
func (s *Service) RefreshCertificateStatuses() (int, error) {
	cutoff := time.Now().AddDate(0, 0, s.Config.Scheduler.ExpiryWarnDays)
	rows, err := s.Store.Certificates.ExpiringBefore(cutoff)
	if err != nil {
		return 0, err
	}

	changed := 0
	for i := range rows {
		row := &rows[i]
		want := row.DeriveStatus(s.Config.Scheduler.ExpiryWarnDays)
		if row.Status == want {
			continue
		}
		if err := s.Store.Certificates.UpdateFields(row.ID, map[string]any{"status": want}); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// Inspect decodes pasted PEM without persisting anything.
func (s *Service) Inspect(data []byte) (*pki.InspectResult, error) {
	result, err := pki.Inspect(data)
	if err != nil {
		return nil, validationError("%s", err)
	}
	return result, nil
}

// distributionPoints wraps a single configured URL into the slice the x509
// template expects, dropping it when empty.
func distributionPoints(url string) []string {
	if url == "" {
		return nil
	}
	return []string{url}
}

// ReleaseHold takes a certificate back off the CRL.
//
// RFC 5280 reserves reason code 6 (certificateHold) for a revocation that can
// be undone, and code 8 (removeFromCRL) for the undoing. Certio accepted the
// hold but had no way to lift it, which made "hold" a slower spelling of
// "revoke" — the whole value of a hold is that the answer might be no.
//
// Only a hold can be released. A certificate revoked for key compromise stays
// revoked: reversing that is not an operation anyone should have.
func (s *Service) ReleaseHold(actor audit.Actor, id, caPassphrase string) (*store.Certificate, error) {
	cert, caRow, err := s.Store.Certificates.GetWithAuthority(id)
	if err != nil {
		return nil, err
	}

	switch cert.Status {
	case store.StatusHeld:
	case store.StatusRevoked:
		return nil, fmt.Errorf(
			"%w: %s was revoked, not held; a revocation cannot be reversed",
			ErrConflict, cert.CommonName)
	default:
		return nil, fmt.Errorf("%w: %s is not on hold", ErrConflict, cert.CommonName)
	}

	rev, err := s.Store.Revocations.ByCertificate(cert.ID)
	if err != nil {
		return nil, err
	}
	if err := s.Store.Revocations.Delete(rev.ID); err != nil {
		return nil, err
	}

	// The clock decides what it becomes: a certificate held for a fortnight
	// may well come back expiring rather than active.
	cert.Status = store.StatusActive
	cert.Status = cert.DeriveStatus(s.Config.Scheduler.ExpiryWarnDays)
	if err := s.Store.Certificates.Update(cert); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action:       audit.ActionCertReleaseHold,
		ResourceType: audit.ResourceCertificate,
		ResourceID:   cert.ID,
		ResourceName: cert.CommonName,
		Metadata: map[string]any{
			"serial_number": cert.SerialNumber, "ca": caRow.Name,
			"held_since": rev.RevokedAt,
		},
	})

	// Until the CRL is republished the certificate is still listed as revoked
	// everywhere that matters, so this is the part that actually lifts it.
	if !caRow.PassphraseProtected || caPassphrase != "" {
		if _, err := s.GenerateCRL(actor, caRow.ID, caPassphrase); err != nil {
			s.Log.Error("hold released but the CRL could not be republished",
				"error", err, "ca", caRow.Slug, "certificate", cert.ID)
		}
	}
	return cert, nil
}
