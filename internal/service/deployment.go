package service

import (
	"context"
	"errors"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/deploy"
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// CreateDeploymentInput describes a deployment target to configure.
type CreateDeploymentInput struct {
	Name       string
	Kind       string
	Config     map[string]string
	Selector   map[string]string
	CommonName string
	Enabled    bool
}

// CreateDeploymentTarget configures somewhere a renewed certificate is written.
func (s *Service) CreateDeploymentTarget(actor audit.Actor, in CreateDeploymentInput) (*store.DeploymentTarget, error) {
	if in.Name == "" {
		return nil, validationError("a target name is required")
	}
	if len(in.Selector) == 0 && in.CommonName == "" {
		return nil, validationError(
			"a target needs a selector or a common name; one that matched everything would " +
				"overwrite every server's key with the wrong certificate")
	}
	// Building the target now surfaces a missing host key or cluster token
	// while the form is open, rather than during an unattended renewal.
	if _, err := deploy.Build(in.Kind, in.Config); err != nil {
		return nil, validationError("%s", err)
	}

	sealed, nonce, salt, err := s.sealConfig(in.Config)
	if err != nil {
		return nil, err
	}

	row := &store.DeploymentTarget{
		Name: in.Name, Kind: in.Kind,
		ConfigEncrypted: sealed, ConfigNonce: nonce, ConfigSalt: salt,
		Selector: store.JSON(in.Selector), CommonName: in.CommonName,
		Enabled: in.Enabled,
	}
	if err := s.Store.Deployments.Create(row); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionDeploymentCreate, ResourceType: audit.ResourceDeployment,
		ResourceID: row.ID, ResourceName: row.Name,
		Metadata: map[string]any{"kind": in.Kind, "selector": in.Selector, "common_name": in.CommonName},
	})
	return row, nil
}

// UpdateDeploymentInput carries the mutable fields of a target.
type UpdateDeploymentInput struct {
	Name       *string
	Config     *map[string]string
	Selector   *map[string]string
	CommonName *string
	Enabled    *bool
}

// UpdateDeploymentTarget edits a target.
func (s *Service) UpdateDeploymentTarget(
	actor audit.Actor, id string, in UpdateDeploymentInput,
) (*store.DeploymentTarget, error) {
	row, err := s.Store.Deployments.Get(id)
	if err != nil {
		return nil, err
	}

	if in.Name != nil {
		row.Name = *in.Name
	}
	if in.Selector != nil {
		row.Selector = store.JSON(*in.Selector)
	}
	if in.CommonName != nil {
		row.CommonName = *in.CommonName
	}
	if in.Enabled != nil {
		row.Enabled = *in.Enabled
	}
	if in.Config != nil {
		if _, err := deploy.Build(row.Kind, *in.Config); err != nil {
			return nil, validationError("%s", err)
		}
		sealed, nonce, salt, err := s.sealConfig(*in.Config)
		if err != nil {
			return nil, err
		}
		row.ConfigEncrypted, row.ConfigNonce, row.ConfigSalt = sealed, nonce, salt
	}
	if len(row.Selector.Data) == 0 && row.CommonName == "" {
		return nil, validationError("a target needs a selector or a common name")
	}

	if err := s.Store.Deployments.Update(row); err != nil {
		return nil, err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionDeploymentUpdate, ResourceType: audit.ResourceDeployment,
		ResourceID: row.ID, ResourceName: row.Name,
	})
	return row, nil
}

// DeleteDeploymentTarget removes a target.
func (s *Service) DeleteDeploymentTarget(actor audit.Actor, id string) error {
	row, err := s.Store.Deployments.Get(id)
	if err != nil {
		return err
	}
	if err := s.Store.Deployments.Delete(id); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionDeploymentDelete, ResourceType: audit.ResourceDeployment,
		ResourceID: row.ID, ResourceName: row.Name,
	})
	return nil
}

// DeployResult reports one target's outcome.
type DeployResult struct {
	TargetID    string `json:"target_id"`
	TargetName  string `json:"target_name"`
	Kind        string `json:"kind"`
	Destination string `json:"destination"`
	Certificate string `json:"certificate,omitempty"`
	Skipped     bool   `json:"skipped"`
	Error       string `json:"error,omitempty"`
}

// deployTimeout bounds one target. An SSH host that accepts the connection and
// then hangs would otherwise hold the renewal pass open indefinitely.
const deployTimeout = 2 * time.Minute

// DeployCertificate pushes one certificate to every target that selects it.
//
// Errors are returned per target rather than aborting: one unreachable server
// must not stop the other five from getting the certificate they need.
func (s *Service) DeployCertificate(actor audit.Actor, certificateID string, force bool) ([]DeployResult, error) {
	cert, err := s.Store.Certificates.Get(certificateID)
	if err != nil {
		return nil, err
	}

	targets, err := s.Store.Deployments.Enabled()
	if err != nil {
		return nil, err
	}

	var results []DeployResult
	for i := range targets {
		target := &targets[i]
		if !target.Matches(cert) {
			continue
		}
		results = append(results, s.runDeployment(actor, target, cert, force))
	}
	return results, nil
}

// runDeployment executes one target and records the outcome on its row.
func (s *Service) runDeployment(
	actor audit.Actor, target *store.DeploymentTarget, cert *store.Certificate, force bool,
) DeployResult {
	result := DeployResult{
		TargetID: target.ID, TargetName: target.Name, Kind: target.Kind,
		Certificate: cert.CommonName,
	}

	// A target that already holds this serial has nothing to do. Without the
	// check, every scheduler pass would rewrite the same files and reload the
	// same services for no reason.
	if !force && target.LastSerial == cert.SerialNumber && target.LastError == "" {
		result.Skipped = true
		return result
	}

	bundle, err := s.deployBundle(cert)
	if err != nil {
		result.Error = err.Error()
		s.recordDeployment(target, cert, err)
		return result
	}

	config, err := s.openTargetConfig(target)
	if err != nil {
		result.Error = err.Error()
		s.recordDeployment(target, cert, err)
		return result
	}

	built, err := deploy.Build(target.Kind, config)
	if err != nil {
		result.Error = err.Error()
		s.recordDeployment(target, cert, err)
		return result
	}
	result.Destination = built.Describe()

	ctx, cancel := context.WithTimeout(context.Background(), deployTimeout)
	defer cancel()

	deployErr := built.Deploy(ctx, bundle)
	s.recordDeployment(target, cert, deployErr)
	s.Metrics.Deployments.WithLabelValues(target.Kind, metrics.Result(deployErr)).Inc()

	if deployErr != nil {
		result.Error = deployErr.Error()
		s.Log.Error("deployment failed", "error", deployErr,
			"target", target.Name, "certificate", cert.CommonName)
		return result
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionDeploymentRun, ResourceType: audit.ResourceDeployment,
		ResourceID: target.ID, ResourceName: target.Name,
		Metadata: map[string]any{
			"certificate": cert.CommonName, "serial_number": cert.SerialNumber,
			"destination": result.Destination,
		},
	})
	return result
}

// deployBundle assembles the material a target writes.
func (s *Service) deployBundle(cert *store.Certificate) (deploy.Bundle, error) {
	bundle, row, err := s.LoadBundle(cert.ID, true)
	if err != nil && !errors.Is(err, ErrKeyUnavailable) {
		return deploy.Bundle{}, err
	}

	out := deploy.Bundle{
		CommonName:     row.CommonName,
		SerialNumber:   row.SerialNumber,
		NotAfter:       row.NotAfter,
		CertificatePEM: bundle.CertPEM(),
		ChainPEM:       bundle.ChainPEM(),
		FullchainPEM:   bundle.FullChainPEM(),
		RootPEM:        bundle.RootPEM(),
	}
	// A BYO-CSR certificate has no key here, and that is not an error: a
	// webhook target may want only the certificate. The targets that do need
	// one say so themselves.
	if bundle.PrivateKey != nil {
		keyPEM, err := pki.MarshalPrivateKeyPEM(bundle.PrivateKey)
		if err != nil {
			return deploy.Bundle{}, err
		}
		out.PrivateKeyPEM = keyPEM
	}
	return out, nil
}

// recordDeployment stamps the attempt on the target row.
func (s *Service) recordDeployment(target *store.DeploymentTarget, cert *store.Certificate, deployErr error) {
	now := time.Now().UTC()
	target.LastRunAt = &now
	target.LastError = ""
	if deployErr != nil {
		target.LastError = deployErr.Error()
	} else {
		target.LastSuccess = &now
		// Only a success records the serial; otherwise a failed push would
		// mark the target as up to date and never be retried.
		target.LastSerial = cert.SerialNumber
	}
	if err := s.Store.Deployments.Update(target); err != nil {
		s.Log.Error("could not record the deployment result", "error", err, "target", target.ID)
	}
}

// openTargetConfig decrypts a target's settings.
func (s *Service) openTargetConfig(target *store.DeploymentTarget) (map[string]string, error) {
	return s.openSealedConfig(target.ConfigEncrypted, target.ConfigNonce, target.ConfigSalt)
}

// DeployPending pushes every certificate whose current serial has not reached
// its targets yet. The scheduler calls it after auto-renewal, which is what
// turns "a new certificate exists" into "the servers are serving it".
func (s *Service) DeployPending(actor audit.Actor) (deployed, failed int, err error) {
	targets, err := s.Store.Deployments.Enabled()
	if err != nil {
		return 0, 0, err
	}
	if len(targets) == 0 {
		return 0, 0, nil
	}

	// Only active certificates are candidates: pushing an expired or revoked
	// one over a working file would be actively harmful.
	page, err := s.Store.Certificates.List(store.CertificateFilter{
		IncludeRevoked: false, SortBy: "not_after",
	}, store.Pagination{Page: 1, Limit: 500})
	if err != nil {
		return 0, 0, err
	}

	for i := range targets {
		target := &targets[i]
		match := newestMatch(target, page.Items)
		if match == nil {
			continue
		}
		result := s.runDeployment(actor, target, match, false)
		switch {
		case result.Skipped:
		case result.Error != "":
			failed++
		default:
			deployed++
		}
	}
	return deployed, failed, nil
}

// newestMatch picks the certificate a target should be holding: of everything
// the selector matches, the one that expires last. After a renewal both the
// old and the new certificate match, and the new one is the point.
func newestMatch(target *store.DeploymentTarget, certs []store.Certificate) *store.Certificate {
	var best *store.Certificate
	for i := range certs {
		cert := &certs[i]
		if !target.Matches(cert) {
			continue
		}
		if best == nil || cert.NotAfter.After(best.NotAfter) {
			best = cert
		}
	}
	return best
}

// TestDeploymentTarget pushes the current matching certificate to one target,
// so a configuration can be proved before a renewal depends on it.
func (s *Service) TestDeploymentTarget(actor audit.Actor, id string) (DeployResult, error) {
	target, err := s.Store.Deployments.Get(id)
	if err != nil {
		return DeployResult{}, err
	}

	page, err := s.Store.Certificates.List(store.CertificateFilter{
		IncludeRevoked: false,
	}, store.Pagination{Page: 1, Limit: 500})
	if err != nil {
		return DeployResult{}, err
	}

	match := newestMatch(target, page.Items)
	if match == nil {
		return DeployResult{}, validationError(
			"no active certificate matches this target's selector, so there is nothing to deploy")
	}
	// The per-target outcome travels in the result; the returned error is
	// reserved for the lookup itself failing.
	return s.runDeployment(actor, target, match, true), nil
}
