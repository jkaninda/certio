package handlers

import (
	"net/http"
	"strings"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// ListCertificates returns a filtered, sorted page of certificates.
func (h *Handler) ListCertificates(c *okapi.Context, req *dto.ListCertificatesRequest) error {
	p := page(req.Page, req.Limit)

	filter := store.CertificateFilter{
		AuthorityID:    req.AuthorityID,
		Status:         req.Status,
		Profile:        req.Profile,
		Query:          req.Query,
		ExpiringInDays: days(req.ExpiringIn),
		AutoRenew:      req.AutoRenew,
		Labels:         parseLabels(req.Label),
		IncludeRevoked: true,
		SortBy:         req.Sort,
		SortDesc:       req.Order == "desc",
	}
	if req.IncludeRevoked != nil {
		filter.IncludeRevoked = *req.IncludeRevoked
	}
	// The filter accepts a CA slug as readily as an ID, matching the API's
	// path parameters.
	if filter.AuthorityID != "" {
		if ca, err := h.Service.Store.Authorities.Resolve(filter.AuthorityID); err == nil {
			filter.AuthorityID = ca.ID
		}
	}

	result, err := h.Service.Store.Certificates.List(filter, p)
	if err != nil {
		return h.fail(c, err)
	}

	names, err := h.authorityNames()
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.CertificateResponse, 0, len(result.Items))
	for i := range result.Items {
		row := &result.Items[i]
		items = append(items, dto.NewCertificateResponse(
			row, names[row.AuthorityID], h.Config.Scheduler.ExpiryWarnDays, false))
	}
	return c.OK(dto.CertificateListResponse{
		Items: items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// IssueCertificate performs a managed issuance.
func (h *Handler) IssueCertificate(c *okapi.Context, req *dto.IssueCertificateRequest) error {
	in := req.Body

	sans, err := in.ResolveSANs()
	if err != nil {
		return badRequest(c, err)
	}

	result, err := h.Service.Issue(h.actor(c), service.IssueInput{
		AuthorityID: in.AuthorityID, CAPassphrase: in.CAPassphrase,
		Subject: in.Subject.ToPKI(), SANs: sans,
		Profile: in.Profile, KeyAlgorithm: in.KeyAlgorithm, ValidityDays: in.ValidityDays,
		KeyUsage: in.KeyUsage, ExtKeyUsage: in.ExtKeyUsage,
		AutoRenew: in.AutoRenew, RenewBeforeDays: in.RenewBeforeDays,
		Labels: in.Labels, Notes: in.Notes,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(h.issueResponse(result))
}

// SignCSR performs a BYO-CSR issuance.
func (h *Handler) SignCSR(c *okapi.Context, req *dto.SignCSRRequest) error {
	in := req.Body

	sans, err := toSANSet(in.SANs)
	if err != nil {
		return badRequest(c, err)
	}

	result, err := h.Service.SignCSR(h.actor(c), service.SignCSRInput{
		AuthorityID: in.AuthorityID, CAPassphrase: in.CAPassphrase,
		CSRPEM: in.CSRPEM, Profile: in.Profile, SANs: sans,
		ValidityDays: in.ValidityDays,
		KeyUsage:     in.KeyUsage, ExtKeyUsage: in.ExtKeyUsage,
		Labels: in.Labels, Notes: in.Notes,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(h.issueResponse(result))
}

// toSANSet validates typed SAN entries into a set. Unlike the issuance flow it
// does not accept the pasted textual form: these endpoints override what a CSR
// already asked for, so every entry is explicit.
func toSANSet(entries []dto.SANDTO) (pki.SANSet, error) {
	var sans pki.SANSet
	for _, entry := range entries {
		san := pki.SAN{Type: entry.Type, Value: entry.Value}
		if err := san.Validate(); err != nil {
			return nil, err
		}
		sans = sans.Add(san)
	}
	return sans, nil
}

// issueResponse assembles the reply for a new certificate, including the
// private key when there is one to hand back.
func (h *Handler) issueResponse(result *service.IssueResult) dto.IssueCertificateResponse {
	caName := ""
	if ca, err := h.Service.Store.Authorities.Get(result.Certificate.AuthorityID); err == nil {
		caName = ca.Name
	}

	resp := dto.IssueCertificateResponse{
		Certificate: dto.NewCertificateResponse(
			result.Certificate, caName, h.Config.Scheduler.ExpiryWarnDays, true),
		CertPEM:      string(result.Bundle.CertPEM()),
		FullchainPEM: string(result.Bundle.FullChainPEM()),
		ChainPEM:     string(result.Bundle.ChainPEM()),
	}
	if len(result.PrivateKeyPEM) > 0 {
		resp.PrivateKeyPEM = string(result.PrivateKeyPEM)
		resp.Warning = "Store the private key now. Depending on the instance's key download policy, " +
			"it may not be retrievable again."
	}
	return resp
}

// GetCertificate returns one certificate with its PEM.
func (h *Handler) GetCertificate(c *okapi.Context, req *dto.CertificateRefRequest) error {
	cert, ca, err := h.Service.Store.Certificates.GetWithAuthority(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewCertificateResponse(cert, ca.Name, h.Config.Scheduler.ExpiryWarnDays, true))
}

// UpdateCertificate edits certificate metadata.
func (h *Handler) UpdateCertificate(c *okapi.Context, req *dto.UpdateCertificateRequest) error {
	cert, err := h.Service.UpdateCertificate(h.actor(c), req.ID, service.UpdateCertificateInput{
		Labels: req.Body.Labels, Notes: req.Body.Notes,
		AutoRenew: req.Body.AutoRenew, RenewBeforeDays: req.Body.RenewBeforeDays,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewCertificateResponse(cert, "", h.Config.Scheduler.ExpiryWarnDays, false))
}

// DeleteCertificate removes a certificate record.
func (h *Handler) DeleteCertificate(c *okapi.Context, req *dto.CertificateRefRequest) error {
	if err := h.Service.DeleteCertificate(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{
		Message: "certificate deleted. Note that deleting is not revoking: if this certificate " +
			"is still deployed, clients will keep accepting it until it expires.",
	})
}

// RenewCertificate re-issues a certificate as a new row.
func (h *Handler) RenewCertificate(c *okapi.Context, req *dto.RenewCertificateRequest) error {
	sans, err := toSANSet(req.Body.SANs)
	if err != nil {
		return badRequest(c, err)
	}

	result, err := h.Service.Renew(h.actor(c), req.ID, service.RenewInput{
		Rekey: req.Body.Rekey, KeyAlgorithm: req.Body.KeyAlgorithm,
		ValidityDays: req.Body.ValidityDays, SANs: sans, CAPassphrase: req.Body.CAPassphrase,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(h.issueResponse(result))
}

// RevokeCertificate revokes a certificate and republishes the CRL.
func (h *Handler) RevokeCertificate(c *okapi.Context, req *dto.RevokeCertificateRequest) error {
	rev, err := h.Service.Revoke(h.actor(c), req.ID, service.RevokeInput{
		ReasonCode: req.Body.ReasonCode, CAPassphrase: req.Body.CAPassphrase,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.RevokeCertificateResponse{
		Message:      "certificate revoked and the CRL republished",
		RevokedAt:    rev.RevokedAt,
		Reason:       rev.Reason,
		ReasonCode:   rev.ReasonCode,
		SerialNumber: rev.SerialNumber,
	})
}

// BulkRenew renews several certificates, reporting each outcome separately so
// one failure does not hide the successes.
func (h *Handler) BulkRenew(c *okapi.Context, req *dto.BulkRenewRequest) error {
	if len(req.Body.IDs) == 0 {
		return badRequest(c, errEmptyBulk)
	}

	resp := dto.BulkResponse{Results: make([]dto.BulkResult, 0, len(req.Body.IDs))}
	for _, id := range req.Body.IDs {
		result, err := h.Service.Renew(h.actor(c), id, service.RenewInput{
			Rekey: req.Body.Rekey, CAPassphrase: req.Body.CAPassphrase,
		})
		if err != nil {
			resp.Failed++
			resp.Results = append(resp.Results, dto.BulkResult{
				ID: id, Success: false, Error: cleanMessage(err),
			})
			continue
		}
		resp.Succeeded++
		resp.Results = append(resp.Results, dto.BulkResult{
			ID: id, Success: true, NewID: result.Certificate.ID,
		})
	}
	return c.OK(resp)
}

// BulkRevoke revokes several certificates and rebuilds each affected CRL once.
func (h *Handler) BulkRevoke(c *okapi.Context, req *dto.BulkRevokeRequest) error {
	in := req.Body
	if len(in.IDs) == 0 {
		return badRequest(c, errEmptyBulk)
	}

	resp := dto.BulkResponse{Results: make([]dto.BulkResult, 0, len(in.IDs))}
	affected := map[string]bool{}

	for _, id := range in.IDs {
		cert, err := h.Service.Store.Certificates.Get(id)
		if err != nil {
			resp.Failed++
			resp.Results = append(resp.Results, dto.BulkResult{ID: id, Success: false, Error: cleanMessage(err)})
			continue
		}
		// SkipCRL defers publication so a hundred revocations rebuild the list
		// once rather than a hundred times.
		if _, err := h.Service.Revoke(h.actor(c), id, service.RevokeInput{
			ReasonCode: in.ReasonCode, CAPassphrase: in.CAPassphrase, SkipCRL: true,
		}); err != nil {
			resp.Failed++
			resp.Results = append(resp.Results, dto.BulkResult{ID: id, Success: false, Error: cleanMessage(err)})
			continue
		}
		affected[cert.AuthorityID] = true
		resp.Succeeded++
		resp.Results = append(resp.Results, dto.BulkResult{ID: id, Success: true})
	}

	for caID := range affected {
		if _, err := h.Service.GenerateCRL(h.actor(c), caID, in.CAPassphrase); err != nil {
			h.Service.Log.Error("could not republish the CRL after a bulk revocation",
				"error", err, "ca", caID)
		}
	}
	return c.OK(resp)
}

// DownloadCertificate renders a certificate in the requested format.
func (h *Handler) DownloadCertificate(c *okapi.Context, req *dto.DownloadCertificateRequest) error {
	format := req.Format
	if format == "" {
		format = service.FormatPEM
	}

	needsKey := service.FormatNeedsKey(format)
	bundle, cert, err := h.Service.LoadBundle(req.ID, needsKey)
	if err != nil {
		return h.fail(c, err)
	}

	// Anything containing key material passes the download policy first, and
	// is audited whichever way it goes.
	if needsKey {
		if err := h.Service.AuthorizeKeyDownload(h.actor(c), cert); err != nil {
			return h.fail(c, err)
		}
	}

	export, err := h.Service.ExportCertificate(cert, bundle, service.ExportOptions{
		Format:     format,
		Password:   req.Password,
		SecretName: req.SecretName,
		Namespace:  req.Namespace,
	})
	if err != nil {
		return h.fail(c, err)
	}

	c.SetHeader("Content-Disposition", `attachment; filename="`+export.Filename+`"`)
	return c.Data(http.StatusOK, export.ContentType, export.Data)
}

// CertificateChain describes each link of a certificate's chain, so the UI can
// point at the exact certificate that broke it.
func (h *Handler) CertificateChain(c *okapi.Context, req *dto.CertificateRefRequest) error {
	bundle, _, err := h.Service.LoadBundle(req.ID, false)
	if err != nil {
		return h.fail(c, err)
	}

	links := bundle.DescribeChain(timeNow())
	valid := true
	for _, link := range links {
		if !link.Valid {
			valid = false
		}
	}
	return c.OK(dto.ChainResponse{Links: links, Valid: valid})
}

// CertificateHistory returns the renewal lineage of a certificate.
func (h *Handler) CertificateHistory(c *okapi.Context, req *dto.CertificateRefRequest) error {
	history, err := h.Service.Store.Certificates.RenewalHistory(req.ID)
	if err != nil {
		return h.fail(c, err)
	}

	names, err := h.authorityNames()
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.CertificateResponse, 0, len(history))
	for i := range history {
		row := &history[i]
		items = append(items, dto.NewCertificateResponse(
			row, names[row.AuthorityID], h.Config.Scheduler.ExpiryWarnDays, false))
	}
	return c.OK(dto.CertificateHistoryResponse{Items: items, Total: len(items)})
}

// Inspect decodes pasted PEM without persisting anything.
func (h *Handler) Inspect(c *okapi.Context, req *dto.InspectRequest) error {
	result, err := h.Service.Inspect([]byte(req.Body.PEM))
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(result)
}

// Dashboard returns the landing page payload.
func (h *Handler) Dashboard(c *okapi.Context) error {
	stats, err := h.Service.Dashboard()
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(stats)
}

// authorityNames builds an ID → name map for enriching list responses without
// an N+1 query per row.
func (h *Handler) authorityNames() (map[string]string, error) {
	authorities, err := h.Service.Store.Authorities.All()
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(authorities))
	for _, a := range authorities {
		names[a.ID] = a.Name
	}
	return names, nil
}

// parseLabels turns repeated key=value query parameters into a filter map. An
// entry without "=" is ignored rather than treated as a key with an empty
// value, which would silently match nothing and read like a broken filter.
func parseLabels(values []string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ReleaseHold takes a held certificate back off the CRL.
func (h *Handler) ReleaseHold(c *okapi.Context, req *dto.ReleaseHoldRequest) error {
	cert, err := h.Service.ReleaseHold(h.actor(c), req.ID, req.Body.CAPassphrase)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewCertificateResponse(cert, "", h.Service.Config.Scheduler.ExpiryWarnDays, false))
}
