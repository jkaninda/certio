package handlers

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// ListAuthorities returns a filtered page of CAs.
func (h *Handler) ListAuthorities(c *okapi.Context, req *dto.ListAuthoritiesRequest) error {
	p := page(req.Page, req.Limit)
	result, err := h.Service.Store.Authorities.List(store.AuthorityFilter{
		Type: req.Type, Status: req.Status, Query: req.Query,
	}, p)
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.AuthorityResponse, 0, len(result.Items))
	for i := range result.Items {
		row := &result.Items[i]
		certs, err := h.Service.Store.Certificates.ByAuthority(row.ID)
		if err != nil {
			return h.fail(c, err)
		}
		items = append(items, dto.NewAuthorityResponse(row, h.Config.Server.BaseURL, int64(len(certs)), false))
	}

	return c.OK(dto.AuthorityListResponse{
		Items: items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// CreateAuthority creates a root or intermediate CA.
func (h *Handler) CreateAuthority(c *okapi.Context, req *dto.CreateAuthorityRequest) error {
	in := req.Body
	ca, err := h.Service.CreateAuthority(h.actor(c), service.CreateAuthorityInput{
		Name: in.Name, Slug: in.Slug, Description: in.Description,
		Type: in.Type, ParentID: in.ParentID, ParentPassphrase: in.ParentPassphrase,
		Subject: in.Subject.ToPKI(), KeyAlgorithm: in.KeyAlgorithm,
		ValidityDays: in.ValidityDays, MaxPathLen: in.MaxPathLen,
		NameConstraints: in.NameConstraints.ToPKI(),
		Passphrase:      in.Passphrase,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.NewAuthorityResponse(ca, h.Config.Server.BaseURL, 0, true))
}

// ImportAuthority adopts an existing CA from PEM material.
func (h *Handler) ImportAuthority(c *okapi.Context, req *dto.ImportAuthorityRequest) error {
	in := req.Body
	ca, err := h.Service.ImportAuthority(h.actor(c), service.ImportAuthorityInput{
		Name: in.Name, Slug: in.Slug, Description: in.Description,
		CertPEM: in.CertPEM, KeyPEM: in.KeyPEM, Passphrase: in.Passphrase,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.NewAuthorityResponse(ca, h.Config.Server.BaseURL, 0, true))
}

// GetAuthority returns one CA.
func (h *Handler) GetAuthority(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	ca, err := h.Service.Store.Authorities.Resolve(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	certs, err := h.Service.Store.Certificates.ByAuthority(ca.ID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewAuthorityResponse(ca, h.Config.Server.BaseURL, int64(len(certs)), true))
}

// UpdateAuthority edits CA metadata.
func (h *Handler) UpdateAuthority(c *okapi.Context, req *dto.UpdateAuthorityRequest) error {
	ca, err := h.Service.UpdateAuthority(h.actor(c), req.ID, service.UpdateAuthorityInput{
		Name: req.Body.Name, Description: req.Body.Description,
		CRLURL: req.Body.CRLURL, OCSPURL: req.Body.OCSPURL,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewAuthorityResponse(ca, h.Config.Server.BaseURL, 0, true))
}

// DeleteAuthority removes a CA, cascading only when ?force=true.
func (h *Handler) DeleteAuthority(c *okapi.Context, req *dto.DeleteAuthorityRequest) error {
	if err := h.Service.DeleteAuthority(h.actor(c), req.ID, req.Force); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "certificate authority deleted"})
}

// RenewAuthority re-issues a CA certificate.
func (h *Handler) RenewAuthority(c *okapi.Context, req *dto.RenewAuthorityRequest) error {
	ca, err := h.Service.RenewAuthority(h.actor(c), req.ID, service.RenewAuthorityInput{
		ValidityDays: req.Body.ValidityDays,
		Passphrase:   req.Body.Passphrase, ParentPassphrase: req.Body.ParentPassphrase,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewAuthorityResponse(ca, h.Config.Server.BaseURL, 0, true))
}

// AuthorityCertificates lists the certificates one CA has issued.
func (h *Handler) AuthorityCertificates(c *okapi.Context, req *dto.AuthorityCertificatesRequest) error {
	ca, err := h.Service.Store.Authorities.Resolve(req.ID)
	if err != nil {
		return h.fail(c, err)
	}

	p := page(req.Page, req.Limit)
	result, err := h.Service.Store.Certificates.List(store.CertificateFilter{
		AuthorityID:    ca.ID,
		Status:         req.Status,
		Query:          req.Query,
		IncludeRevoked: true,
		SortBy:         req.Sort,
		SortDesc:       req.Order == "desc",
	}, p)
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.CertificateResponse, 0, len(result.Items))
	for i := range result.Items {
		items = append(items, dto.NewCertificateResponse(
			&result.Items[i], ca.Name, h.Config.Scheduler.ExpiryWarnDays, false))
	}
	return c.OK(dto.CertificateListResponse{
		Items: items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// RegenerateCRL rebuilds and publishes a CA's revocation list.
func (h *Handler) RegenerateCRL(c *okapi.Context, req *dto.RegenerateCRLRequest) error {
	der, err := h.Service.GenerateCRL(h.actor(c), req.ID, req.Body.Passphrase)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Data(http.StatusOK, "application/x-pem-file", pki.EncodeCRLPEM(der))
}

// TrustGuide returns the per-platform instructions for installing a CA root.
func (h *Handler) TrustGuide(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	ca, err := h.Service.Store.Authorities.Resolve(req.ID)
	if err != nil {
		return h.fail(c, err)
	}

	base := h.Config.Server.BaseURL
	return c.OK(dto.TrustGuideResponse{
		Authority:    dto.NewAuthorityResponse(ca, base, 0, true),
		RootURL:      base + "/ca/" + ca.ID + "/root.crt",
		ChainURL:     base + "/ca/" + ca.ID + "/chain.pem",
		CRLURL:       base + "/ca/" + ca.ID + "/crl.pem",
		Fingerprint:  ca.FingerprintSHA256,
		Instructions: h.Service.TrustGuide(ca),
	})
}

// PublicRoot serves a CA certificate unauthenticated, so a client can fetch
// the trust anchor before it trusts anything.
func (h *Handler) PublicRoot(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	ca, err := h.Service.Store.Authorities.Resolve(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	c.SetHeader("Content-Disposition",
		`attachment; filename="`+service.Slugify(ca.Name)+`-root.crt"`)
	return c.Data(http.StatusOK, "application/x-x509-ca-cert", []byte(ca.CertPEM))
}

// PublicChain serves a CA's full chain, root last.
func (h *Handler) PublicChain(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	ca, err := h.Service.Store.Authorities.Resolve(req.ID)
	if err != nil {
		return h.fail(c, err)
	}

	chain, err := h.Service.Store.Authorities.Chain(ca)
	if err != nil {
		return h.fail(c, err)
	}
	pemBytes := []byte(ca.CertPEM)
	for _, parent := range chain {
		pemBytes = append(pemBytes, parent.CertPEM...)
	}

	c.SetHeader("Content-Disposition",
		`attachment; filename="`+service.Slugify(ca.Name)+`-chain.pem"`)
	return c.Data(http.StatusOK, "application/x-pem-file", pemBytes)
}

// PublicCRL serves a CA's revocation list, unauthenticated — a CRL nobody can
// fetch is a CRL nobody can honour.
func (h *Handler) PublicCRL(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	crlPEM, err := h.Service.CRLFor(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Data(http.StatusOK, "application/x-pem-file", crlPEM)
}

// PublicOCSP answers an RFC 6960 status query for one CA.
//
// Everything an OCSP client understands is DER, including the failures — so a
// bad request comes back as an unsigned malformedRequest body with HTTP 200,
// not as the JSON error every other endpoint returns. An OCSP client shown a
// JSON 400 reports "unable to parse response", which is a far worse thing to
// debug than "malformed".
func (h *Handler) PublicOCSP(c *okapi.Context, req *dto.OCSPRequest) error {
	body, err := h.ocspRequestBody(c, req)
	if err != nil {
		return c.Data(http.StatusOK, ocspContentType, pki.OCSPMalformedRequest)
	}

	der, err := h.Service.OCSPRespond(req.ID, body)
	switch {
	case errors.Is(err, service.ErrOCSPUnauthorized), errors.Is(err, service.ErrNotFound):
		return c.Data(http.StatusOK, ocspContentType, pki.OCSPUnauthorized)
	case errors.Is(err, service.ErrValidation):
		return c.Data(http.StatusOK, ocspContentType, pki.OCSPMalformedRequest)
	case err != nil:
		h.Service.Log.Error("could not answer an OCSP request", "error", err, "ca", req.ID)
		return c.Data(http.StatusOK, ocspContentType, pki.OCSPInternalError)
	}

	// A signed response is safe to cache for exactly as long as it says it is;
	// the responder puts the same window in nextUpdate.
	c.SetHeader("Cache-Control", "public, max-age=3600, no-transform")
	return c.Data(http.StatusOK, ocspContentType, der)
}

// ocspContentType is the media type RFC 6960 §A.2 defines for a response.
const ocspContentType = "application/ocsp-response"

// ocspRequestBody reads the DER request from either transport RFC 6960 allows:
// a POST body, or a base64-encoded path segment on a GET. The GET form is what
// a caching proxy in front of the responder needs, and some embedded clients
// send nothing else.
func (h *Handler) ocspRequestBody(c *okapi.Context, req *dto.OCSPRequest) ([]byte, error) {
	if req.Encoded != "" {
		// The encoding may arrive percent-escaped, because base64 can contain
		// "/" and "+" and a client is entitled to escape them.
		unescaped, err := url.PathUnescape(req.Encoded)
		if err != nil {
			unescaped = req.Encoded
		}
		return base64.StdEncoding.DecodeString(unescaped)
	}
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxOCSPRequestBytes))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("empty OCSP request")
	}
	return body, nil
}

// maxOCSPRequestBytes caps the request body. A status query is a couple of
// hundred bytes; anything larger is a mistake or an attempt to make the
// responder allocate.
const maxOCSPRequestBytes = 16 << 10

// PublicCRLDER serves the same list in DER, which is what most TLS stacks
// fetch from a CRL distribution point.
func (h *Handler) PublicCRLDER(c *okapi.Context, req *dto.AuthorityRefRequest) error {
	crlPEM, err := h.Service.CRLFor(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Data(http.StatusOK, "application/pkix-crl", crl.Raw)
}
