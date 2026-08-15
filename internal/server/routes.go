package server

import (
	"net/http"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/server/middleware"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/okapi"
)

// The route tables below are data, not code: each entry names a method, a
// path, a handler and the request and response types. okapi derives the
// binding, the validation and the whole OpenAPI operation — parameters,
// schemas, required flags, enums — from those two types, so a parameter is
// described exactly once, in the struct that also reads it. Nothing here
// restates a field.
//
// A handler that reads a path, query or body is wrapped in okapi.H, which
// binds and validates the request struct before the handler runs — so a
// handler never begins with a bind-and-check dance and a malformed payload
// never reaches it. A handler that reads none of those takes a plain
// *okapi.Context and is registered unwrapped: there is nothing to bind, and an
// empty request struct would be ceremony around nothing.

// Tag names, so a typo cannot silently split one OpenAPI section in two.
const (
	tagSystem      = "System"
	tagTrust       = "Trust"
	tagAuth        = "Authentication"
	tagTwoFactor   = "Two-factor authentication"
	tagAuthorities = "Authorities"
	tagCerts       = "Certificates"
	tagUsers       = "Users"
	tagTokens      = "API Tokens"
	tagNotify      = "Notifications"
	tagAudit       = "Audit"
	tagSettings    = "Settings"
	tagDeploy      = "Deployments"
	tagACME        = "ACME"
	tagDashboard   = "Dashboard"
)

// groups holds the route groups shared across the tables, built once so the
// middleware and tag metadata for an area live in a single place.
type groups struct {
	// public serves trust distribution: unauthenticated by design.
	public *okapi.Group
	// auth is the sign-in surface, rate-limited and unauthenticated.
	auth *okapi.Group
	// api requires a session or an API token.
	api *okapi.Group
	// acme is the RFC 8555 surface. It authenticates every request itself,
	// with a JWS rather than a bearer token, so it carries none of the API's
	// middleware.
	acme *okapi.Group
}

// newGroups builds the route groups and their shared middleware.
func (s *Server) newGroups(opts Options) groups {
	// One limiter instance guards both sign-in steps, so a two-factor
	// challenge cannot be used to brute-force codes at a rate the password
	// form would refuse.
	loginLimiter := middleware.NewRateLimiter(
		s.cfg.Security.LoginRateLimit, s.cfg.Security.LoginRateWindow)

	public := s.app.Group("/ca").WithTagInfo(okapi.GroupTag{
		Name: tagTrust,
		Description: "Trust distribution. These endpoints are deliberately public: a client has to be " +
			"able to fetch the root before it trusts anything Certio issued.",
	})

	auth := s.app.Group("/api/v1/auth", loginLimiter.Middleware()).WithTagInfo(okapi.GroupTag{
		Name:        tagAuth,
		Description: "Signing in, refreshing a session, and answering a two-factor challenge.",
	})

	api := s.app.Group("/api/v1", middleware.Auth(opts.Service, opts.Auth)).WithBearerAuth()

	acmeGroup := s.app.Group("/acme").WithTagInfo(okapi.GroupTag{
		Name: tagACME,
		Description: "RFC 8555. Every request is a signed JWS carrying its own anti-replay nonce, " +
			"so these endpoints are unauthenticated in the bearer-token sense and authenticated in " +
			"the only sense that matters here.",
	})

	return groups{public: public, auth: auth, api: api, acme: acmeGroup}
}

// routes registers every endpoint. Order matters: the OpenAPI document is
// built from the routes registered before it, and the SPA fallback is
// registered last so it never shadows an API route or the docs.
func (s *Server) routes(opts Options) {
	g := s.newGroups(opts)

	s.app.Register(s.systemRoutes(g)...)
	s.app.Register(s.trustRoutes(g)...)
	s.app.Register(s.authRoutes(g)...)
	s.app.Register(s.twoFactorRoutes(g)...)
	s.app.Register(s.authorityRoutes(g)...)
	s.app.Register(s.certificateRoutes(g)...)
	s.app.Register(s.userRoutes(g)...)
	s.app.Register(s.tokenRoutes(g)...)
	s.app.Register(s.notificationRoutes(g)...)
	s.app.Register(s.deploymentRoutes(g)...)
	s.app.Register(s.acmeRoutes(g)...)
	s.app.Register(s.operationsRoutes(g)...)

	if opts.Config.Server.EnableDocs {
		s.docs(opts.Version)
	}
	s.spa(opts)
}

// systemRoutes registers liveness, metrics and instance metadata.
func (s *Server) systemRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler

	// The metrics registry is per-instance rather than the process-wide
	// default, so two servers in one test binary do not collide on a duplicate
	// registration. It is not a RouteDefinition because the exposition format
	// has no typed request or response to describe.
	s.app.HandleHTTP(http.MethodGet, "/metrics", s.metrics.Handler(),
		okapi.DocSummary("Prometheus metrics"),
		okapi.DocDescription("Certificate and CA expiry timestamps, issuance, renewal, "+
			"revocation, notification and deployment counters, plus Go runtime series."),
		okapi.DocTags(tagSystem),
	)

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/health",
			Handler:     h.Health,
			Tags:        []string{tagSystem},
			Summary:     "Liveness and database reachability",
			Description: "Returns 503 when the database is unreachable, so a load balancer drains the instance.",
			Response:    &dto.HealthResponse{},
		},
		{
			Method:      http.MethodGet,
			Path:        "/about",
			Handler:     h.About,
			Group:       g.api,
			Tags:        []string{tagSystem},
			Summary:     "Build, runtime and instance information",
			Description: "What this binary was built from and how this deployment is configured.",
			Response:    &dto.AboutResponse{},
		},
		{
			Method:      http.MethodGet,
			Path:        "/meta",
			Handler:     h.Meta,
			Group:       g.api,
			Tags:        []string{tagSystem},
			Summary:     "Reference data: profiles, key algorithms, export formats, revocation reasons",
			Description: "So the dashboard never hard-codes a list the backend owns.",
			Response:    &dto.MetaResponse{},
		},
		{
			Method:      http.MethodGet,
			Path:        "/dashboard/stats",
			Handler:     h.Dashboard,
			Group:       g.api,
			Tags:        []string{tagDashboard},
			Summary:     "Dashboard counts, expiry timeline and recent activity",
			Response:    &dto.DashboardResponse{},
			Middlewares: middleware.Read(service.ScopeCertificatesRead),
		},
	}
}

// trustRoutes registers the public trust-distribution endpoints.
func (s *Server) trustRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler

	return []okapi.RouteDefinition{
		{
			Method:  http.MethodGet,
			Path:    "/{id}/root.crt",
			Handler: okapi.H(h.PublicRoot),
			Group:   g.public,
			Summary: "Download a CA root certificate (public)",
			Request: &dto.AuthorityRefRequest{},
		},
		{
			Method:  http.MethodGet,
			Path:    "/{id}/chain.pem",
			Handler: okapi.H(h.PublicChain),
			Group:   g.public,
			Summary: "Download a CA's full chain (public)",
			Request: &dto.AuthorityRefRequest{},
		},
		{
			Method:  http.MethodGet,
			Path:    "/{id}/crl.pem",
			Handler: okapi.H(h.PublicCRL),
			Group:   g.public,
			Summary: "Download a CA's revocation list as PEM (public)",
			Request: &dto.AuthorityRefRequest{},
		},
		{
			Method:  http.MethodPost,
			Path:    "/{id}/ocsp",
			Handler: okapi.H(h.PublicOCSP),
			Group:   g.public,
			Summary: "OCSP responder (public)",
			Description: "RFC 6960 status for a certificate this CA issued, signed by the CA itself. " +
				"The answer is derived from the revocations table, not from the published CRL, so a " +
				"certificate revoked seconds ago reports revoked without waiting for the next CRL refresh.",
			Request: &dto.OCSPRequest{},
		},
		{
			Method:  http.MethodGet,
			Path:    "/{id}/ocsp/{encoded}",
			Handler: okapi.H(h.PublicOCSP),
			Group:   g.public,
			Summary: "OCSP responder, GET form (public)",
			Description: "The same query with the DER request base64-encoded in the path, which is what " +
				"RFC 6960 §A.1 defines so a caching proxy can sit in front of the responder.",
			Request: &dto.OCSPRequest{},
		},
		{
			Method:      http.MethodGet,
			Path:        "/{id}/crl.der",
			Handler:     okapi.H(h.PublicCRLDER),
			Group:       g.public,
			Summary:     "Download a CA's revocation list as DER (public)",
			Description: "DER is what most TLS stacks fetch from a CRL distribution point.",
			Request:     &dto.AuthorityRefRequest{},
		},
	}
}

// authRoutes registers the sign-in surface.
func (s *Server) authRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler

	return []okapi.RouteDefinition{
		{
			Method:  http.MethodPost,
			Path:    "/login",
			Handler: okapi.H(h.Login),
			Group:   g.auth,
			Summary: "Sign in and receive an access/refresh token pair",
			Description: "When the account has two-factor authentication enabled the reply carries " +
				"two_factor_required and a short-lived challenge_token instead of a session; exchange it " +
				"at /auth/2fa/verify. A non-interactive client may send totp_code here and skip that step.",
			Request:  &dto.LoginRequest{},
			Response: &dto.LoginResponse{},
			Options: []okapi.RouteOption{
				okapi.DocErrorResponse(401, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(429, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/2fa/verify",
			Handler:     okapi.H(h.VerifyTwoFactor),
			Group:       g.auth,
			Tags:        []string{tagTwoFactor},
			Summary:     "Exchange a two-factor challenge and code for a session",
			Description: "The code may be a six-digit authenticator code or an unspent recovery code.",
			Request:     &dto.TwoFactorVerifyRequest{},
			Response:    &dto.LoginResponse{},
			Options: []okapi.RouteOption{
				okapi.DocErrorResponse(401, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(429, &dto.ErrorResponse{}),
			},
		},
		{
			Method:   http.MethodPost,
			Path:     "/refresh",
			Handler:  okapi.H(h.Refresh),
			Group:    g.auth,
			Summary:  "Exchange a refresh token for a new pair",
			Request:  &dto.RefreshRequest{},
			Response: &dto.TokenResponse{},
			Options:  []okapi.RouteOption{okapi.DocErrorResponse(401, &dto.ErrorResponse{})},
		},
		{
			Method:  http.MethodPost,
			Path:    "/logout",
			Handler: h.Logout,
			Group:   g.auth,
			Summary: "Sign out",
			Description: "Clears the session cookie and denies the session, so the access token and the " +
				"refresh token that would replace it both stop working immediately rather than at expiry.",
			Response: &dto.MessageResponse{},
		},
		{
			Method:   http.MethodGet,
			Path:     "/auth/me",
			Handler:  h.Me,
			Group:    g.api,
			Tags:     []string{tagAuth},
			Summary:  "The authenticated account",
			Response: &dto.UserResponse{},
		},
	}
}

// twoFactorRoutes registers second-factor enrolment and management. Every
// route here acts on the caller's own account; resetting somebody else's
// factor is an admin action and lives with the user routes.
func (s *Server) twoFactorRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagTwoFactor}

	return []okapi.RouteDefinition{
		{
			Method:   http.MethodGet,
			Path:     "/auth/2fa",
			Handler:  h.TwoFactorStatus,
			Group:    g.api,
			Tags:     tag,
			Summary:  "Whether your account has a second factor enrolled",
			Response: &dto.TwoFactorStatusResponse{},
		},
		{
			Method:  http.MethodPost,
			Path:    "/auth/2fa/setup",
			Handler: h.SetupTwoFactor,
			Group:   g.api,
			Tags:    tag,
			Summary: "Start enrolment and return a secret and QR code",
			Description: "Generates a pending secret. Nothing is enforced until it is confirmed, so an " +
				"abandoned setup cannot lock the account out. Calling it again replaces the pending secret.",
			Response: &dto.TwoFactorSetupResponse{},
			Options: []okapi.RouteOption{
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(403, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/auth/2fa/enable",
			Handler:     okapi.H(h.EnableTwoFactor),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Confirm enrolment with a code and receive recovery codes",
			Description: "The recovery codes are returned exactly once; only their digests are stored.",
			Request:     &dto.TwoFactorCodeRequest{},
			Response:    &dto.RecoveryCodesResponse{},
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(401, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPost,
			Path:        "/auth/2fa/disable",
			Handler:     okapi.H(h.DisableTwoFactor),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Remove the second factor from your account",
			Description: "Requires the account password as well as a current code.",
			Request:     &dto.TwoFactorDisableRequest{},
			Response:    &dto.MessageResponse{},
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(401, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPost,
			Path:        "/auth/2fa/recovery-codes",
			Handler:     okapi.H(h.RegenerateRecoveryCodes),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Issue a fresh set of recovery codes",
			Description: "Every previously issued code stops working.",
			Request:     &dto.TwoFactorCodeRequest{},
			Response:    &dto.RecoveryCodesResponse{},
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(401, &dto.ErrorResponse{})},
		},
	}
}

// authorityRoutes registers the CA endpoints.
func (s *Server) authorityRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagAuthorities}
	read := middleware.Read(service.ScopeAuthoritiesRead)
	write := middleware.Write(service.ScopeAuthoritiesWrite)
	admin := middleware.Admin(service.ScopeAuthoritiesWrite)

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/authorities",
			Handler:     okapi.H(h.ListAuthorities),
			Group:       g.api,
			Tags:        tag,
			Summary:     "List certificate authorities",
			Request:     &dto.ListAuthoritiesRequest{},
			Response:    &dto.AuthorityListResponse{},
			Middlewares: read,
		},
		{
			Method:  http.MethodPost,
			Path:    "/authorities",
			Handler: okapi.H(h.CreateAuthority),
			Group:   g.api,
			Tags:    tag,
			Summary: "Create a root or intermediate certificate authority",
			Description: "Generates a key pair, self-signs a root or has the parent CA sign an intermediate, " +
				"and stores the key AES-256-GCM encrypted. An optional passphrase is folded into the " +
				"key derivation and is never persisted.",
			Request:     &dto.CreateAuthorityRequest{},
			Middlewares: write,
			Options: []okapi.RouteOption{
				okapi.DocResponse(201, &dto.AuthorityResponse{}),
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(403, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/authorities/import",
			Handler:     okapi.H(h.ImportAuthority),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Adopt an existing CA from PEM certificate and key",
			Description: "Nothing is re-issued: the certificate and key you already have are stored as they are.",
			Request:     &dto.ImportAuthorityRequest{},
			Middlewares: write,
			Options: []okapi.RouteOption{
				okapi.DocResponse(201, &dto.AuthorityResponse{}),
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(409, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodGet,
			Path:        "/authorities/{id}",
			Handler:     okapi.H(h.GetAuthority),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Get one certificate authority",
			Request:     &dto.AuthorityRefRequest{},
			Response:    &dto.AuthorityResponse{},
			Middlewares: read,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(404, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPatch,
			Path:        "/authorities/{id}",
			Handler:     okapi.H(h.UpdateAuthority),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Edit certificate authority metadata",
			Request:     &dto.UpdateAuthorityRequest{},
			Response:    &dto.AuthorityResponse{},
			Middlewares: write,
		},
		{
			Method:  http.MethodDelete,
			Path:    "/authorities/{id}",
			Handler: okapi.H(h.DeleteAuthority),
			Group:   g.api,
			Tags:    tag,
			Summary: "Delete a certificate authority",
			Description: "Refused while certificates or intermediates still reference it, unless force=true. " +
				"Both outcomes are audited.",
			Request:     &dto.DeleteAuthorityRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: admin,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(409, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPost,
			Path:        "/authorities/{id}/renew",
			Handler:     okapi.H(h.RenewAuthority),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Re-issue a CA certificate with the same key",
			Description: "The key is preserved, so everything this CA already signed stays verifiable.",
			Request:     &dto.RenewAuthorityRequest{},
			Response:    &dto.AuthorityResponse{},
			Middlewares: admin,
		},
		{
			Method:      http.MethodGet,
			Path:        "/authorities/{id}/certificates",
			Handler:     okapi.H(h.AuthorityCertificates),
			Group:       g.api,
			Tags:        tag,
			Summary:     "List the certificates a CA has issued",
			Request:     &dto.AuthorityCertificatesRequest{},
			Response:    &dto.CertificateListResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodPost,
			Path:        "/authorities/{id}/crl",
			Handler:     okapi.H(h.RegenerateCRL),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Regenerate and publish a CA's revocation list",
			Description: "Returns the freshly signed list as PEM.",
			Request:     &dto.RegenerateCRLRequest{},
			Middlewares: write,
		},
		{
			Method:      http.MethodGet,
			Path:        "/authorities/{id}/trust",
			Handler:     okapi.H(h.TrustGuide),
			Group:       g.api,
			Tags:        []string{tagTrust},
			Summary:     "Per-platform instructions for installing this CA root",
			Description: "Copy-paste recipes for Debian, RHEL, macOS, Windows, Java, Node.js, Docker and curl.",
			Request:     &dto.AuthorityRefRequest{},
			Response:    &dto.TrustGuideResponse{},
			Middlewares: read,
		},
	}
}

// certificateRoutes registers the certificate endpoints.
func (s *Server) certificateRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagCerts}
	read := middleware.Read(service.ScopeCertificatesRead)
	write := middleware.Write(service.ScopeCertificatesWrite)

	// Signing is the one authenticated operation that costs real CPU and
	// leaves a permanent row behind, so it gets a budget of its own. The
	// limiter is keyed by principal rather than by IP: a runaway CI token
	// should be throttled even when it shares an egress address with everyone
	// else.
	issueLimiter := middleware.NewRateLimiter(
		s.cfg.Security.IssueRateLimit, s.cfg.Security.IssueRateWindow)
	issue := append(append([]okapi.Middleware{}, write...), issueLimiter.PerPrincipal())

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/certificates",
			Handler:     okapi.H(h.ListCertificates),
			Group:       g.api,
			Tags:        tag,
			Summary:     "List certificates",
			Request:     &dto.ListCertificatesRequest{},
			Response:    &dto.CertificateListResponse{},
			Middlewares: read,
		},
		{
			Method:  http.MethodPost,
			Path:    "/certificates",
			Handler: okapi.H(h.IssueCertificate),
			Group:   g.api,
			Tags:    tag,
			Summary: "Issue a certificate from a CA",
			Description: "Managed issuance: Certio generates the key pair, signs the certificate and stores " +
				"the key encrypted. The private key is returned in this response and, depending on the " +
				"instance's key download policy, may never be retrievable again.",
			Request:     &dto.IssueCertificateRequest{},
			Middlewares: issue,
			Options: []okapi.RouteOption{
				okapi.DocResponse(201, &dto.IssueCertificateResponse{}),
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
				okapi.DocErrorResponse(428, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/certificates/sign-csr",
			Handler:     okapi.H(h.SignCSR),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Sign an externally generated CSR",
			Description: "BYO-CSR issuance: the requester keeps the private key and Certio never sees it.",
			Request:     &dto.SignCSRRequest{},
			Middlewares: issue,
			Options: []okapi.RouteOption{
				okapi.DocResponse(201, &dto.IssueCertificateResponse{}),
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/certificates/inspect",
			Handler:     okapi.H(h.Inspect),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Decode any pasted PEM without storing it",
			Description: "Accepts a certificate, a full chain, a CSR, a private key or a CRL.",
			Request:     &dto.InspectRequest{},
			Middlewares: read,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(400, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPost,
			Path:        "/certificates/bulk/renew",
			Handler:     okapi.H(h.BulkRenew),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Renew several certificates at once",
			Description: "Each outcome is reported separately, so one failure does not hide the successes.",
			Request:     &dto.BulkRenewRequest{},
			Response:    &dto.BulkResponse{},
			Middlewares: write,
		},
		{
			Method:      http.MethodPost,
			Path:        "/certificates/bulk/revoke",
			Handler:     okapi.H(h.BulkRevoke),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Revoke several certificates at once",
			Description: "Each affected CA's CRL is rebuilt once at the end rather than per certificate.",
			Request:     &dto.BulkRevokeRequest{},
			Response:    &dto.BulkResponse{},
			Middlewares: write,
		},
		{
			Method:      http.MethodGet,
			Path:        "/certificates/{id}",
			Handler:     okapi.H(h.GetCertificate),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Get one certificate",
			Request:     &dto.CertificateRefRequest{},
			Response:    &dto.CertificateResponse{},
			Middlewares: read,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(404, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodPatch,
			Path:        "/certificates/{id}",
			Handler:     okapi.H(h.UpdateCertificate),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Edit labels, notes and renewal settings",
			Request:     &dto.UpdateCertificateRequest{},
			Response:    &dto.CertificateResponse{},
			Middlewares: write,
		},
		{
			Method:  http.MethodDelete,
			Path:    "/certificates/{id}",
			Handler: okapi.H(h.DeleteCertificate),
			Group:   g.api,
			Tags:    tag,
			Summary: "Delete a certificate record",
			Description: "Deleting is not revoking. A deleted-but-unrevoked certificate stays valid to every " +
				"client until it expires — revoke it first if it is still deployed.",
			Request:     &dto.CertificateRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: write,
		},
		{
			Method:  http.MethodPost,
			Path:    "/certificates/{id}/renew",
			Handler: okapi.H(h.RenewCertificate),
			Group:   g.api,
			Tags:    tag,
			Summary: "Renew a certificate",
			Description: "Creates a new certificate linked to the old one through renewed_from_id; nothing is " +
				"mutated in place. The key is preserved unless rekey is set, so pinning survives.",
			Request:     &dto.RenewCertificateRequest{},
			Middlewares: issue,
			Options:     []okapi.RouteOption{okapi.DocResponse(201, &dto.IssueCertificateResponse{})},
		},
		{
			Method:      http.MethodPost,
			Path:        "/certificates/{id}/revoke",
			Handler:     okapi.H(h.RevokeCertificate),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Revoke a certificate and republish the CRL",
			Request:     &dto.RevokeCertificateRequest{},
			Response:    &dto.RevokeCertificateResponse{},
			Middlewares: write,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(409, &dto.ErrorResponse{})},
		},
		{
			Method:  http.MethodGet,
			Path:    "/certificates/{id}/download",
			Handler: okapi.H(h.DownloadCertificate),
			Group:   g.api,
			Tags:    tag,
			Summary: "Download a certificate in any supported format",
			Description: "Formats containing private key material are subject to the instance's key " +
				"download policy and are always audited.",
			Request:     &dto.DownloadCertificateRequest{},
			Middlewares: read,
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(403, &dto.ErrorResponse{})},
		},
		{
			Method:      http.MethodGet,
			Path:        "/certificates/{id}/chain",
			Handler:     okapi.H(h.CertificateChain),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Describe each link of a certificate's chain",
			Description: "So a broken chain can be pointed at the exact certificate that broke it.",
			Request:     &dto.CertificateRefRequest{},
			Response:    &dto.ChainResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodGet,
			Path:        "/certificates/{id}/history",
			Handler:     okapi.H(h.CertificateHistory),
			Group:       g.api,
			Tags:        tag,
			Summary:     "The renewal lineage of a certificate",
			Request:     &dto.CertificateRefRequest{},
			Response:    &dto.CertificateHistoryResponse{},
			Middlewares: read,
		},
	}
}

// userRoutes registers account administration. Every route is admin-only,
// except the second-factor reset which is also admin-only but documented with
// the two-factor endpoints it undoes.
func (s *Server) userRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagUsers}
	read := middleware.Admin(service.ScopeUsersRead)
	admin := middleware.Admin(service.ScopeUsersWrite)

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/users",
			Handler:     okapi.H(h.ListUsers),
			Group:       g.api,
			Tags:        tag,
			Summary:     "List accounts",
			Request:     &dto.ListUsersRequest{},
			Response:    &dto.UserListResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodPost,
			Path:        "/users",
			Handler:     okapi.H(h.CreateUser),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Create an account",
			Request:     &dto.CreateUserRequest{},
			Middlewares: admin,
			Options:     []okapi.RouteOption{okapi.DocResponse(201, &dto.UserResponse{})},
		},
		{
			Method:      http.MethodGet,
			Path:        "/users/{id}",
			Handler:     okapi.H(h.GetUser),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Get one account",
			Request:     &dto.UserRefRequest{},
			Response:    &dto.UserResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodPatch,
			Path:        "/users/{id}",
			Handler:     okapi.H(h.UpdateUser),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Edit an account",
			Description: "The last active administrator cannot be demoted or disabled.",
			Request:     &dto.UpdateUserRequest{},
			Response:    &dto.UserResponse{},
			Middlewares: admin,
		},
		{
			Method:      http.MethodDelete,
			Path:        "/users/{id}",
			Handler:     okapi.H(h.DeleteUser),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Delete an account",
			Description: "Their API tokens go too. Audit entries they created are kept.",
			Request:     &dto.UserRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: admin,
		},
		{
			Method:  http.MethodDelete,
			Path:    "/users/{id}/2fa",
			Handler: okapi.H(h.ResetUserTwoFactor),
			Group:   g.api,
			Tags:    tag,
			Summary: "Reset an account's second factor",
			Description: "The way back in for someone who lost both their device and their recovery codes. " +
				"The account can then sign in with its password alone until it enrols again.",
			Request:     &dto.UserRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: admin,
		},
	}
}

// tokenRoutes registers API token management. These are deliberately not
// admin-only: anyone may manage their own.
func (s *Server) tokenRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagTokens}

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/api-tokens",
			Handler:     h.ListTokens,
			Group:       g.api,
			Tags:        tag,
			Summary:     "List API tokens (your own, or all for an admin)",
			Response:    &dto.TokenListResponse{},
			Middlewares: middleware.Read(service.ScopeTokensRead),
		},
		{
			Method:      http.MethodPost,
			Path:        "/api-tokens",
			Handler:     okapi.H(h.CreateToken),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Mint an API token",
			Description: "The plaintext is returned exactly once and only its SHA-256 digest is stored.",
			Request:     &dto.CreateTokenRequest{},
			Middlewares: middleware.Read(service.ScopeTokensWrite),
			Options:     []okapi.RouteOption{okapi.DocResponse(201, &dto.CreateTokenResponse{})},
		},
		{
			Method:      http.MethodDelete,
			Path:        "/api-tokens/{id}",
			Handler:     okapi.H(h.RevokeToken),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Revoke an API token",
			Description: "Anything using it stops working immediately. Only an admin may revoke someone else's.",
			Request:     &dto.TokenRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: middleware.Read(service.ScopeTokensWrite),
			Options:     []okapi.RouteOption{okapi.DocErrorResponse(403, &dto.ErrorResponse{})},
		},
	}
}

// notificationRoutes registers the delivery channels.
func (s *Server) notificationRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagNotify}
	read := middleware.Admin(service.ScopeNotificationsRead)
	admin := middleware.Admin(service.ScopeNotificationsWrite)

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/notifications",
			Handler:     h.ListNotifications,
			Group:       g.api,
			Tags:        tag,
			Summary:     "List notification channels",
			Response:    &dto.NotificationListResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodPost,
			Path:        "/notifications",
			Handler:     okapi.H(h.CreateNotification),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Configure a notification channel",
			Description: "Channel settings are encrypted at rest with the master key.",
			Request:     &dto.CreateNotificationRequest{},
			Middlewares: admin,
			Options:     []okapi.RouteOption{okapi.DocResponse(201, &dto.NotificationResponse{})},
		},
		{
			Method:      http.MethodPatch,
			Path:        "/notifications/{id}",
			Handler:     okapi.H(h.UpdateNotification),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Edit a notification channel",
			Request:     &dto.UpdateNotificationRequest{},
			Response:    &dto.NotificationResponse{},
			Middlewares: admin,
		},
		{
			Method:      http.MethodDelete,
			Path:        "/notifications/{id}",
			Handler:     okapi.H(h.DeleteNotification),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Delete a notification channel",
			Request:     &dto.NotificationRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: admin,
		},
		{
			Method:      http.MethodPost,
			Path:        "/notifications/{id}/test",
			Handler:     okapi.H(h.TestNotification),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Send a test notification through a channel",
			Description: "So a channel can be proved before an expiry warning depends on it.",
			Request:     &dto.NotificationRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: admin,
		},
	}
}

// deploymentRoutes registers the targets a renewed certificate is pushed to.
func (s *Server) deploymentRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagDeploy}
	read := middleware.Read(service.ScopeDeploymentsRead)
	write := middleware.Admin(service.ScopeDeploymentsWrite)

	return []okapi.RouteDefinition{
		{
			Method:  http.MethodGet,
			Path:    "/deployments",
			Handler: h.ListDeployments,
			Group:   g.api,
			Tags:    tag,
			Summary: "List deployment targets",
			Description: "Where renewed certificates are written. Targets select certificates by label " +
				"rather than by id, because renewal creates a new certificate row.",
			Response:    &dto.DeploymentListResponse{},
			Middlewares: read,
		},
		{
			Method:      http.MethodPost,
			Path:        "/deployments",
			Handler:     okapi.H(h.CreateDeployment),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Configure a deployment target",
			Description: "Target settings — SSH keys, cluster tokens — are encrypted at rest with the master key.",
			Request:     &dto.CreateDeploymentRequest{},
			Middlewares: write,
			Options: []okapi.RouteOption{
				okapi.DocResponse(201, &dto.DeploymentResponse{}),
				okapi.DocErrorResponse(400, &dto.ErrorResponse{}),
			},
		},
		{
			Method:      http.MethodPatch,
			Path:        "/deployments/{id}",
			Handler:     okapi.H(h.UpdateDeployment),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Edit a deployment target",
			Request:     &dto.UpdateDeploymentRequest{},
			Response:    &dto.DeploymentResponse{},
			Middlewares: write,
		},
		{
			Method:      http.MethodDelete,
			Path:        "/deployments/{id}",
			Handler:     okapi.H(h.DeleteDeployment),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Delete a deployment target",
			Request:     &dto.DeploymentRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: write,
		},
		{
			Method:      http.MethodPost,
			Path:        "/deployments/{id}/test",
			Handler:     okapi.H(h.TestDeployment),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Push the matching certificate to one target now",
			Description: "So a target can be proved before an unattended renewal depends on it.",
			Request:     &dto.DeploymentRefRequest{},
			Response:    &dto.DeployResultResponse{},
			Middlewares: write,
		},
	}
}

// acmeRoutes registers the RFC 8555 surface.
//
// None of these take a typed request: an ACME request is a JWS whose signature
// has to be checked before its payload can be trusted, and binding a struct
// out of an unverified body would be exactly the wrong order.
func (s *Server) acmeRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler
	tag := []string{tagACME}

	// One limiter across the whole ACME surface, keyed by IP. Issuance here is
	// unattended by design, so a misconfigured client retrying in a tight loop
	// is the normal failure — not an attack, but just as expensive.
	limiter := middleware.NewRateLimiter(
		s.cfg.Security.IssueRateLimit*4, s.cfg.Security.IssueRateWindow)
	limited := []okapi.Middleware{limiter.Middleware()}

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/directory",
			Handler:     h.ACMEDirectory,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "ACME directory",
			Description: "Point an ACME client at this URL. Everything else is discovered from it.",
		},
		{
			Method:  http.MethodGet,
			Path:    "/new-nonce",
			Handler: h.ACMENewNonce,
			Group:   g.acme,
			Tags:    tag,
			Summary: "Fetch an anti-replay nonce",
		},
		{
			Method:  http.MethodHead,
			Path:    "/new-nonce",
			Handler: h.ACMENewNonce,
			Group:   g.acme,
			Tags:    tag,
			Summary: "Fetch an anti-replay nonce (HEAD)",
		},
		{
			Method:      http.MethodPost,
			Path:        "/new-account",
			Handler:     h.ACMENewAccount,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Register an ACME account",
			Description: "Requires external account binding unless the instance is configured otherwise.",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/account/{id}",
			Handler:     h.ACMEAccount,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Read or update an account",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/account/{id}/orders",
			Handler:     h.ACMEOrderList,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "List an account's orders",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/new-order",
			Handler:     h.ACMENewOrder,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Open an order for a set of names",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/order/{id}",
			Handler:     h.ACMEOrder,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Poll an order",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/order/{id}/finalize",
			Handler:     h.ACMEFinalize,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Submit the CSR for a ready order",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/authz/{id}",
			Handler:     h.ACMEAuthorization,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Read an authorization and its challenges",
			Middlewares: limited,
		},
		{
			Method:  http.MethodPost,
			Path:    "/challenge/{id}",
			Handler: h.ACMEChallenge,
			Group:   g.acme,
			Tags:    tag,
			Summary: "Trigger or poll a challenge",
			Description: "A body of {} says the client is ready and makes Certio validate; " +
				"an empty POST-as-GET body is a poll and dials out to nothing.",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/cert/{id}",
			Handler:     h.ACMECertificate,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Download the issued chain",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/revoke-cert",
			Handler:     h.ACMERevokeCert,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Revoke a certificate",
			Description: "Signed either by the ordering account or by the certificate's own key.",
			Middlewares: limited,
		},
		{
			Method:      http.MethodPost,
			Path:        "/key-change",
			Handler:     h.ACMEKeyChange,
			Group:       g.acme,
			Tags:        tag,
			Summary:     "Account key rollover (not supported)",
			Middlewares: limited,
		},

		// Administration of the credentials that admit ACME clients. These are
		// ordinary API routes and live behind the usual auth.
		{
			Method:  http.MethodGet,
			Path:    "/acme/external-accounts",
			Handler: h.ListExternalAccounts,
			Group:   g.api,
			Tags:    tag,
			Summary: "List ACME external account bindings",
			Description: "The credentials that let a client register at all. Without them, anything " +
				"that can reach the directory could obtain a certificate.",
			Response:    &dto.ExternalAccountListResponse{},
			Middlewares: middleware.Admin(service.ScopeSettingsRead),
		},
		{
			Method:      http.MethodPost,
			Path:        "/acme/external-accounts",
			Handler:     okapi.H(h.CreateExternalAccount),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Issue an ACME external account binding",
			Description: "The HMAC key is returned exactly once; only its sealed form is stored.",
			Request:     &dto.CreateExternalAccountRequest{},
			Middlewares: middleware.Admin(service.ScopeSettingsWrite),
			Options:     []okapi.RouteOption{okapi.DocResponse(201, &dto.CreateExternalAccountResponse{})},
		},
		{
			Method:      http.MethodDelete,
			Path:        "/acme/external-accounts/{id}",
			Handler:     okapi.H(h.DeleteExternalAccount),
			Group:       g.api,
			Tags:        tag,
			Summary:     "Revoke an ACME external account binding",
			Description: "Stops new registrations. Accounts already registered with it keep working.",
			Request:     &dto.ExternalAccountRefRequest{},
			Response:    &dto.MessageResponse{},
			Middlewares: middleware.Admin(service.ScopeSettingsWrite),
		},
		{
			Method:      http.MethodGet,
			Path:        "/acme/accounts",
			Handler:     okapi.H(h.ListACMEAccounts),
			Group:       g.api,
			Tags:        tag,
			Summary:     "List registered ACME accounts",
			Request:     &dto.ListACMEAccountsRequest{},
			Response:    &dto.ACMEAccountListResponse{},
			Middlewares: middleware.Admin(service.ScopeSettingsRead),
		},
	}
}

// operationsRoutes registers the audit log, scheduler history and settings.
func (s *Server) operationsRoutes(g groups) []okapi.RouteDefinition {
	h := s.handler

	return []okapi.RouteDefinition{
		{
			Method:      http.MethodGet,
			Path:        "/audit-logs",
			Handler:     okapi.H(h.ListAuditLogs),
			Group:       g.api,
			Tags:        []string{tagAudit},
			Summary:     "Search the append-only audit log",
			Description: "The log has no update or delete endpoint by design.",
			Request:     &dto.ListAuditLogsRequest{},
			Response:    &dto.AuditListResponse{},
			Middlewares: middleware.Admin(service.ScopeAuditRead),
		},
		{
			Method:      http.MethodGet,
			Path:        "/jobs",
			Handler:     okapi.H(h.ListJobs),
			Group:       g.api,
			Tags:        []string{tagSystem},
			Summary:     "Scheduler run history",
			Request:     &dto.ListJobsRequest{},
			Response:    &dto.JobListResponse{},
			Middlewares: middleware.Admin(service.ScopeSettingsRead),
		},
		{
			Method:      http.MethodGet,
			Path:        "/settings",
			Handler:     h.GetSettings,
			Group:       g.api,
			Tags:        []string{tagSettings},
			Summary:     "Instance defaults",
			Response:    &dto.SettingsResponse{},
			Middlewares: middleware.Read(service.ScopeSettingsRead),
		},
		{
			Method:      http.MethodPatch,
			Path:        "/settings",
			Handler:     okapi.H(h.UpdateSettings),
			Group:       g.api,
			Tags:        []string{tagSettings},
			Summary:     "Edit instance defaults",
			Description: "Applied to the running configuration immediately; no restart is needed.",
			Request:     &dto.UpdateSettingsRequest{},
			Response:    &dto.SettingsResponse{},
			Middlewares: middleware.Admin(service.ScopeSettingsWrite),
		},
	}
}
