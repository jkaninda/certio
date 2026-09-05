package dto

// This file holds the request shapes okapi binds and validates automatically.
//
// Each one follows okapi's Body style: sibling fields carry the path, query
// and header parameters, and a `Body` field carries the payload. One struct is
// therefore the whole contract for an endpoint — binding, validation and the
// OpenAPI parameter and schema documentation all come from these tags, so a
// route definition never has to restate a parameter by hand.
//
// The payload types themselves live in dto.go as `…Body`.

// ---- Pagination -------------------------------------------------------------

// Page and Limit are repeated on each list request rather than embedded: the
// binder reads struct tags field by field and does not descend into an
// embedded struct, so an embedded Pagination would silently never bind.
//
// They carry `default` as well as `min`, and the default is load-bearing. The
// validator checks `min` against whatever the field holds, so an absent
// ?page= would leave it at 0 and fail min:"1" — the default fills it first and
// the constraint then documents a real bound instead of rejecting every
// unparameterised list request.

// ---- Authentication ---------------------------------------------------------

// LoginRequest is a sign-in attempt.
type LoginRequest struct {
	Body LoginBody `json:"body"`
}

// RefreshRequest exchanges a refresh token for a new pair.
type RefreshRequest struct {
	Body RefreshBody `json:"body"`
}

// TwoFactorVerifyRequest exchanges a login challenge and a code for a session.
type TwoFactorVerifyRequest struct {
	Body TwoFactorVerifyBody `json:"body"`
}

// TwoFactorCodeRequest proves the caller still holds the second factor.
type TwoFactorCodeRequest struct {
	Body TwoFactorCodeBody `json:"body"`
}

// TwoFactorDisableRequest removes the caller's second factor.
type TwoFactorDisableRequest struct {
	Body TwoFactorDisableBody `json:"body"`
}

// SaveOAuthProviderRequest configures federated sign-in.
type SaveOAuthProviderRequest struct {
	Body SaveOAuthProviderBody `json:"body"`
}

// OAuthCallbackRequest exchanges an authorization code for a session.
type OAuthCallbackRequest struct {
	Body OAuthCallbackBody `json:"body"`
}

// ---- Users and tokens -------------------------------------------------------

// ListUsersRequest is a page of accounts.
type ListUsersRequest struct {
	Page  int `query:"page" default:"1" min:"1" description:"Page number, from 1"`
	Limit int `query:"limit" default:"25" min:"1" max:"200" description:"Page size, up to 200"`
}

// UserRefRequest addresses one account.
type UserRefRequest struct {
	ID string `path:"id" required:"true" description:"Account ID"`
}

// CreateUserRequest adds an account.
type CreateUserRequest struct {
	Body CreateUserBody `json:"body"`
}

// UpdateUserRequest edits an account.
type UpdateUserRequest struct {
	ID   string         `path:"id" required:"true" description:"Account ID"`
	Body UpdateUserBody `json:"body"`
}

// CreateTokenRequest mints an API token.
type CreateTokenRequest struct {
	Body CreateTokenBody `json:"body"`
}

// TokenRefRequest addresses one API token.
type TokenRefRequest struct {
	ID string `path:"id" required:"true" description:"API token ID"`
}

// ---- Authorities ------------------------------------------------------------

// ListAuthoritiesRequest is a filtered page of certificate authorities.
type ListAuthoritiesRequest struct {
	Type   string `query:"type" enum:"root,intermediate" description:"Filter by root or intermediate"`
	Status string `query:"status" enum:"active,expiring,expired,revoked" description:"Filter by lifecycle status"`
	Query  string `query:"q" description:"Search by name, slug or serial number"`
	Page   int    `query:"page" default:"1" min:"1" description:"Page number, from 1"`
	Limit  int    `query:"limit" default:"25" min:"1" max:"200" description:"Page size, up to 200"`
}

// AuthorityRefRequest addresses one CA by ID or slug.
type AuthorityRefRequest struct {
	ID string `path:"id" required:"true" description:"Authority ID or slug"`
}

// OCSPRequest addresses the responder for one CA. RFC 6960 allows the query
// either as a POST body or base64-encoded in the path, so the encoded segment
// is optional and the handler falls back to reading the body.
type OCSPRequest struct {
	ID      string `path:"id" required:"true" description:"Authority ID or slug"`
	Encoded string `path:"encoded" description:"Base64-encoded DER request, for the GET form"`
}

// CreateDeploymentRequest configures a deployment target.
type CreateDeploymentRequest struct {
	Body CreateDeploymentBody `json:"body"`
}

// UpdateDeploymentRequest edits a deployment target.
type UpdateDeploymentRequest struct {
	ID   string               `path:"id" required:"true"`
	Body UpdateDeploymentBody `json:"body"`
}

// DeploymentRefRequest addresses one deployment target.
type DeploymentRefRequest struct {
	ID string `path:"id" required:"true" description:"Deployment target ID"`
}

// DeployCertificateRequest pushes one certificate to its targets.
type DeployCertificateRequest struct {
	ID    string `path:"id" required:"true" description:"Certificate ID"`
	Force bool   `query:"force" description:"Deploy even when the target already holds this serial"`
}

// CreateAuthorityRequest creates a root or intermediate CA.
type CreateAuthorityRequest struct {
	Body CreateAuthorityBody `json:"body"`
}

// ImportAuthorityRequest adopts an existing CA.
type ImportAuthorityRequest struct {
	Body ImportAuthorityBody `json:"body"`
}

// UpdateAuthorityRequest edits CA metadata.
type UpdateAuthorityRequest struct {
	ID   string              `path:"id" required:"true" description:"Authority ID or slug"`
	Body UpdateAuthorityBody `json:"body"`
}

// DeleteAuthorityRequest removes a CA.
type DeleteAuthorityRequest struct {
	ID string `path:"id" required:"true" description:"Authority ID or slug"`
	// Force cascades to issued certificates and child CAs. Without it a CA
	// that is still referenced is refused rather than silently orphaning rows.
	Force bool `query:"force" description:"Cascade to issued certificates and child CAs"`
}

// RenewAuthorityRequest re-issues a CA certificate.
type RenewAuthorityRequest struct {
	ID   string             `path:"id" required:"true" description:"Authority ID or slug"`
	Body RenewAuthorityBody `json:"body"`
}

// AuthorityCertificatesRequest lists the certificates one CA has issued.
type AuthorityCertificatesRequest struct {
	ID     string `path:"id" required:"true" description:"Authority ID or slug"`
	Status string `query:"status" enum:"active,expiring,expired,revoked"`
	Query  string `query:"q" description:"Search common name, SANs, serial or fingerprint"`
	Sort   string `query:"sort" enum:"common_name,not_after,status,created_at"`
	Order  string `query:"order" enum:"asc,desc"`
	Page   int    `query:"page" default:"1" min:"1"`
	Limit  int    `query:"limit" default:"25" min:"1" max:"200"`
}

// RegenerateCRLRequest rebuilds a CA's revocation list. The body is optional:
// an unprotected CA needs no passphrase.
type RegenerateCRLRequest struct {
	ID   string `path:"id" required:"true" description:"Authority ID or slug"`
	Body struct {
		Passphrase string `json:"passphrase,omitempty" description:"Required only for a passphrase-protected CA"`
	} `json:"body"`
}

// ---- Certificates -----------------------------------------------------------

// ListCertificatesRequest is a filtered, sorted page of certificates.
type ListCertificatesRequest struct {
	AuthorityID string `query:"ca" description:"Filter by issuing CA (ID or slug)"`
	Status      string `query:"status" enum:"active,expiring,expired,revoked,held"`
	Profile     string `query:"profile" enum:"server,client,peer,code-signing"`
	// ExpiringIn is a string because "30" and "30d" both mean thirty days.
	ExpiringIn string `query:"expiring_in" description:"Only those expiring within N days, e.g. 30 or 30d"`
	// AutoRenew and IncludeRevoked are pointers so an absent parameter stays
	// distinguishable from an explicit false.
	AutoRenew      *bool  `query:"auto_renew" description:"Filter by the auto-renewal flag"`
	IncludeRevoked *bool  `query:"include_revoked" description:"Defaults to true"`
	Query          string `query:"q" description:"Search common name, SANs, serial or fingerprint"`
	// Label is repeatable: ?label=env%3Dprod&label=team%3Dpayments narrows to
	// certificates carrying every pair.
	Label []string `query:"label" description:"Filter by label, as key=value; repeat to require several"`
	Sort  string   `query:"sort" enum:"common_name,not_after,status,created_at"`
	Order string   `query:"order" enum:"asc,desc"`
	Page  int      `query:"page" default:"1" min:"1" description:"Page number, from 1"`
	Limit int      `query:"limit" default:"25" min:"1" max:"200" description:"Page size, up to 200"`
}

// ReleaseHoldRequest lifts a certificateHold.
type ReleaseHoldRequest struct {
	ID   string          `path:"id" required:"true" description:"Certificate ID"`
	Body ReleaseHoldBody `json:"body"`
}

// ReleaseHoldBody carries the CA passphrase when one is needed to republish
// the CRL without the hold.
type ReleaseHoldBody struct {
	CAPassphrase string `json:"ca_passphrase,omitempty"`
}

// CertificateRefRequest addresses one certificate.
type CertificateRefRequest struct {
	ID string `path:"id" required:"true" description:"Certificate ID"`
}

// IssueCertificateRequest is a managed issuance.
type IssueCertificateRequest struct {
	Body IssueCertificateBody `json:"body"`
}

// SignCSRRequest is a BYO-CSR issuance.
type SignCSRRequest struct {
	Body SignCSRBody `json:"body"`
}

// InspectRequest decodes pasted PEM without storing it.
type InspectRequest struct {
	Body InspectBody `json:"body"`
}

// UpdateCertificateRequest edits labels, notes and renewal settings.
type UpdateCertificateRequest struct {
	ID   string                `path:"id" required:"true" description:"Certificate ID"`
	Body UpdateCertificateBody `json:"body"`
}

// RenewCertificateRequest re-issues a certificate as a new row.
type RenewCertificateRequest struct {
	ID   string               `path:"id" required:"true" description:"Certificate ID"`
	Body RenewCertificateBody `json:"body"`
}

// RevokeCertificateRequest revokes a certificate and republishes the CRL.
type RevokeCertificateRequest struct {
	ID   string                `path:"id" required:"true" description:"Certificate ID"`
	Body RevokeCertificateBody `json:"body"`
}

// BulkRenewRequest renews several certificates at once.
type BulkRenewRequest struct {
	Body BulkRenewBody `json:"body"`
}

// BulkRevokeRequest revokes several certificates at once.
type BulkRevokeRequest struct {
	Body BulkRevokeBody `json:"body"`
}

// DownloadCertificateRequest renders a certificate in one of the export
// formats. Formats containing key material are subject to the instance's key
// download policy and are always audited.
type DownloadCertificateRequest struct {
	ID     string `path:"id" required:"true" description:"Certificate ID"`
	Format string `query:"format" description:"pem | key | fullchain | chain | root | csr | p12 | zip | k8s | nginx | traefik | haproxy | goma | goma-route | compose; defaults to pem"`
	// Password is required for p12 and optionally encrypts an exported key.
	Password   string `query:"password" description:"Required for p12; optionally encrypts an exported key"`
	Namespace  string `query:"namespace" description:"Namespace for the k8s format"`
	SecretName string `query:"secret_name" description:"Secret name for the k8s format"`
}

// ---- Operations -------------------------------------------------------------

// ListAuditLogsRequest searches the append-only audit log.
type ListAuditLogsRequest struct {
	ActorID      string `query:"actor_id" description:"Filter by the actor's ID"`
	Action       string `query:"action" description:"Filter by action, e.g. cert.issue"`
	ResourceType string `query:"resource_type" enum:"authority,certificate,user,api_token,notification,setting,job"`
	ResourceID   string `query:"resource_id"`
	Query        string `query:"q" description:"Search action, resource name or actor name"`
	Since        string `query:"since" description:"RFC 3339 lower bound"`
	Until        string `query:"until" description:"RFC 3339 upper bound"`
	Page         int    `query:"page" default:"1" min:"1"`
	Limit        int    `query:"limit" default:"25" min:"1" max:"200"`
}

// ListJobsRequest is a page of scheduler history.
type ListJobsRequest struct {
	Kind  string `query:"kind" enum:"expiry_scan,auto_renew,crl_refresh,notify"`
	Page  int    `query:"page" default:"1" min:"1"`
	Limit int    `query:"limit" default:"25" min:"1" max:"200"`
}

// CreateNotificationRequest configures a delivery channel.
type CreateNotificationRequest struct {
	Body CreateNotificationBody `json:"body"`
}

// UpdateNotificationRequest edits a delivery channel.
type UpdateNotificationRequest struct {
	ID   string                 `path:"id" required:"true" description:"Notification channel ID"`
	Body UpdateNotificationBody `json:"body"`
}

// NotificationRefRequest addresses one delivery channel.
type NotificationRefRequest struct {
	ID string `path:"id" required:"true" description:"Notification channel ID"`
}

// UpdateSettingsRequest edits the instance defaults.
type UpdateSettingsRequest struct {
	Body UpdateSettingsBody `json:"body"`
}

// There is deliberately no empty request type. An endpoint that reads no path,
// query or body takes a plain okapi handler instead — a struct with no fields
// would be binding ceremony around nothing.
