// Package dto holds the request and response shapes of the HTTP API. Each
// struct carries okapi binding and validation tags, so binding, validation and
// the OpenAPI schema all come from one definition.
package dto

import (
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
)

// ErrorResponse is the body of every non-2xx reply.
type ErrorResponse struct {
	Error   string            `json:"error"`
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// MessageResponse is a bare acknowledgement.
type MessageResponse struct {
	Message string `json:"message"`
}

// PageMeta is the pagination envelope shared by every list response.
type PageMeta struct {
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
}

// LoginBody is the credentials payload.
type LoginBody struct {
	Email    string `json:"email" form:"email" required:"true" description:"Account email address"`
	Password string `json:"password" form:"password" required:"true" minLength:"1" description:"Account password"`
	// TOTPCode lets a non-interactive client finish a two-factor login in a
	// single request. A browser leaves it empty and answers the challenge.
	TOTPCode string `json:"totp_code,omitempty" form:"totp_code" description:"Optional two-factor code, to skip the challenge round-trip"`
}

// LoginResponse is the reply to a sign-in attempt. An account with a second
// factor gets a challenge to exchange; everyone else gets a session.
type LoginResponse struct {
	// TwoFactorRequired means the password was accepted but a code is owed:
	// no session has been issued yet.
	TwoFactorRequired  bool   `json:"two_factor_required"`
	ChallengeToken     string `json:"challenge_token,omitempty"`
	ChallengeExpiresIn int    `json:"challenge_expires_in,omitempty" description:"Challenge lifetime in seconds"`

	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	TokenType    string        `json:"token_type,omitempty"`
	ExpiresIn    int           `json:"expires_in,omitempty"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty"`
	User         *UserResponse `json:"user,omitempty"`

	// UsedRecoveryCode warns that a single-use code was spent to get in.
	UsedRecoveryCode       bool `json:"used_recovery_code,omitempty"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining,omitempty"`
}

// NewLoginResponse maps a sign-in outcome onto its API shape.
func NewLoginResponse(result *service.LoginResult) LoginResponse {
	if result.TwoFactorRequired {
		return LoginResponse{
			TwoFactorRequired:  true,
			ChallengeToken:     result.Challenge,
			ChallengeExpiresIn: result.ChallengeExpiresIn,
		}
	}

	user := NewUserResponse(result.User)
	expiresAt := result.Tokens.ExpiresAt
	return LoginResponse{
		AccessToken:            result.Tokens.AccessToken,
		RefreshToken:           result.Tokens.RefreshToken,
		TokenType:              result.Tokens.TokenType,
		ExpiresIn:              result.Tokens.ExpiresIn,
		ExpiresAt:              &expiresAt,
		User:                   &user,
		UsedRecoveryCode:       result.UsedRecoveryCode,
		RecoveryCodesRemaining: result.RecoveryCodesRemaining,
	}
}

// TwoFactorVerifyBody exchanges a login challenge for a session.
type TwoFactorVerifyBody struct {
	ChallengeToken string `json:"challenge_token" required:"true"`
	Code           string `json:"code" required:"true" description:"A six-digit authenticator code, or a recovery code"`
}

// TwoFactorStatusResponse describes an account's second factor.
type TwoFactorStatusResponse struct {
	Enabled bool `json:"enabled"`
	// Pending means a secret has been generated but never confirmed, so the
	// factor is not yet in force.
	Pending                bool       `json:"pending"`
	EnabledAt              *time.Time `json:"enabled_at,omitempty"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
}

// NewTwoFactorStatusResponse maps the service status onto its API shape.
func NewTwoFactorStatusResponse(s *service.TwoFactorStatus) TwoFactorStatusResponse {
	return TwoFactorStatusResponse{
		Enabled:                s.Enabled,
		Pending:                s.Pending,
		EnabledAt:              s.EnabledAt,
		RecoveryCodesRemaining: s.RecoveryCodesRemaining,
	}
}

// TwoFactorSetupResponse is everything needed to add the account to an
// authenticator app.
type TwoFactorSetupResponse struct {
	// Secret is the base32 shared secret, spaced for manual entry.
	Secret string `json:"secret"`
	// URI is the otpauth:// URL encoded in the QR code.
	URI string `json:"uri"`
	// QRCode is a PNG data URI, so the dashboard needs no QR library.
	QRCode  string `json:"qr_code"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

// TwoFactorCodeBody carries a single code, for the endpoints that only need
// proof the caller still holds the factor.
type TwoFactorCodeBody struct {
	Code string `json:"code" required:"true" description:"A six-digit authenticator code, or a recovery code"`
}

// TwoFactorDisableBody turns the second factor off. The password is
// required as well as a code: a borrowed session must not be enough.
type TwoFactorDisableBody struct {
	Password string `json:"password" required:"true" description:"The account password"`
	Code     string `json:"code,omitempty" description:"Required once enrolment has been confirmed"`
}

// RecoveryCodesResponse returns single-use codes, which are shown exactly once.
type RecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
	Warning       string   `json:"warning"`
}

// RefreshBody exchanges a refresh token for a new pair.
type RefreshBody struct {
	RefreshToken string `json:"refresh_token" required:"true"`
}

// TokenResponse is what a successful login or refresh returns.
type TokenResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in"`
	ExpiresAt    time.Time    `json:"expires_at"`
	User         UserResponse `json:"user"`
}

// UserResponse is an account as the API returns it — never with a hash, and
// never with the second factor's shared secret.
type UserResponse struct {
	ID               string     `json:"id"`
	Email            string     `json:"email"`
	Name             string     `json:"name"`
	Role             string     `json:"role"`
	Status           string     `json:"status"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// NewUserResponse maps a stored user onto its API shape.
func NewUserResponse(u *store.User) UserResponse {
	return UserResponse{
		ID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role,
		Status: u.Status, TwoFactorEnabled: u.HasTwoFactor(),
		LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt,
	}
}

// CreateUserBody adds an account.
type CreateUserBody struct {
	Email    string `json:"email" required:"true" description:"Email address, used to sign in"`
	Name     string `json:"name" description:"Display name"`
	Password string `json:"password" required:"true" description:"At least 12 characters"`
	Role     string `json:"role" enum:"admin,operator,viewer" default:"viewer"`
}

// UpdateUserBody edits an account. Omitted fields are left alone.
type UpdateUserBody struct {
	Name     *string `json:"name,omitempty"`
	Role     *string `json:"role,omitempty" enum:"admin,operator,viewer"`
	Status   *string `json:"status,omitempty" enum:"active,disabled"`
	Password *string `json:"password,omitempty" description:"At least 12 characters"`
}

// CreateTokenBody mints an API token.
type CreateTokenBody struct {
	Name string `json:"name" required:"true" description:"A label so the token can be recognised later"`
	// UserID defaults to the caller; only an admin may set it to someone else.
	UserID    string   `json:"user_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn string   `json:"expires_in,omitempty" description:"Go duration such as 720h; empty means it never expires"`
}

// TokenResponseItem is an API token as listed — never the plaintext.
type TokenResponseItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	UserID     string     `json:"user_id"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateTokenResponse includes the plaintext, which is shown exactly once.
type CreateTokenResponse struct {
	Token TokenResponseItem `json:"token"`
	// PlaintextToken is returned only here and is never recoverable later.
	PlaintextToken string `json:"plaintext_token"`
	Warning        string `json:"warning"`
}

// NewTokenResponseItem maps a stored token onto its API shape.
func NewTokenResponseItem(t *store.APIToken) TokenResponseItem {
	return TokenResponseItem{
		ID: t.ID, Name: t.Name, UserID: t.UserID, Prefix: t.Prefix,
		Scopes: t.Scopes.Data, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt,
		RevokedAt: t.RevokedAt, CreatedAt: t.CreatedAt,
	}
}

// SubjectDTO is the distinguished name as the API accepts and returns it.
type SubjectDTO struct {
	CommonName         string `json:"common_name" required:"true" maxLength:"64" description:"CN, e.g. *.jkaninda.dev"`
	Country            string `json:"country,omitempty" maxLength:"2" description:"Two-letter ISO 3166 code"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Email              string `json:"email,omitempty"`
}

// ToPKI converts the DTO into the engine's subject type.
func (s SubjectDTO) ToPKI() pki.Subject {
	return pki.Subject{
		CommonName: s.CommonName, Country: s.Country, Province: s.Province,
		Locality: s.Locality, Organization: s.Organization,
		OrganizationalUnit: s.OrganizationalUnit, Email: s.Email,
	}
}

// NewSubjectDTO converts an engine subject into the DTO.
func NewSubjectDTO(s pki.Subject) SubjectDTO {
	return SubjectDTO{
		CommonName: s.CommonName, Country: s.Country, Province: s.Province,
		Locality: s.Locality, Organization: s.Organization,
		OrganizationalUnit: s.OrganizationalUnit, Email: s.Email,
	}
}

// CreateAuthorityBody creates a root or intermediate CA.
type CreateAuthorityBody struct {
	Name         string     `json:"name" description:"Display name; defaults to the common name"`
	Slug         string     `json:"slug,omitempty" description:"URL-safe identifier; derived from the name when empty"`
	Description  string     `json:"description,omitempty"`
	Type         string     `json:"type" enum:"root,intermediate" default:"root"`
	ParentID     string     `json:"parent_id,omitempty" description:"Issuing CA; required for an intermediate"`
	Subject      SubjectDTO `json:"subject" required:"true"`
	KeyAlgorithm string     `json:"key_algorithm,omitempty" enum:"ecdsa-p256,ecdsa-p384,ecdsa-p521,rsa-2048,rsa-3072,rsa-4096,ed25519"`
	ValidityDays int        `json:"validity_days,omitempty" description:"1–36500; omit for the profile default"`
	MaxPathLen   *int       `json:"max_path_len,omitempty" description:"How many CAs may sit below this one; 0 means leaves only"`
	// NameConstraints limits what this CA may certify. Leaving it empty means
	// the CA can certify any name, which is what makes a stolen private root
	// dangerous well beyond the organisation that owns it.
	NameConstraints *NameConstraintsDTO `json:"name_constraints,omitempty"`
	// Passphrase adds a second factor to the stored key; it is never persisted.
	Passphrase       string `json:"passphrase,omitempty"`
	ParentPassphrase string `json:"parent_passphrase,omitempty"`
}

// NameConstraintsDTO is the RFC 5280 name-constraints extension as the API
// takes it. An empty list means "no limit of this kind"; an exclusion always
// beats a permission.
type NameConstraintsDTO struct {
	PermittedDNS   []string `json:"permitted_dns,omitempty" description:"Domains this CA may certify, e.g. corp.example.com — subdomains included"`
	ExcludedDNS    []string `json:"excluded_dns,omitempty"`
	PermittedIP    []string `json:"permitted_ip,omitempty" description:"CIDR ranges, e.g. 10.0.0.0/8"`
	ExcludedIP     []string `json:"excluded_ip,omitempty"`
	PermittedEmail []string `json:"permitted_email,omitempty" description:"Addresses, hosts or domains"`
	ExcludedEmail  []string `json:"excluded_email,omitempty"`
	PermittedURI   []string `json:"permitted_uri,omitempty"`
	ExcludedURI    []string `json:"excluded_uri,omitempty"`
}

// ToPKI converts the DTO into the engine's type.
func (n *NameConstraintsDTO) ToPKI() pki.NameConstraints {
	if n == nil {
		return pki.NameConstraints{}
	}
	return pki.NameConstraints{
		PermittedDNS: n.PermittedDNS, ExcludedDNS: n.ExcludedDNS,
		PermittedIP: n.PermittedIP, ExcludedIP: n.ExcludedIP,
		PermittedEmail: n.PermittedEmail, ExcludedEmail: n.ExcludedEmail,
		PermittedURI: n.PermittedURI, ExcludedURI: n.ExcludedURI,
	}
}

// NewNameConstraints renders the engine's type for a response, or nil when the
// CA is unconstrained — so an unconstrained CA reads as absent rather than as
// a page of empty arrays.
func NewNameConstraints(n pki.NameConstraints) *NameConstraintsDTO {
	if n.IsZero() {
		return nil
	}
	return &NameConstraintsDTO{
		PermittedDNS: n.PermittedDNS, ExcludedDNS: n.ExcludedDNS,
		PermittedIP: n.PermittedIP, ExcludedIP: n.ExcludedIP,
		PermittedEmail: n.PermittedEmail, ExcludedEmail: n.ExcludedEmail,
		PermittedURI: n.PermittedURI, ExcludedURI: n.ExcludedURI,
	}
}

// ImportAuthorityBody adopts an existing CA.
type ImportAuthorityBody struct {
	Name        string `json:"name,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	CertPEM     string `json:"cert_pem" required:"true" description:"PEM-encoded CA certificate"`
	KeyPEM      string `json:"key_pem" required:"true" description:"PEM-encoded private key (PKCS#8, PKCS#1 or SEC 1)"`
	Passphrase  string `json:"passphrase,omitempty"`
}

// UpdateAuthorityBody edits CA metadata.
type UpdateAuthorityBody struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	CRLURL      *string `json:"crl_url,omitempty"`
	OCSPURL     *string `json:"ocsp_url,omitempty"`
}

// RenewAuthorityBody re-issues a CA certificate.
type RenewAuthorityBody struct {
	ValidityDays     int    `json:"validity_days,omitempty" description:"1–36500; omit to keep the current lifetime"`
	Passphrase       string `json:"passphrase,omitempty"`
	ParentPassphrase string `json:"parent_passphrase,omitempty"`
}

// AuthorityResponse is a CA as the API returns it.
type AuthorityResponse struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Slug                string     `json:"slug"`
	Type                string     `json:"type"`
	ParentID            *string    `json:"parent_id,omitempty"`
	Description         string     `json:"description,omitempty"`
	Subject             SubjectDTO `json:"subject"`
	SubjectDN           string     `json:"subject_dn"`
	KeyAlgorithm        string     `json:"key_algorithm"`
	SerialNumber        string     `json:"serial_number"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	DaysRemaining       int        `json:"days_remaining"`
	PathLenConstraint   *int       `json:"path_len_constraint,omitempty"`
	PassphraseProtected bool       `json:"passphrase_protected"`
	Status              string     `json:"status"`
	FingerprintSHA256   string     `json:"fingerprint_sha256"`
	CRLURL              string     `json:"crl_url,omitempty"`
	OCSPURL             string     `json:"ocsp_url,omitempty"`
	CRLNumber           int64      `json:"crl_number"`
	NextCRLUpdate       *time.Time `json:"next_crl_update,omitempty"`
	// NameConstraints is absent when the CA may certify anything.
	NameConstraints  *NameConstraintsDTO `json:"name_constraints,omitempty"`
	CertificateCount int64               `json:"certificate_count"`
	CertPEM          string              `json:"cert_pem,omitempty"`
	RootURL          string              `json:"root_url,omitempty"`
	ChainURL         string              `json:"chain_url,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

// NewAuthorityResponse maps a stored CA onto its API shape.
func NewAuthorityResponse(a *store.Authority, baseURL string, certCount int64, includePEM bool) AuthorityResponse {
	resp := AuthorityResponse{
		ID: a.ID, Name: a.Name, Slug: a.Slug, Type: a.Type, ParentID: a.ParentID,
		Description: a.Description,
		Subject:     NewSubjectDTO(a.Subject.Data), SubjectDN: a.Subject.Data.DN(),
		KeyAlgorithm: a.KeySpec().Display(),
		SerialNumber: a.SerialNumber,
		NotBefore:    a.NotBefore, NotAfter: a.NotAfter,
		DaysRemaining:       int(time.Until(a.NotAfter).Hours() / 24),
		PathLenConstraint:   a.PathLenConstraint,
		PassphraseProtected: a.PassphraseProtected,
		Status:              a.Status,
		FingerprintSHA256:   a.FingerprintSHA256,
		CRLURL:              a.CRLURL, OCSPURL: a.OCSPURL,
		NameConstraints: NewNameConstraints(a.NameConstraints.Data),
		CRLNumber:       a.CRLNumber, NextCRLUpdate: a.NextCRLUpdate,
		CertificateCount: certCount,
		CreatedAt:        a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	if baseURL != "" {
		resp.RootURL = baseURL + "/ca/" + a.ID + "/root.crt"
		resp.ChainURL = baseURL + "/ca/" + a.ID + "/chain.pem"
	}
	if includePEM {
		resp.CertPEM = a.CertPEM
	}
	return resp
}

// AuthorityListResponse is a page of CAs.
type AuthorityListResponse struct {
	Items []AuthorityResponse `json:"items"`
	PageMeta
}

// SANDTO is one Subject Alternative Name entry.
type SANDTO struct {
	Type  string `json:"type" enum:"dns,ip,email,uri" required:"true"`
	Value string `json:"value" required:"true"`
}

// IssueCertificateBody is a managed issuance: Certio generates the key.
type IssueCertificateBody struct {
	AuthorityID string     `json:"ca_id" required:"true" description:"Issuing CA, by ID or slug"`
	Subject     SubjectDTO `json:"subject" required:"true"`
	// SANs accepts typed entries; SANList accepts the pasted textual form.
	SANs    []SANDTO `json:"sans,omitempty"`
	SANList string   `json:"san_list,omitempty" description:"Newline- or comma-separated SANs, e.g. \"dns:api.example.com, ip:10.0.0.1\""`

	Profile      string `json:"profile,omitempty" enum:"server,client,peer,code-signing" default:"server"`
	KeyAlgorithm string `json:"key_algorithm,omitempty" enum:"ecdsa-p256,ecdsa-p384,ecdsa-p521,rsa-2048,rsa-3072,rsa-4096,ed25519"`
	ValidityDays int    `json:"validity_days,omitempty" description:"1–36500; omit for the profile default"`

	KeyUsage    []string `json:"key_usage,omitempty" description:"Overrides the profile default"`
	ExtKeyUsage []string `json:"ext_key_usage,omitempty" description:"Overrides the profile default"`

	AutoRenew       bool              `json:"auto_renew,omitempty"`
	RenewBeforeDays int               `json:"renew_before_days,omitempty" description:"1–365; defaults to 30"`
	Labels          map[string]string `json:"labels,omitempty"`
	Notes           string            `json:"notes,omitempty"`

	CAPassphrase string `json:"ca_passphrase,omitempty"`
}

// ResolveSANs merges the typed and pasted SAN inputs into one set.
func (r IssueCertificateBody) ResolveSANs() (pki.SANSet, error) {
	var set pki.SANSet
	for _, entry := range r.SANs {
		san := pki.SAN{Type: entry.Type, Value: entry.Value}
		if san.Type == "" {
			parsed, err := pki.ParseSAN(entry.Value)
			if err != nil {
				return nil, err
			}
			san = parsed
		} else if err := san.Validate(); err != nil {
			return nil, err
		}
		set = set.Add(san)
	}
	if r.SANList != "" {
		parsed, err := pki.ParseSANList(r.SANList)
		if err != nil {
			return nil, err
		}
		for _, san := range parsed {
			set = set.Add(san)
		}
	}
	return set, nil
}

// SignCSRBody is a BYO-CSR issuance: the requester keeps the key.
type SignCSRBody struct {
	AuthorityID  string   `json:"ca_id" required:"true"`
	CSRPEM       string   `json:"csr_pem" required:"true" description:"PEM-encoded PKCS#10 request"`
	Profile      string   `json:"profile,omitempty" enum:"server,client,peer,code-signing" default:"server"`
	ValidityDays int      `json:"validity_days,omitempty" description:"1–36500; omit to keep the current lifetime"`
	SANs         []SANDTO `json:"sans,omitempty" description:"Overrides the SANs the CSR asked for"`
	KeyUsage     []string `json:"key_usage,omitempty"`
	ExtKeyUsage  []string `json:"ext_key_usage,omitempty"`

	Labels       map[string]string `json:"labels,omitempty"`
	Notes        string            `json:"notes,omitempty"`
	CAPassphrase string            `json:"ca_passphrase,omitempty"`
}

// RenewCertificateBody re-issues a certificate.
type RenewCertificateBody struct {
	Rekey        bool     `json:"rekey,omitempty" description:"Generate a fresh key pair; the default re-signs the existing one"`
	KeyAlgorithm string   `json:"key_algorithm,omitempty" description:"Only meaningful with rekey"`
	ValidityDays int      `json:"validity_days,omitempty" description:"1–36500; omit to keep the current lifetime"`
	SANs         []SANDTO `json:"sans,omitempty"`
	CAPassphrase string   `json:"ca_passphrase,omitempty"`
}

// RevokeCertificateBody revokes a certificate.
type RevokeCertificateBody struct {
	ReasonCode   int    `json:"reason_code" description:"RFC 5280 reason code 0–10; 7 is unassigned"`
	CAPassphrase string `json:"ca_passphrase,omitempty"`
}

// UpdateCertificateBody edits certificate metadata.
type UpdateCertificateBody struct {
	Labels          *map[string]string `json:"labels,omitempty"`
	Notes           *string            `json:"notes,omitempty"`
	AutoRenew       *bool              `json:"auto_renew,omitempty"`
	RenewBeforeDays *int               `json:"renew_before_days,omitempty" description:"1–365"`
}

// BulkRenewBody renews several certificates at once.
type BulkRenewBody struct {
	IDs          []string `json:"ids" required:"true"`
	Rekey        bool     `json:"rekey,omitempty"`
	CAPassphrase string   `json:"ca_passphrase,omitempty"`
}

// BulkRevokeBody revokes several certificates at once.
type BulkRevokeBody struct {
	IDs          []string `json:"ids" required:"true"`
	ReasonCode   int      `json:"reason_code,omitempty" description:"RFC 5280 reason code 0–10; 7 is unassigned"`
	CAPassphrase string   `json:"ca_passphrase,omitempty"`
}

// BulkResult reports the outcome of one item in a bulk operation.
type BulkResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	NewID   string `json:"new_id,omitempty"`
	Error   string `json:"error,omitempty"`
}

// BulkResponse is the outcome of a whole bulk operation.
type BulkResponse struct {
	Succeeded int          `json:"succeeded"`
	Failed    int          `json:"failed"`
	Results   []BulkResult `json:"results"`
}

// CertificateResponse is a certificate as the API returns it.
type CertificateResponse struct {
	ID            string     `json:"id"`
	AuthorityID   string     `json:"ca_id"`
	AuthorityName string     `json:"ca_name,omitempty"`
	CommonName    string     `json:"common_name"`
	Subject       SubjectDTO `json:"subject"`
	SubjectDN     string     `json:"subject_dn"`
	Profile       string     `json:"profile"`

	KeyAlgorithm string `json:"key_algorithm"`
	SerialNumber string `json:"serial_number"`

	SANs        []SANDTO `json:"sans"`
	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`

	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ValidityDays  int       `json:"validity_days"`
	DaysRemaining int       `json:"days_remaining"`

	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Status            string `json:"status"`
	Severity          string `json:"severity"`

	HasPrivateKey    bool `json:"has_private_key"`
	KeyDownloadCount int  `json:"key_download_count"`

	AutoRenew       bool    `json:"auto_renew"`
	RenewBeforeDays int     `json:"renew_before_days"`
	RenewedFromID   *string `json:"renewed_from_id,omitempty"`

	Labels map[string]string `json:"labels"`
	Notes  string            `json:"notes,omitempty"`

	CertPEM      string `json:"cert_pem,omitempty"`
	CSRPEM       string `json:"csr_pem,omitempty"`
	FullchainPEM string `json:"fullchain_pem,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewCertificateResponse maps a stored certificate onto its API shape.
func NewCertificateResponse(c *store.Certificate, caName string, warnDays int, includePEM bool) CertificateResponse {
	sans := make([]SANDTO, 0, len(c.SANs.Data))
	for _, san := range c.SANs.Data {
		sans = append(sans, SANDTO{Type: san.Type, Value: san.Value})
	}

	resp := CertificateResponse{
		ID: c.ID, AuthorityID: c.AuthorityID, AuthorityName: caName,
		CommonName: c.CommonName,
		Subject:    NewSubjectDTO(c.Subject.Data), SubjectDN: c.Subject.Data.DN(),
		Profile:      c.Profile,
		KeyAlgorithm: pki.KeySpec{Algorithm: c.KeyAlgorithm, Size: c.KeySize, Curve: c.KeyCurve}.Display(),
		SerialNumber: c.SerialNumber,
		SANs:         sans,
		KeyUsage:     valueOrEmpty(c.KeyUsage.Data),
		ExtKeyUsage:  valueOrEmpty(c.ExtKeyUsage.Data),
		NotBefore:    c.NotBefore, NotAfter: c.NotAfter,
		ValidityDays: c.ValidityDays, DaysRemaining: c.DaysRemaining(),
		FingerprintSHA256: c.FingerprintSHA256,
		Status:            c.DeriveStatus(warnDays),
		Severity:          severity(c, warnDays),
		HasPrivateKey:     c.HasPrivateKey(),
		KeyDownloadCount:  c.KeyDownloadCount,
		AutoRenew:         c.AutoRenew, RenewBeforeDays: c.RenewBeforeDays,
		RenewedFromID: c.RenewedFromID,
		Labels:        c.Labels.Data,
		Notes:         c.Notes,
		CreatedAt:     c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	if resp.Labels == nil {
		resp.Labels = map[string]string{}
	}
	if includePEM {
		resp.CertPEM = c.CertPEM
		resp.CSRPEM = c.CSRPEM
	}
	return resp
}

// severity mirrors the dashboard's colour ramp for a single certificate.
func severity(c *store.Certificate, warnDays int) string {
	now := time.Now()
	switch {
	case c.Status == store.StatusRevoked, now.After(c.NotAfter):
		return service.SeverityExpired
	case now.AddDate(0, 0, 7).After(c.NotAfter):
		return service.SeverityCritical
	case now.AddDate(0, 0, warnDays).After(c.NotAfter):
		return service.SeverityWarning
	default:
		return service.SeverityOK
	}
}

func valueOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// CertificateListResponse is a page of certificates.
type CertificateListResponse struct {
	Items []CertificateResponse `json:"items"`
	PageMeta
}

// IssueCertificateResponse adds the downloadable material to a new
// certificate. The private key appears here and nowhere else.
type IssueCertificateResponse struct {
	Certificate   CertificateResponse `json:"certificate"`
	CertPEM       string              `json:"cert_pem"`
	FullchainPEM  string              `json:"fullchain_pem"`
	ChainPEM      string              `json:"chain_pem,omitempty"`
	PrivateKeyPEM string              `json:"private_key_pem,omitempty"`
	Warning       string              `json:"warning,omitempty"`
}

// InspectBody carries pasted PEM to decode.
type InspectBody struct {
	PEM string `json:"pem" required:"true" description:"A certificate, chain, CSR, private key or CRL"`
}

// ChainResponse describes each link of a certificate's chain.
type ChainResponse struct {
	Links []pki.ChainStatus `json:"links"`
	Valid bool              `json:"valid"`
}

// DashboardResponse is the landing page payload.
type DashboardResponse = service.DashboardStats

// UserListResponse is a page of accounts.
type UserListResponse struct {
	Items []UserResponse `json:"items"`
	PageMeta
}

// TokenListResponse is the caller's API tokens, or every token for an admin.
// It is unpaginated: an instance has tens of tokens, not thousands.
type TokenListResponse struct {
	Items []TokenResponseItem `json:"items"`
	Total int                 `json:"total"`
}

// NotificationListResponse is every configured delivery channel.
type NotificationListResponse struct {
	Items []NotificationResponse `json:"items"`
	Total int                    `json:"total"`
}

// CertificateHistoryResponse is the renewal lineage of one certificate,
// oldest first.
type CertificateHistoryResponse struct {
	Items []CertificateResponse `json:"items"`
	Total int                   `json:"total"`
}

// RevokeCertificateResponse confirms a revocation and echoes what was recorded
// on the CRL.
type RevokeCertificateResponse struct {
	Message      string    `json:"message"`
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       string    `json:"reason"`
	ReasonCode   int       `json:"reason_code"`
	SerialNumber string    `json:"serial_number"`
}

// AuditListResponse is a page of audit entries.
type AuditListResponse struct {
	Items []store.AuditLog `json:"items"`
	PageMeta
}

// JobListResponse is a page of scheduler runs.
type JobListResponse struct {
	Items []store.Job `json:"items"`
	PageMeta
}

// AboutResponse describes the running instance: what it is, what it was built
// from, and how it is configured. Everything here is already visible to a
// signed-in user elsewhere; it is gathered in one place so the About page does
// not have to piece it together from four endpoints.
type AboutResponse struct {
	Name        string `json:"name"`
	Tagline     string `json:"tagline"`
	Description string `json:"description"`

	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform" description:"GOOS/GOARCH"`

	License       string `json:"license"`
	LicenseURL    string `json:"license_url"`
	Repository    string `json:"repository"`
	Documentation string `json:"documentation"`
	IssuesURL     string `json:"issues_url"`

	StartedAt time.Time `json:"started_at"`
	Uptime    string    `json:"uptime"`

	Instance AboutInstance `json:"instance"`
}

// AboutInstance is the deployment-specific half of the About payload.
type AboutInstance struct {
	BaseURL           string `json:"base_url,omitempty"`
	DatabaseDriver    string `json:"database_driver"`
	TLS               bool   `json:"tls" description:"Whether this process terminates TLS itself"`
	DocsEnabled       bool   `json:"docs_enabled"`
	SchedulerEnabled  bool   `json:"scheduler_enabled"`
	KeyDownloadPolicy string `json:"key_download_policy"`
	ExpiryWarnDays    int    `json:"expiry_warn_days"`
	// AccessTokenTTL and RefreshTokenTTL are rendered as Go durations, the
	// same form the configuration accepts.
	AccessTokenTTL  string `json:"access_token_ttl"`
	RefreshTokenTTL string `json:"refresh_token_ttl"`
}

// HealthResponse is the liveness payload.
type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Database string `json:"database"`
	Uptime   string `json:"uptime"`
}

// ProfileResponse describes one issuance profile for the wizard.
type ProfileResponse struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	KeyUsage     []string `json:"key_usage"`
	ExtKeyUsage  []string `json:"ext_key_usage"`
	ValidityDays int      `json:"default_validity_days"`
	IsCA         bool     `json:"is_ca"`
}

// MetaResponse is the static reference data the UI needs to render its forms.
type MetaResponse struct {
	Profiles          []ProfileResponse `json:"profiles"`
	KeyAlgorithms     []string          `json:"key_algorithms"`
	ExportFormats     []string          `json:"export_formats"`
	RevocationReasons []ReasonDTO       `json:"revocation_reasons"`
	SANTypes          []string          `json:"san_types"`
	TokenScopes       []ScopeDTO        `json:"token_scopes"`
	MaxLeafValidity   int               `json:"max_leaf_validity_days"`
	KeyDownloadPolicy string            `json:"key_download_policy"`
	Version           string            `json:"version"`
}

// ScopeDTO is one API-token scope and the sentence describing it.
type ScopeDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ReasonDTO is one RFC 5280 revocation reason.
type ReasonDTO struct {
	Code int    `json:"code"`
	Name string `json:"name"`
}

// CreateDeploymentBody configures a deployment target.
type CreateDeploymentBody struct {
	Name   string            `json:"name" required:"true"`
	Kind   string            `json:"kind" required:"true" enum:"kubernetes,ssh,webhook"`
	Config map[string]string `json:"config" required:"true" description:"Target settings; secrets are encrypted at rest"`
	// Selector matches certificates by label and survives renewal, which a
	// certificate id would not.
	Selector   map[string]string `json:"selector,omitempty" description:"Label selector, e.g. {\"env\":\"prod\"}"`
	CommonName string            `json:"common_name,omitempty" description:"Narrow to one certificate by common name"`
	Enabled    bool              `json:"enabled"`
}

// UpdateDeploymentBody edits a deployment target.
type UpdateDeploymentBody struct {
	Name       *string            `json:"name,omitempty"`
	Config     *map[string]string `json:"config,omitempty"`
	Selector   *map[string]string `json:"selector,omitempty"`
	CommonName *string            `json:"common_name,omitempty"`
	Enabled    *bool              `json:"enabled,omitempty"`
}

// DeploymentResponse is a target as the API returns it — never with its
// decrypted configuration.
type DeploymentResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Selector    map[string]string `json:"selector,omitempty"`
	CommonName  string            `json:"common_name,omitempty"`
	Enabled     bool              `json:"enabled"`
	LastRunAt   *time.Time        `json:"last_run_at,omitempty"`
	LastSuccess *time.Time        `json:"last_success_at,omitempty"`
	LastError   string            `json:"last_error,omitempty"`
	LastSerial  string            `json:"last_serial,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// NewDeploymentResponse maps a target row onto its API shape.
func NewDeploymentResponse(d *store.DeploymentTarget) DeploymentResponse {
	return DeploymentResponse{
		ID: d.ID, Name: d.Name, Kind: d.Kind,
		Selector: d.Selector.Data, CommonName: d.CommonName,
		Enabled: d.Enabled, LastRunAt: d.LastRunAt, LastSuccess: d.LastSuccess,
		LastError: d.LastError, LastSerial: d.LastSerial, CreatedAt: d.CreatedAt,
	}
}

// DeploymentListResponse is a page of targets.
type DeploymentListResponse struct {
	Items []DeploymentResponse `json:"items"`
	Total int                  `json:"total"`
}

// DeployResultResponse reports what one deployment pass did.
type DeployResultResponse struct {
	Results []service.DeployResult `json:"results"`
}

// CreateExternalAccountBody issues an ACME external account binding.
type CreateExternalAccountBody struct {
	Description string `json:"description,omitempty" description:"What this credential is for, e.g. \"payments cluster\""`
	// AllowedDomains narrows what accounts bound with this credential may
	// request, below whatever the CA's own name constraints already allow.
	AllowedDomains []string `json:"allowed_domains,omitempty" description:"Domains this credential may request, subdomains included"`
	ExpiresInDays  int      `json:"expires_in_days,omitempty" description:"Omit for a credential that does not expire"`
}

// CreateExternalAccountRequest wraps the body.
type CreateExternalAccountRequest struct {
	Body CreateExternalAccountBody `json:"body"`
}

// ExternalAccountRefRequest addresses one binding.
type ExternalAccountRefRequest struct {
	ID string `path:"id" required:"true" description:"External account binding ID"`
}

// ListACMEAccountsRequest pages the registered ACME accounts.
type ListACMEAccountsRequest struct {
	Page  int `query:"page" default:"1" min:"1"`
	Limit int `query:"limit" default:"25" min:"1" max:"200"`
}

// ExternalAccountResponse is a binding as the API returns it — never with its
// HMAC key.
type ExternalAccountResponse struct {
	ID             string     `json:"id"`
	KID            string     `json:"kid"`
	Description    string     `json:"description,omitempty"`
	AllowedDomains []string   `json:"allowed_domains,omitempty"`
	Enabled        bool       `json:"enabled"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// NewExternalAccountResponse maps a binding row onto its API shape.
func NewExternalAccountResponse(e *store.ACMEExternalAccount) ExternalAccountResponse {
	return ExternalAccountResponse{
		ID: e.ID, KID: e.KID, Description: e.Description,
		AllowedDomains: e.AllowedDomains.Data, Enabled: e.Enabled,
		ExpiresAt: e.ExpiresAt, LastUsedAt: e.LastUsedAt, CreatedAt: e.CreatedAt,
	}
}

// ExternalAccountListResponse is the list of bindings.
type ExternalAccountListResponse struct {
	Items []ExternalAccountResponse `json:"items"`
	Total int                       `json:"total"`
}

// CreateExternalAccountResponse carries the HMAC key, which is shown once and
// never again.
type CreateExternalAccountResponse struct {
	ExternalAccount ExternalAccountResponse `json:"external_account"`
	// HMACKey is base64url, the form every ACME client's --eab-hmac-key
	// expects. It is not recoverable: issue a new binding if it is lost.
	HMACKey string `json:"hmac_key"`
	// DirectoryURL is where to point the client, so the reply is everything
	// needed to configure one.
	DirectoryURL string `json:"directory_url"`
	Warning      string `json:"warning"`
}

// ACMEAccountResponse is a registered ACME client.
type ACMEAccountResponse struct {
	ID              string     `json:"id"`
	KeyThumbprint   string     `json:"key_thumbprint"`
	Contact         []string   `json:"contact,omitempty"`
	Status          string     `json:"status"`
	ExternalAccount string     `json:"external_account_id,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// NewACMEAccountResponse maps an account row onto its API shape.
func NewACMEAccountResponse(a *store.ACMEAccount) ACMEAccountResponse {
	return ACMEAccountResponse{
		ID: a.ID, KeyThumbprint: a.KeyThumbprint, Contact: a.Contact.Data,
		Status: a.Status, ExternalAccount: a.ExternalAccountID,
		LastUsedAt: a.LastUsedAt, CreatedAt: a.CreatedAt,
	}
}

// ACMEAccountListResponse is a page of ACME accounts.
type ACMEAccountListResponse struct {
	Items      []ACMEAccountResponse `json:"items"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	Limit      int                   `json:"limit"`
	TotalPages int                   `json:"total_pages"`
}

// TrustGuideResponse is the per-platform CA installation guide.
type TrustGuideResponse struct {
	Authority    AuthorityResponse           `json:"authority"`
	RootURL      string                      `json:"root_url"`
	ChainURL     string                      `json:"chain_url"`
	CRLURL       string                      `json:"crl_url"`
	Fingerprint  string                      `json:"fingerprint_sha256"`
	Instructions []service.TrustInstructions `json:"instructions"`
}

// CreateNotificationBody configures a delivery channel.
type CreateNotificationBody struct {
	Name    string            `json:"name" required:"true"`
	Channel string            `json:"channel" required:"true" enum:"webhook,smtp,slack,telegram"`
	Config  map[string]string `json:"config" required:"true" description:"Channel settings; secrets are encrypted at rest"`
	Events  []string          `json:"events,omitempty" description:"Event names, or [\"*\"] for all"`
	Enabled bool              `json:"enabled"`
}

// UpdateNotificationBody edits a delivery channel.
type UpdateNotificationBody struct {
	Name    *string            `json:"name,omitempty"`
	Config  *map[string]string `json:"config,omitempty"`
	Events  *[]string          `json:"events,omitempty"`
	Enabled *bool              `json:"enabled,omitempty"`
}

// NotificationResponse is a channel as the API returns it — never with its
// decrypted configuration.
type NotificationResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Channel    string     `json:"channel"`
	Events     []string   `json:"events"`
	Enabled    bool       `json:"enabled"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// NewNotificationResponse maps a stored channel onto its API shape.
func NewNotificationResponse(n *store.Notification) NotificationResponse {
	return NotificationResponse{
		ID: n.ID, Name: n.Name, Channel: n.Channel,
		Events: valueOrEmpty(n.Events.Data), Enabled: n.Enabled,
		LastSentAt: n.LastSentAt, LastError: n.LastError, CreatedAt: n.CreatedAt,
	}
}

// SettingsResponse is the instance defaults an admin may edit.
type SettingsResponse struct {
	DefaultOrganization string `json:"default_organization"`
	DefaultCountry      string `json:"default_country"`
	DefaultKeyAlgorithm string `json:"default_key_algorithm"`
	DefaultValidityDays int    `json:"default_validity_days"`
	ExpiryWarnDays      int    `json:"expiry_warn_days"`
	KeyDownloadPolicy   string `json:"key_download_policy"`
	BaseURL             string `json:"base_url"`
	SchedulerEnabled    bool   `json:"scheduler_enabled"`
}

// UpdateSettingsBody edits instance defaults.
type UpdateSettingsBody struct {
	DefaultOrganization *string `json:"default_organization,omitempty"`
	DefaultCountry      *string `json:"default_country,omitempty" maxLength:"2"`
	DefaultKeyAlgorithm *string `json:"default_key_algorithm,omitempty"`
	DefaultValidityDays *int    `json:"default_validity_days,omitempty" description:"1–36500"`
	ExpiryWarnDays      *int    `json:"expiry_warn_days,omitempty" description:"1–365"`
}
