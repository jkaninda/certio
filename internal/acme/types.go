package acme

import (
	"fmt"
	"net/http"
)

// Resource statuses, as RFC 8555 §7.1.6 defines them.
const (
	StatusPending     = "pending"
	StatusReady       = "ready"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// Challenge types Certio can validate.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
)

// Directory is the entry point every ACME client fetches first.
type Directory struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       DirectoryMeta `json:"meta"`
}

// DirectoryMeta carries the human-facing metadata.
type DirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Identifier names something a certificate is requested for.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Account is an ACME account as the API returns it.
type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`
	// TermsOfServiceAgreed is echoed back so a client can confirm what it sent.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`
}

// NewAccountRequest is the newAccount payload.
type NewAccountRequest struct {
	Contact                []string `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool     `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding *JWS     `json:"externalAccountBinding,omitempty"`
}

// UpdateAccountRequest changes a contact list or deactivates an account.
type UpdateAccountRequest struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status,omitempty"`
}

// NewOrderRequest is the newOrder payload.
type NewOrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// Order is an order as the API returns it.
type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

// Authorization is one identifier's proof-of-control state.
type Authorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Expires    string      `json:"expires,omitempty"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
}

// Challenge is one way of proving control.
type Challenge struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

// FinalizeRequest carries the CSR.
type FinalizeRequest struct {
	CSR string `json:"csr"`
}

// RevokeRequest asks for a certificate to be revoked.
type RevokeRequest struct {
	Certificate string `json:"certificate"`
	Reason      *int   `json:"reason,omitempty"`
}

// Problem is RFC 7807 as ACME profiles it (§6.7). Clients parse the type
// field and act on it, so the URNs below are load-bearing rather than
// decorative — certbot decides whether to retry from this alone.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail,omitempty"`
	Status      int         `json:"status,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
	Subproblems []Problem   `json:"subproblems,omitempty"`
}

// Error makes Problem usable as an error, so the handlers can return one.
func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Detail
	}
	return p.Type
}

// Problem type URNs from the IANA registry.
const (
	ErrAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ErrBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ErrBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	ErrBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ErrBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrConnection              = "urn:ietf:params:acme:error:connection"
	ErrDNS                     = "urn:ietf:params:acme:error:dns"
	ErrExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	ErrInvalidContact          = "urn:ietf:params:acme:error:invalidContact"
	ErrMalformed               = "urn:ietf:params:acme:error:malformed"
	ErrOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	ErrRateLimited             = "urn:ietf:params:acme:error:rateLimited"
	ErrRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ErrUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ErrUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
	ErrAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
)

// NewProblem builds a problem document with the status the type implies.
func NewProblem(problemType, format string, args ...any) *Problem {
	return &Problem{
		Type:   problemType,
		Detail: fmt.Sprintf(format, args...),
		Status: statusFor(problemType),
	}
}

// statusFor maps a problem type onto the HTTP status clients expect with it.
// badNonce in particular must come back as 400 with a fresh Replay-Nonce, or a
// client will not know to retry.
func statusFor(problemType string) int {
	switch problemType {
	case ErrAccountDoesNotExist, ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrRateLimited:
		return http.StatusTooManyRequests
	case ErrServerInternal:
		return http.StatusInternalServerError
	case ErrOrderNotReady:
		return http.StatusForbidden
	case ErrExternalAccountRequired, ErrUserActionRequired:
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}
