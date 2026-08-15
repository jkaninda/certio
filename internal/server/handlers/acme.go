package handlers

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/acme"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// The ACME endpoints do not use the typed request binding the rest of the API
// does, and deliberately so: every request is a JWS whose signature has to be
// checked before its payload can be trusted, and binding a struct out of an
// unverified body would put the cart in front of the horse. Each handler takes
// the raw context, verifies, and only then decodes.

// maxACMEBody caps a request body. An ACME request is a few kilobytes at most;
// a CSR for a hundred names is still well under this.
const maxACMEBody = 256 << 10

// acmeURL builds an absolute URL under the ACME prefix. Clients follow these
// literally, so they have to be reachable as written — which is why they are
// derived from the configured base URL rather than from the request's Host.
func (h *Handler) acmeURL(format string, args ...any) string {
	base := strings.TrimRight(h.Config.Server.BaseURL, "/")
	return base + "/acme" + fmt.Sprintf(format, args...)
}

// ACMEDirectory is the entry point every client fetches first.
func (h *Handler) ACMEDirectory(c *okapi.Context) error {
	if !h.Service.ACMEEnabled() {
		return h.acmeDisabled(c)
	}

	directory := acme.Directory{
		NewNonce:   h.acmeURL("/new-nonce"),
		NewAccount: h.acmeURL("/new-account"),
		NewOrder:   h.acmeURL("/new-order"),
		RevokeCert: h.acmeURL("/revoke-cert"),
		KeyChange:  h.acmeURL("/key-change"),
		Meta: acme.DirectoryMeta{
			TermsOfService:          h.Config.ACME.TermsURL,
			Website:                 h.Config.ACME.WebsiteURL,
			ExternalAccountRequired: h.Config.ACME.RequireEAB,
		},
	}
	h.attachNonce(c)
	return c.OK(directory)
}

// ACMENewNonce answers the nonce endpoint. RFC 8555 §7.2 wants HEAD to return
// 200 and GET to return 204; both carry the nonce in a header.
func (h *Handler) ACMENewNonce(c *okapi.Context) error {
	if !h.Service.ACMEEnabled() {
		return h.acmeDisabled(c)
	}
	h.attachNonce(c)
	c.SetHeader("Cache-Control", "no-store")

	if c.Request().Method == http.MethodHead {
		return c.Data(http.StatusOK, "application/octet-stream", nil)
	}
	return c.Data(http.StatusNoContent, "application/octet-stream", nil)
}

// acmeVerified is everything a handler needs once the JWS has been checked.
type acmeVerified struct {
	Account *store.ACMEAccount
	Key     *acme.JWK
	Payload []byte
	JWS     *acme.JWS
	Header  *acme.ProtectedHeader
}

// verifyACME performs the checks RFC 8555 §6 requires of every POST: the body
// is a JWS, its nonce is unspent, its url matches the endpoint it arrived at,
// and its signature verifies under the key it names.
//
// The url check is not ceremony. Without it, a JWS captured at one endpoint
// could be replayed at another that happens to accept the same payload shape.
func (h *Handler) verifyACME(c *okapi.Context, endpoint string) (*acmeVerified, *acme.Problem) {
	if !h.Service.ACMEEnabled() {
		return nil, acme.NewProblem(acme.ErrServerInternal, "ACME is not enabled on this instance")
	}

	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxACMEBody))
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "could not read the request body")
	}

	jws, header, payload, err := acme.ParseJWS(body)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "%s", err)
	}

	if problem := h.Service.SpendNonce(header.Nonce); problem != nil {
		return nil, problem
	}
	if want := h.acmeURL("%s", endpoint); header.URL != want {
		return nil, acme.NewProblem(acme.ErrMalformed,
			"the JWS url is %q but this is %q", header.URL, want)
	}

	verified := &acmeVerified{Payload: payload, JWS: jws, Header: header}

	// A jwk header introduces a key: new-account, and the revocation form
	// signed with the certificate's own key. Everything else names an account.
	if header.JWK != nil {
		key, err := header.JWK.PublicKey()
		if err != nil {
			return nil, acme.NewProblem(acme.ErrBadPublicKey, "%s", err)
		}
		if err := jws.Verify(header, key); err != nil {
			return nil, acme.NewProblem(acme.ErrUnauthorized, "%s", err)
		}
		verified.Key = header.JWK
		return verified, nil
	}

	accountID := accountIDFromKID(header.KID)
	if accountID == "" {
		return nil, acme.NewProblem(acme.ErrMalformed, "the kid %q is not an account URL", header.KID)
	}
	account, err := h.Service.Store.ACME.GetAccount(accountID)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrAccountDoesNotExist, "no such account")
	}
	if account.Status == store.ACMEStatusDeactivated {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "this account has been deactivated")
	}

	stored, err := acme.DecodeJWK(account.KeyJWK)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not read the account key")
	}
	key, err := stored.PublicKey()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not read the account key")
	}
	if err := jws.Verify(header, key); err != nil {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "%s", err)
	}

	if err := h.Service.Store.ACME.TouchAccount(account.ID); err != nil {
		h.Service.Log.Debug("could not stamp the ACME account", "error", err)
	}
	verified.Account = account
	verified.Key = stored
	return verified, nil
}

// accountIDFromKID pulls the account ID out of the URL a client echoes back.
func accountIDFromKID(kid string) string {
	trimmed := strings.TrimRight(kid, "/")
	index := strings.LastIndex(trimmed, "/")
	if index < 0 {
		return ""
	}
	return trimmed[index+1:]
}

// ACMENewAccount registers a client, or returns the account its key already has.
func (h *Handler) ACMENewAccount(c *okapi.Context) error {
	verified, problem := h.verifyACME(c, "/new-account")
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Key == nil || verified.Header.JWK == nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed,
			"new-account must be signed with an embedded jwk, not a kid"))
	}

	var req acme.NewAccountRequest
	if len(verified.Payload) > 0 {
		if err := json.Unmarshal(verified.Payload, &req); err != nil {
			return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "the payload is not valid JSON"))
		}
	}

	result, problem := h.Service.ACMERegister(verified.Header.JWK, req, h.acmeURL("/new-account"))
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	h.attachNonce(c)
	c.SetHeader("Location", h.acmeURL("/account/%s", result.Account.ID))

	payload := acme.Account{
		Status:               result.Account.Status,
		Contact:              result.Account.Contact.Data,
		Orders:               h.acmeURL("/account/%s/orders", result.Account.ID),
		TermsOfServiceAgreed: result.Account.TermsAgreed,
	}
	if result.Created {
		return c.JSON(http.StatusCreated, payload)
	}
	return c.OK(payload)
}

// ACMEAccount returns or updates an account.
func (h *Handler) ACMEAccount(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/account/"+id)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Account == nil || verified.Account.ID != id {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized,
			"an account may only be read or changed by itself"))
	}

	account := verified.Account
	// An empty payload is POST-as-GET: a read, not an update.
	if len(verified.Payload) > 0 {
		var req acme.UpdateAccountRequest
		if err := json.Unmarshal(verified.Payload, &req); err != nil {
			return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "the payload is not valid JSON"))
		}
		if req.Status == acme.StatusDeactivated {
			if err := h.Service.ACMEDeactivateAccount(account); err != nil {
				return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not deactivate the account"))
			}
		} else if req.Contact != nil {
			account.Contact = store.JSON(req.Contact)
			if err := h.Service.Store.ACME.UpdateAccount(account); err != nil {
				return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not update the account"))
			}
		}
	}

	h.attachNonce(c)
	return c.OK(acme.Account{
		Status:               account.Status,
		Contact:              account.Contact.Data,
		Orders:               h.acmeURL("/account/%s/orders", account.ID),
		TermsOfServiceAgreed: account.TermsAgreed,
	})
}

// ACMENewOrder opens an order.
func (h *Handler) ACMENewOrder(c *okapi.Context) error {
	verified, problem := h.verifyACME(c, "/new-order")
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Account == nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "new-order must be signed with a kid"))
	}

	var req acme.NewOrderRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "the payload is not valid JSON"))
	}

	order, authorizations, problem := h.Service.ACMENewOrder(verified.Account, req)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	h.attachNonce(c)
	c.SetHeader("Location", h.acmeURL("/order/%s", order.ID))
	return c.JSON(http.StatusCreated, h.renderOrder(order, authorizations))
}

// ACMEOrder returns an order's current state; clients poll this.
func (h *Handler) ACMEOrder(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/order/"+id)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	order, err := h.Service.Store.ACME.GetOrder(id)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "no such order"))
	}
	if verified.Account == nil || order.AccountID != verified.Account.ID {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized, "this order belongs to another account"))
	}

	authorizations, err := h.Service.Store.ACME.AuthorizationsByOrder(order.ID)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not load the authorizations"))
	}

	h.attachNonce(c)
	return c.OK(h.renderOrder(order, authorizations))
}

// ACMEOrderList returns an account's orders.
func (h *Handler) ACMEOrderList(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/account/"+id+"/orders")
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Account == nil || verified.Account.ID != id {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized, "this list belongs to another account"))
	}

	rows, err := h.Service.Store.ACME.OrdersByAccount(id, 100)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not load the orders"))
	}
	urls := make([]string, 0, len(rows))
	for i := range rows {
		urls = append(urls, h.acmeURL("/order/%s", rows[i].ID))
	}

	h.attachNonce(c)
	return c.OK(map[string]any{"orders": urls})
}

// ACMEAuthorization returns one authorization and its challenges.
func (h *Handler) ACMEAuthorization(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/authz/"+id)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	authz, err := h.Service.Store.ACME.GetAuthorization(id)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "no such authorization"))
	}
	if verified.Account == nil || authz.AccountID != verified.Account.ID {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized,
			"this authorization belongs to another account"))
	}

	rendered, problem := h.renderAuthorization(authz)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	h.attachNonce(c)
	return c.OK(rendered)
}

// ACMEChallenge triggers or reports a challenge. A POST with a body of "{}" is
// the client saying it is ready; POST-as-GET is a poll.
func (h *Handler) ACMEChallenge(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/challenge/"+id)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Account == nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "this endpoint needs a kid"))
	}

	challenge, err := h.Service.Store.ACME.GetChallenge(id)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "no such challenge"))
	}

	// Only a non-empty payload asks for validation. Polling must not make
	// Certio dial out again — a client checking every two seconds would turn
	// into a small outbound flood.
	if strings.TrimSpace(string(verified.Payload)) != "" {
		challenge, problem = h.Service.ACMEValidateChallenge(c.Request().Context(), verified.Account, id)
		if problem != nil {
			return h.acmeProblem(c, problem)
		}
	}

	authz, err := h.Service.Store.ACME.GetAuthorization(challenge.AuthorizationID)
	if err != nil || authz.AccountID != verified.Account.ID {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized,
			"this challenge belongs to another account"))
	}

	h.attachNonce(c)
	// The Link header points a client at the authorization the challenge
	// belongs to, which RFC 8555 §7.5.1 requires.
	c.SetHeader("Link", fmt.Sprintf(`<%s>;rel="up"`, h.acmeURL("/authz/%s", authz.ID)))
	return c.OK(h.renderChallenge(challenge))
}

// ACMEFinalize signs the CSR for a ready order.
func (h *Handler) ACMEFinalize(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/order/"+id+"/finalize")
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	if verified.Account == nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "finalize must be signed with a kid"))
	}

	var req acme.FinalizeRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "the payload is not valid JSON"))
	}

	order, problem := h.Service.ACMEFinalize(verified.Account, id, req.CSR)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}
	authorizations, err := h.Service.Store.ACME.AuthorizationsByOrder(order.ID)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not load the authorizations"))
	}

	h.attachNonce(c)
	c.SetHeader("Location", h.acmeURL("/order/%s", order.ID))
	return c.OK(h.renderOrder(order, authorizations))
}

// ACMECertificate serves the issued chain as PEM.
func (h *Handler) ACMECertificate(c *okapi.Context) error {
	id := c.Param("id")
	verified, problem := h.verifyACME(c, "/cert/"+id)
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	order, err := h.Service.Store.ACME.GetOrder(id)
	if err != nil || order.CertificateID == "" {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "no certificate for that order"))
	}
	if verified.Account == nil || order.AccountID != verified.Account.ID {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized, "this order belongs to another account"))
	}

	bundle, _, err := h.Service.LoadBundle(order.CertificateID, false)
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrServerInternal, "could not load the certificate"))
	}

	h.attachNonce(c)
	// application/pem-certificate-chain, leaf first — RFC 8555 §7.4.2.
	return c.Data(http.StatusOK, "application/pem-certificate-chain", bundle.FullChainPEM())
}

// ACMERevokeCert revokes a certificate.
func (h *Handler) ACMERevokeCert(c *okapi.Context) error {
	verified, problem := h.verifyACME(c, "/revoke-cert")
	if problem != nil {
		return h.acmeProblem(c, problem)
	}

	var req acme.RevokeRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed, "the payload is not valid JSON"))
	}
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(req.Certificate, "="))
	if err != nil {
		return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed,
			"the certificate is not valid base64url DER"))
	}

	reason := pki.ReasonUnspecified
	if req.Reason != nil {
		reason = *req.Reason
	}

	// A JWS signed with the certificate's own key is the second form RFC 8555
	// allows, and it is the one that matters: it is how a compromised key is
	// withdrawn by whoever found the compromise, with no account involved.
	signedByCertKey := false
	if verified.Account == nil && verified.Header.JWK != nil {
		if ok, problem := h.matchesCertificateKey(verified, der); problem != nil {
			return h.acmeProblem(c, problem)
		} else if ok {
			signedByCertKey = true
		} else {
			return h.acmeProblem(c, acme.NewProblem(acme.ErrUnauthorized,
				"the signing key is neither a registered account nor the certificate's own key"))
		}
	}

	if problem := h.Service.ACMERevoke(verified.Account, der, reason, signedByCertKey); problem != nil {
		return h.acmeProblem(c, problem)
	}

	h.attachNonce(c)
	return c.Data(http.StatusOK, "application/json", nil)
}

// matchesCertificateKey reports whether the JWS was signed by the key inside
// the certificate being revoked.
func (h *Handler) matchesCertificateKey(verified *acmeVerified, der []byte) (bool, *acme.Problem) {
	cert, err := pki.ParseCertificateDER(der)
	if err != nil {
		return false, acme.NewProblem(acme.ErrMalformed, "the certificate is not valid DER")
	}
	signing, err := verified.Header.JWK.PublicKey()
	if err != nil {
		return false, acme.NewProblem(acme.ErrBadPublicKey, "%s", err)
	}

	// crypto.PublicKey has no comparison contract, so the check goes through
	// the Equal method every stdlib key type implements.
	certKey, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, acme.NewProblem(acme.ErrBadPublicKey,
			"the certificate carries a key type that cannot be compared")
	}
	return certKey.Equal(signing), nil
}

// ACMEKeyChange is advertised in the directory because clients expect the
// field to exist, but rolling an account key is not implemented: it is rarely
// used, and an endpoint that half-works here would be worse than one that says
// so plainly.
func (h *Handler) ACMEKeyChange(c *okapi.Context) error {
	h.attachNonce(c)
	return h.acmeProblem(c, acme.NewProblem(acme.ErrMalformed,
		"account key rollover is not supported; register a new account instead"))
}

// --- rendering ---

func (h *Handler) renderOrder(order *store.ACMEOrder, authorizations []store.ACMEAuthorization) acme.Order {
	identifiers := make([]acme.Identifier, 0, len(order.Identifiers.Data))
	for _, name := range order.Identifiers.Data {
		identifiers = append(identifiers, acme.Identifier{Type: "dns", Value: name})
	}
	urls := make([]string, 0, len(authorizations))
	for i := range authorizations {
		urls = append(urls, h.acmeURL("/authz/%s", authorizations[i].ID))
	}

	out := acme.Order{
		Status:         order.Status,
		Expires:        order.ExpiresAt.Format(time.RFC3339),
		Identifiers:    identifiers,
		Authorizations: urls,
		Finalize:       h.acmeURL("/order/%s/finalize", order.ID),
	}
	if order.NotBefore != nil {
		out.NotBefore = order.NotBefore.Format(time.RFC3339)
	}
	if order.NotAfter != nil {
		out.NotAfter = order.NotAfter.Format(time.RFC3339)
	}
	if order.CertificateID != "" {
		out.Certificate = h.acmeURL("/cert/%s", order.ID)
	}
	if order.Error != "" {
		out.Error = &acme.Problem{Type: acme.ErrServerInternal, Detail: order.Error}
	}
	return out
}

func (h *Handler) renderAuthorization(authz *store.ACMEAuthorization) (acme.Authorization, *acme.Problem) {
	challenges, err := h.Service.Store.ACME.ChallengesByAuthorization(authz.ID)
	if err != nil {
		return acme.Authorization{}, acme.NewProblem(acme.ErrServerInternal, "could not load the challenges")
	}
	rendered := make([]acme.Challenge, 0, len(challenges))
	for i := range challenges {
		rendered = append(rendered, h.renderChallenge(&challenges[i]))
	}

	// The identifier is reported without the wildcard prefix and with the
	// wildcard flag set, which is how RFC 8555 §7.1.4 spells it.
	return acme.Authorization{
		Identifier: acme.Identifier{Type: "dns", Value: strings.TrimPrefix(authz.Identifier, "*.")},
		Status:     authz.Status,
		Expires:    authz.ExpiresAt.Format(time.RFC3339),
		Challenges: rendered,
		Wildcard:   authz.Wildcard,
	}, nil
}

func (h *Handler) renderChallenge(challenge *store.ACMEChallenge) acme.Challenge {
	out := acme.Challenge{
		Type:   challenge.Type,
		URL:    h.acmeURL("/challenge/%s", challenge.ID),
		Status: challenge.Status,
		Token:  challenge.Token,
	}
	if challenge.ValidatedAt != nil {
		out.Validated = challenge.ValidatedAt.Format(time.RFC3339)
	}
	if challenge.Error != "" {
		out.Error = &acme.Problem{Type: acme.ErrIncorrectResponse, Detail: challenge.Error}
	}
	return out
}

// --- responses ---

// attachNonce puts a fresh nonce on the response. Every ACME response carries
// one, including the errors: a client that gets badNonce has to have something
// to retry with, or it is stuck.
func (h *Handler) attachNonce(c *okapi.Context) {
	nonce, err := h.Service.NewNonce()
	if err != nil {
		h.Service.Log.Error("could not mint an ACME nonce", "error", err)
		return
	}
	c.SetHeader("Replay-Nonce", nonce)
	c.SetHeader("Link", fmt.Sprintf(`<%s>;rel="index"`, h.acmeURL("/directory")))
}

// acmeProblem renders an RFC 7807 document with the ACME content type.
func (h *Handler) acmeProblem(c *okapi.Context, problem *acme.Problem) error {
	h.attachNonce(c)
	c.SetHeader("Content-Type", "application/problem+json")

	status := problem.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	return c.JSON(status, problem)
}

func (h *Handler) acmeDisabled(c *okapi.Context) error {
	return h.acmeProblem(c, &acme.Problem{
		Type:   acme.ErrServerInternal,
		Detail: "ACME is not enabled on this instance; set CERTIO_ACME_ENABLED=true and CERTIO_ACME_AUTHORITY",
		Status: http.StatusNotFound,
	})
}

// --- administration of the credentials that admit ACME clients ---

// ListExternalAccounts returns every binding credential.
func (h *Handler) ListExternalAccounts(c *okapi.Context) error {
	rows, err := h.Service.Store.ACME.ListExternalAccounts()
	if err != nil {
		return h.fail(c, err)
	}
	items := make([]dto.ExternalAccountResponse, 0, len(rows))
	for i := range rows {
		items = append(items, dto.NewExternalAccountResponse(&rows[i]))
	}
	return c.OK(dto.ExternalAccountListResponse{Items: items, Total: len(items)})
}

// CreateExternalAccount issues a binding credential.
func (h *Handler) CreateExternalAccount(c *okapi.Context, req *dto.CreateExternalAccountRequest) error {
	in := service.CreateExternalAccountInput{
		Description:    req.Body.Description,
		AllowedDomains: req.Body.AllowedDomains,
	}
	if req.Body.ExpiresInDays > 0 {
		in.ExpiresIn = time.Duration(req.Body.ExpiresInDays) * 24 * time.Hour
	}

	row, secret, err := h.Service.CreateExternalAccount(h.actor(c), in)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.CreateExternalAccountResponse{
		ExternalAccount: dto.NewExternalAccountResponse(row),
		HMACKey:         secret,
		DirectoryURL:    h.acmeURL("/directory"),
		Warning:         "this HMAC key is shown once and is not recoverable; issue a new binding if it is lost",
	})
}

// DeleteExternalAccount revokes a binding credential.
func (h *Handler) DeleteExternalAccount(c *okapi.Context, req *dto.ExternalAccountRefRequest) error {
	if err := h.Service.DeleteExternalAccount(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "external account binding revoked"})
}

// ListACMEAccounts returns the clients that have registered.
func (h *Handler) ListACMEAccounts(c *okapi.Context, req *dto.ListACMEAccountsRequest) error {
	result, err := h.Service.Store.ACME.ListAccounts(page(req.Page, req.Limit))
	if err != nil {
		return h.fail(c, err)
	}
	items := make([]dto.ACMEAccountResponse, 0, len(result.Items))
	for i := range result.Items {
		items = append(items, dto.NewACMEAccountResponse(&result.Items[i]))
	}
	return c.OK(dto.ACMEAccountListResponse{
		Items: items, Total: result.Total, Page: result.Page,
		Limit: result.Limit, TotalPages: result.TotalPages,
	})
}
