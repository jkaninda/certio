package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/acme"
	"github.com/jkaninda/certio/internal/audit"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// nonceTTL is how long an unspent nonce stays usable. Long enough for a slow
// client on a slow link, short enough that the table does not become a log.
const nonceTTL = 1 * time.Hour

// orderTTL is how long a client has to complete an order. Beyond this the
// authorizations are stale and the whole thing is better restarted.
const orderTTL = 7 * 24 * time.Hour

// authorizationTTL is how long a *valid* authorization is reused for. Proof of
// control ages: a name that pointed at your load balancer a month ago may not
// today, and re-proving it is cheap.
const authorizationTTL = 30 * 24 * time.Hour

// maxChallengeAttempts bounds how many times a client may ask Certio to dial
// out for one challenge.
const maxChallengeAttempts = 10

// ACMEEnabled reports whether the ACME endpoints should serve.
func (s *Service) ACMEEnabled() bool { return s.Config.ACME.Enabled }

// NewNonce mints and records an anti-replay value.
func (s *Service) NewNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("acme: generate a nonce: %w", err)
	}
	value := acme.Base64URL(raw)
	if err := s.Store.ACME.IssueNonce(value, nonceTTL); err != nil {
		return "", err
	}
	return value, nil
}

// SpendNonce consumes a nonce, returning an ACME problem when it is unusable.
func (s *Service) SpendNonce(value string) *acme.Problem {
	if value == "" {
		return acme.NewProblem(acme.ErrBadNonce, "the request carried no anti-replay nonce")
	}
	ok, err := s.Store.ACME.SpendNonce(value)
	if err != nil {
		s.Log.Error("could not check an ACME nonce", "error", err)
		return acme.NewProblem(acme.ErrServerInternal, "could not verify the nonce")
	}
	if !ok {
		// A client that sees this is expected to retry with the fresh nonce
		// the response carries, which is why the handler always attaches one.
		return acme.NewProblem(acme.ErrBadNonce, "the nonce %q is unknown, expired or already used", value)
	}
	return nil
}

// ACMENewAccountResult is what registration produced.
type ACMENewAccountResult struct {
	Account *store.ACMEAccount
	// Created distinguishes a registration from a returning client, so the
	// handler can answer 201 or 200 as RFC 8555 §7.3 requires.
	Created bool
}

// ACMERegister creates or returns an account for a key.
func (s *Service) ACMERegister(
	key *acme.JWK, req acme.NewAccountRequest, eabURL string,
) (*ACMENewAccountResult, *acme.Problem) {
	thumbprint, err := key.Thumbprint()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrBadPublicKey, "%s", err)
	}

	existing, err := s.Store.ACME.AccountByThumbprint(thumbprint)
	switch {
	case err == nil:
		if existing.Status == store.ACMEStatusDeactivated {
			return nil, acme.NewProblem(acme.ErrUnauthorized, "this account has been deactivated")
		}
		return &ACMENewAccountResult{Account: existing}, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not look the account up")
	}

	if req.OnlyReturnExisting {
		return nil, acme.NewProblem(acme.ErrAccountDoesNotExist, "no account is registered for this key")
	}

	// External account binding is what keeps a private CA from issuing to
	// anything that can reach the network.
	var externalID string
	if s.Config.ACME.RequireEAB {
		binding, problem := s.verifyExternalBinding(req.ExternalAccountBinding, key, eabURL)
		if problem != nil {
			return nil, problem
		}
		externalID = binding.ID

		now := time.Now().UTC()
		binding.LastUsedAt = &now
		if err := s.Store.ACME.UpdateExternalAccount(binding); err != nil {
			s.Log.Error("could not stamp the external account binding", "error", err)
		}
	}

	if s.Config.ACME.TermsURL != "" && !req.TermsOfServiceAgreed {
		return nil, acme.NewProblem(acme.ErrUserActionRequired,
			"the terms of service at %s have to be agreed to", s.Config.ACME.TermsURL)
	}

	encoded, err := key.Encode()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrBadPublicKey, "%s", err)
	}

	account := &store.ACMEAccount{
		KeyThumbprint:     thumbprint,
		KeyJWK:            encoded,
		Contact:           store.JSON(req.Contact),
		Status:            store.ACMEStatusValid,
		TermsAgreed:       req.TermsOfServiceAgreed,
		ExternalAccountID: externalID,
	}
	if err := s.Store.ACME.CreateAccount(account); err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not register the account")
	}

	s.Audit.Record(audit.SystemActor(), audit.Entry{
		Action: audit.ActionACMEAccountCreate, ResourceType: audit.ResourceACMEAccount,
		ResourceID: account.ID, ResourceName: strings.Join(req.Contact, ", "),
		Metadata: map[string]any{"thumbprint": thumbprint, "external_account": externalID},
	})
	return &ACMENewAccountResult{Account: account, Created: true}, nil
}

// verifyExternalBinding checks the inner JWS an administrator's credential
// signed (RFC 8555 §7.3.4).
func (s *Service) verifyExternalBinding(
	binding *acme.JWS, accountKey *acme.JWK, expectedURL string,
) (*store.ACMEExternalAccount, *acme.Problem) {
	if binding == nil {
		return nil, acme.NewProblem(acme.ErrExternalAccountRequired,
			"this ACME server requires external account binding; ask an administrator for a key id and HMAC key")
	}

	_, header, payload, err := acme.ParseJWS(mustMarshal(binding))
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "the external account binding is malformed: %s", err)
	}
	if header.KID == "" {
		return nil, acme.NewProblem(acme.ErrMalformed, "the external account binding needs a kid")
	}
	// The binding's url must match the newAccount URL, so a binding captured
	// from one server cannot be replayed at another.
	if header.URL != expectedURL {
		return nil, acme.NewProblem(acme.ErrMalformed,
			"the external account binding is for %q, not %q", header.URL, expectedURL)
	}

	row, err := s.Store.ACME.ExternalAccountByKID(header.KID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, acme.NewProblem(acme.ErrUnauthorized, "unknown external account key id")
		}
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not look the binding up")
	}
	if !row.IsUsable() {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "this external account key has been disabled or has expired")
	}

	secret, err := s.openExternalHMAC(row)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not read the binding key")
	}
	if err := binding.VerifyHMAC(header.Alg, secret); err != nil {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "%s", err)
	}

	// The payload has to be the account key itself. Without this check a
	// captured binding could be attached to somebody else's key.
	bound, err := acme.DecodeJWK(string(payload))
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "the binding payload is not a JWK")
	}
	boundPrint, err := bound.Thumbprint()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "%s", err)
	}
	accountPrint, err := accountKey.Thumbprint()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrBadPublicKey, "%s", err)
	}
	if boundPrint != accountPrint {
		return nil, acme.NewProblem(acme.ErrUnauthorized,
			"the external account binding is for a different key than the one signing this request")
	}
	return row, nil
}

// ACMENewOrder opens an order for a set of identifiers.
func (s *Service) ACMENewOrder(
	account *store.ACMEAccount, req acme.NewOrderRequest,
) (*store.ACMEOrder, []store.ACMEAuthorization, *acme.Problem) {
	if len(req.Identifiers) == 0 {
		return nil, nil, acme.NewProblem(acme.ErrMalformed, "an order needs at least one identifier")
	}
	if len(req.Identifiers) > maxOrderIdentifiers {
		return nil, nil, acme.NewProblem(acme.ErrRateLimited,
			"an order may carry at most %d identifiers", maxOrderIdentifiers)
	}

	names := make([]string, 0, len(req.Identifiers))
	for _, identifier := range req.Identifiers {
		if identifier.Type != "dns" {
			return nil, nil, acme.NewProblem(acme.ErrUnsupportedIdentifier,
				"only dns identifiers are supported, not %q", identifier.Type)
		}
		name := strings.ToLower(strings.TrimSpace(identifier.Value))
		if problem := s.checkACMEIdentifier(account, name); problem != nil {
			return nil, nil, problem
		}
		names = append(names, name)
	}

	now := time.Now().UTC()
	order := &store.ACMEOrder{
		AccountID:   account.ID,
		Status:      store.ACMEStatusPending,
		Identifiers: store.JSON(names),
		ExpiresAt:   now.Add(orderTTL),
	}
	if req.NotBefore != "" {
		if t, err := time.Parse(time.RFC3339, req.NotBefore); err == nil {
			order.NotBefore = &t
		}
	}
	if req.NotAfter != "" {
		if t, err := time.Parse(time.RFC3339, req.NotAfter); err == nil {
			order.NotAfter = &t
		}
	}
	if err := s.Store.ACME.CreateOrder(order); err != nil {
		return nil, nil, acme.NewProblem(acme.ErrServerInternal, "could not create the order")
	}

	authorizations := make([]store.ACMEAuthorization, 0, len(names))
	for _, name := range names {
		authz := &store.ACMEAuthorization{
			OrderID:    order.ID,
			AccountID:  account.ID,
			Identifier: name,
			Wildcard:   strings.HasPrefix(name, "*."),
			Status:     store.ACMEStatusPending,
			ExpiresAt:  now.Add(orderTTL),
		}
		if err := s.Store.ACME.CreateAuthorization(authz); err != nil {
			return nil, nil, acme.NewProblem(acme.ErrServerInternal, "could not create an authorization")
		}
		if problem := s.createChallenges(authz); problem != nil {
			return nil, nil, problem
		}
		authorizations = append(authorizations, *authz)
	}
	return order, authorizations, nil
}

// maxOrderIdentifiers caps a single order. A hundred names in one certificate
// is already unusual; a thousand is a mistake or an attack.
const maxOrderIdentifiers = 100

// createChallenges offers the ways an identifier may be proved.
func (s *Service) createChallenges(authz *store.ACMEAuthorization) *acme.Problem {
	types := []string{acme.ChallengeDNS01}
	// http-01 cannot prove a wildcard — there is no single host to serve the
	// file from — so it is simply not offered for one.
	if !authz.Wildcard && s.Config.ACME.HTTP01Enabled {
		types = append(types, acme.ChallengeHTTP01)
	}
	if !s.Config.ACME.DNS01Enabled {
		types = types[:0]
		if !authz.Wildcard && s.Config.ACME.HTTP01Enabled {
			types = append(types, acme.ChallengeHTTP01)
		}
	}
	if len(types) == 0 {
		return acme.NewProblem(acme.ErrServerInternal,
			"no challenge type is enabled that can validate %q", authz.Identifier)
	}

	for _, challengeType := range types {
		token, err := randomToken()
		if err != nil {
			return acme.NewProblem(acme.ErrServerInternal, "could not generate a challenge token")
		}
		challenge := &store.ACMEChallenge{
			AuthorizationID: authz.ID,
			Type:            challengeType,
			Token:           token,
			Status:          store.ACMEStatusPending,
		}
		if err := s.Store.ACME.CreateChallenge(challenge); err != nil {
			return acme.NewProblem(acme.ErrServerInternal, "could not create a challenge")
		}
	}
	return nil
}

// checkACMEIdentifier decides whether this server will issue for a name.
func (s *Service) checkACMEIdentifier(account *store.ACMEAccount, name string) *acme.Problem {
	if name == "" {
		return acme.NewProblem(acme.ErrMalformed, "an identifier cannot be empty")
	}
	// An IP address is not a DNS identifier, and treating one as a hostname
	// would let a client claim a name that is not one.
	if net.ParseIP(strings.TrimPrefix(name, "*.")) != nil {
		return acme.NewProblem(acme.ErrUnsupportedIdentifier,
			"%q is an IP address; ACME issuance here is for DNS names", name)
	}
	if strings.Count(name, "*") > 1 || (strings.Contains(name, "*") && !strings.HasPrefix(name, "*.")) {
		return acme.NewProblem(acme.ErrMalformed,
			"%q is not a valid wildcard; only a leading *. is allowed", name)
	}

	// The binding that admitted the account may narrow it further than the CA
	// does, which is how one team's credential is kept to one team's domain.
	if account.ExternalAccountID != "" {
		binding, err := s.Store.ACME.GetExternalAccount(account.ExternalAccountID)
		if err == nil && len(binding.AllowedDomains.Data) > 0 {
			allowed := pki.NameConstraints{PermittedDNS: binding.AllowedDomains.Data}
			if !allowed.PermitsDNS(name) {
				return acme.NewProblem(acme.ErrRejectedIdentifier,
					"%q is outside the domains this ACME credential may request (%s)",
					name, strings.Join(binding.AllowedDomains.Data, ", "))
			}
		}
	}

	caRow, err := s.acmeAuthority()
	if err != nil {
		return acme.NewProblem(acme.ErrServerInternal, "the ACME issuing CA is not available")
	}
	// The CA's own name constraints are the real limit, and refusing here
	// means the client is told which name is the problem rather than watching
	// finalize fail later.
	constraints := caRow.NameConstraints.Data
	if !constraints.IsZero() && !constraints.PermitsDNS(name) {
		return acme.NewProblem(acme.ErrRejectedIdentifier,
			"%q is outside the issuing CA's name constraints", name)
	}
	return nil
}

// acmeAuthority resolves the CA that signs ACME orders.
func (s *Service) acmeAuthority() (*store.Authority, error) {
	if s.Config.ACME.Authority == "" {
		return nil, errors.New("acme.authority is not configured")
	}
	return s.Store.Authorities.Resolve(s.Config.ACME.Authority)
}

// ACMEValidateChallenge performs a challenge and updates the order state.
//
// Validation runs inline rather than on a queue: it is one HTTP fetch or one
// DNS lookup, and a client that just told us it is ready is expecting an
// answer. RFC 8555 allows either, and inline means no second moving part to
// watch when issuance stops working.
func (s *Service) ACMEValidateChallenge(
	ctx context.Context, account *store.ACMEAccount, challengeID string,
) (*store.ACMEChallenge, *acme.Problem) {
	challenge, err := s.Store.ACME.GetChallenge(challengeID)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "no such challenge")
	}
	authz, err := s.Store.ACME.GetAuthorization(challenge.AuthorizationID)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not load the authorization")
	}
	if authz.AccountID != account.ID {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "this challenge belongs to another account")
	}

	// Re-triggering a settled challenge is a no-op, not an error: a client
	// that lost the response and retried should get the same answer.
	if challenge.Status == store.ACMEStatusValid || challenge.Status == store.ACMEStatusInvalid {
		return challenge, nil
	}
	if challenge.Attempts >= maxChallengeAttempts {
		return nil, acme.NewProblem(acme.ErrRateLimited,
			"this challenge has been attempted %d times; open a new order", challenge.Attempts)
	}

	key, err := acme.DecodeJWK(account.KeyJWK)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not read the account key")
	}
	keyAuthorization, err := acme.KeyAuthorization(challenge.Token, key)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "%s", err)
	}

	challenge.Attempts++
	challenge.Status = store.ACMEStatusProcessing
	if err := s.Store.ACME.UpdateChallenge(challenge); err != nil {
		s.Log.Error("could not mark an ACME challenge as processing", "error", err)
	}

	validator := acme.NewValidator(s.Config.ACME.Resolver, s.Config.ACME.HTTP01Port)
	problem := validator.Validate(ctx, challenge.Type, authz.Identifier, challenge.Token, keyAuthorization)

	now := time.Now().UTC()
	if problem != nil {
		challenge.Status = store.ACMEStatusInvalid
		challenge.Error = problem.Detail
		if err := s.Store.ACME.UpdateChallenge(challenge); err != nil {
			s.Log.Error("could not record a failed ACME challenge", "error", err)
		}
		// The authorization is only failed once every challenge on it has
		// been: a client that tried http-01 and failed may still succeed with
		// dns-01.
		s.failAuthorizationIfExhausted(authz)
		return challenge, nil
	}

	challenge.Status = store.ACMEStatusValid
	challenge.ValidatedAt = &now
	challenge.Error = ""
	if err := s.Store.ACME.UpdateChallenge(challenge); err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not record the validation")
	}

	authz.Status = store.ACMEStatusValid
	authz.ExpiresAt = now.Add(authorizationTTL)
	if err := s.Store.ACME.UpdateAuthorization(authz); err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not record the authorization")
	}
	s.refreshOrderStatus(authz.OrderID)

	return challenge, nil
}

// failAuthorizationIfExhausted marks an authorization invalid once no
// challenge on it can still succeed.
func (s *Service) failAuthorizationIfExhausted(authz *store.ACMEAuthorization) {
	challenges, err := s.Store.ACME.ChallengesByAuthorization(authz.ID)
	if err != nil {
		return
	}
	for i := range challenges {
		if challenges[i].Status != store.ACMEStatusInvalid {
			return
		}
	}
	authz.Status = store.ACMEStatusInvalid
	if err := s.Store.ACME.UpdateAuthorization(authz); err != nil {
		s.Log.Error("could not record a failed ACME authorization", "error", err)
		return
	}

	if order, err := s.Store.ACME.GetOrder(authz.OrderID); err == nil {
		order.Status = store.ACMEStatusInvalid
		order.Error = fmt.Sprintf("could not validate %s", authz.Identifier)
		if err := s.Store.ACME.UpdateOrder(order); err != nil {
			s.Log.Error("could not record a failed ACME order", "error", err)
		}
		s.Metrics.ACMEOrders.WithLabelValues("invalid").Inc()
	}
}

// refreshOrderStatus moves an order to ready once every authorization is valid.
func (s *Service) refreshOrderStatus(orderID string) {
	order, err := s.Store.ACME.GetOrder(orderID)
	if err != nil || order.Status != store.ACMEStatusPending {
		return
	}
	authzs, err := s.Store.ACME.AuthorizationsByOrder(orderID)
	if err != nil {
		return
	}
	for i := range authzs {
		if authzs[i].Status != store.ACMEStatusValid {
			return
		}
	}
	order.Status = store.ACMEStatusReady
	if err := s.Store.ACME.UpdateOrder(order); err != nil {
		s.Log.Error("could not mark an ACME order ready", "error", err)
	}
}

// ACMEFinalize signs the CSR and attaches the certificate to the order.
func (s *Service) ACMEFinalize(
	account *store.ACMEAccount, orderID, csrBase64 string,
) (*store.ACMEOrder, *acme.Problem) {
	order, err := s.Store.ACME.GetOrder(orderID)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrMalformed, "no such order")
	}
	if order.AccountID != account.ID {
		return nil, acme.NewProblem(acme.ErrUnauthorized, "this order belongs to another account")
	}
	switch order.Status {
	case store.ACMEStatusReady:
	case store.ACMEStatusValid:
		// Already finalised; a client that lost the response gets the order.
		return order, nil
	default:
		return nil, acme.NewProblem(acme.ErrOrderNotReady,
			"the order is %s; every authorization has to be valid before it can be finalized", order.Status)
	}

	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(csrBase64, "="))
	if err != nil {
		return nil, acme.NewProblem(acme.ErrBadCSR, "the CSR is not valid base64url DER")
	}
	csr, err := pki.ParseCSRDER(der)
	if err != nil {
		return nil, acme.NewProblem(acme.ErrBadCSR, "%s", err)
	}

	// The CSR must ask for exactly what the order authorised — no more, and
	// nothing else. Without this check a validated order for one name could
	// be finalised into a certificate for another.
	if problem := checkCSRAgainstOrder(csr, order.Identifiers.Data); problem != nil {
		order.Status = store.ACMEStatusInvalid
		order.Error = problem.Detail
		if err := s.Store.ACME.UpdateOrder(order); err != nil {
			s.Log.Error("could not record a rejected ACME finalize", "error", err)
		}
		s.Metrics.ACMEOrders.WithLabelValues("invalid").Inc()
		return nil, problem
	}

	caRow, err := s.acmeAuthority()
	if err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "the ACME issuing CA is not available")
	}

	validity := s.Config.ACME.ValidityDays
	if validity <= 0 {
		validity = pki.MaxLeafValidityDays
	}

	result, err := s.SignCSR(acmeActor(account), SignCSRInput{
		AuthorityID:  caRow.ID,
		CSRPEM:       string(pki.EncodeCSRPEM(der)),
		Profile:      pki.ProfileServer,
		ValidityDays: validity,
		Labels:       map[string]string{"acme": "true", "acme_account": account.ID},
	})
	if err != nil {
		problem := acme.NewProblem(acme.ErrServerInternal, "could not issue the certificate: %s", err)
		if errors.Is(err, ErrValidation) {
			problem = acme.NewProblem(acme.ErrBadCSR, "%s", cleanValidationMessage(err))
		}
		order.Status = store.ACMEStatusInvalid
		order.Error = problem.Detail
		if updateErr := s.Store.ACME.UpdateOrder(order); updateErr != nil {
			s.Log.Error("could not record a failed ACME finalize", "error", updateErr)
		}
		s.Metrics.ACMEOrders.WithLabelValues("invalid").Inc()
		return nil, problem
	}

	order.Status = store.ACMEStatusValid
	order.CertificateID = result.Certificate.ID
	order.Error = ""
	if err := s.Store.ACME.UpdateOrder(order); err != nil {
		return nil, acme.NewProblem(acme.ErrServerInternal, "could not attach the certificate to the order")
	}

	s.Metrics.ACMEOrders.WithLabelValues("valid").Inc()
	return order, nil
}

// checkCSRAgainstOrder is the check that makes a validated order mean
// something: the names in the CSR have to be exactly the names that were
// proved, in any order, with nothing extra.
func checkCSRAgainstOrder(csr *pki.CertificateRequest, identifiers []string) *acme.Problem {
	authorized := make(map[string]bool, len(identifiers))
	for _, name := range identifiers {
		authorized[strings.ToLower(name)] = true
	}

	requested := make(map[string]bool, len(csr.DNSNames)+1)
	for _, name := range csr.DNSNames {
		requested[strings.ToLower(name)] = true
	}
	// A common name that is a hostname counts as a request for that name,
	// because plenty of clients still read it.
	if cn := strings.ToLower(strings.TrimSpace(csr.Subject.CommonName)); cn != "" && strings.Contains(cn, ".") {
		requested[cn] = true
	}
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return acme.NewProblem(acme.ErrBadCSR,
			"the CSR carries IP, email or URI names, which this order did not authorise")
	}

	for name := range requested {
		if !authorized[name] {
			return acme.NewProblem(acme.ErrBadCSR,
				"the CSR asks for %q, which this order did not authorise", name)
		}
	}
	if len(requested) == 0 {
		return acme.NewProblem(acme.ErrBadCSR, "the CSR names nothing")
	}
	return nil
}

// ACMERevoke revokes a certificate on an ACME client's request.
//
// RFC 8555 §7.6 allows either the account that ordered it or the holder of the
// certificate's own key to revoke. The second case is the important one: it is
// how a compromised key is withdrawn by whoever discovers the compromise.
func (s *Service) ACMERevoke(
	account *store.ACMEAccount, certDER []byte, reason int, signedByCertKey bool,
) *acme.Problem {
	cert, err := pki.ParseCertificateDER(certDER)
	if err != nil {
		return acme.NewProblem(acme.ErrMalformed, "the certificate is not valid DER")
	}

	row, err := s.Store.Certificates.GetByFingerprint(pki.Fingerprint(cert))
	if err != nil {
		return acme.NewProblem(acme.ErrMalformed, "this certificate was not issued here")
	}
	if row.Status == store.StatusRevoked {
		return acme.NewProblem(acme.ErrAlreadyRevoked, "this certificate is already revoked")
	}

	if !signedByCertKey {
		if account == nil {
			return acme.NewProblem(acme.ErrUnauthorized, "authentication is required to revoke")
		}
		// An account may only revoke what it ordered. Anything else and one
		// tenant could revoke another's certificates.
		if row.Labels.Data["acme_account"] != account.ID {
			return acme.NewProblem(acme.ErrUnauthorized,
				"this account did not order this certificate; revoke with the certificate's own key instead")
		}
	}

	if err := pki.ValidateRevocationReason(reason); err != nil {
		return acme.NewProblem(acme.ErrBadRevocationReason, "%s", err)
	}

	if _, err := s.Revoke(acmeActor(account), row.ID, RevokeInput{ReasonCode: reason}); err != nil {
		return acme.NewProblem(acme.ErrServerInternal, "could not revoke: %s", err)
	}
	return nil
}

// ACMEDeactivateAccount closes an account at the client's request.
func (s *Service) ACMEDeactivateAccount(account *store.ACMEAccount) error {
	account.Status = store.ACMEStatusDeactivated
	return s.Store.ACME.UpdateAccount(account)
}

// --- external account administration ---

// CreateExternalAccountInput describes a binding credential to issue.
type CreateExternalAccountInput struct {
	Description    string
	AllowedDomains []string
	ExpiresIn      time.Duration
}

// CreateExternalAccount issues an ACME binding credential and returns the HMAC
// key exactly once — only its sealed form is stored.
func (s *Service) CreateExternalAccount(
	actor audit.Actor, in CreateExternalAccountInput,
) (*store.ACMEExternalAccount, string, error) {
	kidRaw := make([]byte, 12)
	if _, err := rand.Read(kidRaw); err != nil {
		return nil, "", fmt.Errorf("generate an ACME key id: %w", err)
	}
	secretRaw := make([]byte, 32)
	if _, err := rand.Read(secretRaw); err != nil {
		return nil, "", fmt.Errorf("generate an ACME HMAC key: %w", err)
	}

	kid := hex.EncodeToString(kidRaw)
	// The HMAC key is handed to the client base64url-encoded, which is the
	// form every ACME client's --eab-hmac-key flag expects.
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)

	env, err := s.Keyring.Seal([]byte(secret), "")
	if err != nil {
		return nil, "", err
	}

	row := &store.ACMEExternalAccount{
		KID: kid, Description: in.Description,
		HMACEncrypted: env.Ciphertext, HMACNonce: env.Nonce, HMACSalt: env.Salt,
		AllowedDomains: store.JSON(in.AllowedDomains),
		Enabled:        true,
		CreatedBy:      actor.ID,
	}
	if in.ExpiresIn > 0 {
		expiry := time.Now().Add(in.ExpiresIn).UTC()
		row.ExpiresAt = &expiry
	}
	if err := s.Store.ACME.CreateExternalAccount(row); err != nil {
		return nil, "", err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionACMEExternalCreate, ResourceType: audit.ResourceACMEExternal,
		ResourceID: row.ID, ResourceName: in.Description,
		Metadata: map[string]any{"kid": kid, "allowed_domains": in.AllowedDomains},
	})
	return row, secret, nil
}

// DeleteExternalAccount revokes a binding credential.
func (s *Service) DeleteExternalAccount(actor audit.Actor, id string) error {
	row, err := s.Store.ACME.GetExternalAccount(id)
	if err != nil {
		return err
	}
	if err := s.Store.ACME.DeleteExternalAccount(id); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionACMEExternalDelete, ResourceType: audit.ResourceACMEExternal,
		ResourceID: row.ID, ResourceName: row.Description,
		Metadata: map[string]any{"kid": row.KID},
	})
	return nil
}

// openExternalHMAC decrypts a binding's shared secret.
func (s *Service) openExternalHMAC(row *store.ACMEExternalAccount) ([]byte, error) {
	raw, err := s.Keyring.Open(certiocrypto.Envelope{
		Ciphertext: row.HMACEncrypted, Nonce: row.HMACNonce, Salt: row.HMACSalt,
	}, "")
	if err != nil {
		return nil, err
	}
	// The stored value is the base64url text the client was given, and the
	// HMAC is computed over the bytes it decodes to.
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(raw), "="))
	if err != nil {
		return nil, fmt.Errorf("acme: the stored HMAC key is not base64url: %w", err)
	}
	return decoded, nil
}

// PruneACME drops expired nonces and orders.
func (s *Service) PruneACME() (nonces, orders int64, err error) {
	now := time.Now()
	if nonces, err = s.Store.ACME.PruneNonces(now); err != nil {
		return 0, 0, err
	}
	if orders, err = s.Store.ACME.PruneOrders(now); err != nil {
		return nonces, 0, err
	}
	return nonces, orders, nil
}

// acmeActor attributes an audited action to the ACME account behind it.
func acmeActor(account *store.ACMEAccount) audit.Actor {
	actor := audit.Actor{Type: store.ActorSystem, Name: "acme"}
	if account != nil {
		actor.ID = account.ID
		actor.Name = "acme:" + account.ID
	}
	return actor
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return acme.Base64URL(raw), nil
}

// mustMarshal re-encodes the inner JWS so it can be parsed by the same code
// path as the outer one. The value came from json.Unmarshal, so it cannot fail.
func mustMarshal(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

// cleanValidationMessage strips the sentinel prefix so an ACME problem reads
// as a sentence rather than as Go error wrapping.
func cleanValidationMessage(err error) string {
	msg := err.Error()
	if _, after, ok := strings.Cut(msg, "validation failed: "); ok {
		return after
	}
	return msg
}
