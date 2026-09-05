package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/store"
)

var ErrOAuthNotConfigured = errors.New("single sign-on is not configured on this instance")

var ErrOAuthDenied = errors.New("this account may not sign in")

const (
	oauthStateTTL = 10 * time.Minute

	oauthHTTPTimeout = 15 * time.Second

	oauthMaxResponse = 1 << 20
)

type oauthStateStore struct {
	mu      sync.Mutex
	entries map[string]oauthPending
	lastGC  time.Time
}

// oauthPending is one authorization request awaiting its callback.
type oauthPending struct {
	verifier  string
	expiresAt time.Time
}

func newOAuthStateStore() *oauthStateStore {
	return &oauthStateStore{entries: make(map[string]oauthPending), lastGC: time.Now()}
}

// issue mints a state and its PKCE verifier and remembers the pair.
func (s *oauthStateStore) issue() (state, verifier string, err error) {
	state, err = randomURLSafe(32)
	if err != nil {
		return "", "", err
	}
	verifier, err = randomURLSafe(32)
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.collect(time.Now())
	s.entries[state] = oauthPending{verifier: verifier, expiresAt: time.Now().Add(oauthStateTTL)}
	return state, verifier, nil
}

// redeem consumes a state and returns its verifier. A state is answerable
// exactly once: replaying a callback must not mint a second session.
func (s *oauthStateStore) redeem(state string) (string, bool) {
	if state == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	pending, ok := s.entries[state]
	if !ok {
		return "", false
	}
	delete(s.entries, state)
	if time.Now().After(pending.expiresAt) {
		return "", false
	}
	return pending.verifier, true
}

func (s *oauthStateStore) collect(now time.Time) {
	if now.Sub(s.lastGC) < oauthStateTTL {
		return
	}
	for state, pending := range s.entries {
		if now.After(pending.expiresAt) {
			delete(s.entries, state)
		}
	}
	s.lastGC = now
}

// randomURLSafe returns n random bytes as an unpadded URL-safe string.
func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

type OAuthProviderInput struct {
	Name         string
	DisplayName  string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string

	SubjectField string
	EmailField   string
	NameField    string

	AllowedDomains []string
	AllowSignup    bool
	DefaultRole    string
	Enabled        bool
}

// OAuthProvider returns the configured provider, or ErrNotFound when sign-in
// has not been federated.
func (s *Service) OAuthProvider() (*store.OAuthProvider, error) {
	return s.Store.OAuth.Get()
}

func (s *Service) enabledOAuthProvider() (*store.OAuthProvider, error) {
	provider, err := s.Store.OAuth.Get()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrOAuthNotConfigured
	case err != nil:
		return nil, err
	case !provider.Enabled:
		return nil, ErrOAuthNotConfigured
	}
	return provider, nil
}

func (s *Service) SaveOAuthProvider(actor audit.Actor, in OAuthProviderInput) (*store.OAuthProvider, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		return nil, validationError("a provider name is required, e.g. keycloak or entra")
	}
	if strings.TrimSpace(in.ClientID) == "" {
		return nil, validationError("a client ID is required")
	}
	for label, raw := range map[string]string{
		"authorization URL": in.AuthURL,
		"token URL":         in.TokenURL,
		"userinfo URL":      in.UserInfoURL,
	} {
		if err := validateEndpoint(label, raw); err != nil {
			return nil, err
		}
	}
	role := defaultString(in.DefaultRole, store.RoleViewer)
	if err := validateRole(role); err != nil {
		return nil, err
	}

	existing, err := s.Store.OAuth.Get()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	provider := &store.OAuthProvider{
		Name:           name,
		DisplayName:    strings.TrimSpace(in.DisplayName),
		ClientID:       strings.TrimSpace(in.ClientID),
		AuthURL:        strings.TrimSpace(in.AuthURL),
		TokenURL:       strings.TrimSpace(in.TokenURL),
		UserInfoURL:    strings.TrimSpace(in.UserInfoURL),
		Scopes:         store.JSON(normalizeList(in.Scopes)),
		SubjectField:   strings.TrimSpace(in.SubjectField),
		EmailField:     strings.TrimSpace(in.EmailField),
		NameField:      strings.TrimSpace(in.NameField),
		AllowedDomains: store.JSON(normalizeDomains(in.AllowedDomains)),
		AllowSignup:    in.AllowSignup,
		DefaultRole:    role,
		Enabled:        in.Enabled,
	}
	provider.ApplyDefaults()

	switch {
	case in.ClientSecret != "":
		env, err := s.Keyring.SealString(in.ClientSecret, "")
		if err != nil {
			return nil, err
		}
		provider.ClientSecretEncrypted = env.Ciphertext
		provider.ClientSecretNonce = env.Nonce
		provider.ClientSecretSalt = env.Salt

	case existing != nil && len(existing.ClientSecretEncrypted) > 0:
		// A re-save that leaves the field blank keeps the stored secret: the
		// form cannot show it, so it cannot send it back.
		provider.ClientSecretEncrypted = existing.ClientSecretEncrypted
		provider.ClientSecretNonce = existing.ClientSecretNonce
		provider.ClientSecretSalt = existing.ClientSecretSalt

	default:
		return nil, validationError("a client secret is required")
	}

	if err := s.Store.OAuth.Save(provider); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionOAuthConfigured, ResourceType: audit.ResourceOAuth,
		ResourceID: provider.ID, ResourceName: provider.Name,
		Metadata: map[string]any{
			"enabled":         provider.Enabled,
			"allow_signup":    provider.AllowSignup,
			"default_role":    provider.DefaultRole,
			"allowed_domains": provider.AllowedDomains.Data,
		},
	})
	return provider, nil
}

// DeleteOAuthProvider removes federated sign-in. Accounts it provisioned stay:
// deleting them with the configuration would destroy their certificates'
// ownership trail, and an administrator who wants them gone can say so.
func (s *Service) DeleteOAuthProvider(actor audit.Actor) error {
	provider, err := s.Store.OAuth.Get()
	if err != nil {
		return err
	}
	if err := s.Store.OAuth.Delete(); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionOAuthRemoved, ResourceType: audit.ResourceOAuth,
		ResourceID: provider.ID, ResourceName: provider.Name,
	})
	return nil
}

func (s *Service) OAuthRedirectURI() string {
	if s.Config == nil {
		return ""
	}
	return strings.TrimRight(s.Config.Server.BaseURL, "/") + "/oauth/callback"
}

// validateEndpoint rejects a provider URL that could not work.
func validateEndpoint(label, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return validationError("a %s is required", label)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return validationError("the %s must be an absolute URL", label)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return validationError("the %s must be an http or https URL", label)
	}
	return nil
}

// normalizeList trims, lowercases nothing and drops blanks and duplicates,
// preserving the order the operator wrote — scope order is not meaningful to a
// provider but a stable list is easier to read back in the form.
func normalizeList(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		value := strings.TrimSpace(raw)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// normalizeDomains lowercases and strips a leading "@", so both "example.com"
// and "@example.com" mean the same thing in the settings form.
func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range normalizeList(in) {
		out = append(out, strings.ToLower(strings.TrimPrefix(raw, "@")))
	}
	return out
}

// StartOAuth begins a sign-in and returns the provider's authorization URL.
func (s *Service) StartOAuth() (string, error) {
	provider, err := s.enabledOAuthProvider()
	if err != nil {
		return "", err
	}

	state, verifier, err := s.oauthStates.issue()
	if err != nil {
		return "", err
	}

	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {provider.ClientID},
		"redirect_uri":          {s.OAuthRedirectURI()},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	if scopes := provider.Scopes.Data; len(scopes) > 0 {
		query.Set("scope", strings.Join(scopes, " "))
	}

	separator := "?"
	if strings.Contains(provider.AuthURL, "?") {
		separator = "&"
	}
	return provider.AuthURL + separator + query.Encode(), nil
}

func (s *Service) LoginWithOAuth(
	ctx context.Context, actor audit.Actor, auth *Authenticator, code, state string,
) (*LoginResult, error) {
	provider, err := s.enabledOAuthProvider()
	if err != nil {
		return nil, err
	}

	verifier, ok := s.oauthStates.redeem(state)
	if !ok {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionLoginFailed, ResourceType: audit.ResourceUser,
			Metadata: map[string]any{metaMethod: methodOAuth, "reason": "invalid_state"},
		}, ErrInvalidCredentials)
		return nil, fmt.Errorf("%w: this sign-in attempt expired or was already used", ErrInvalidCredentials)
	}
	if code == "" {
		return nil, validationError("the provider returned no authorization code")
	}

	secret, err := s.Keyring.OpenString(certiocrypto.Envelope{
		Ciphertext: provider.ClientSecretEncrypted,
		Nonce:      provider.ClientSecretNonce,
		Salt:       provider.ClientSecretSalt,
	}, "")
	if err != nil {
		return nil, fmt.Errorf("unseal the OAuth client secret: %w", err)
	}

	accessToken, err := s.exchangeOAuthCode(ctx, provider, secret, code, verifier)
	if err != nil {
		return nil, err
	}

	profile, err := s.fetchOAuthProfile(ctx, provider, accessToken)
	if err != nil {
		return nil, err
	}

	user, err := s.resolveOAuthUser(actor, provider, profile)
	if err != nil {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionLoginFailed, ResourceType: audit.ResourceUser,
			ResourceName: profile.Email,
			Metadata:     map[string]any{metaMethod: methodOAuth, metaProvider: provider.Name},
		}, err)
		return nil, err
	}
	if !user.IsActive() {
		return nil, ErrAccountDisabled
	}

	if user.HasTwoFactor() {
		challenge, ttl, err := auth.IssueChallenge(user)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			User: user, TwoFactorRequired: true,
			Challenge: challenge, ChallengeExpiresIn: int(ttl.Seconds()),
		}, nil
	}

	return s.issueSession(actor, auth, user, map[string]any{
		metaMethod: methodOAuth, metaProvider: provider.Name,
	})
}

// oauthProfile is what a provider told Certio about the person signing in.
type oauthProfile struct {
	Subject string
	Email   string
	Name    string

	EmailVerified bool
}

func (s *Service) exchangeOAuthCode(
	ctx context.Context, provider *store.OAuthProvider, secret, code, verifier string,
) (string, error) {
	form := func() url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {s.OAuthRedirectURI()},
			"client_id":     {provider.ClientID},
			"code_verifier": {verifier},
		}
	}

	inBody := form()
	inBody.Set("client_secret", secret)
	token, status, err := s.postOAuthToken(ctx, provider.TokenURL, inBody, "", "")
	if err == nil {
		return token, nil
	}
	if status != http.StatusUnauthorized {
		return "", err
	}

	token, _, basicErr := s.postOAuthToken(ctx, provider.TokenURL, form(), provider.ClientID, secret)
	if basicErr != nil {

		return "", err
	}
	return token, nil
}

func (s *Service) postOAuthToken(
	ctx context.Context, tokenURL string, form url.Values, basicUser, basicPassword string,
) (accessToken string, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPassword))
	}

	body, status, err := s.doOAuthRequest(req)
	if err != nil {
		return "", status, err
	}

	var payload struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		// A provider that answers a token request with HTML is almost always
		// one whose token URL points at a login page.
		return "", status, fmt.Errorf("the token endpoint did not return JSON (HTTP %d)", status)
	}
	if payload.Error != "" {
		return "", status, fmt.Errorf("the provider rejected the authorization code: %s",
			defaultString(payload.ErrorDescription, payload.Error))
	}
	if status != http.StatusOK {
		return "", status, fmt.Errorf("the token endpoint returned HTTP %d", status)
	}
	if payload.AccessToken == "" {
		return "", status, errors.New("the token endpoint returned no access token")
	}
	return payload.AccessToken, status, nil
}

// fetchOAuthProfile reads the userinfo document and maps it onto a profile
// using the field names the provider was configured with.
func (s *Service) fetchOAuthProfile(
	ctx context.Context, provider *store.OAuthProvider, accessToken string,
) (oauthProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserInfoURL, http.NoBody)
	if err != nil {
		return oauthProfile{}, fmt.Errorf("build the userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	body, status, err := s.doOAuthRequest(req)
	if err != nil {
		return oauthProfile{}, err
	}
	if status != http.StatusOK {
		return oauthProfile{}, fmt.Errorf("the userinfo endpoint returned HTTP %d", status)
	}

	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return oauthProfile{}, fmt.Errorf("the userinfo endpoint did not return a JSON object: %w", err)
	}

	profile := oauthProfile{
		Subject:       oauthString(document, provider.SubjectField),
		Email:         strings.ToLower(oauthString(document, provider.EmailField)),
		Name:          oauthString(document, provider.NameField),
		EmailVerified: true,
	}
	if raw, ok := oauthLookup(document, "email_verified"); ok {
		profile.EmailVerified = oauthBool(raw)
	}

	if profile.Subject == "" {
		return oauthProfile{}, fmt.Errorf(
			"%w: the provider returned no %q field to identify the account by",
			ErrOAuthDenied, provider.SubjectField)
	}
	if profile.Email == "" {
		return oauthProfile{}, fmt.Errorf(
			"%w: the provider returned no %q field; sign-in needs an email address",
			ErrOAuthDenied, provider.EmailField)
	}
	return profile, nil
}

// doOAuthRequest sends a request to the provider and reads a bounded body.
func (s *Service) doOAuthRequest(req *http.Request) (body []byte, status int, err error) {
	client := &http.Client{Timeout: oauthHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("reach the identity provider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(io.LimitReader(resp.Body, oauthMaxResponse))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read the provider's response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// resolveOAuthUser maps a provider profile onto a Certio account, creating one
// when the provider is allowed to provision.
//
// The lookup is by subject first and by email second. That order matters: the
// subject is the provider's permanent handle for a person, while an email
// address can be reassigned, and matching on email alone would hand a new
// employee the previous holder's account.
func (s *Service) resolveOAuthUser(
	actor audit.Actor, provider *store.OAuthProvider, profile oauthProfile,
) (*store.User, error) {
	if err := checkOAuthDomain(provider.AllowedDomains.Data, profile.Email); err != nil {
		return nil, err
	}

	user, err := s.Store.Users.GetByOAuth(provider.Name, profile.Subject)
	switch {
	case err == nil:
		// The address on file follows the directory, so a rename at the
		// provider does not leave a stale email in the audit log.
		if !strings.EqualFold(user.Email, profile.Email) || (profile.Name != "" && user.Name != profile.Name) {
			user.Email = profile.Email
			if profile.Name != "" {
				user.Name = profile.Name
			}
			if err := s.Store.Users.Update(user); err != nil {
				return nil, err
			}
		}
		return user, nil

	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	if !profile.EmailVerified {
		return nil, fmt.Errorf("%w: %s has not verified this email address", ErrOAuthDenied, provider.Label())
	}

	existing, err := s.Store.Users.GetByEmail(profile.Email)
	switch {
	case err == nil:
		return s.linkOAuthUser(actor, provider, existing, profile)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	if !provider.AllowSignup {
		return nil, fmt.Errorf(
			"%w: no account exists for %s, and this instance does not create them automatically",
			ErrOAuthDenied, profile.Email)
	}
	return s.provisionOAuthUser(actor, provider, profile)
}

func (s *Service) linkOAuthUser(
	actor audit.Actor, provider *store.OAuthProvider, user *store.User, profile oauthProfile,
) (*store.User, error) {

	if user.OAuthSubject != "" && user.OAuthSubject != profile.Subject {
		return nil, fmt.Errorf(
			"%w: %s is already linked to a different %s identity; an administrator has to unlink it first",
			ErrOAuthDenied, user.Email, provider.Label())
	}

	user.OAuthProvider = provider.Name
	user.OAuthSubject = profile.Subject
	if user.Name == "" && profile.Name != "" {
		user.Name = profile.Name
	}
	if err := s.Store.Users.Update(user); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionOAuthLinked, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{metaProvider: provider.Name},
	})
	return user, nil
}

func (s *Service) provisionOAuthUser(
	actor audit.Actor, provider *store.OAuthProvider, profile oauthProfile,
) (*store.User, error) {
	user := &store.User{
		Email:         profile.Email,
		Name:          defaultString(profile.Name, profile.Email),
		Role:          defaultString(provider.DefaultRole, store.RoleViewer),
		Status:        store.StatusActive,
		OAuthProvider: provider.Name,
		OAuthSubject:  profile.Subject,
	}
	if err := s.Store.Users.Create(user); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionOAuthProvisioned, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{metaProvider: provider.Name, "role": user.Role},
	})
	s.Log.Info("provisioned an account from the identity provider",
		"email", user.Email, "provider", provider.Name, "role", user.Role)
	return user, nil
}

// checkOAuthDomain enforces the allowed-domain list. An empty list allows any
// address the provider vouches for.
func checkOAuthDomain(allowed []string, email string) error {
	if len(allowed) == 0 {
		return nil
	}
	_, domain, found := strings.Cut(email, "@")
	if !found {
		return fmt.Errorf("%w: %q is not an email address", ErrOAuthDenied, email)
	}
	domain = strings.ToLower(domain)
	for _, candidate := range allowed {
		if domain == candidate {
			return nil
		}
	}
	return fmt.Errorf("%w: sign-in is restricted to %s", ErrOAuthDenied, strings.Join(allowed, ", "))
}

func oauthLookup(document map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var current any = document
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, current != nil
}

// oauthString reads a field as text. Numbers are rendered without a decimal
// point, because a provider that returns an integer user id — GitHub does —
// must not produce a subject of "12345.000000".
func oauthString(document map[string]any, path string) string {
	value, ok := oauthLookup(document, path)
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

// oauthBool reads a flag that a provider may send as a JSON boolean or, less
// correctly but not rarely, as the string "true".
func oauthBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(typed)
		return err == nil && parsed
	default:
		return false
	}
}
