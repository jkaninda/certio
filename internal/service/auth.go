package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jkaninda/certio/internal/audit"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/store"
)

// ErrInvalidCredentials is returned for a bad email or password. The two cases
// are deliberately indistinguishable so the endpoint cannot enumerate accounts.
var ErrInvalidCredentials = errors.New("invalid email or password")

// ErrAccountDisabled is returned when the credentials are right but the
// account is not active.
var ErrAccountDisabled = errors.New("this account is disabled")

// Token types carried in the "typ" claim, so a refresh token cannot be
// replayed as an access token — nor a half-finished login as either.
const (
	tokenTypeAccess    = "access"
	tokenTypeRefresh   = "refresh"
	tokenTypeChallenge = "2fa"
)

// Audit metadata keys used by the sign-in paths. They end up in exported audit
// trails and in operators' alerting rules, so they are named once rather than
// spelled out at each call site.
const (
	metaMethod   = "method"
	metaProvider = "provider"

	// methodOAuth marks a sign-in that came through the identity provider.
	// Federated sign-ins are recorded as ActionLogin like any other, so a rule
	// watching for logins keeps working when an instance federates.
	methodOAuth = "oauth"
)

// challengeTTL is how long a user has to enter their second factor after the
// password step. Long enough to fetch a phone, short enough that a leaked
// challenge is worthless by the time it is found.
const challengeTTL = 5 * time.Minute

// Principal is the authenticated identity attached to a request.
type Principal struct {
	UserID  string   `json:"user_id"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	TokenID string   `json:"token_id,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	// SessionID ties an access token to the refresh token it was issued with,
	// so revoking a session kills both. Empty for an API token, which is
	// revoked through its own row instead.
	SessionID string `json:"session_id,omitempty"`
	// SessionExpiry is when the longest-lived token of this session lapses,
	// which is how long a denylist entry has to outlive it.
	SessionExpiry time.Time `json:"-"`
}

// IsAdmin reports whether the principal holds the admin role.
func (p *Principal) IsAdmin() bool { return p != nil && p.Role == store.RoleAdmin }

// CanWrite reports whether the principal may mutate PKI objects.
func (p *Principal) CanWrite() bool {
	return p != nil && (p.Role == store.RoleAdmin || p.Role == store.RoleOperator)
}

// Actor converts a principal into an audit actor.
func (p *Principal) Actor(ip, userAgent string) audit.Actor {
	if p == nil {
		return audit.Actor{Type: store.ActorSystem, IP: ip, UserAgent: userAgent}
	}
	actorType := store.ActorUser
	id := p.UserID
	if p.TokenID != "" {
		actorType = store.ActorToken
		id = p.TokenID
	}
	return audit.Actor{Type: actorType, ID: id, Name: p.Email, IP: ip, UserAgent: userAgent}
}

// TokenPair is what a successful login returns.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	// SessionID and SessionExpiry are what a later sign-out needs to deny this
	// pair. Neither is serialised: the client already holds the tokens that
	// carry them.
	SessionID     string    `json:"-"`
	SessionExpiry time.Time `json:"-"`
}

// Authenticator issues and validates JWTs.
type Authenticator struct {
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewAuthenticator builds an Authenticator from configuration.
func NewAuthenticator(secret []byte, issuer string, accessTTL, refreshTTL time.Duration) *Authenticator {
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	if issuer == "" {
		issuer = "certio"
	}
	return &Authenticator{secret: secret, issuer: issuer, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// Secret exposes the signing key for okapi's JWT middleware.
func (a *Authenticator) Secret() []byte { return a.secret }

// Issuer exposes the configured issuer claim.
func (a *Authenticator) Issuer() string { return a.issuer }

// Issue mints an access/refresh pair for a user, in a fresh session.
func (a *Authenticator) Issue(u *store.User) (*TokenPair, error) {
	return a.IssueForSession(u, uuid.NewString())
}

// IssueForSession mints a pair inside an existing session, which is what a
// refresh does: rotating the tokens without starting a new session means a
// sign-out recorded against that session still ends the whole lineage.
func (a *Authenticator) IssueForSession(u *store.User, sessionID string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(a.accessTTL)
	refreshExpiry := now.Add(a.refreshTTL)

	access, err := a.sign(u, tokenTypeAccess, accessExpiry, now, sessionID)
	if err != nil {
		return nil, err
	}
	refresh, err := a.sign(u, tokenTypeRefresh, refreshExpiry, now, sessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:   access,
		RefreshToken:  refresh,
		TokenType:     "Bearer",
		ExpiresIn:     int(a.accessTTL.Seconds()),
		ExpiresAt:     accessExpiry,
		SessionID:     sessionID,
		SessionExpiry: refreshExpiry,
	}, nil
}

// IssueChallenge mints the short-lived token that stands between a correct
// password and a session. It carries no authority of its own: PrincipalFromClaims
// rejects it, so it can only ever be exchanged at the second-factor endpoint.
func (a *Authenticator) IssueChallenge(u *store.User) (string, time.Duration, error) {
	now := time.Now()
	// A challenge belongs to no session: it cannot authorise anything, and
	// giving it one would let a sign-out race invalidate a login in progress.
	token, err := a.sign(u, tokenTypeChallenge, now.Add(challengeTTL), now, "")
	if err != nil {
		return "", 0, err
	}
	return token, challengeTTL, nil
}

func (a *Authenticator) sign(u *store.User, typ string, expiry, now time.Time, sessionID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   u.ID,
		"email": u.Email,
		"name":  u.Name,
		"role":  u.Role,
		"typ":   typ,
		"iss":   a.issuer,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   expiry.Unix(),
	}
	if sessionID != "" {
		claims["sid"] = sessionID
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	if err != nil {
		return "", fmt.Errorf("sign %s token: %w", typ, err)
	}
	return token, nil
}

// Parse validates a JWT and returns its claims.
func (a *Authenticator) Parse(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return a.secret, nil
	}, jwt.WithIssuer(a.issuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// PrincipalFromClaims converts validated access-token claims into a Principal.
// A refresh token is rejected here: it may only be exchanged, never used to
// authorise a request.
func PrincipalFromClaims(claims jwt.MapClaims) (*Principal, error) {
	if typ, _ := claims["typ"].(string); typ != tokenTypeAccess {
		return nil, errors.New("a refresh token cannot authorise a request")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("token has no subject")
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	role, _ := claims["role"].(string)
	sid, _ := claims["sid"].(string)

	principal := &Principal{UserID: sub, Email: email, Name: name, Role: role, SessionID: sid}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		principal.SessionExpiry = exp.Time
	}
	return principal, nil
}

// LoginResult is the outcome of a sign-in attempt: either a token pair, or —
// when the account carries a second factor — a challenge to exchange for one.
type LoginResult struct {
	Tokens *TokenPair
	User   *store.User

	TwoFactorRequired  bool
	Challenge          string
	ChallengeExpiresIn int

	UsedRecoveryCode       bool
	RecoveryCodesRemaining int
}

// LoginInput carries the credentials of a password sign-in. TOTPCode is empty
// on the first step and set when answering a two-factor challenge.
type LoginInput struct {
	Email    string
	Password string
	TOTPCode string
}

// Login verifies credentials and either issues tokens or, when the account
// carries a second factor, returns a challenge to exchange for them.
func (s *Service) Login(actor audit.Actor, auth *Authenticator, in LoginInput) (*LoginResult, error) {
	user, err := s.Store.Users.GetByEmail(in.Email)
	if err != nil {

		_ = certiocrypto.VerifyPassword(in.Password, dummyHash)
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionLoginFailed, ResourceType: audit.ResourceUser, ResourceName: in.Email,
		}, ErrInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	hash := user.PasswordHash
	if hash == "" {
		hash = dummyHash
	}
	if err := certiocrypto.VerifyPassword(in.Password, hash); err != nil || user.PasswordHash == "" {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionLoginFailed, ResourceType: audit.ResourceUser,
			ResourceID: user.ID, ResourceName: user.Email,
		}, ErrInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive() {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionLoginFailed, ResourceType: audit.ResourceUser,
			ResourceID: user.ID, ResourceName: user.Email,
		}, ErrAccountDisabled)
		return nil, ErrAccountDisabled
	}

	if user.HasTwoFactor() {
		if in.TOTPCode == "" {
			challenge, ttl, err := auth.IssueChallenge(user)
			if err != nil {
				return nil, err
			}
			return &LoginResult{
				User: user, TwoFactorRequired: true,
				Challenge: challenge, ChallengeExpiresIn: int(ttl.Seconds()),
			}, nil
		}
		return s.completeLogin(actor, auth, user, in.TOTPCode)
	}

	return s.completeLogin(actor, auth, user, "")
}

// CompleteTwoFactorLogin exchanges a challenge and a code for a session. The
// code may be a TOTP code or an unspent recovery code.
func (s *Service) CompleteTwoFactorLogin(actor audit.Actor, auth *Authenticator, challenge, code string) (*LoginResult, error) {
	claims, err := auth.Parse(challenge)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if typ, _ := claims["typ"].(string); typ != tokenTypeChallenge {
		return nil, fmt.Errorf("%w: not a two-factor challenge", ErrInvalidCredentials)
	}
	sub, _ := claims["sub"].(string)

	user, err := s.Store.Users.Get(sub)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !user.IsActive() {
		return nil, ErrAccountDisabled
	}

	if !user.HasTwoFactor() {
		return s.completeLogin(actor, auth, user, "")
	}

	return s.completeLogin(actor, auth, user, code)
}

// completeLogin verifies the second factor when there is one and issues the
// token pair.
func (s *Service) completeLogin(actor audit.Actor, auth *Authenticator, user *store.User, code string) (*LoginResult, error) {
	actor.ID, actor.Name, actor.Type = user.ID, user.Email, store.ActorUser

	usedRecovery := false
	if user.HasTwoFactor() {
		var err error
		usedRecovery, err = s.verifySecondFactor(actor, user, code)
		if err != nil {
			return nil, err
		}
	}

	metadata := map[string]any{}
	if user.HasTwoFactor() {
		method := "totp"
		if usedRecovery {
			method = "recovery_code"
		}
		metadata["second_factor"] = method
	}

	result, err := s.issueSession(actor, auth, user, metadata)
	if err != nil {
		return nil, err
	}
	result.UsedRecoveryCode = usedRecovery
	result.RecoveryCodesRemaining = user.RecoveryCodesRemaining()
	return result, nil
}

func (s *Service) issueSession(
	actor audit.Actor, auth *Authenticator, user *store.User, metadata map[string]any,
) (*LoginResult, error) {
	actor.ID, actor.Name, actor.Type = user.ID, user.Email, store.ActorUser

	pair, err := auth.Issue(user)
	if err != nil {
		return nil, err
	}
	if err := s.Store.Users.TouchLogin(user.ID); err != nil {
		s.Log.Warn("could not record the login timestamp", "error", err, "user", user.ID)
	}

	entry := audit.Entry{
		Action: audit.ActionLogin, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
	}
	if len(metadata) > 0 {
		entry.Metadata = metadata
	}
	s.Audit.Record(actor, entry)

	return &LoginResult{Tokens: pair, User: user}, nil
}

// dummyHash is a valid Argon2id hash of a random value, used so a login
// attempt against a non-existent account performs the same work as a real one.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$Y2VydGlzLWR1bW15LXNhbHQ$" +
	"3Xh1QW5vdGhlckR1bW15VmFsdWVGb3JUaW1pbmdTYWZldHk"

// Refresh exchanges a refresh token for a new pair.
func (s *Service) Refresh(auth *Authenticator, refreshToken string) (*TokenPair, *store.User, error) {
	claims, err := auth.Parse(refreshToken)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	if typ, _ := claims["typ"].(string); typ != tokenTypeRefresh {
		return nil, nil, fmt.Errorf("%w: not a refresh token", ErrInvalidCredentials)
	}
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)

	if revoked, err := s.Store.Sessions.IsRevoked(sid, sub); err != nil {
		return nil, nil, err
	} else if revoked {
		return nil, nil, fmt.Errorf("%w: this session has been signed out", ErrInvalidCredentials)
	}

	user, err := s.Store.Users.Get(sub)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	if !user.IsActive() {
		return nil, nil, ErrAccountDisabled
	}

	// The rotated pair stays in the same session, so a later sign-out ends the
	// whole lineage rather than only the token the user happens to hold.
	if sid == "" {
		sid = uuid.NewString()
	}
	pair, err := auth.IssueForSession(user, sid)
	if err != nil {
		return nil, nil, err
	}
	return pair, user, nil
}

// AuthenticateAPIToken resolves a bearer token to a principal.
func (s *Service) AuthenticateAPIToken(raw string) (*Principal, error) {
	token, err := s.Store.Tokens.GetByHash(certiocrypto.HashAPIToken(raw))
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !token.IsUsable() {
		return nil, fmt.Errorf("%w: this API token has expired or been revoked", ErrInvalidCredentials)
	}

	user, err := s.Store.Users.Get(token.UserID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !user.IsActive() {
		return nil, ErrAccountDisabled
	}

	if err := s.Store.Tokens.TouchUsed(token.ID); err != nil {
		s.Log.Warn("could not record API token use", "error", err, "token", token.ID)
	}

	return &Principal{
		UserID: user.ID, Email: user.Email, Name: user.Name, Role: user.Role,
		TokenID: token.ID, Scopes: token.Scopes.Data,
	}, nil
}

// CreateUserInput describes a new account.
type CreateUserInput struct {
	Email    string
	Name     string
	Password string
	Role     string
}

// CreateUser adds an account.
func (s *Service) CreateUser(actor audit.Actor, in CreateUserInput) (*store.User, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, validationError("a valid email address is required")
	}
	if err := validatePassword(in.Password); err != nil {
		return nil, err
	}
	role := defaultString(in.Role, store.RoleViewer)
	if err := validateRole(role); err != nil {
		return nil, err
	}

	hash, err := certiocrypto.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	user := &store.User{
		Email: email, Name: defaultString(in.Name, email),
		PasswordHash: hash, Role: role, Status: store.StatusActive,
	}
	if err := s.Store.Users.Create(user); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionUserCreate, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{"role": role},
	})
	return user, nil
}

// UpdateUserInput carries the mutable fields of an account.
type UpdateUserInput struct {
	Name     *string
	Role     *string
	Status   *string
	Password *string
}

// UpdateUser edits an account, refusing to remove the last admin.
func (s *Service) UpdateUser(actor audit.Actor, id string, in UpdateUserInput) (*store.User, error) {
	user, err := s.Store.Users.Get(id)
	if err != nil {
		return nil, err
	}

	// Demoting or disabling the last admin would lock everyone out of the
	// instance, so it is refused rather than merely warned about.
	losingAdmin := user.Role == store.RoleAdmin &&
		((in.Role != nil && *in.Role != store.RoleAdmin) ||
			(in.Status != nil && *in.Status != store.StatusActive))
	if losingAdmin {
		admins, err := s.Store.Users.CountAdmins()
		if err != nil {
			return nil, err
		}
		if admins <= 1 {
			return nil, validationError("this is the last active administrator; promote another account first")
		}
	}

	if in.Name != nil {
		user.Name = *in.Name
	}
	if in.Role != nil {
		if err := validateRole(*in.Role); err != nil {
			return nil, err
		}
		user.Role = *in.Role
	}
	if in.Status != nil {
		user.Status = *in.Status
	}
	if in.Password != nil {
		if err := validatePassword(*in.Password); err != nil {
			return nil, err
		}
		hash, err := certiocrypto.HashPassword(*in.Password)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = hash
	}

	if err := s.Store.Users.Update(user); err != nil {
		return nil, err
	}

	// A password change, a demotion or a suspension has to end the sessions
	// already open. Otherwise the account someone just locked out keeps
	// working from whatever browser is already signed in, for as long as its
	// refresh token lives.
	endSessions := in.Password != nil ||
		(in.Role != nil && *in.Role != store.RoleAdmin) ||
		(in.Status != nil && *in.Status != store.StatusActive)
	if endSessions {
		if err := s.RevokeAllSessions(user.ID, "account changed"); err != nil {
			s.Log.Error("account updated but its sessions could not be ended",
				"error", err, "user", user.ID)
		}
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionUserUpdate, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{"sessions_ended": endSessions},
	})
	return user, nil
}

// DeleteUser removes an account, refusing to remove the last admin.
func (s *Service) DeleteUser(actor audit.Actor, id string) error {
	user, err := s.Store.Users.Get(id)
	if err != nil {
		return err
	}
	if user.Role == store.RoleAdmin {
		admins, err := s.Store.Users.CountAdmins()
		if err != nil {
			return err
		}
		if admins <= 1 {
			return validationError("this is the last active administrator and cannot be deleted")
		}
	}
	if err := s.Store.Users.Delete(id); err != nil {
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionUserDelete, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
	})
	return nil
}

// CreateTokenInput describes an API token to mint.
type CreateTokenInput struct {
	UserID    string
	Name      string
	Scopes    []string
	ExpiresIn time.Duration
}

// CreateAPIToken mints a token and returns the plaintext exactly once.
func (s *Service) CreateAPIToken(actor audit.Actor, in CreateTokenInput) (*store.APIToken, string, error) {
	if in.Name == "" {
		return nil, "", validationError("a token name is required")
	}
	if _, err := s.Store.Users.Get(in.UserID); err != nil {
		return nil, "", err
	}
	// A typo in a scope would mint a token that looks restrictive and grants
	// nothing, and the mistake would only show up as a 403 in whatever depends
	// on it — so it is rejected here, while someone is still watching.
	if err := ValidateScopes(in.Scopes); err != nil {
		return nil, "", err
	}
	in.Scopes = NormalizeScopes(in.Scopes)

	plaintext, hash, err := certiocrypto.GenerateAPIToken()
	if err != nil {
		return nil, "", err
	}

	token := &store.APIToken{
		UserID: in.UserID, Name: in.Name,
		TokenHash: hash, Prefix: plaintext[:14],
		Scopes: store.JSON(in.Scopes),
	}
	if in.ExpiresIn > 0 {
		expiry := time.Now().Add(in.ExpiresIn).UTC()
		token.ExpiresAt = &expiry
	}
	if err := s.Store.Tokens.Create(token); err != nil {
		return nil, "", err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionTokenIssued, ResourceType: audit.ResourceToken,
		ResourceID: token.ID, ResourceName: token.Name,
		Metadata: map[string]any{"scopes": in.Scopes, "expires_at": token.ExpiresAt},
	})
	return token, plaintext, nil
}

// RevokeAPIToken marks a token unusable.
func (s *Service) RevokeAPIToken(actor audit.Actor, id string) error {
	token, err := s.Store.Tokens.Get(id)
	if err != nil {
		return err
	}
	if err := s.Store.Tokens.Revoke(id); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionTokenRevoked, ResourceType: audit.ResourceToken,
		ResourceID: token.ID, ResourceName: token.Name,
	})
	return nil
}

// NeedsBootstrap reports whether the instance holds no account at all, and so
// still needs its first administrator. Callers use it to decide whether to
// generate a password before calling Bootstrap — asking afterwards would mean
// generating one on every boot and throwing it away.
func (s *Service) NeedsBootstrap() (bool, error) {
	count, err := s.Store.Users.Count()
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// Bootstrap creates the first administrator on an empty instance. It is a
// no-op once any account exists, so restarting the server never resets
// credentials.
func (s *Service) Bootstrap(email, password, name string) (*store.User, error) {
	count, err := s.Store.Users.Count()
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, nil
	}
	if email == "" || password == "" {
		return nil, nil
	}

	user, err := s.CreateUser(audit.SystemActor(), CreateUserInput{
		Email: email, Password: password, Name: name, Role: store.RoleAdmin,
	})
	if err != nil {
		return nil, err
	}
	s.Log.Info("created the initial administrator account", "email", user.Email)
	return user, nil
}

func validateRole(role string) error {
	switch role {
	case store.RoleAdmin, store.RoleOperator, store.RoleViewer:
		return nil
	default:
		return validationError("role must be one of admin, operator or viewer")
	}
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return validationError("password must be at least 12 characters")
	}
	if len(password) > 256 {
		return validationError("password must be at most 256 characters")
	}
	return nil
}

// RevokeSession denies a session so its access and refresh tokens stop working
// before they expire. This is what turns signing out from a cosmetic act into
// a real one.
func (s *Service) RevokeSession(actor audit.Actor, principal *Principal, reason string) error {
	if principal == nil || principal.SessionID == "" {
		// An API token or a session minted before this existed: nothing to
		// deny, and saying so is better than inventing a row.
		return nil
	}
	// The entry has to outlive the longest-lived token of the pair. The access
	// token's own expiry is not enough — the refresh token outlives it, and is
	// precisely what would mint a replacement.
	until := principal.SessionExpiry.Add(s.Config.Security.RefreshTokenTTL)
	if err := s.Store.Sessions.Revoke(principal.SessionID, principal.UserID, reason, until); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionLogout, ResourceType: audit.ResourceUser,
		ResourceID: principal.UserID, ResourceName: principal.Email,
		Metadata: map[string]any{"reason": reason},
	})
	return nil
}

// RevokeAllSessions denies every session a user holds. A password change or a
// two-factor reset calls it: the sessions someone else may already be holding
// are exactly the ones those actions are meant to end.
func (s *Service) RevokeAllSessions(userID, reason string) error {
	until := time.Now().Add(s.Config.Security.RefreshTokenTTL * 2)
	return s.Store.Sessions.RevokeAllForUser(userID, reason, until)
}

// SessionRevoked reports whether a principal's session has been signed out.
func (s *Service) SessionRevoked(principal *Principal) (bool, error) {
	if principal == nil || principal.SessionID == "" {
		return false, nil
	}
	return s.Store.Sessions.IsRevoked(principal.SessionID, principal.UserID)
}
