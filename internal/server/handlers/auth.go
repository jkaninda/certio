package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/server/middleware"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// Login exchanges credentials for a token pair, or for a two-factor challenge
// when the account carries a second factor.
func (h *Handler) Login(c *okapi.Context, req *dto.LoginRequest) error {
	result, err := h.Service.Login(h.actor(c), h.Auth, service.LoginInput{
		Email: req.Body.Email, Password: req.Body.Password, TOTPCode: req.Body.TOTPCode,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return h.loginReply(c, result)
}

// VerifyTwoFactor exchanges a login challenge and a code for a session.
func (h *Handler) VerifyTwoFactor(c *okapi.Context, req *dto.TwoFactorVerifyRequest) error {
	result, err := h.Service.CompleteTwoFactorLogin(h.actor(c), h.Auth,
		req.Body.ChallengeToken, req.Body.Code)
	if err != nil {
		return h.fail(c, err)
	}
	return h.loginReply(c, result)
}

// loginReply writes the outcome of a sign-in attempt, setting the session
// cookie only once a session actually exists — a pending challenge must not
// leave anything behind that looks like one.
func (h *Handler) loginReply(c *okapi.Context, result *service.LoginResult) error {
	if !result.TwoFactorRequired {
		h.setSessionCookie(c, result.Tokens.AccessToken, h.Config.Security.AccessTokenTTL)
	}
	return c.OK(dto.NewLoginResponse(result))
}

// Refresh exchanges a refresh token for a new pair.
func (h *Handler) Refresh(c *okapi.Context, req *dto.RefreshRequest) error {
	pair, user, err := h.Service.Refresh(h.Auth, req.Body.RefreshToken)
	if err != nil {
		return h.fail(c, err)
	}

	h.setSessionCookie(c, pair.AccessToken, h.Config.Security.AccessTokenTTL)
	return c.OK(dto.TokenResponse{
		AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken,
		TokenType: pair.TokenType, ExpiresIn: pair.ExpiresIn, ExpiresAt: pair.ExpiresAt,
		User: dto.NewUserResponse(user),
	})
}

// Logout clears the session cookie. The JWT itself stays valid until it
// expires — Certio does not keep a denylist, which is the usual trade for
// stateless tokens with a short lifetime.
func (h *Handler) Logout(c *okapi.Context) error {
	// The route is unauthenticated — signing out must work even with an
	// expiring token — so the principal is read from the credential directly
	// rather than from the middleware that did not run here.
	if principal := h.principalFromCredential(c); principal != nil {
		if err := h.Service.RevokeSession(h.actor(c), principal, "signed out"); err != nil {
			// The cookie is still cleared: telling someone their sign-out
			// failed while leaving them signed in is the worst of both.
			h.Service.Log.Error("could not deny the session on sign-out",
				"error", err, "user", principal.UserID)
		}
	}
	h.setSessionCookie(c, "", -time.Second)
	return c.OK(dto.MessageResponse{Message: "signed out"})
}

// principalFromCredential reads the caller's identity off the request without
// requiring the auth middleware. It returns nil for anything it cannot read:
// an unparseable token means there is no session to end.
func (h *Handler) principalFromCredential(c *okapi.Context) *service.Principal {
	if principal := middleware.PrincipalOf(c); principal != nil {
		return principal
	}
	raw := c.Header("Authorization")
	if after, ok := strings.CutPrefix(raw, "Bearer "); ok {
		raw = after
	}
	if raw == "" {
		if cookie, err := c.Cookie("certio_token"); err == nil {
			raw = cookie
		}
	}
	if raw = strings.TrimSpace(raw); raw == "" {
		return nil
	}

	claims, err := h.Auth.Parse(raw)
	if err != nil {
		return nil
	}
	principal, err := service.PrincipalFromClaims(claims)
	if err != nil {
		return nil
	}
	return principal
}

// Me returns the authenticated account.
func (h *Handler) Me(c *okapi.Context) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}
	user, err := h.Service.Store.Users.Get(principal.UserID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewUserResponse(user))
}

// setSessionCookie mirrors the access token into an HttpOnly cookie so the SPA
// survives a page reload without putting the token in localStorage.
func (h *Handler) setSessionCookie(c *okapi.Context, token string, ttl time.Duration) {
	secure := h.Config.Production || h.Config.Server.TLSCert != ""
	c.SetCookie("certio_token", token, int(ttl.Seconds()), "/", "", secure, true)
}

// ListUsers returns a page of accounts.
func (h *Handler) ListUsers(c *okapi.Context, req *dto.ListUsersRequest) error {
	p := page(req.Page, req.Limit)
	result, err := h.Service.Store.Users.List(p)
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.UserResponse, 0, len(result.Items))
	for i := range result.Items {
		items = append(items, dto.NewUserResponse(&result.Items[i]))
	}
	return c.OK(dto.UserListResponse{
		Items: items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// CreateUser adds an account.
func (h *Handler) CreateUser(c *okapi.Context, req *dto.CreateUserRequest) error {
	user, err := h.Service.CreateUser(h.actor(c), service.CreateUserInput{
		Email: req.Body.Email, Name: req.Body.Name,
		Password: req.Body.Password, Role: req.Body.Role,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.NewUserResponse(user))
}

// GetUser returns one account.
func (h *Handler) GetUser(c *okapi.Context, req *dto.UserRefRequest) error {
	user, err := h.Service.Store.Users.Get(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewUserResponse(user))
}

// UpdateUser edits an account.
func (h *Handler) UpdateUser(c *okapi.Context, req *dto.UpdateUserRequest) error {
	user, err := h.Service.UpdateUser(h.actor(c), req.ID, service.UpdateUserInput{
		Name: req.Body.Name, Role: req.Body.Role,
		Status: req.Body.Status, Password: req.Body.Password,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewUserResponse(user))
}

// DeleteUser removes an account.
func (h *Handler) DeleteUser(c *okapi.Context, req *dto.UserRefRequest) error {
	principal := middleware.PrincipalOf(c)
	if principal != nil && principal.UserID == req.ID {
		return c.AbortWithJSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "validation_failed", Message: "you cannot delete your own account",
		})
	}
	if err := h.Service.DeleteUser(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "account deleted"})
}

// ListTokens returns API tokens: an admin sees every token, anyone else sees
// only their own.
func (h *Handler) ListTokens(c *okapi.Context) error {
	principal := middleware.PrincipalOf(c)

	var (
		tokens []store.APIToken
		err    error
	)
	if principal.IsAdmin() {
		tokens, err = h.Service.Store.Tokens.All()
	} else {
		tokens, err = h.Service.Store.Tokens.ByUser(principal.UserID)
	}
	if err != nil {
		return h.fail(c, err)
	}

	items := make([]dto.TokenResponseItem, 0, len(tokens))
	for i := range tokens {
		items = append(items, dto.NewTokenResponseItem(&tokens[i]))
	}
	return c.OK(dto.TokenListResponse{Items: items, Total: len(items)})
}

// CreateToken mints an API token and returns the plaintext once.
func (h *Handler) CreateToken(c *okapi.Context, req *dto.CreateTokenRequest) error {
	principal := middleware.PrincipalOf(c)
	userID := req.Body.UserID
	// Minting a token for someone else is an admin action: the token inherits
	// that user's role, so it is a privilege grant.
	if userID == "" || (!principal.IsAdmin() && userID != principal.UserID) {
		userID = principal.UserID
	}

	var expiresIn time.Duration
	if req.Body.ExpiresIn != "" {
		d, err := time.ParseDuration(req.Body.ExpiresIn)
		if err != nil {
			return badRequest(c, err)
		}
		expiresIn = d
	}

	token, plaintext, err := h.Service.CreateAPIToken(h.actor(c), service.CreateTokenInput{
		UserID: userID, Name: req.Body.Name, Scopes: req.Body.Scopes, ExpiresIn: expiresIn,
	})
	if err != nil {
		return h.fail(c, err)
	}

	return c.Created(dto.CreateTokenResponse{
		Token:          dto.NewTokenResponseItem(token),
		PlaintextToken: plaintext,
		Warning:        "This is the only time the token is shown. Store it now — it cannot be recovered.",
	})
}

// RevokeToken makes an API token unusable.
func (h *Handler) RevokeToken(c *okapi.Context, req *dto.TokenRefRequest) error {
	principal := middleware.PrincipalOf(c)
	token, err := h.Service.Store.Tokens.Get(req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	if !principal.IsAdmin() && token.UserID != principal.UserID {
		return c.AbortWithJSON(http.StatusForbidden, dto.ErrorResponse{
			Error: "forbidden", Message: "you can only revoke your own API tokens",
		})
	}

	if err := h.Service.RevokeAPIToken(h.actor(c), token.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "token revoked"})
}
