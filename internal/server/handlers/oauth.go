package handlers

import (
	"errors"
	"net/http"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// OAuthStatus tells the sign-in page whether to offer single sign-on.
//
// It is unauthenticated, because the page that needs it is the one nobody has
// signed in to yet, and it says only whether federation is on and what to
// write on the button. The endpoints and the client id are not secret — the
// browser is handed them a moment later on the way to the provider — but there
// is no reason to publish them to somebody who never presses the button.
func (h *Handler) OAuthStatus(c *okapi.Context) error {
	provider, err := h.Service.OAuthProvider()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return c.OK(dto.OAuthStatusResponse{Enabled: false})
		}
		return h.fail(c, err)
	}
	if !provider.Enabled {
		return c.OK(dto.OAuthStatusResponse{Enabled: false})
	}

	return c.OK(dto.OAuthStatusResponse{
		Enabled:  true,
		Name:     provider.Name,
		Label:    provider.Label(),
		StartURL: "/api/v1/auth/oauth/authorize",
	})
}

// OAuthAuthorize sends the browser to the provider's authorization page.
//
// The redirect is built here rather than in the dashboard so the CSRF state
// and the PKCE verifier never exist in JavaScript: the browser carries only
// the state and a hash of the verifier, and an authorization code intercepted
// on the way back cannot be exchanged by whoever intercepted it.
func (h *Handler) OAuthAuthorize(c *okapi.Context) error {
	target, err := h.Service.StartOAuth()
	if err != nil {
		return h.fail(c, err)
	}
	c.Redirect(http.StatusFound, target)
	return nil
}

// OAuthCallback exchanges the provider's authorization code for a session.
func (h *Handler) OAuthCallback(c *okapi.Context, req *dto.OAuthCallbackRequest) error {
	result, err := h.Service.LoginWithOAuth(c.Request().Context(), h.actor(c), h.Auth,
		req.Body.Code, req.Body.State)
	if err != nil {
		return h.fail(c, err)
	}
	return h.loginReply(c, result)
}

// GetOAuthProvider returns the administrator's view of the configuration,
// never the client secret.
func (h *Handler) GetOAuthProvider(c *okapi.Context) error {
	provider, err := h.Service.OAuthProvider()
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewOAuthProviderResponse(provider, h.Service.OAuthRedirectURI()))
}

func (h *Handler) SaveOAuthProvider(c *okapi.Context, req *dto.SaveOAuthProviderRequest) error {
	in := req.Body
	provider, err := h.Service.SaveOAuthProvider(h.actor(c), service.OAuthProviderInput{
		Name:           in.Name,
		DisplayName:    in.DisplayName,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		AuthURL:        in.AuthURL,
		TokenURL:       in.TokenURL,
		UserInfoURL:    in.UserInfoURL,
		Scopes:         in.Scopes,
		SubjectField:   in.SubjectField,
		EmailField:     in.EmailField,
		NameField:      in.NameField,
		AllowedDomains: in.AllowedDomains,
		AllowSignup:    in.AllowSignup,
		DefaultRole:    in.DefaultRole,
		Enabled:        in.Enabled,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewOAuthProviderResponse(provider, h.Service.OAuthRedirectURI()))
}

func (h *Handler) DeleteOAuthProvider(c *okapi.Context) error {
	if err := h.Service.DeleteOAuthProvider(h.actor(c)); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "single sign-on removed"})
}
