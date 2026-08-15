// Package middleware holds the HTTP concerns that wrap every request:
// authentication, role checks and rate limiting.
package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// PrincipalKey is the context key under which the authenticated identity is
// stored for handlers to read.
const PrincipalKey = "certio.principal"

// Auth authenticates a request from either a JWT or an API token. Both arrive
// as `Authorization: Bearer <value>`; a Certio API token is recognised by its
// `certio_` prefix, and anything else is treated as a JWT.
func Auth(svc *service.Service, auth *service.Authenticator) okapi.Middleware {
	return func(c *okapi.Context) error {
		raw := bearerToken(c)
		if raw == "" {
			return unauthorized(c, "authentication required")
		}

		principal, err := resolve(svc, auth, raw)
		if err != nil {
			return unauthorized(c, err.Error())
		}

		// A JWT is valid until it expires no matter what has happened since,
		// so signing out only means anything if every request checks. The
		// lookup is a single indexed read and only runs for sessions — an API
		// token has already been checked against its own row.
		if revoked, err := svc.SessionRevoked(principal); err != nil {
			svc.Log.Error("could not check the session denylist", "error", err)
			return c.AbortWithJSON(http.StatusServiceUnavailable, dto.ErrorResponse{
				Error:   "unavailable",
				Message: "could not verify the session; please retry",
			})
		} else if revoked {
			return unauthorized(c, "this session has been signed out")
		}

		c.Set(PrincipalKey, principal)
		return c.Next()
	}
}

// resolve turns a bearer value into a Principal.
func resolve(svc *service.Service, auth *service.Authenticator, raw string) (*service.Principal, error) {
	if strings.HasPrefix(raw, "certio_") {
		return svc.AuthenticateAPIToken(raw)
	}
	claims, err := auth.Parse(raw)
	if err != nil {
		return nil, service.ErrInvalidCredentials
	}
	return service.PrincipalFromClaims(claims)
}

// bearerToken extracts the credential from the Authorization header, falling
// back to a cookie so the SPA can rely on the browser to carry it.
func bearerToken(c *okapi.Context) string {
	header := c.Header("Authorization")
	if header != "" {
		if after, ok := strings.CutPrefix(header, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return strings.TrimSpace(header)
	}
	if cookie, err := c.Cookie("certio_token"); err == nil {
		return cookie
	}
	return ""
}

// PrincipalOf returns the authenticated identity, or nil on an unauthenticated
// route.
func PrincipalOf(c *okapi.Context) *service.Principal {
	value, ok := c.Get(PrincipalKey)
	if !ok {
		return nil
	}
	principal, _ := value.(*service.Principal)
	return principal
}

// RequireRole rejects a request whose principal does not hold one of the
// listed roles.
func RequireRole(roles ...string) okapi.Middleware {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}

	return func(c *okapi.Context) error {
		principal := PrincipalOf(c)
		if principal == nil {
			return unauthorized(c, "authentication required")
		}
		if !allowed[principal.Role] {
			return c.AbortWithJSON(http.StatusForbidden, dto.ErrorResponse{
				Error: "forbidden",
				Message: "this action requires the " + strings.Join(roles, " or ") +
					" role; your account is " + principal.Role,
			})
		}
		return c.Next()
	}
}

// RequireWrite allows admins and operators — everyone who may change PKI
// state. It is the guard on every mutating certificate route.
func RequireWrite() okapi.Middleware {
	return RequireRole(store.RoleAdmin, store.RoleOperator)
}

// RequireAdmin allows admins only.
func RequireAdmin() okapi.Middleware {
	return RequireRole(store.RoleAdmin)
}

// RequireScope rejects a request whose API token was not granted the scope the
// route needs. It is a second gate below RequireRole, not a replacement for
// it: a viewer's token holding certificates:write still cannot issue anything,
// because the role check runs too.
//
// A signed-in session is unaffected — scopes only ever narrow a token.
func RequireScope(scope string) okapi.Middleware {
	return func(c *okapi.Context) error {
		principal := PrincipalOf(c)
		if principal == nil {
			return unauthorized(c, "authentication required")
		}
		if !principal.HasScope(scope) {
			return c.AbortWithJSON(http.StatusForbidden, dto.ErrorResponse{
				Error:   "insufficient_scope",
				Message: service.ScopeError(scope),
			})
		}
		return c.Next()
	}
}

// Guard composes the role and scope checks a route needs into the one slice a
// RouteDefinition carries, so a route states its requirements once.
func Guard(role okapi.Middleware, scope string) []okapi.Middleware {
	if role == nil {
		return []okapi.Middleware{RequireScope(scope)}
	}
	return []okapi.Middleware{role, RequireScope(scope)}
}

// Read builds the guard for a read-only route: no role restriction (every
// signed-in account may look), but a token still needs the scope.
func Read(scope string) []okapi.Middleware { return Guard(nil, scope) }

// Write builds the guard for a mutating route.
func Write(scope string) []okapi.Middleware { return Guard(RequireWrite(), scope) }

// Admin builds the guard for an administrator-only route.
func Admin(scope string) []okapi.Middleware { return Guard(RequireAdmin(), scope) }

// RateLimiter is a fixed-window limiter keyed by client IP. It is deliberately
// in-process: Certio is a single binary, and a shared limiter would mean a
// Redis dependency for a feature that only needs to slow down credential
// stuffing against one instance.
type RateLimiter struct {
	mu     sync.Mutex
	hits   map[string]*window
	limit  int
	window time.Duration
	lastGC time.Time
}

type window struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter builds a limiter allowing limit requests per window.
func NewRateLimiter(limit int, per time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if per <= 0 {
		per = time.Minute
	}
	return &RateLimiter{hits: make(map[string]*window), limit: limit, window: per, lastGC: time.Now()}
}

// Allow reports whether a key may proceed, and how long until it may retry.
func (r *RateLimiter) Allow(key string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.collect(now)

	w, ok := r.hits[key]
	if !ok || now.After(w.resetAt) {
		r.hits[key] = &window{count: 1, resetAt: now.Add(r.window)}
		return true, 0
	}

	w.count++
	if w.count > r.limit {
		return false, time.Until(w.resetAt)
	}
	return true, 0
}

// collect drops expired windows so the map cannot grow without bound. It runs
// at most once per window, under the lock the caller already holds.
func (r *RateLimiter) collect(now time.Time) {
	if now.Sub(r.lastGC) < r.window {
		return
	}
	for key, w := range r.hits {
		if now.After(w.resetAt) {
			delete(r.hits, key)
		}
	}
	r.lastGC = now
}

// Middleware applies the limiter to a route, keyed by client IP.
func (r *RateLimiter) Middleware() okapi.Middleware {
	return r.keyed(func(c *okapi.Context) string { return c.RealIP() })
}

// PerPrincipal applies the limiter keyed by the authenticated identity, with
// the client IP as the fallback. Two CI jobs behind one NAT gateway should not
// share a budget, and one token looping should not be masked by the address it
// happens to come from.
func (r *RateLimiter) PerPrincipal() okapi.Middleware {
	return r.keyed(func(c *okapi.Context) string {
		principal := PrincipalOf(c)
		switch {
		case principal == nil:
			return c.RealIP()
		case principal.TokenID != "":
			return "token:" + principal.TokenID
		default:
			return "user:" + principal.UserID
		}
	})
}

func (r *RateLimiter) keyed(key func(*okapi.Context) string) okapi.Middleware {
	return func(c *okapi.Context) error {
		allowed, retryAfter := r.Allow(key(c))
		if !allowed {
			c.SetHeader("Retry-After", formatSeconds(retryAfter))
			return c.AbortWithJSON(http.StatusTooManyRequests, dto.ErrorResponse{
				Error:   "rate_limited",
				Message: "too many requests; please wait " + formatSeconds(retryAfter) + " seconds",
			})
		}
		return c.Next()
	}
}

func formatSeconds(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return itoa(seconds)
}

// itoa avoids pulling strconv in for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// SecurityHeaders sets the response headers that make sense for an app that
// serves both an API and an embedded SPA.
//
// The policy arrives as a function rather than a string: it depends on hashes
// of the dashboard's and the docs page's inline scripts, and the latter cannot
// be computed until the routes exist. An empty policy omits the header, which
// is what a caller with nothing to protect should get.
func SecurityHeaders(policy func() string) okapi.Middleware {
	return func(c *okapi.Context) error {
		c.SetHeader("X-Content-Type-Options", "nosniff")
		c.SetHeader("X-Frame-Options", "DENY")
		c.SetHeader("Referrer-Policy", "no-referrer")
		if value := policy(); value != "" {
			c.SetHeader("Content-Security-Policy", value)
		}
		// A private PKI dashboard has no business appearing in a search
		// index, even if it is reachable from the internet.
		c.SetHeader("X-Robots-Tag", "noindex, nofollow")
		return c.Next()
	}
}

func unauthorized(c *okapi.Context, message string) error {
	c.SetHeader("WWW-Authenticate", `Bearer realm="certio"`)
	return c.AbortWithJSON(http.StatusUnauthorized, dto.ErrorResponse{
		Error: "unauthorized", Message: message,
	})
}
