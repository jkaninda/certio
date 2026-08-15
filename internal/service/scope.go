package service

import (
	"fmt"
	"sort"
	"strings"
)

// Scopes narrow what an API token may do, below whatever its owner's role
// already allows. They are a second gate, never a first one: a token held by a
// viewer does not become able to issue certificates by asking for
// certificates:write.
//
// A scope is "<resource>:<action>". Two wildcards are understood — "*" for
// everything and "<resource>:*" for both actions on one resource — because a
// CI token that legitimately needs the whole certificate surface should not
// have to enumerate it.
const (
	ScopeAll = "*"

	ScopeAuthoritiesRead  = "authorities:read"
	ScopeAuthoritiesWrite = "authorities:write"

	ScopeCertificatesRead  = "certificates:read"
	ScopeCertificatesWrite = "certificates:write"

	ScopeDeploymentsRead  = "deployments:read"
	ScopeDeploymentsWrite = "deployments:write"

	ScopeNotificationsRead  = "notifications:read"
	ScopeNotificationsWrite = "notifications:write"

	ScopeUsersRead  = "users:read"
	ScopeUsersWrite = "users:write"

	ScopeTokensRead  = "tokens:read"
	ScopeTokensWrite = "tokens:write"

	ScopeAuditRead = "audit:read"

	ScopeSettingsRead  = "settings:read"
	ScopeSettingsWrite = "settings:write"
)

// scopeCatalog is every scope a token may hold, with the sentence the settings
// UI shows next to its checkbox.
var scopeCatalog = []struct {
	Name        string
	Description string
}{
	{ScopeAll, "Everything this account's role allows."},
	{ScopeAuthoritiesRead, "List and inspect certificate authorities."},
	{ScopeAuthoritiesWrite, "Create, edit, renew and delete authorities, and republish CRLs."},
	{ScopeCertificatesRead, "List, inspect and download certificates."},
	{ScopeCertificatesWrite, "Issue, sign, renew, revoke and delete certificates."},
	{ScopeDeploymentsRead, "List deployment targets and their delivery history."},
	{ScopeDeploymentsWrite, "Create, edit, delete and trigger deployment targets."},
	{ScopeNotificationsRead, "List notification channels."},
	{ScopeNotificationsWrite, "Create, edit, test and delete notification channels."},
	{ScopeUsersRead, "List accounts."},
	{ScopeUsersWrite, "Create, edit and delete accounts."},
	{ScopeTokensRead, "List API tokens."},
	{ScopeTokensWrite, "Create and revoke API tokens."},
	{ScopeAuditRead, "Read the audit log."},
	{ScopeSettingsRead, "Read instance settings."},
	{ScopeSettingsWrite, "Change instance settings."},
}

// ScopeInfo describes one scope for the API's reference-data endpoint.
type ScopeInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Scopes lists every scope a token may be granted, in presentation order.
func Scopes() []ScopeInfo {
	out := make([]ScopeInfo, 0, len(scopeCatalog))
	for _, s := range scopeCatalog {
		out = append(out, ScopeInfo{Name: s.Name, Description: s.Description})
	}
	return out
}

// scopeNames is the lookup set behind ValidateScopes.
var scopeNames = func() map[string]bool {
	m := make(map[string]bool, len(scopeCatalog)*2)
	for _, s := range scopeCatalog {
		m[s.Name] = true
		if resource, _, ok := strings.Cut(s.Name, ":"); ok {
			m[resource+":*"] = true
		}
	}
	return m
}()

// ValidateScopes rejects a scope the server does not know. A token minted with
// a typo would otherwise look restrictive while granting nothing, and the
// mistake would only surface as a 403 in whatever automation depends on it.
func ValidateScopes(scopes []string) error {
	for _, raw := range scopes {
		scope := strings.ToLower(strings.TrimSpace(raw))
		if scope == "" {
			continue
		}
		if !scopeNames[scope] {
			return validationError("unknown scope %q (see /api/v1/meta for the list)", raw)
		}
	}
	return nil
}

// NormalizeScopes lowercases, trims, de-duplicates and sorts a scope list so
// two tokens granting the same access compare equal in the audit log.
func NormalizeScopes(scopes []string) []string {
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		scope := strings.ToLower(strings.TrimSpace(raw))
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	// "*" subsumes everything else; keeping the rest would imply a narrowing
	// that is not there.
	if seen[ScopeAll] {
		return []string{ScopeAll}
	}
	sort.Strings(out)
	return out
}

// HasScope reports whether the principal may perform an action.
//
// A session (a signed-in human) carries no scopes and is bounded by its role
// alone. An API token with an empty scope list is unrestricted too: tokens
// minted before scopes were enforced must keep working, and a token that
// silently lost access on upgrade would be a worse failure than a broad one.
// The UI grants explicit scopes by default so new tokens are narrow.
func (p *Principal) HasScope(required string) bool {
	if p == nil {
		return false
	}
	if p.TokenID == "" || len(p.Scopes) == 0 {
		return true
	}

	resource, action, _ := strings.Cut(required, ":")
	for _, granted := range p.Scopes {
		switch strings.ToLower(strings.TrimSpace(granted)) {
		case ScopeAll, required, resource + ":*":
			return true
		case resource + ":write":
			// Write implies read. Nobody grants certificates:write meaning
			// "may issue but may not list", and forcing both to be selected
			// only trains people to tick every box.
			if action == "read" {
				return true
			}
		}
	}
	return false
}

// ScopeError is the message a 403 carries when a token is too narrow. It names
// the missing scope so the fix is to re-mint the token, not to guess.
func ScopeError(required string) string {
	return fmt.Sprintf("this API token is missing the %q scope", required)
}
