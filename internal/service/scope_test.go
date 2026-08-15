package service

import (
	"reflect"
	"testing"
)

// TestHasScope covers the matching rules a token is judged by.
func TestHasScope(t *testing.T) {
	cases := []struct {
		name      string
		principal *Principal
		required  string
		want      bool
	}{
		{
			name:      "a session is bounded by its role, not by scopes",
			principal: &Principal{Role: "admin"},
			required:  ScopeCertificatesWrite,
			want:      true,
		},
		{
			name:      "a token with no scopes keeps working",
			principal: &Principal{TokenID: "t1"},
			required:  ScopeCertificatesWrite,
			want:      true,
		},
		{
			name:      "an exact grant matches",
			principal: &Principal{TokenID: "t1", Scopes: []string{ScopeCertificatesRead}},
			required:  ScopeCertificatesRead,
			want:      true,
		},
		{
			name:      "a read grant does not imply write",
			principal: &Principal{TokenID: "t1", Scopes: []string{ScopeCertificatesRead}},
			required:  ScopeCertificatesWrite,
			want:      false,
		},
		{
			name:      "a write grant implies read",
			principal: &Principal{TokenID: "t1", Scopes: []string{ScopeCertificatesWrite}},
			required:  ScopeCertificatesRead,
			want:      true,
		},
		{
			name:      "a resource wildcard covers both actions",
			principal: &Principal{TokenID: "t1", Scopes: []string{"certificates:*"}},
			required:  ScopeCertificatesWrite,
			want:      true,
		},
		{
			name:      "a resource grant does not leak into another resource",
			principal: &Principal{TokenID: "t1", Scopes: []string{"certificates:*"}},
			required:  ScopeAuthoritiesRead,
			want:      false,
		},
		{
			name:      "the global wildcard covers everything",
			principal: &Principal{TokenID: "t1", Scopes: []string{ScopeAll}},
			required:  ScopeUsersWrite,
			want:      true,
		},
		{
			name:      "a nil principal is never authorised",
			principal: nil,
			required:  ScopeCertificatesRead,
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.principal.HasScope(tc.required); got != tc.want {
				t.Errorf("HasScope(%q) = %v, want %v", tc.required, got, tc.want)
			}
		})
	}
}

// TestValidateScopes checks that a mistyped scope is refused at mint time.
func TestValidateScopes(t *testing.T) {
	if err := ValidateScopes([]string{ScopeCertificatesRead, "authorities:*", ScopeAll}); err != nil {
		t.Fatalf("ValidateScopes rejected a valid list: %v", err)
	}
	if err := ValidateScopes([]string{"certificate:read"}); err == nil {
		t.Error("ValidateScopes accepted a mistyped resource")
	}
	if err := ValidateScopes([]string{"certificates:delete"}); err == nil {
		t.Error("ValidateScopes accepted an unknown action")
	}
}

// TestNormalizeScopes checks de-duplication, ordering, and that the global
// wildcard collapses the rest.
func TestNormalizeScopes(t *testing.T) {
	got := NormalizeScopes([]string{" Certificates:Read ", "certificates:read", "authorities:read", ""})
	want := []string{ScopeAuthoritiesRead, ScopeCertificatesRead}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NormalizeScopes = %v, want %v", got, want)
	}

	if got := NormalizeScopes([]string{ScopeCertificatesRead, ScopeAll}); !reflect.DeepEqual(got, []string{ScopeAll}) {
		t.Errorf("NormalizeScopes with a wildcard = %v, want [*]", got)
	}
}
