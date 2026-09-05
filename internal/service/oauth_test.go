package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/store"
)

// fakeIdP stands in for the identity provider. It records what the token
// endpoint was sent, so the tests can assert on PKCE and the redirect URI
// rather than only on the happy-path outcome.
type fakeIdP struct {
	server *httptest.Server

	// userinfo is the document the provider returns. Tests rewrite it to
	// exercise the field mapping and the verified-email guard.
	userinfo map[string]any
	// tokenStatus and tokenBody override the token endpoint's reply when set.
	tokenStatus int
	tokenBody   string
	// requireBasicAuth refuses credentials in the form body, the way some
	// providers do, so the fallback to HTTP Basic is exercised.
	requireBasicAuth bool

	lastTokenForm url.Values
	lastBearer    string
	tokenCalls    int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()

	idp := &fakeIdP{
		userinfo: map[string]any{
			"sub":            "provider-subject-1",
			"email":          "Ada@Example.com",
			"email_verified": true,
			"name":           "Ada Lovelace",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenCalls++
		_ = r.ParseForm()
		idp.lastTokenForm = r.PostForm

		if idp.tokenStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(idp.tokenStatus)
			_, _ = w.Write([]byte(idp.tokenBody))
			return
		}

		_, _, hasBasic := r.BasicAuth()
		if idp.requireBasicAuth && !hasBasic {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"provider-access-token","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		idp.lastBearer = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.userinfo)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// configure saves the fake provider, returning the stored row.
func (f *fakeIdP) configure(t *testing.T, s *Service, mutate func(*OAuthProviderInput)) *store.OAuthProvider {
	t.Helper()

	in := OAuthProviderInput{
		Name:         "keycloak",
		DisplayName:  "Company SSO",
		ClientID:     "certio",
		ClientSecret: "client-secret-value",
		AuthURL:      f.server.URL + "/authorize",
		TokenURL:     f.server.URL + "/token",
		UserInfoURL:  f.server.URL + "/userinfo",
		AllowSignup:  true,
		Enabled:      true,
	}
	if mutate != nil {
		mutate(&in)
	}

	provider, err := s.SaveOAuthProvider(testActor(), in)
	if err != nil {
		t.Fatalf("SaveOAuthProvider: %v", err)
	}
	return provider
}

// signIn runs a full authorize-then-callback round trip and returns the result.
func signIn(t *testing.T, s *Service, auth *Authenticator) (*LoginResult, error) {
	t.Helper()

	authorizeURL, err := s.StartOAuth()
	if err != nil {
		t.Fatalf("StartOAuth: %v", err)
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("the authorize URL carries no state")
	}
	return s.LoginWithOAuth(context.Background(), testActor(), auth, "provider-code", state)
}

func testAuthenticator() *Authenticator {
	return NewAuthenticator([]byte("test-signing-secret"), "certio", time.Hour, 24*time.Hour)
}

func TestOAuthProvisionsAnAccountOnFirstSignIn(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)

	result, err := signIn(t, s, testAuthenticator())
	if err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}
	if result.Tokens == nil || result.Tokens.AccessToken == "" {
		t.Fatal("a successful OAuth sign-in returned no session")
	}

	user := result.User
	if user.Email != "ada@example.com" {
		t.Errorf("email = %q, want it lowercased to ada@example.com", user.Email)
	}
	if user.Name != "Ada Lovelace" {
		t.Errorf("name = %q, want Ada Lovelace", user.Name)
	}
	if user.Role != store.RoleViewer {
		t.Errorf("role = %q, want viewer: an identity provider says who somebody is, not what they may sign", user.Role)
	}
	if user.OAuthProvider != "keycloak" || user.OAuthSubject != "provider-subject-1" {
		t.Errorf("federated identity = %q/%q, want keycloak/provider-subject-1",
			user.OAuthProvider, user.OAuthSubject)
	}
	// No password hash: the provider is the only way in, and that has to be
	// true rather than merely intended.
	if user.HasPassword() {
		t.Error("a provisioned account carries a password hash")
	}
}

func TestOAuthSendsPKCEAndRedirectURI(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)

	authorizeURL, err := s.StartOAuth()
	if err != nil {
		t.Fatalf("StartOAuth: %v", err)
	}
	parsed, _ := url.Parse(authorizeURL)
	query := parsed.Query()

	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	challenge := query.Get("code_challenge")
	if challenge == "" {
		t.Fatal("no code_challenge in the authorize URL")
	}
	if want := s.OAuthRedirectURI(); query.Get("redirect_uri") != want {
		t.Errorf("redirect_uri = %q, want %q", query.Get("redirect_uri"), want)
	}
	if got := query.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want the OIDC defaults", got)
	}

	if _, err := s.LoginWithOAuth(context.Background(), testActor(), testAuthenticator(),
		"provider-code", query.Get("state")); err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}

	// The verifier reaches the provider, never the browser: what the browser
	// saw was its SHA-256 hash.
	verifier := idp.lastTokenForm.Get("code_verifier")
	if verifier == "" {
		t.Fatal("the token request carried no code_verifier")
	}
	if verifier == challenge {
		t.Error("the verifier was sent as the challenge; PKCE is not doing anything")
	}
	if got := idp.lastTokenForm.Get("redirect_uri"); got != s.OAuthRedirectURI() {
		t.Errorf("token redirect_uri = %q, want %q", got, s.OAuthRedirectURI())
	}
}

func TestOAuthStateIsSingleUse(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)
	auth := testAuthenticator()

	authorizeURL, _ := s.StartOAuth()
	parsed, _ := url.Parse(authorizeURL)
	state := parsed.Query().Get("state")

	if _, err := s.LoginWithOAuth(context.Background(), testActor(), auth, "code", state); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	// Replaying the callback must not mint a second session.
	_, err := s.LoginWithOAuth(context.Background(), testActor(), auth, "code", state)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("replayed callback error = %v, want ErrInvalidCredentials", err)
	}
}

func TestOAuthRejectsAnUnknownState(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)

	_, err := s.LoginWithOAuth(context.Background(), testActor(), testAuthenticator(),
		"code", "a-state-nobody-issued")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("error = %v, want ErrInvalidCredentials", err)
	}
	if idp.tokenCalls != 0 {
		t.Error("a forged state reached the token endpoint; the state check is not first")
	}
}

func TestOAuthLinksAnExistingAccountBySubjectThereafter(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)

	existing, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "ada@example.com", Name: "Ada", Password: "a-long-enough-password",
		Role: store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	result, err := signIn(t, s, testAuthenticator())
	if err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}
	if result.User.ID != existing.ID {
		t.Fatal("sign-in created a second account instead of linking the existing one")
	}
	if result.User.Role != store.RoleAdmin {
		t.Errorf("role = %q, want the linked account to keep admin", result.User.Role)
	}

	// The address moves at the provider. The subject is what the account is
	// keyed on, so the same person still lands on the same row.
	idp.userinfo["email"] = "ada.lovelace@example.com"
	result, err = signIn(t, s, testAuthenticator())
	if err != nil {
		t.Fatalf("second LoginWithOAuth: %v", err)
	}
	if result.User.ID != existing.ID {
		t.Error("a renamed address created a new account instead of following the subject")
	}
	if result.User.Email != "ada.lovelace@example.com" {
		t.Errorf("email = %q, want it to follow the directory", result.User.Email)
	}
}

func TestOAuthRefusesToLinkAnUnverifiedAddress(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)
	idp.userinfo["email_verified"] = false

	if _, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "ada@example.com", Password: "a-long-enough-password", Role: store.RoleAdmin,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// This is the takeover path: asserting an administrator's address at a
	// provider that never checked it must not hand over their account.
	_, err := signIn(t, s, testAuthenticator())
	if !errors.Is(err, ErrOAuthDenied) {
		t.Fatalf("error = %v, want ErrOAuthDenied", err)
	}
}

func TestOAuthEnforcesAllowedDomains(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, func(in *OAuthProviderInput) {
		// Written with the "@" a person naturally types.
		in.AllowedDomains = []string{"@jkaninda.dev"}
	})

	if _, err := signIn(t, s, testAuthenticator()); !errors.Is(err, ErrOAuthDenied) {
		t.Fatalf("error = %v, want ErrOAuthDenied for an outside domain", err)
	}

	idp.userinfo["email"] = "ada@jkaninda.dev"
	if _, err := signIn(t, s, testAuthenticator()); err != nil {
		t.Fatalf("an allowed domain was refused: %v", err)
	}
}

func TestOAuthWithoutSignupRefusesAnUnknownIdentity(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, func(in *OAuthProviderInput) { in.AllowSignup = false })

	_, err := signIn(t, s, testAuthenticator())
	if !errors.Is(err, ErrOAuthDenied) {
		t.Fatalf("error = %v, want ErrOAuthDenied", err)
	}

	count, err := s.Store.Users.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("user count = %d, want 0: signup is off", count)
	}
}

func TestOAuthStillOwesTheSecondFactor(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)
	auth := testAuthenticator()

	// First sign-in provisions the account; then it enrols a second factor.
	first, err := signIn(t, s, auth)
	if err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}
	secret, _ := enrolTwoFactor(t, s, first.User.ID)

	second, err := signIn(t, s, auth)
	if err != nil {
		t.Fatalf("second LoginWithOAuth: %v", err)
	}
	if !second.TwoFactorRequired {
		t.Fatal("the provider was allowed to retire the second factor")
	}
	if second.Tokens != nil {
		t.Fatal("a session was issued before the code was entered")
	}

	// The step enrolment confirmed with is already spent, so the code has to
	// come from the next one.
	code, err := certiocrypto.TOTPCode(secret, time.Now().Add(certiocrypto.TOTPPeriod*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	final, err := s.CompleteTwoFactorLogin(testActor(), auth, second.Challenge, code)
	if err != nil {
		t.Fatalf("CompleteTwoFactorLogin: %v", err)
	}
	if final.Tokens == nil {
		t.Fatal("the challenge did not yield a session")
	}
}

func TestOAuthAccountCannotSignInWithAPassword(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)
	auth := testAuthenticator()

	if _, err := signIn(t, s, auth); err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}

	// An empty stored hash must not be a password anybody can guess, and an
	// empty password must not be treated as a match for it.
	for _, password := range []string{"", "anything"} {
		_, err := s.Login(testActor(), auth, LoginInput{Email: "ada@example.com", Password: password})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("password %q: error = %v, want ErrInvalidCredentials", password, err)
		}
	}
}

func TestOAuthFallsBackToBasicAuthAtTheTokenEndpoint(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.requireBasicAuth = true
	idp.configure(t, s, nil)

	if _, err := signIn(t, s, testAuthenticator()); err != nil {
		t.Fatalf("a provider that wants HTTP Basic credentials was not accommodated: %v", err)
	}
	if idp.tokenCalls != 2 {
		t.Errorf("token calls = %d, want 2 (body then Basic)", idp.tokenCalls)
	}
}

func TestOAuthReportsAProviderRejection(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)
	idp.tokenStatus = http.StatusBadRequest
	idp.tokenBody = `{"error":"invalid_grant","error_description":"code already redeemed"}`

	_, err := signIn(t, s, testAuthenticator())
	if err == nil {
		t.Fatal("a rejected code produced no error")
	}
	if !strings.Contains(err.Error(), "code already redeemed") {
		t.Errorf("error = %q, want the provider's description in it", err)
	}
}

func TestOAuthDisabledProviderIsIndistinguishableFromNone(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, func(in *OAuthProviderInput) { in.Enabled = false })

	if _, err := s.StartOAuth(); !errors.Is(err, ErrOAuthNotConfigured) {
		t.Errorf("StartOAuth error = %v, want ErrOAuthNotConfigured", err)
	}
	_, err := s.LoginWithOAuth(context.Background(), testActor(), testAuthenticator(), "code", "state")
	if !errors.Is(err, ErrOAuthNotConfigured) {
		t.Errorf("LoginWithOAuth error = %v, want ErrOAuthNotConfigured", err)
	}
}

func TestSaveOAuthProviderSealsAndKeepsTheSecret(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	saved := idp.configure(t, s, nil)

	if len(saved.ClientSecretEncrypted) == 0 {
		t.Fatal("the client secret was not sealed")
	}
	if strings.Contains(string(saved.ClientSecretEncrypted), "client-secret-value") {
		t.Fatal("the client secret is recoverable from the stored ciphertext")
	}

	// A re-save that leaves the secret blank keeps the stored one, which is
	// the only way to edit the other fields from a form that cannot show it.
	updated, err := s.SaveOAuthProvider(testActor(), OAuthProviderInput{
		Name: "keycloak", ClientID: "certio", DisplayName: "Renamed SSO",
		AuthURL: saved.AuthURL, TokenURL: saved.TokenURL, UserInfoURL: saved.UserInfoURL,
		AllowSignup: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("SaveOAuthProvider: %v", err)
	}
	if updated.DisplayName != "Renamed SSO" {
		t.Errorf("display name = %q, want Renamed SSO", updated.DisplayName)
	}

	opened, err := s.Keyring.OpenString(certiocrypto.Envelope{
		Ciphertext: updated.ClientSecretEncrypted,
		Nonce:      updated.ClientSecretNonce,
		Salt:       updated.ClientSecretSalt,
	}, "")
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if opened != "client-secret-value" {
		t.Errorf("secret = %q, want the original to have been kept", opened)
	}

	// And there is still exactly one provider.
	if _, err := s.Store.OAuth.Get(); err != nil {
		t.Fatalf("OAuth.Get: %v", err)
	}
	var count int64
	if err := s.Store.DB().Model(&store.OAuthProvider{}).Count(&count).Error; err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if count != 1 {
		t.Errorf("provider rows = %d, want 1", count)
	}
}

func TestSaveOAuthProviderValidates(t *testing.T) {
	s := newTestService(t)
	base := OAuthProviderInput{
		Name: "keycloak", ClientID: "certio", ClientSecret: "secret",
		AuthURL:     "https://idp.example.com/authorize",
		TokenURL:    "https://idp.example.com/token",
		UserInfoURL: "https://idp.example.com/userinfo",
	}

	cases := map[string]func(*OAuthProviderInput){
		"no name":            func(in *OAuthProviderInput) { in.Name = "" },
		"no client id":       func(in *OAuthProviderInput) { in.ClientID = "" },
		"no secret":          func(in *OAuthProviderInput) { in.ClientSecret = "" },
		"relative token URL": func(in *OAuthProviderInput) { in.TokenURL = "/token" },
		"unknown role":       func(in *OAuthProviderInput) { in.DefaultRole = "superuser" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			mutate(&in)
			if _, err := s.SaveOAuthProvider(testActor(), in); !errors.Is(err, ErrValidation) {
				t.Errorf("error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestOAuthFieldMappingReadsNestedAndNumericValues(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	// A provider that wraps its answer and numbers its users — GitHub does the
	// latter, and a dotted path handles the former.
	idp.userinfo = map[string]any{
		"data": map[string]any{
			"id":       float64(4815162342),
			"mail":     "grace@example.com",
			"fullName": "Grace Hopper",
		},
	}
	idp.configure(t, s, func(in *OAuthProviderInput) {
		in.SubjectField = "data.id"
		in.EmailField = "data.mail"
		in.NameField = "data.fullName"
	})

	result, err := signIn(t, s, testAuthenticator())
	if err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}
	if result.User.OAuthSubject != "4815162342" {
		t.Errorf("subject = %q, want 4815162342 without a decimal point", result.User.OAuthSubject)
	}
	if result.User.Email != "grace@example.com" || result.User.Name != "Grace Hopper" {
		t.Errorf("profile = %q/%q, want the nested values",
			result.User.Email, result.User.Name)
	}
}

func TestDeleteOAuthProviderKeepsProvisionedAccounts(t *testing.T) {
	s := newTestService(t)
	idp := newFakeIdP(t)
	idp.configure(t, s, nil)

	if _, err := signIn(t, s, testAuthenticator()); err != nil {
		t.Fatalf("LoginWithOAuth: %v", err)
	}
	if err := s.DeleteOAuthProvider(testActor()); err != nil {
		t.Fatalf("DeleteOAuthProvider: %v", err)
	}

	if _, err := s.OAuthProvider(); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("OAuthProvider error = %v, want ErrNotFound", err)
	}
	if _, err := s.Store.Users.GetByEmail("ada@example.com"); err != nil {
		t.Errorf("the provisioned account went with the configuration: %v", err)
	}
}
