package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	certiocrypto "github.com/jkaninda/certio/internal/crypto"
)

// enrol takes the seeded admin through the HTTP enrolment flow and returns the
// raw secret plus the recovery codes.
func (h *harness) enrol() (secret string, recovery []string) {
	h.t.Helper()

	status, body := h.do(http.MethodPost, "/api/v1/auth/2fa/setup", h.adminTk, nil)
	if status != http.StatusOK {
		h.t.Fatalf("POST /auth/2fa/setup: status %d, body %v", status, body)
	}
	secret = strings.ReplaceAll(body["secret"].(string), " ", "")

	code, err := certiocrypto.TOTPCode(secret, time.Now())
	if err != nil {
		h.t.Fatalf("TOTPCode: %v", err)
	}
	status, body = h.do(http.MethodPost, "/api/v1/auth/2fa/enable", h.adminTk,
		map[string]string{"code": code})
	if status != http.StatusOK {
		h.t.Fatalf("POST /auth/2fa/enable: status %d, body %v", status, body)
	}

	raw, _ := body["recovery_codes"].([]any)
	for _, item := range raw {
		recovery = append(recovery, item.(string))
	}
	if len(recovery) == 0 {
		h.t.Fatalf("enabling returned no recovery codes: %v", body)
	}
	return secret, recovery
}

func TestTwoFactorLoginOverHTTP(t *testing.T) {
	h := newHarness(t)
	secret, recovery := h.enrol()

	status, body := h.do(http.MethodGet, "/api/v1/auth/2fa", h.adminTk, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /auth/2fa: status %d, body %v", status, body)
	}
	if body["enabled"] != true {
		t.Errorf("status after enrolment = %v, want enabled", body)
	}

	// The password alone must now yield a challenge, not a session.
	status, body = h.do(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": h.cfg.Admin.Email, "password": h.cfg.Admin.Password,
	})
	if status != http.StatusOK {
		t.Fatalf("login: status %d, body %v", status, body)
	}
	if body["two_factor_required"] != true {
		t.Fatalf("login did not demand a second factor: %v", body)
	}
	if body["access_token"] != nil {
		t.Fatal("login handed out an access token alongside the challenge")
	}
	challenge, _ := body["challenge_token"].(string)
	if challenge == "" {
		t.Fatalf("login returned no challenge: %v", body)
	}

	// The challenge itself must not authenticate a request.
	if status, _ := h.do(http.MethodGet, "/api/v1/auth/me", challenge, nil); status != http.StatusUnauthorized {
		t.Errorf("GET /auth/me with a challenge: status %d, want 401", status)
	}

	// A wrong code is rejected with its own error code.
	status, body = h.do(http.MethodPost, "/api/v1/auth/2fa/verify", "", map[string]string{
		"challenge_token": challenge, "code": "000000",
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_two_factor_code" {
		t.Errorf("bad code: status %d, body %v", status, body)
	}

	// A recovery code completes the login and is then spent.
	status, body = h.do(http.MethodPost, "/api/v1/auth/2fa/verify", "", map[string]string{
		"challenge_token": challenge, "code": recovery[0],
	})
	if status != http.StatusOK {
		t.Fatalf("verify with a recovery code: status %d, body %v", status, body)
	}
	if body["access_token"] == nil || body["used_recovery_code"] != true {
		t.Fatalf("recovery login: %v", body)
	}

	// And a fresh authenticator code works in one request.
	code, err := certiocrypto.TOTPCode(secret, time.Now().Add(certiocrypto.TOTPPeriod*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	status, body = h.do(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": h.cfg.Admin.Email, "password": h.cfg.Admin.Password, "totp_code": code,
	})
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("single-request login: status %d, body %v", status, body)
	}
}

// TestTwoFactorResetIsAdminOnly checks that clearing somebody else's factor is
// not something an operator can do.
func TestTwoFactorResetIsAdminOnly(t *testing.T) {
	h := newHarness(t)
	operator := h.userToken("operator@certio.test", "operator")

	status, body := h.do(http.MethodGet, "/api/v1/auth/me", operator, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /auth/me: status %d, body %v", status, body)
	}
	operatorID := body["id"].(string)

	if status, _ := h.do(http.MethodDelete, "/api/v1/users/"+operatorID+"/2fa", operator, nil); status != http.StatusForbidden {
		t.Errorf("operator resetting a factor: status %d, want 403", status)
	}
}

func TestAboutEndpoint(t *testing.T) {
	h := newHarness(t)

	if status, _ := h.do(http.MethodGet, "/api/v1/about", "", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /about without a token: status %d, want 401", status)
	}

	status, body := h.do(http.MethodGet, "/api/v1/about", h.adminTk, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /about: status %d, body %v", status, body)
	}
	if body["name"] != "Certio" || body["version"] != "test" {
		t.Errorf("about = %v, want the seeded name and version", body)
	}
	if body["go_version"] == "" || body["platform"] == "" {
		t.Errorf("about is missing runtime details: %v", body)
	}

	instance, ok := body["instance"].(map[string]any)
	if !ok {
		t.Fatalf("about has no instance block: %v", body)
	}
	if instance["base_url"] != h.cfg.Server.BaseURL {
		t.Errorf("base_url = %v, want %s", instance["base_url"], h.cfg.Server.BaseURL)
	}
	if instance["scheduler_enabled"] != false {
		t.Errorf("scheduler_enabled = %v, want false in the test harness", instance["scheduler_enabled"])
	}
}
