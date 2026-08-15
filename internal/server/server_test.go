package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
)

// harness is a running API with a seeded admin, exercised over real HTTP.
type harness struct {
	t       *testing.T
	server  *httptest.Server
	svc     *service.Service
	cfg     *config.Config
	adminTk string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "server-test.db")
	cfg.Server.BaseURL = "http://certio.test"
	cfg.Scheduler.Enabled = false
	cfg.Admin.Email = "admin@certio.test"
	cfg.Admin.Password = "a-long-enough-password"

	st, err := store.Open(cfg, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	master, _ := certiocrypto.GenerateMasterKey()
	keyring, err := certiocrypto.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	svc := service.New(st, keyring, cfg, nil)
	auth := service.NewAuthenticator([]byte("server-test-signing-secret"), "certio",
		15*time.Minute, 24*time.Hour)

	if err := EnsureSchema(st, svc, cfg, nil); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	srv := New(Options{Service: svc, Auth: auth, Config: cfg, Version: "test"})
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	h := &harness{t: t, server: httpSrv, svc: svc, cfg: cfg}
	h.adminTk = h.login(cfg.Admin.Email, cfg.Admin.Password)
	return h
}

// do issues a request and returns the status and decoded body.
func (h *harness) do(method, path, token string, body any) (status int, out map[string]any) {
	h.t.Helper()

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

// raw fetches a non-JSON endpoint, for the PEM and DER downloads.
func (h *harness) raw(path, token string) (status int, body string, header http.Header) {
	h.t.Helper()

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(raw), resp.Header
}

func (h *harness) login(email, password string) string {
	h.t.Helper()
	status, body := h.do(http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": email, "password": password})
	if status != http.StatusOK {
		h.t.Fatalf("login as %s: status %d, body %v", email, status, body)
	}
	token, _ := body["access_token"].(string)
	if token == "" {
		h.t.Fatalf("login returned no access token: %v", body)
	}
	return token
}

// userToken creates an account with a role and returns a token for it.
func (h *harness) userToken(email, role string) string {
	h.t.Helper()
	const password = "another-long-password"
	if _, err := h.svc.CreateUser(audit.SystemActor(), service.CreateUserInput{
		Email: email, Password: password, Role: role,
	}); err != nil {
		h.t.Fatalf("CreateUser: %v", err)
	}
	return h.login(email, password)
}

// createCA creates an authority and returns its ID.
func (h *harness) createCA(name string) string {
	h.t.Helper()
	status, body := h.do(http.MethodPost, "/api/v1/authorities", h.adminTk, map[string]any{
		"name": name,
		"type": "root",
		"subject": map[string]string{
			"common_name": name, "organization": "Certio Test", "country": "CD",
		},
		"key_algorithm": "ecdsa-p256",
		"validity_days": 3650,
	})
	if status != http.StatusCreated {
		h.t.Fatalf("create CA: status %d, body %v", status, body)
	}
	return body["id"].(string)
}

func TestBootstrapAndLogin(t *testing.T) {
	h := newHarness(t)

	// The seeded admin can identify itself.
	status, body := h.do(http.MethodGet, "/api/v1/auth/me", h.adminTk, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /auth/me: status %d, body %v", status, body)
	}
	if body["email"] != "admin@certio.test" || body["role"] != "admin" {
		t.Errorf("unexpected principal: %v", body)
	}

	// Wrong credentials and unknown accounts look identical from outside.
	for _, creds := range []map[string]string{
		{"email": "admin@certio.test", "password": "wrong"},
		{"email": "nobody@certio.test", "password": "whatever-it-is"},
	} {
		status, _ := h.do(http.MethodPost, "/api/v1/auth/login", "", creds)
		if status != http.StatusUnauthorized {
			t.Errorf("login %v: status %d, want 401", creds["email"], status)
		}
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/authorities",
		"/api/v1/audit-logs",
		"/api/v1/dashboard/stats",
	} {
		status, _ := h.do(http.MethodGet, path, "", nil)
		if status != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: status %d, want 401", path, status)
		}
	}

	// A garbage token must not be treated as anonymous-but-allowed.
	status, _ := h.do(http.MethodGet, "/api/v1/certificates", "not-a-real-token", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("GET with a bad token: status %d, want 401", status)
	}
}

func TestPublicEndpointsNeedNoAuth(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Public Root CA")

	status, body, _ := h.raw("/health", "")
	if status != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("GET /health: status %d, body %s", status, body)
	}

	// The trust anchor has to be fetchable before anything trusts it.
	status, body, headers := h.raw("/ca/"+caID+"/root.crt", "")
	if status != http.StatusOK {
		t.Fatalf("GET root.crt: status %d", status)
	}
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Errorf("root.crt is not PEM: %s", body[:min(120, len(body))])
	}
	if !strings.Contains(headers.Get("Content-Disposition"), "attachment") {
		t.Errorf("root.crt Content-Disposition = %q", headers.Get("Content-Disposition"))
	}

	// A CRL is generated on first request rather than 404ing on a CA that has
	// simply never revoked anything.
	status, body, _ = h.raw("/ca/"+caID+"/crl.pem", "")
	if status != http.StatusOK || !strings.Contains(body, "BEGIN X509 CRL") {
		t.Errorf("GET crl.pem: status %d, body %s", status, body[:min(120, len(body))])
	}

	status, _, _ = h.raw("/ca/"+caID+"/crl.der", "")
	if status != http.StatusOK {
		t.Errorf("GET crl.der: status %d", status)
	}

	status, _, _ = h.raw("/ca/"+caID+"/chain.pem", "")
	if status != http.StatusOK {
		t.Errorf("GET chain.pem: status %d", status)
	}
}

func TestRBACOnMutatingRoutes(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("RBAC Root CA")

	viewer := h.userToken("viewer@certio.test", store.RoleViewer)
	operator := h.userToken("operator@certio.test", store.RoleOperator)

	issueBody := map[string]any{
		"ca_id":    caID,
		"subject":  map[string]string{"common_name": "rbac.example.com"},
		"san_list": "rbac.example.com",
		"profile":  "server",
	}

	// A viewer may read but not write.
	if status, _ := h.do(http.MethodGet, "/api/v1/certificates", viewer, nil); status != http.StatusOK {
		t.Errorf("viewer GET /certificates: status %d, want 200", status)
	}
	if status, body := h.do(http.MethodPost, "/api/v1/certificates", viewer, issueBody); status != http.StatusForbidden {
		t.Errorf("viewer POST /certificates: status %d, want 403 (body %v)", status, body)
	}

	// An operator may issue.
	status, body := h.do(http.MethodPost, "/api/v1/certificates", operator, issueBody)
	if status != http.StatusCreated {
		t.Fatalf("operator POST /certificates: status %d, body %v", status, body)
	}

	// But not reach admin-only routes.
	for _, path := range []string{"/api/v1/users", "/api/v1/audit-logs", "/api/v1/notifications"} {
		if status, _ := h.do(http.MethodGet, path, operator, nil); status != http.StatusForbidden {
			t.Errorf("operator GET %s: status %d, want 403", path, status)
		}
	}
	// The admin can.
	for _, path := range []string{"/api/v1/users", "/api/v1/audit-logs", "/api/v1/notifications"} {
		if status, _ := h.do(http.MethodGet, path, h.adminTk, nil); status != http.StatusOK {
			t.Errorf("admin GET %s: status %d, want 200", path, status)
		}
	}

	// Deleting a CA is admin-only even for an operator who may issue from it.
	if status, _ := h.do(http.MethodDelete, "/api/v1/authorities/"+caID, operator, nil); status != http.StatusForbidden {
		t.Errorf("operator DELETE /authorities: status %d, want 403", status)
	}
}

func TestIssueRevokeAndDownloadFlow(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Flow Root CA")

	status, body := h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, map[string]any{
		"ca_id":         caID,
		"subject":       map[string]string{"common_name": "*.flow.example.com"},
		"san_list":      "flow.example.com, *.flow.example.com, 10.0.0.1, ops@flow.example.com",
		"profile":       "server",
		"validity_days": 397,
	})
	if status != http.StatusCreated {
		t.Fatalf("issue: status %d, body %v", status, body)
	}

	// A managed issuance hands the key back exactly here.
	if key, _ := body["private_key_pem"].(string); !strings.Contains(key, "BEGIN PRIVATE KEY") {
		t.Error("the issuance response did not include the private key")
	}
	if chain, _ := body["fullchain_pem"].(string); strings.Count(chain, "BEGIN CERTIFICATE") != 2 {
		t.Error("the fullchain does not contain the leaf and its issuer")
	}

	cert := body["certificate"].(map[string]any)
	certID := cert["id"].(string)

	// All four SAN types survived the bulk-paste parse.
	sans := cert["sans"].([]any)
	if len(sans) != 4 {
		t.Errorf("got %d SANs, want 4: %v", len(sans), sans)
	}

	// Downloads render the requested format.
	for _, tc := range []struct{ format, contains string }{
		{"pem", "BEGIN CERTIFICATE"},
		{"fullchain", "BEGIN CERTIFICATE"},
		{"key", "BEGIN PRIVATE KEY"},
		{"k8s", "kubernetes.io/tls"},
		{"nginx", "ssl_certificate"},
	} {
		status, out, _ := h.raw("/api/v1/certificates/"+certID+"/download?format="+tc.format, h.adminTk)
		if status != http.StatusOK {
			t.Errorf("download %s: status %d", tc.format, status)
			continue
		}
		if !strings.Contains(out, tc.contains) {
			t.Errorf("download %s does not contain %q", tc.format, tc.contains)
		}
	}

	// The chain verifies.
	status, body = h.do(http.MethodGet, "/api/v1/certificates/"+certID+"/chain", h.adminTk, nil)
	if status != http.StatusOK {
		t.Fatalf("chain: status %d", status)
	}
	if body["valid"] != true {
		t.Errorf("the issued chain does not verify: %v", body)
	}

	// Revoking publishes the serial on the CRL.
	status, body = h.do(http.MethodPost, "/api/v1/certificates/"+certID+"/revoke", h.adminTk,
		map[string]any{"reason_code": 1})
	if status != http.StatusOK {
		t.Fatalf("revoke: status %d, body %v", status, body)
	}
	if body["reason"] != "keyCompromise" {
		t.Errorf("revocation reason = %v", body["reason"])
	}

	_, crl, _ := h.raw("/ca/"+caID+"/crl.pem", "")
	if !strings.Contains(crl, "BEGIN X509 CRL") {
		t.Error("the CRL was not republished after the revocation")
	}

	// Revoking twice is a conflict, not a silent success.
	if status, _ := h.do(http.MethodPost, "/api/v1/certificates/"+certID+"/revoke", h.adminTk,
		map[string]any{"reason_code": 1}); status != http.StatusConflict {
		t.Errorf("second revoke: status %d, want 409", status)
	}
}

func TestValidationErrorsAreBadRequests(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Validation Root CA")

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no SANs", map[string]any{
			"ca_id": caID, "subject": map[string]string{"common_name": "Not A Hostname"},
		}},
		{"bad wildcard", map[string]any{
			"ca_id": caID, "subject": map[string]string{"common_name": "x.example.com"},
			"san_list": "*.*.example.com",
		}},
		{"unknown CA", map[string]any{
			"ca_id": "does-not-exist", "subject": map[string]string{"common_name": "x.example.com"},
			"san_list": "x.example.com",
		}},
		{"unknown profile", map[string]any{
			"ca_id": caID, "subject": map[string]string{"common_name": "x.example.com"},
			"san_list": "x.example.com", "profile": "not-a-profile",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, tc.body)
			// 400 for a bad payload, 404 for a CA that is not there — never 500.
			if status != http.StatusBadRequest && status != http.StatusNotFound {
				t.Errorf("status %d, want 400 or 404; body %v", status, body)
			}
			if body["message"] == nil || body["message"] == "" {
				t.Errorf("the error carries no message: %v", body)
			}
		})
	}
}

func TestPassphraseProtectedCAReturns428(t *testing.T) {
	h := newHarness(t)

	status, body := h.do(http.MethodPost, "/api/v1/authorities", h.adminTk, map[string]any{
		"name": "Locked Root CA", "type": "root",
		"subject":       map[string]string{"common_name": "Locked Root CA"},
		"key_algorithm": "ecdsa-p256",
		"passphrase":    "the-passphrase-is-never-stored",
	})
	if status != http.StatusCreated {
		t.Fatalf("create locked CA: status %d, body %v", status, body)
	}
	caID := body["id"].(string)

	issueBody := map[string]any{
		"ca_id": caID, "subject": map[string]string{"common_name": "locked.example.com"},
		"san_list": "locked.example.com",
	}

	// Without the passphrase, the request is well-formed but cannot proceed.
	status, body = h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, issueBody)
	if status != http.StatusPreconditionRequired {
		t.Errorf("issue without the passphrase: status %d, want 428; body %v", status, body)
	}
	if body["error"] != "passphrase_required" {
		t.Errorf("error code = %v, want passphrase_required", body["error"])
	}

	// With it, issuance succeeds.
	issueBody["ca_passphrase"] = "the-passphrase-is-never-stored"
	if status, body := h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, issueBody); status != http.StatusCreated {
		t.Errorf("issue with the passphrase: status %d, body %v", status, body)
	}
}

func TestAPITokenAuthenticatesLikeASession(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Token Root CA")

	status, body := h.do(http.MethodPost, "/api/v1/api-tokens", h.adminTk,
		map[string]any{"name": "ci-pipeline"})
	if status != http.StatusCreated {
		t.Fatalf("create token: status %d, body %v", status, body)
	}

	plaintext, _ := body["plaintext_token"].(string)
	if !strings.HasPrefix(plaintext, "certio_") {
		t.Fatalf("token plaintext = %q", plaintext)
	}

	// The token authenticates and inherits the owner's role.
	status, _ = h.do(http.MethodPost, "/api/v1/certificates", plaintext, map[string]any{
		"ca_id": caID, "subject": map[string]string{"common_name": "ci.example.com"},
		"san_list": "ci.example.com",
	})
	if status != http.StatusCreated {
		t.Errorf("issue with an API token: status %d, want 201", status)
	}

	// Revoking it takes effect immediately.
	tokenID := body["token"].(map[string]any)["id"].(string)
	if status, _ := h.do(http.MethodDelete, "/api/v1/api-tokens/"+tokenID, h.adminTk, nil); status != http.StatusOK {
		t.Fatalf("revoke token: status %d", status)
	}
	if status, _ := h.do(http.MethodGet, "/api/v1/certificates", plaintext, nil); status != http.StatusUnauthorized {
		t.Errorf("revoked token still works: status %d, want 401", status)
	}
}

func TestInspectDoesNotPersist(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Inspect Root CA")

	_, body := h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, map[string]any{
		"ca_id": caID, "subject": map[string]string{"common_name": "inspect.example.com"},
		"san_list": "inspect.example.com",
	})
	pem := body["cert_pem"].(string)

	before, err := h.svc.Store.Certificates.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	status, result := h.do(http.MethodPost, "/api/v1/certificates/inspect", h.adminTk,
		map[string]string{"pem": pem})
	if status != http.StatusOK {
		t.Fatalf("inspect: status %d, body %v", status, result)
	}
	if result["kind"] != "certificate" {
		t.Errorf("kind = %v", result["kind"])
	}

	after, err := h.svc.Store.Certificates.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if after != before {
		t.Errorf("inspect stored a record: %d → %d", before, after)
	}

	// Garbage is a 400, not a 500.
	if status, _ := h.do(http.MethodPost, "/api/v1/certificates/inspect", h.adminTk,
		map[string]string{"pem": "hello world"}); status != http.StatusBadRequest {
		t.Errorf("inspect garbage: status %d, want 400", status)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := newHarness(t)
	h.cfg.Security.LoginRateLimit = 10

	limited := false
	for range 30 {
		status, _ := h.do(http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "admin@certio.test", "password": "wrong"})
		if status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("30 failed logins were not rate limited")
	}
}

func TestBulkRenewReportsPerItemOutcomes(t *testing.T) {
	h := newHarness(t)
	caID := h.createCA("Bulk Root CA")

	ids := make([]string, 0, 3)
	for _, cn := range []string{"a.bulk.example.com", "b.bulk.example.com", "c.bulk.example.com"} {
		_, body := h.do(http.MethodPost, "/api/v1/certificates", h.adminTk, map[string]any{
			"ca_id": caID, "subject": map[string]string{"common_name": cn}, "san_list": cn,
		})
		ids = append(ids, body["certificate"].(map[string]any)["id"].(string))
	}

	// One real ID replaced with a bogus one: the batch must still renew the rest.
	mixed := append([]string{"not-a-real-id"}, ids...)

	status, body := h.do(http.MethodPost, "/api/v1/certificates/bulk/renew", h.adminTk,
		map[string]any{"ids": mixed})
	if status != http.StatusOK {
		t.Fatalf("bulk renew: status %d, body %v", status, body)
	}
	if body["succeeded"] != float64(3) {
		t.Errorf("succeeded = %v, want 3", body["succeeded"])
	}
	if body["failed"] != float64(1) {
		t.Errorf("failed = %v, want 1", body["failed"])
	}

	// The failure names itself rather than being swallowed by the count.
	results := body["results"].([]any)
	for _, entry := range results {
		row := entry.(map[string]any)
		if row["id"] == "not-a-real-id" && row["error"] == nil {
			t.Error("the failed item carries no error message")
		}
	}
}

func TestOpenAPIDocumentIsServed(t *testing.T) {
	h := newHarness(t)

	status, body, _ := h.raw("/openapi.json", "")
	if status != http.StatusOK {
		t.Fatalf("GET /openapi.json: status %d", status)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the OpenAPI document is not valid JSON: %v", err)
	}

	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) < 20 {
		t.Fatalf("the document describes %d paths, want at least 20", len(paths))
	}
	for _, want := range []string{
		"/api/v1/certificates",
		"/api/v1/authorities",
		"/api/v1/certificates/{id}/download",
		"/ca/{id}/crl.pem",
	} {
		if _, found := paths[want]; !found {
			t.Errorf("the OpenAPI document is missing %s", want)
		}
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	h := newHarness(t)

	_, _, headers := h.raw("/health", "")
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-Robots-Tag":           "noindex, nofollow",
	} {
		if got := headers.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
