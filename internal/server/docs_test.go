package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
)

// newServerWithSPA builds a server with the dashboard mounted, which is the
// only configuration the shipped binary ever runs in. The rest of the suite
// leaves WebFS nil, and that is precisely how the docs routes came to be
// shadowed by the SPA fallback without a test noticing.
func newServerWithSPA(t *testing.T, configure func(*config.Config)) *httptest.Server {
	t.Helper()

	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "docs-test.db")
	cfg.Scheduler.Enabled = false
	if configure != nil {
		configure(cfg)
	}

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
	if err := st.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	auth := service.NewAuthenticator([]byte("docs-test-signing-secret"), "certio",
		time.Minute, time.Hour)

	web := fstest.MapFS{
		"public/index.html":   {Data: []byte("<!doctype html><title>Certio</title>")},
		"public/favicon.svg":  {Data: []byte("<svg/>")},
		"public/200.html":     {Data: []byte("<!doctype html>")},
		"public/settings.txt": {Data: []byte("placeholder")},
	}

	srv := New(Options{
		Service: svc, Auth: auth, Config: cfg, Version: "test",
		WebFS: web, WebRoot: "public",
	})
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func get(t *testing.T, url string) (status int, body string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // a test against a local httptest server
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// TestDocsSurviveTheSPAFallback is the regression: the SPA owns "/", so the
// OpenAPI routes have to be registered before it or they are unreachable in
// every real deployment.
func TestDocsSurviveTheSPAFallback(t *testing.T) {
	srv := newServerWithSPA(t, nil)

	for _, path := range []string{"/docs", "/openapi.json"} {
		status, body := get(t, srv.URL+path)
		if status != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 — the SPA fallback is shadowing it", path, status)
			continue
		}
		if strings.Contains(body, "<title>Certio</title>") {
			t.Errorf("GET %s served the SPA shell instead of the documentation", path)
		}
	}

	// The spec must describe the API, not just parse.
	status, body := get(t, srv.URL+"/openapi.json")
	if status != http.StatusOK {
		t.Fatalf("GET /openapi.json: status %d", status)
	}
	for _, want := range []string{"/api/v1/certificates", "/api/v1/auth/2fa/verify", "/api/v1/about"} {
		if !strings.Contains(body, want) {
			t.Errorf("the OpenAPI document does not mention %s", want)
		}
	}
}

// TestDocsCanBeTurnedOff checks the switch still switches, and that turning it
// off does not hand /docs to the SPA instead.
func TestDocsCanBeTurnedOff(t *testing.T) {
	srv := newServerWithSPA(t, func(c *config.Config) { c.Server.EnableDocs = false })

	for _, path := range []string{"/docs", "/openapi.json", "/openapi.yaml"} {
		status, body := get(t, srv.URL+path)
		if status != http.StatusNotFound {
			t.Errorf("GET %s with docs disabled: status %d, want 404", path, status)
		}
		// A 200 carrying the dashboard shell would be the subtler failure:
		// the spec path answering with HTML rather than not answering.
		if strings.Contains(body, "<title>Certio</title>") {
			t.Errorf("GET %s with docs disabled served the SPA shell", path)
		}
	}
}

// TestSPAStillServesItsOwnRoutes guards the other half of the ordering: moving
// the docs earlier must not stop the dashboard from being served.
func TestSPAStillServesItsOwnRoutes(t *testing.T) {
	srv := newServerWithSPA(t, nil)

	status, body := get(t, srv.URL+"/")
	if status != http.StatusOK || !strings.Contains(body, "<title>Certio</title>") {
		t.Errorf("GET /: status %d, body %q — want the dashboard shell", status, body)
	}

	// A mistyped API path deserves a 404, not an HTML page.
	if status, _ := get(t, srv.URL+"/api/v1/nope"); status != http.StatusNotFound {
		t.Errorf("GET /api/v1/nope: status %d, want 404", status)
	}
}
