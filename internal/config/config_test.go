package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Default()

	if cfg.Security.AccessTokenTTL != time.Hour {
		t.Errorf("access token TTL = %s, want 1h", cfg.Security.AccessTokenTTL)
	}
	if cfg.Security.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("refresh token TTL = %s, want 168h", cfg.Security.RefreshTokenTTL)
	}
	if !cfg.Server.EnableDocs {
		t.Error("the OpenAPI docs are off by default, want on")
	}
	if !cfg.Scheduler.Enabled {
		t.Error("the scheduler is off by default, want on")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the default configuration does not validate: %v", err)
	}
}

// TestPrecedence pins the layering the whole package exists to provide:
// environment beats file beats Default().
func TestPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certio.yaml")
	body := `
server:
  port: 9090
  base_url: https://from-file.example
  enable_docs: false
security:
  access_token_ttl: 30m
  key_download_policy: never
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// The file wins over the defaults.
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("port = %d, want 9090 from the file", cfg.Server.Port)
	}
	if cfg.Server.EnableDocs {
		t.Error("enable_docs = true, want the file's false to win over the default")
	}
	if cfg.Security.AccessTokenTTL != 30*time.Minute {
		t.Errorf("access token TTL = %s, want 30m from the file", cfg.Security.AccessTokenTTL)
	}
	// A field the file omits keeps its default.
	if cfg.Security.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("refresh token TTL = %s, want the 168h default", cfg.Security.RefreshTokenTTL)
	}

	// The environment wins over the file.
	t.Setenv("CERTIO_PORT", "7070")
	t.Setenv("CERTIO_ENABLE_DOCS", "true")
	t.Setenv("CERTIO_ACCESS_TOKEN_TTL", "2h")
	t.Setenv("CERTIO_BASE_URL", "https://from-env.example/")

	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load with the environment set: %v", err)
	}
	if cfg.Server.Port != 7070 {
		t.Errorf("port = %d, want 7070 from the environment", cfg.Server.Port)
	}
	if !cfg.Server.EnableDocs {
		t.Error("enable_docs = false, want the environment's true to win over the file")
	}
	if cfg.Security.AccessTokenTTL != 2*time.Hour {
		t.Errorf("access token TTL = %s, want 2h from the environment", cfg.Security.AccessTokenTTL)
	}
	// Validate strips the trailing slash, since it is concatenated into URLs.
	if cfg.Server.BaseURL != "https://from-env.example" {
		t.Errorf("base URL = %q, want the trailing slash trimmed", cfg.Server.BaseURL)
	}
	// A field only the file sets is still the file's.
	if cfg.Security.KeyDownloadPolicy != KeyDownloadNever {
		t.Errorf("key download policy = %q, want the file's never", cfg.Security.KeyDownloadPolicy)
	}
}

func TestEnvOverridesDefaultWithoutAFile(t *testing.T) {
	t.Setenv("CERTIO_HOST", "127.0.0.1")
	t.Setenv("CERTIO_PORT", "9443")
	t.Setenv("CERTIO_SCHEDULER_ENABLED", "false")
	t.Setenv("CERTIO_CORS_ORIGINS", "https://a.example, https://b.example ,")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr() != "127.0.0.1:9443" {
		t.Errorf("Addr = %s, want 127.0.0.1:9443", cfg.Addr())
	}
	if cfg.Scheduler.Enabled {
		t.Error("the scheduler stayed on, want the environment's false to win")
	}
	// The blank left by the trailing comma must not become an allowed origin.
	want := []string{"https://a.example", "https://b.example"}
	if len(cfg.Server.CORSOrigins) != len(want) {
		t.Fatalf("CORS origins = %q, want %q", cfg.Server.CORSOrigins, want)
	}
	for i, origin := range want {
		if cfg.Server.CORSOrigins[i] != origin {
			t.Errorf("CORS origin %d = %q, want %q", i, cfg.Server.CORSOrigins[i], origin)
		}
	}
}

// TestUnparseableValuesFallBack covers the boot-safety rule: a typo in one
// variable degrades to the default rather than taking the server down.
func TestUnparseableValuesFallBack(t *testing.T) {
	t.Setenv("CERTIO_ACCESS_TOKEN_TTL", "an hour or so")
	t.Setenv("CERTIO_PORT", "not-a-number")
	t.Setenv("CERTIO_ENABLE_DOCS", "yes please")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Security.AccessTokenTTL != time.Hour {
		t.Errorf("access token TTL = %s, want the 1h default", cfg.Security.AccessTokenTTL)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("port = %d, want the 8080 default", cfg.Server.Port)
	}
	if !cfg.Server.EnableDocs {
		t.Error("enable_docs fell to false, want the true default")
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]func(*Config){
		"port out of range":   func(c *Config) { c.Server.Port = 70000 },
		"unknown driver":      func(c *Config) { c.Database.Driver = "postgres" },
		"unknown key policy":  func(c *Config) { c.Security.KeyDownloadPolicy = "sometimes" },
		"sqlite with no path": func(c *Config) { c.Database.Path, c.Database.DSN = "", "" },
	}

	for name, mutate := range cases {
		cfg := Default()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it, want an error", name)
		}
	}
}
