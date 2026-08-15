package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testBundle() Bundle {
	return Bundle{
		CommonName:     "api.example.com",
		SerialNumber:   "0A1B",
		NotAfter:       time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"),
		ChainPEM:       []byte("-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"),
		FullchainPEM:   []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"),
		RootPEM:        []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
	}
}

// TestWebhookSignsTheExactBytes is the property a receiver depends on: the
// signature must verify against the body as it arrives, or a receiver about to
// install a private key has no way to tell where it came from.
func TestWebhookSignsTheExactBytes(t *testing.T) {
	const secret = "s3cret"
	var gotBody []byte
	var gotSignature string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-Certio-Signature")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	target := &Webhook{URL: server.URL, Secret: secret, IncludeKey: true}
	if err := target.Deploy(context.Background(), testBundle()); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSignature != want {
		t.Errorf("signature = %q, want %q", gotSignature, want)
	}

	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("the body was not valid JSON: %v", err)
	}
	if payload["common_name"] != "api.example.com" {
		t.Errorf("common_name = %v", payload["common_name"])
	}
	if payload["private_key_pem"] == "" || payload["private_key_pem"] == nil {
		t.Error("include_key was set but no key was sent")
	}
}

// TestWebhookOmitsTheKey checks that a receiver that does not need the key is
// not handed one anyway.
func TestWebhookOmitsTheKey(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	target := &Webhook{URL: server.URL, IncludeKey: false}
	if err := target.Deploy(context.Background(), testBundle()); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if _, present := payload["private_key_pem"]; present {
		t.Error("the private key was sent to a target configured without it")
	}
}

// TestWebhookReportsAFailure checks that a rejecting receiver produces an
// error rather than a silent success.
func TestWebhookReportsAFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("the reload script exited 1"))
	}))
	defer server.Close()

	target := &Webhook{URL: server.URL, Secret: "x", IncludeKey: true}
	err := target.Deploy(context.Background(), testBundle())
	if err == nil {
		t.Fatal("Deploy returned nil for a 500")
	}
	if !strings.Contains(err.Error(), "the reload script exited 1") {
		t.Errorf("error = %v, want it to quote the receiver's message", err)
	}
}

// TestBuildWebhookRequiresASecretForKeys checks the guard that keeps private
// key material from being posted to an endpoint that cannot authenticate it.
func TestBuildWebhookRequiresASecretForKeys(t *testing.T) {
	if _, err := Build(KindWebhook, map[string]string{"url": "https://example.com/hook"}); err == nil {
		t.Error("Build accepted a key-carrying webhook with no secret")
	}
	if _, err := Build(KindWebhook, map[string]string{
		"url": "https://example.com/hook", "include_key": "false",
	}); err != nil {
		t.Errorf("Build rejected a webhook that does not receive the key: %v", err)
	}
}

// TestBuildSSHRequiresAHostKey is the guard that keeps a private key from
// being handed to whoever answers the address.
func TestBuildSSHRequiresAHostKey(t *testing.T) {
	base := map[string]string{
		"host":      "server.example.com",
		"user":      "deploy",
		"password":  "hunter2",
		"cert_path": "/etc/ssl/api.crt",
	}
	if _, err := Build(KindSSH, base); err == nil {
		t.Fatal("Build accepted an ssh target with no host key")
	}

	withOptOut := map[string]string{"insecure_ignore_host_key": "true"}
	for k, v := range base {
		withOptOut[k] = v
	}
	if _, err := Build(KindSSH, withOptOut); err != nil {
		t.Errorf("Build rejected an explicit opt-out: %v", err)
	}
}

// TestBuildSSHNeedsCredentialsAndPaths checks the rest of the guards.
func TestBuildSSHNeedsCredentialsAndPaths(t *testing.T) {
	noAuth := map[string]string{
		"host": "h", "cert_path": "/x", "insecure_ignore_host_key": "true",
	}
	if _, err := Build(KindSSH, noAuth); err == nil {
		t.Error("Build accepted an ssh target with neither a key nor a password")
	}

	noPaths := map[string]string{
		"host": "h", "password": "p", "insecure_ignore_host_key": "true",
	}
	if _, err := Build(KindSSH, noPaths); err == nil {
		t.Error("Build accepted an ssh target with nothing to write")
	}
}

// TestBuildKubernetes checks the required fields and the defaults.
func TestBuildKubernetes(t *testing.T) {
	target, err := Build(KindKubernetes, map[string]string{
		"api_url": "https://10.0.0.1:6443", "token": "t", "secret_name": "api-tls",
		"annotations": "reloader.stakater.com/match=true, team=payments",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	k, ok := target.(*Kubernetes)
	if !ok {
		t.Fatalf("Build returned %T", target)
	}
	if k.Namespace != "default" {
		t.Errorf("namespace = %q, want the default", k.Namespace)
	}
	if k.Annotations["reloader.stakater.com/match"] != "true" || k.Annotations["team"] != "payments" {
		t.Errorf("annotations = %v", k.Annotations)
	}

	if _, err := Build(KindKubernetes, map[string]string{"api_url": "https://x"}); err == nil {
		t.Error("Build accepted a kubernetes target with no token or secret name")
	}
}

// TestKubernetesUpdatesThenCreates checks the PUT-then-POST flow, and that the
// Secret carries the full chain rather than the leaf alone — serving only the
// leaf is the classic cause of "works in curl -k, fails everywhere else".
func TestKubernetesUpdatesThenCreates(t *testing.T) {
	var methods []string
	var created map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"secrets \"api-tls\" not found"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&created)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer server.Close()

	target := &Kubernetes{
		APIURL: server.URL, Token: "t", Namespace: "prod", SecretName: "api-tls",
	}
	if err := target.Deploy(context.Background(), testBundle()); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	if len(methods) != 2 || methods[0] != http.MethodPut || methods[1] != http.MethodPost {
		t.Errorf("methods = %v, want PUT then POST", methods)
	}
	if created["type"] != "kubernetes.io/tls" {
		t.Errorf("type = %v, want kubernetes.io/tls", created["type"])
	}

	data, _ := created["data"].(map[string]any)
	certData, _ := data["tls.crt"].(string)
	decoded := decodeBase64(t, certData)
	if strings.Count(decoded, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("tls.crt holds %d certificates, want the full chain",
			strings.Count(decoded, "BEGIN CERTIFICATE"))
	}
}

// TestKubernetesRefusesWithoutAKey checks that a BYO-CSR certificate fails
// loudly rather than writing a Secret with an empty tls.key.
func TestKubernetesRefusesWithoutAKey(t *testing.T) {
	bundle := testBundle()
	bundle.PrivateKeyPEM = nil

	target := &Kubernetes{APIURL: "https://x", Token: "t", SecretName: "s", Namespace: "default"}
	err := target.Deploy(context.Background(), bundle)
	if err == nil {
		t.Fatal("Deploy accepted a bundle with no private key")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error = %v, want it to name the missing key", err)
	}
}

// TestBuildUnknownKind checks the error names the kinds that do exist.
func TestBuildUnknownKind(t *testing.T) {
	_, err := Build("ftp", map[string]string{})
	if err == nil {
		t.Fatal("Build accepted an unknown kind")
	}
	for _, kind := range Kinds() {
		if !strings.Contains(err.Error(), kind) {
			t.Errorf("error %q does not mention %q", err, kind)
		}
	}
}

func decodeBase64(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return string(raw)
}
