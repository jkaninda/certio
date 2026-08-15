package acme

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// validatorFor points a Validator at a local test server standing in for the
// host being validated.
func validatorFor(t *testing.T, handler http.Handler) (validator *Validator, host string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return NewValidator("", number), host
}

// TestHTTP01Succeeds walks the fetch a real validation makes, including the
// path and the Host header the server is expected to route on.
func TestHTTP01Succeeds(t *testing.T) {
	const token = "tok3n"
	const keyAuth = "tok3n.thumbprint"

	var gotPath, gotHost string
	validator, host := validatorFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHost = r.URL.Path, r.Host
		_, _ = w.Write([]byte(keyAuth))
	}))

	if problem := validator.Validate(context.Background(), ChallengeHTTP01, host, token, keyAuth); problem != nil {
		t.Fatalf("Validate: %s", problem.Detail)
	}
	if want := "/.well-known/acme-challenge/" + token; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	// The Host header carries the bare identifier even though the URL had a
	// port, so a virtual host matches the name under validation.
	if gotHost != host {
		t.Errorf("Host = %q, want %q", gotHost, host)
	}
}

// TestHTTP01ToleratesTrailingWhitespace: a shell redirect adds a newline, and
// failing an otherwise correct deployment over it helps nobody.
func TestHTTP01ToleratesTrailingWhitespace(t *testing.T) {
	const keyAuth = "tok3n.thumbprint"
	validator, host := validatorFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(keyAuth + "\n"))
	}))

	if problem := validator.Validate(context.Background(), ChallengeHTTP01, host, "tok3n", keyAuth); problem != nil {
		t.Errorf("a trailing newline failed validation: %s", problem.Detail)
	}
}

// TestHTTP01RejectsTheWrongContent is the check the whole challenge exists for.
func TestHTTP01RejectsTheWrongContent(t *testing.T) {
	validator, host := validatorFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("some other value"))
	}))

	problem := validator.Validate(context.Background(), ChallengeHTTP01, host, "tok3n", "tok3n.thumbprint")
	if problem == nil {
		t.Fatal("Validate accepted the wrong key authorization")
	}
	if problem.Type != ErrIncorrectResponse {
		t.Errorf("problem type = %q, want %q", problem.Type, ErrIncorrectResponse)
	}
}

// TestHTTP01ReportsANon200 distinguishes "served the wrong thing" from "served
// nothing", which is the difference between a bad deployment and a 404.
func TestHTTP01ReportsANon200(t *testing.T) {
	validator, host := validatorFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	problem := validator.Validate(context.Background(), ChallengeHTTP01, host, "tok3n", "tok3n.thumbprint")
	if problem == nil {
		t.Fatal("Validate accepted a 404")
	}
	if !strings.Contains(problem.Detail, "404") {
		t.Errorf("detail = %q, want it to name the status", problem.Detail)
	}
}

// TestHTTP01RefusesWildcards: there is no single host to serve the file from,
// so offering this for a wildcard would be a promise the protocol cannot keep.
func TestHTTP01RefusesWildcards(t *testing.T) {
	validator := NewValidator("", 80)
	problem := validator.Validate(context.Background(), ChallengeHTTP01, "*.example.com", "t", "t.x")
	if problem == nil {
		t.Fatal("Validate accepted a wildcard for http-01")
	}
	if !strings.Contains(problem.Detail, "dns-01") {
		t.Errorf("detail = %q, want it to point at dns-01", problem.Detail)
	}
}

// TestConnectionFailureIsReportedAsSuch so a firewall reads differently from a
// misconfiguration.
func TestConnectionFailureIsReportedAsSuch(t *testing.T) {
	// Port 1 on localhost refuses fast and reliably.
	validator := NewValidator("", 1)
	problem := validator.Validate(context.Background(), ChallengeHTTP01, "127.0.0.1", "t", "t.x")
	if problem == nil {
		t.Fatal("Validate succeeded against a closed port")
	}
	if problem.Type != ErrConnection {
		t.Errorf("problem type = %q, want %q", problem.Type, ErrConnection)
	}
}

// TestUnsupportedChallengeType checks the fall-through.
func TestUnsupportedChallengeType(t *testing.T) {
	validator := NewValidator("", 80)
	problem := validator.Validate(context.Background(), "tls-alpn-01", "example.com", "t", "t.x")
	if problem == nil {
		t.Fatal("Validate accepted an unsupported challenge type")
	}
	if problem.Type != ErrMalformed {
		t.Errorf("problem type = %q", problem.Type)
	}
}
