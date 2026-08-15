package server

import (
	"net/http"
	"strings"
	"testing"
)

// TestErrorShapeIsUniform pins the API's one error contract. Binding and
// validation now happen inside okapi, before a handler runs, and okapi's own
// error shape is {code, message, details, timestamp} — a different dialect
// from the {error, message} every handler returns. The dashboard branches on
// the machine-readable `error` field, so a second dialect would reach it as an
// unrecognised body carrying only "Bad Request".
func TestErrorShapeIsUniform(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name     string
		method   string
		path     string
		token    string
		body     any
		status   int
		wantCode string
		// wantIn is a fragment the message must carry, so the reply says what
		// is actually wrong rather than just naming the status.
		wantIn string
	}{
		{
			name:   "missing required body field",
			method: http.MethodPost, path: "/api/v1/certificates", token: h.adminTk,
			body:     map[string]any{"subject": map[string]any{"common_name": "x"}},
			status:   http.StatusBadRequest,
			wantCode: "invalid_request",
			wantIn:   "AuthorityID",
		},
		{
			name:   "value outside an enum",
			method: http.MethodGet, path: "/api/v1/certificates?status=bogus", token: h.adminTk,
			status:   http.StatusBadRequest,
			wantCode: "invalid_request",
			wantIn:   "Status",
		},
		{
			name:   "unauthenticated",
			method: http.MethodGet, path: "/api/v1/certificates",
			status:   http.StatusUnauthorized,
			wantCode: "unauthorized",
		},
		{
			name:   "not found",
			method: http.MethodGet, path: "/api/v1/certificates/does-not-exist", token: h.adminTk,
			status:   http.StatusNotFound,
			wantCode: "not_found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := h.do(tc.method, tc.path, tc.token, tc.body)
			if status != tc.status {
				t.Fatalf("status %d, want %d (body %v)", status, tc.status, body)
			}
			if body["error"] != tc.wantCode {
				t.Errorf("error = %v, want %q (body %v)", body["error"], tc.wantCode, body)
			}
			// okapi's own shape would leave these set; Certio's must not.
			if _, ok := body["code"]; ok {
				t.Errorf("reply carries okapi's `code` field: %v", body)
			}
			if _, ok := body["timestamp"]; ok {
				t.Errorf("reply carries okapi's `timestamp` field: %v", body)
			}
			if tc.wantIn != "" {
				msg, _ := body["message"].(string)
				if !strings.Contains(msg, tc.wantIn) {
					t.Errorf("message = %q, want it to mention %q", msg, tc.wantIn)
				}
			}
		})
	}
}
