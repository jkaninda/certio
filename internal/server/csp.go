package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
)

// scalarCDN is where okapi's Scalar template loads its bundle from.
const scalarCDN = "https://cdn.jsdelivr.net"

// scalarFonts is where Scalar's webfont lives. Allowing it is what makes the
// docs render in the typeface they were designed in; a font cannot execute, so
// this is a far smaller concession than the bundle above.
//
// Scalar also calls https://api.scalar.com for its "Ask AI" and "Generate MCP"
// features. That one is deliberately *not* allowed: this is the admin console
// of a private certificate authority, and an outbound connection to a third
// party from it is not a trade worth making for a button nobody asked for.
// Blocking it costs those two features and nothing else.
const scalarFonts = "https://fonts.scalar.com"

// basePolicy is everything the Content-Security-Policy says apart from
// script-src, which is assembled per build.
//
// Everything the dashboard loads is compiled into the binary, so the policy can
// forbid every external origin outright — a CDN, a font host, a stray fetch to
// somewhere else all fail closed. 'unsafe-inline' survives for styles only:
// scoped styles in single-file components are emitted as inline blocks, and
// nonce-ing those would mean rewriting the SPA shell on every request.
var basePolicy = []string{
	"img-src 'self' data: blob:",
	"connect-src 'self'",
	"object-src 'none'",
	"base-uri 'none'",
	"form-action 'self'",
	"frame-ancestors 'none'",
}

// inlineScript matches a <script> element with no src attribute.
var inlineScript = regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)

// policyBuilder accumulates the script sources a build needs.
//
// Nuxt and Scalar both bootstrap from inline scripts, and blocking either one
// yields a blank page rather than a degraded one — the dashboard because
// window.__NUXT__ is never defined, the docs because Scalar is never called.
// Neither 'unsafe-inline' (which gives up most of what the header is for) nor a
// per-request nonce (which would mean rewriting static documents on every hit)
// is the answer: the markup is fixed once the server is built, so its hashes
// are computed once, here, from the very bytes that will be served.
type policyBuilder struct {
	hosts     []string
	fontHosts []string
	hashes    []string
	seen      map[string]bool
}

func newPolicyBuilder() *policyBuilder {
	return &policyBuilder{seen: map[string]bool{}}
}

// allowHost permits an external script origin.
func (b *policyBuilder) allowHost(host string) {
	if !b.seen[host] {
		b.seen[host] = true
		b.hosts = append(b.hosts, host)
	}
}

// allowFontHost permits an external font origin.
func (b *policyBuilder) allowFontHost(host string) {
	key := "font:" + host
	if !b.seen[key] {
		b.seen[key] = true
		b.fontHosts = append(b.fontHosts, host)
	}
}

// allowInlineScriptsIn hashes every inline script in an HTML document.
func (b *policyBuilder) allowInlineScriptsIn(document []byte) {
	for _, match := range inlineScript.FindAllSubmatch(document, -1) {
		attrs, script := strings.ToLower(string(match[1])), match[2]
		// A script with a src is fetched, not inlined, and is covered by a
		// source expression already. A JSON payload is data and never executes.
		if len(script) == 0 || strings.Contains(attrs, "src=") ||
			strings.Contains(attrs, "application/json") {
			continue
		}

		sum := sha256.Sum256(script)
		expr := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !b.seen[expr] {
			b.seen[expr] = true
			b.hashes = append(b.hashes, expr)
		}
	}
}

// allowInlineScriptsInFS hashes the inline scripts in the dashboard's entry
// documents. Nuxt prerenders the same shell into several of them; they usually
// carry identical scripts, but all are read and the results de-duplicated.
func (b *policyBuilder) allowInlineScriptsInFS(webFS fs.FS, root string) {
	if webFS == nil {
		return
	}
	sub := webFS
	if root != "" && root != "." {
		nested, err := fs.Sub(webFS, root)
		if err != nil {
			return
		}
		sub = nested
	}

	for _, name := range []string{"index.html", "200.html", "404.html"} {
		if body, err := fs.ReadFile(sub, name); err == nil {
			b.allowInlineScriptsIn(body)
		}
	}
}

// String renders the finished policy.
func (b *policyBuilder) String() string {
	scriptSrc := append([]string{"script-src 'self'"}, b.hosts...)
	scriptSrc = append(scriptSrc, b.hashes...)

	fontSrc := append([]string{"font-src 'self' data:"}, b.fontHosts...)

	directives := []string{
		"default-src 'self'",
		strings.Join(scriptSrc, " "),

		"style-src 'self' 'unsafe-inline'",
		strings.Join(fontSrc, " "),
	}
	directives = append(directives, basePolicy...)
	return strings.Join(directives, "; ")
}

// renderDocsPage asks the application for its own /docs page, so the inline
// script okapi's template carries can be hashed without this package having to
// know what that template says.
//
// Reading it back rather than hardcoding the hash is the difference between a
// policy that survives an okapi upgrade and one that silently blanks the docs
// on the next `go get`. It runs once, at construction, against an in-memory
// recorder — no listener, no network.
func renderDocsPage(handler http.Handler) []byte {
	request := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return nil
	}
	return recorder.Body.Bytes()
}
