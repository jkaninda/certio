package server

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"testing/fstest"
)

// nuxtShell is the shape of the document Nuxt prerenders: two inline scripts
// that have to run for the dashboard to mount at all, plus a JSON payload that
// never executes.
const nuxtShell = `<!DOCTYPE html><html><head>
<script>(function(){try{document.documentElement.setAttribute('data-theme','dark')}catch(e){}})();</script>
<script type="module" src="/_nuxt/entry.js" crossorigin></script>
</head><body><div id="__nuxt"></div>
<script>window.__NUXT__={};window.__NUXT__.config={app:{baseURL:"/"}}</script>
<script type="application/json" id="__NUXT_DATA__">[{"a":1}]</script>
</body></html>`

func hashOf(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// TestPolicyAllowsTheDashboardToBoot is the regression test for a policy that
// shipped once and broke the dashboard completely: `script-src 'self'` blocks
// Nuxt's inline bootstrap, window.__NUXT__ is never defined, and the SPA mounts
// nothing at all. The failure is a blank page, which no API test would catch.
func TestPolicyAllowsTheDashboardToBoot(t *testing.T) {
	web := fstest.MapFS{"dist/index.html": &fstest.MapFile{Data: []byte(nuxtShell)}}

	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(web, "dist")
	policy := builder.String()

	const themeScript = `(function(){try{document.documentElement.setAttribute('data-theme','dark')}catch(e){}})();`
	const configScript = `window.__NUXT__={};window.__NUXT__.config={app:{baseURL:"/"}}`

	for name, script := range map[string]string{
		"the theme script": themeScript,
		"the Nuxt config":  configScript,
	} {
		if want := hashOf(script); !strings.Contains(policy, want) {
			t.Errorf("the policy does not allow %s\n  want a source expression %s\n  policy: %s",
				name, want, policy)
		}
	}
}

// TestPolicyStaysStrict checks that allowing the bootstrap did not turn into
// allowing everything — 'unsafe-inline' on scripts would defeat most of what
// the header is for.
func TestPolicyStaysStrict(t *testing.T) {
	web := fstest.MapFS{"dist/index.html": &fstest.MapFile{Data: []byte(nuxtShell)}}
	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(web, "dist")
	policy := builder.String()

	// style-src legitimately carries 'unsafe-inline'; script-src must not, so
	// the directive is isolated before it is checked.
	if start := strings.Index(policy, "script-src"); start >= 0 {
		scriptSrc := policy[start:]
		if end := strings.Index(scriptSrc, ";"); end >= 0 {
			scriptSrc = scriptSrc[:end]
		}
		if strings.Contains(scriptSrc, "'unsafe-inline'") {
			t.Errorf("script-src allows unsafe-inline: %s", scriptSrc)
		}
	}

	for _, want := range []string{
		"default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the policy is missing %q: %s", want, policy)
		}
	}
}

// TestPolicySkipsScriptsItMustNot checks the two exclusions: a script with a
// src is fetched and already covered by 'self', and a JSON block never runs.
// Hashing either would be noise in a header clients have to parse.
func TestPolicySkipsScriptsItMustNot(t *testing.T) {
	web := fstest.MapFS{"dist/index.html": &fstest.MapFile{Data: []byte(nuxtShell)}}
	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(web, "dist")
	policy := builder.String()

	if got := strings.Count(policy, "'sha256-"); got != 2 {
		t.Errorf("hashed %d scripts, want exactly the 2 inline executable ones: %s", got, policy)
	}
}

// TestPolicyWithoutADashboard checks the API-only build: no inline scripts to
// allow for, and no reason to loosen anything.
func TestPolicyWithoutADashboard(t *testing.T) {
	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(nil, "")
	policy := builder.String()

	if strings.Contains(policy, "sha256-") {
		t.Errorf("an API-only build hashed something: %s", policy)
	}
	if !strings.Contains(policy, "script-src 'self'") {
		t.Errorf("the policy lost its script-src: %s", policy)
	}
}

// scalarShell is what okapi's Scalar template renders: a CDN bundle and an
// inline call that has to run for anything to appear.
const scalarShell = `<!doctype html><html><head><title>Certio API | Scalar</title></head>
<body><div id="app"></div>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
<script>
      Scalar.createApiReference('#app', {
        url: '/openapi.json',
      });
</script>
</body></html>`

// TestPolicyAllowsTheDocsToRender is the regression test for the second page
// the strict policy blanked. Scalar needs its CDN bundle *and* the inline call
// that invokes it; blocking either leaves /docs empty while /openapi.json keeps
// working, which is a confusing way to fail.
func TestPolicyAllowsTheDocsToRender(t *testing.T) {
	builder := newPolicyBuilder()
	builder.allowHost(scalarCDN)
	builder.allowInlineScriptsIn([]byte(scalarShell))
	policy := builder.String()

	if !strings.Contains(policy, scalarCDN) {
		t.Errorf("the policy does not allow the Scalar bundle: %s", policy)
	}

	const initialiser = `
      Scalar.createApiReference('#app', {
        url: '/openapi.json',
      });
`
	if want := hashOf(initialiser); !strings.Contains(policy, want) {
		t.Errorf("the policy does not allow Scalar's initialiser\n  want %s\n  policy: %s", want, policy)
	}
}

// TestPolicyWithoutDocsAllowsNoCDN checks that turning docs off takes the one
// external origin with it — an operator who does not want a CDN reaching an
// admin host should get exactly that.
func TestPolicyWithoutDocsAllowsNoCDN(t *testing.T) {
	web := fstest.MapFS{"dist/index.html": &fstest.MapFile{Data: []byte(nuxtShell)}}
	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(web, "dist")

	if policy := builder.String(); strings.Contains(policy, "jsdelivr") {
		t.Errorf("a docs-less build still allows the CDN: %s", policy)
	}
}
