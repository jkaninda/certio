package acme

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Validator proves that whoever asked for a certificate controls the name.
//
// Both challenge types are outbound checks made by the server, which is the
// only arrangement that means anything: a client asserting it controls a name
// proves nothing, so Certio goes and looks.
type Validator struct {
	// HTTPClient fetches http-01 challenges. Redirects are followed because
	// RFC 8555 §8.3 allows them, but only a bounded number.
	HTTPClient *http.Client
	// Resolver answers dns-01 lookups. A private PKI usually wants the
	// internal resolver rather than the system one, since the names being
	// validated only exist there.
	Resolver *net.Resolver
	// HTTPPort is the port http-01 is fetched on. RFC 8555 fixes it at 80 and
	// forbids anything else for the public internet, but a private CA on a
	// segmented network sometimes has no choice.
	HTTPPort int
}

// NewValidator builds a validator with sane defaults.
func NewValidator(resolverAddress string, httpPort int) *Validator {
	v := &Validator{
		HTTPPort: httpPort,
		Resolver: net.DefaultResolver,
	}
	if v.HTTPPort == 0 {
		v.HTTPPort = 80
	}
	if resolverAddress != "" {
		v.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, network, resolverAddress)
			},
		}
	}

	v.HTTPClient = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	return v
}

// Validate performs the challenge and returns a problem when it fails.
//
// The returned error is always a *Problem, because the failure goes straight
// into the challenge object the client polls — and "connection refused" versus
// "wrong content" is the difference between a firewall and a misconfiguration.
func (v *Validator) Validate(ctx context.Context, challengeType, identifier, token, keyAuthorization string) *Problem {
	switch challengeType {
	case ChallengeHTTP01:
		return v.validateHTTP01(ctx, identifier, token, keyAuthorization)
	case ChallengeDNS01:
		return v.validateDNS01(ctx, identifier, keyAuthorization)
	}
	return NewProblem(ErrMalformed, "unsupported challenge type %q", challengeType)
}

// maxChallengeBody caps what a challenge response may return. A key
// authorization is under a hundred bytes; anything larger is a web server
// answering with a page, and reading all of it helps nobody.
const maxChallengeBody = 4096

// validateHTTP01 fetches the well-known path and compares the body.
func (v *Validator) validateHTTP01(ctx context.Context, identifier, token, keyAuthorization string) *Problem {
	// A wildcard cannot be proved by serving a file, because there is no one
	// host to serve it from. RFC 8555 §8.3 says so; the order builder should
	// never have offered this challenge, and refusing here is the backstop.
	if strings.HasPrefix(identifier, "*.") {
		return NewProblem(ErrMalformed, "http-01 cannot validate the wildcard %q; use dns-01", identifier)
	}

	host := identifier
	if v.HTTPPort != 80 {
		host = net.JoinHostPort(identifier, fmt.Sprint(v.HTTPPort))
	}
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", host, token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return NewProblem(ErrMalformed, "could not build a request for %s: %s", url, err)
	}
	req.Header.Set("User-Agent", "certio-acme/1.0")
	req.Header.Set("Accept", "*/*")
	// The Host header carries the bare identifier even when the URL has a
	// port, so a virtual host matches the name being validated.
	req.Host = identifier

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return NewProblem(ErrConnection, "could not fetch %s: %s", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return NewProblem(ErrIncorrectResponse, "%s returned %s, want 200", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody))
	if err != nil {
		return NewProblem(ErrConnection, "could not read %s: %s", url, err)
	}

	// Trailing whitespace is forgiven: a shell redirect adds a newline, and
	// failing an otherwise correct deployment over it helps nobody.
	if strings.TrimSpace(string(body)) != keyAuthorization {
		return NewProblem(ErrIncorrectResponse,
			"%s served the wrong key authorization; expected %q", url, keyAuthorization)
	}
	return nil
}

// validateDNS01 looks up the TXT record and compares the digest.
func (v *Validator) validateDNS01(ctx context.Context, identifier, keyAuthorization string) *Problem {
	// The wildcard is validated against the domain it stands for: there is one
	// _acme-challenge record for *.example.com and for example.com alike.
	domain := strings.TrimPrefix(identifier, "*.")
	name := "_acme-challenge." + domain
	want := DNSRecordValue(keyAuthorization)

	records, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		return NewProblem(ErrDNS, "could not look up TXT %s: %s", name, err)
	}
	if len(records) == 0 {
		return NewProblem(ErrDNS, "no TXT record at %s", name)
	}

	for _, record := range records {
		// Several records may coexist — two certificates being issued at once
		// is normal — so any match is enough.
		if strings.TrimSpace(record) == want {
			return nil
		}
	}
	return NewProblem(ErrIncorrectResponse,
		"none of the %d TXT records at %s matched; expected %q", len(records), name, want)
}
