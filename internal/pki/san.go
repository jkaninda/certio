package pki

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strings"
)

// SAN entry types.
const (
	SANDNS   = "dns"
	SANIP    = "ip"
	SANEmail = "email"
	SANURI   = "uri"
)

// SAN is a single Subject Alternative Name entry.
type SAN struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// String renders the entry in the "type:value" form the CLI accepts.
func (s SAN) String() string { return s.Type + ":" + s.Value }

// SANSet is an ordered, de-duplicated collection of SAN entries.
type SANSet []SAN

// ParseSAN reads a single entry. An explicit "dns:", "ip:", "email:" or "uri:"
// prefix wins; otherwise the type is detected from the value itself.
func ParseSAN(raw string) (SAN, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return SAN{}, fmt.Errorf("pki: empty SAN entry")
	}

	if typ, rest, ok := splitSANPrefix(value); ok {
		san := SAN{Type: typ, Value: strings.TrimSpace(rest)}
		if err := san.Validate(); err != nil {
			return SAN{}, err
		}
		return san, nil
	}

	san := SAN{Type: DetectSANType(value), Value: value}
	if err := san.Validate(); err != nil {
		return SAN{}, err
	}
	return san, nil
}

// splitSANPrefix separates a leading "type:" label. It deliberately does not
// treat "https://example.com" as a "https" type, and it leaves bare IPv6
// literals (which are full of colons) alone.
func splitSANPrefix(value string) (typ, rest string, ok bool) {
	idx := strings.Index(value, ":")
	if idx <= 0 {
		return "", "", false
	}
	switch strings.ToLower(value[:idx]) {
	case SANDNS:
		return SANDNS, value[idx+1:], true
	case SANIP:
		return SANIP, value[idx+1:], true
	case SANEmail:
		return SANEmail, value[idx+1:], true
	case SANURI:
		return SANURI, value[idx+1:], true
	}
	return "", "", false
}

// DetectSANType infers the entry type from an unprefixed value. This is the
// same logic the UI chip input uses so typed and pasted values agree.
func DetectSANType(value string) string {
	switch {
	case net.ParseIP(value) != nil:
		return SANIP
	case strings.Contains(value, "://"):
		return SANURI
	case strings.Contains(value, "@"):
		return SANEmail
	default:
		return SANDNS
	}
}

// Validate checks a single entry against its type's rules.
func (s SAN) Validate() error {
	if s.Value == "" {
		return fmt.Errorf("pki: SAN of type %q has an empty value", s.Type)
	}
	switch s.Type {
	case SANDNS:
		return validateDNSName(s.Value)
	case SANIP:
		if net.ParseIP(s.Value) == nil {
			return fmt.Errorf("pki: %q is not a valid IP address", s.Value)
		}
		return nil
	case SANEmail:
		if _, err := mail.ParseAddress(s.Value); err != nil {
			return fmt.Errorf("pki: %q is not a valid email address", s.Value)
		}
		if strings.Count(s.Value, "@") != 1 {
			return fmt.Errorf("pki: %q is not a valid email address", s.Value)
		}
		return nil
	case SANURI:
		u, err := url.Parse(s.Value)
		if err != nil {
			return fmt.Errorf("pki: %q is not a valid URI: %w", s.Value, err)
		}
		if u.Scheme == "" {
			return fmt.Errorf("pki: URI SAN %q must be absolute (include a scheme)", s.Value)
		}
		return nil
	default:
		return fmt.Errorf("pki: unknown SAN type %q (want dns, ip, email or uri)", s.Type)
	}
}

// validateDNSName enforces DNS syntax plus the wildcard rule browsers apply:
// at most one '*', and only as the entire leftmost label.
func validateDNSName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("pki: DNS name %q exceeds 253 characters", name)
	}

	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("pki: DNS name %q has an empty label", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("pki: DNS name %q has a label longer than 63 characters", name)
		}
		if strings.Contains(label, "*") {
			if i != 0 {
				return fmt.Errorf("pki: wildcard in %q must be the leftmost label", name)
			}
			if label != "*" {
				return fmt.Errorf("pki: wildcard label in %q must be exactly \"*\" — "+
					"partial wildcards like \"*.foo\" are not accepted by browsers", name)
			}
			if len(labels) < 3 {
				return fmt.Errorf("pki: wildcard %q must cover a subdomain, e.g. *.example.com", name)
			}
			continue
		}
		if err := validateDNSLabel(label, name); err != nil {
			return err
		}
	}
	return nil
}

func validateDNSLabel(label, name string) error {
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return fmt.Errorf("pki: DNS label %q in %q may not start or end with '-'", label, name)
	}
	for _, r := range label {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '-' && r != '_' {
			return fmt.Errorf("pki: DNS name %q contains an invalid character %q", name, r)
		}
	}
	return nil
}

// ParseSANList parses a newline-, comma- or space-separated list — the format
// the UI's bulk-paste box and the CLI's repeated --san flag both produce.
func ParseSANList(raw string) (SANSet, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	})

	var set SANSet
	for _, f := range fields {
		san, err := ParseSAN(f)
		if err != nil {
			return nil, err
		}
		set = set.Add(san)
	}
	return set, nil
}

// Add appends an entry unless an equal one is already present.
func (s SANSet) Add(entry SAN) SANSet {
	for _, existing := range s {
		if existing.Type == entry.Type && strings.EqualFold(existing.Value, entry.Value) {
			return s
		}
	}
	return append(s, entry)
}

// AddDNS is a shorthand used to fold the CN into the DNS names.
func (s SANSet) AddDNS(name string) SANSet {
	if name == "" {
		return s
	}
	if validateDNSName(name) != nil {
		// A CN like "jkanTech Root CA" is a label, not a hostname. Skip it
		// rather than failing the whole request.
		return s
	}
	return s.Add(SAN{Type: SANDNS, Value: name})
}

// Validate checks every entry and rejects an empty set.
func (s SANSet) Validate() error {
	if len(s) == 0 {
		return fmt.Errorf("pki: at least one SAN is required — modern clients ignore the Common Name")
	}
	for _, entry := range s {
		if err := entry.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Sorted returns the set ordered by type then value, for stable output.
func (s SANSet) Sorted() SANSet {
	out := append(SANSet{}, s...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// Strings renders the set as "type:value" entries.
func (s SANSet) Strings() []string {
	out := make([]string, len(s))
	for i, entry := range s {
		out[i] = entry.String()
	}
	return out
}

// Split fans the set out into the four typed slices x509.Certificate wants.
func (s SANSet) Split() (dns []string, ips []net.IP, emails []string, uris []*url.URL, err error) {
	for _, entry := range s {
		switch entry.Type {
		case SANDNS:
			dns = append(dns, entry.Value)
		case SANIP:
			ip := net.ParseIP(entry.Value)
			if ip == nil {
				return nil, nil, nil, nil, fmt.Errorf("pki: %q is not a valid IP address", entry.Value)
			}
			ips = append(ips, ip)
		case SANEmail:
			emails = append(emails, entry.Value)
		case SANURI:
			u, parseErr := url.Parse(entry.Value)
			if parseErr != nil {
				return nil, nil, nil, nil, fmt.Errorf("pki: %q is not a valid URI: %w", entry.Value, parseErr)
			}
			uris = append(uris, u)
		default:
			return nil, nil, nil, nil, fmt.Errorf("pki: unknown SAN type %q", entry.Type)
		}
	}
	return dns, ips, emails, uris, nil
}

// SANsFromCertificateLike collects the SAN entries out of the four typed
// slices carried by x509.Certificate and x509.CertificateRequest.
func SANsFromCertificateLike(dns []string, ips []net.IP, emails []string, uris []*url.URL) SANSet {
	var set SANSet
	for _, d := range dns {
		set = set.Add(SAN{Type: SANDNS, Value: d})
	}
	for _, ip := range ips {
		set = set.Add(SAN{Type: SANIP, Value: ip.String()})
	}
	for _, e := range emails {
		set = set.Add(SAN{Type: SANEmail, Value: e})
	}
	for _, u := range uris {
		set = set.Add(SAN{Type: SANURI, Value: u.String()})
	}
	return set
}

// PrimaryName is the name a certificate should carry as its common name when
// the request did not supply one: the first DNS entry, or the first entry of
// any kind if there is no DNS name at all.
//
// The CN is vestigial — no modern client reads it — but x509 still has the
// field and a certificate with an empty subject is awkward to look at in every
// tool that displays one.
func (s SANSet) PrimaryName() string {
	for _, san := range s {
		if san.Type == SANDNS {
			return san.Value
		}
	}
	if len(s) > 0 {
		return s[0].Value
	}
	return ""
}
