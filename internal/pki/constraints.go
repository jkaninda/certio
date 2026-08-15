package pki

import (
	"fmt"
	"net"
	"strings"
)

// NameConstraints limits the names a CA is allowed to certify, as RFC 5280
// §4.2.1.10 defines them.
//
// This is the single most valuable extension on a private root, and the one
// most often left off. A root installed in a laptop's system trust store can,
// without constraints, mint a certificate for any name on the internet — so a
// stolen CA key is not "an internal problem", it is a universal one. With
// `PermittedDNS: ["corp.example.com"]` the same stolen key can only lie about
// names the organisation already owns.
//
// Enforcement is the verifier's job, not the issuer's. Go's crypto/x509,
// OpenSSL, macOS and Windows all check constraints while building a chain, so
// a constrained CA is enforced by the clients that matter even if Certio
// itself is compromised. Certio additionally refuses at issuance time, so the
// failure shows up at the point someone can fix it rather than as a mystery
// browser error later.
type NameConstraints struct {
	PermittedDNS   []string `json:"permitted_dns,omitempty"`
	ExcludedDNS    []string `json:"excluded_dns,omitempty"`
	PermittedIP    []string `json:"permitted_ip,omitempty"`
	ExcludedIP     []string `json:"excluded_ip,omitempty"`
	PermittedEmail []string `json:"permitted_email,omitempty"`
	ExcludedEmail  []string `json:"excluded_email,omitempty"`
	PermittedURI   []string `json:"permitted_uri,omitempty"`
	ExcludedURI    []string `json:"excluded_uri,omitempty"`
}

// IsZero reports whether no constraint is set.
func (n NameConstraints) IsZero() bool {
	return len(n.PermittedDNS) == 0 && len(n.ExcludedDNS) == 0 &&
		len(n.PermittedIP) == 0 && len(n.ExcludedIP) == 0 &&
		len(n.PermittedEmail) == 0 && len(n.ExcludedEmail) == 0 &&
		len(n.PermittedURI) == 0 && len(n.ExcludedURI) == 0
}

// Normalize trims, lowercases and drops empty entries.
func (n NameConstraints) Normalize() NameConstraints {
	return NameConstraints{
		PermittedDNS:   cleanList(n.PermittedDNS),
		ExcludedDNS:    cleanList(n.ExcludedDNS),
		PermittedIP:    cleanList(n.PermittedIP),
		ExcludedIP:     cleanList(n.ExcludedIP),
		PermittedEmail: cleanList(n.PermittedEmail),
		ExcludedEmail:  cleanList(n.ExcludedEmail),
		PermittedURI:   cleanList(n.PermittedURI),
		ExcludedURI:    cleanList(n.ExcludedURI),
	}
}

// Validate checks that every entry is well formed. A malformed constraint is
// worse than none: crypto/x509 treats a CA whose constraints it cannot parse
// as untrusted, so the mistake surfaces as "certificate signed by unknown
// authority" long after issuance.
func (n NameConstraints) Validate() error {
	for _, cidr := range append(append([]string{}, n.PermittedIP...), n.ExcludedIP...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("pki: %q is not a CIDR range (name constraints on IPs need one, e.g. 10.0.0.0/8)", cidr)
		}
	}
	for _, domain := range append(append([]string{}, n.PermittedDNS...), n.ExcludedDNS...) {
		if strings.ContainsAny(domain, "*/ ") {
			return fmt.Errorf(
				"pki: %q is not a valid DNS name constraint; use the domain itself (example.com), "+
					"which already covers its subdomains", domain)
		}
	}
	return nil
}

// IPNets parses the permitted and excluded IP ranges.
func (n NameConstraints) IPNets() (permitted, excluded []*net.IPNet, err error) {
	if permitted, err = parseCIDRs(n.PermittedIP); err != nil {
		return nil, nil, err
	}
	if excluded, err = parseCIDRs(n.ExcludedIP); err != nil {
		return nil, nil, err
	}
	return permitted, excluded, nil
}

// PermitsDNS reports whether a DNS name satisfies the constraints, using RFC
// 5280 matching: a constraint of "example.com" covers "example.com" and
// anything under it, and an exclusion always beats a permission.
func (n NameConstraints) PermitsDNS(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	// A wildcard is judged by the domain it stands for: *.corp.example.com is
	// a name under corp.example.com.
	name = strings.TrimPrefix(name, "*.")
	if name == "" {
		return false
	}

	for _, excluded := range n.ExcludedDNS {
		if dnsWithin(name, excluded) {
			return false
		}
	}
	if len(n.PermittedDNS) == 0 {
		return true
	}
	for _, permitted := range n.PermittedDNS {
		if dnsWithin(name, permitted) {
			return true
		}
	}
	return false
}

// PermitsIP reports whether an IP satisfies the constraints.
func (n NameConstraints) PermitsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	permitted, excluded, err := n.IPNets()
	if err != nil {
		// Validate rejects this at configuration time; reaching here means a
		// row was written around it, and refusing is the safe reading.
		return false
	}

	for _, network := range excluded {
		if network.Contains(ip) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, network := range permitted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// PermitsEmail reports whether an email address satisfies the constraints. A
// constraint may be a full address, a host, or a domain covering subdomains.
func (n NameConstraints) PermitsEmail(address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return false
	}
	for _, excluded := range n.ExcludedEmail {
		if emailWithin(address, excluded) {
			return false
		}
	}
	if len(n.PermittedEmail) == 0 {
		return true
	}
	for _, permitted := range n.PermittedEmail {
		if emailWithin(address, permitted) {
			return true
		}
	}
	return false
}

// PermitsSANs checks a whole SAN set and names the first entry that fails, so
// the error tells the operator which name to remove rather than that "the
// request was rejected".
func (n NameConstraints) PermitsSANs(sans SANSet) error {
	if n.IsZero() {
		return nil
	}
	for _, san := range sans {
		switch san.Type {
		case SANDNS:
			if !n.PermitsDNS(san.Value) {
				return fmt.Errorf("pki: %q is outside this CA's name constraints (permitted: %s)",
					san.Value, describe(n.PermittedDNS, n.ExcludedDNS))
			}
		case SANIP:
			if !n.PermitsIP(net.ParseIP(san.Value)) {
				return fmt.Errorf("pki: IP %s is outside this CA's name constraints (permitted: %s)",
					san.Value, describe(n.PermittedIP, n.ExcludedIP))
			}
		case SANEmail:
			if !n.PermitsEmail(san.Value) {
				return fmt.Errorf("pki: %q is outside this CA's name constraints (permitted: %s)",
					san.Value, describe(n.PermittedEmail, n.ExcludedEmail))
			}
		}
	}
	return nil
}

// dnsWithin reports whether name is the constraint domain or sits under it.
// "example.com" matches "example.com" and "a.example.com" but never
// "notexample.com" — the boundary has to fall on a label.
func dnsWithin(name, constraint string) bool {
	constraint = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(constraint), "."))
	// A leading dot is the other spelling of the same idea, and is what an
	// operator who has read the RFC is likely to type.
	constraint = strings.TrimPrefix(constraint, ".")
	if constraint == "" {
		return false
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

// emailWithin matches an address against a full address, a host, or a domain.
func emailWithin(address, constraint string) bool {
	constraint = strings.ToLower(strings.TrimSpace(constraint))
	if constraint == "" {
		return false
	}
	if strings.Contains(constraint, "@") {
		return address == constraint
	}

	_, host, ok := strings.Cut(address, "@")
	if !ok {
		return false
	}
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(host, constraint)
	}
	return host == constraint
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for _, raw := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("pki: parse IP name constraint %q: %w", raw, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func cleanList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		if v := strings.ToLower(strings.TrimSpace(raw)); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// describe renders a constraint pair for an error message.
func describe(permitted, excluded []string) string {
	var b strings.Builder
	if len(permitted) == 0 {
		b.WriteString("anything")
	} else {
		b.WriteString(strings.Join(permitted, ", "))
	}
	if len(excluded) > 0 {
		b.WriteString("; excluded: " + strings.Join(excluded, ", "))
	}
	return b.String()
}
