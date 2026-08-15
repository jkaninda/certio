package pki

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// Issuance profiles. A profile presets key usage, extended key usage and the
// default validity so the common cases need no extension knowledge.
const (
	ProfileServer       = "server"
	ProfileClient       = "client"
	ProfilePeer         = "peer"
	ProfileCodeSigning  = "code-signing"
	ProfileIntermediate = "intermediate"
	ProfileRoot         = "root"
)

// MaxLeafValidityDays is the CA/Browser Forum ceiling for publicly trusted
// server certificates. Certio defaults to it so habits stay portable, but a
// private CA may legitimately exceed it, so it is a default and not a limit.
const MaxLeafValidityDays = 397

// Profile describes the extensions and defaults applied at signing time.
type Profile struct {
	Name         string
	Description  string
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	ValidityDays int
	IsCA         bool
}

// profiles is the built-in profile table.
var profiles = map[string]Profile{
	ProfileServer: {
		Name:         ProfileServer,
		Description:  "TLS server — presented by an HTTPS endpoint to prove its identity.",
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ValidityDays: MaxLeafValidityDays,
	},
	ProfileClient: {
		Name:         ProfileClient,
		Description:  "TLS client — presented by a user or service to authenticate itself.",
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ValidityDays: MaxLeafValidityDays,
	},
	ProfilePeer: {
		Name:         ProfilePeer,
		Description:  "mTLS peer — valid on both ends of a mutually authenticated connection.",
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ValidityDays: MaxLeafValidityDays,
	},
	ProfileCodeSigning: {
		Name:         ProfileCodeSigning,
		Description:  "Code signing — signs artifacts rather than terminating connections.",
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ValidityDays: 1095,
	},
	ProfileIntermediate: {
		Name:         ProfileIntermediate,
		Description:  "Intermediate CA — signs leaf certificates on behalf of a root.",
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ValidityDays: 1825,
		IsCA:         true,
	},
	ProfileRoot: {
		Name:         ProfileRoot,
		Description:  "Root CA — self-signed trust anchor.",
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ValidityDays: 3650,
		IsCA:         true,
	},
}

// LookupProfile returns a profile by name.
func LookupProfile(name string) (Profile, error) {
	p, ok := profiles[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Profile{}, fmt.Errorf("pki: unknown profile %q (want one of %s)",
			name, strings.Join(ProfileNames(), ", "))
	}
	return p, nil
}

// ProfileNames lists every profile, in presentation order.
func ProfileNames() []string {
	return []string{ProfileServer, ProfileClient, ProfilePeer, ProfileCodeSigning, ProfileIntermediate, ProfileRoot}
}

// Profiles returns the full profile table in presentation order, for the API
// endpoint that populates the wizard's profile selector.
func Profiles() []Profile {
	names := ProfileNames()
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		out = append(out, profiles[n])
	}
	return out
}

// KeyUsageStrings renders a KeyUsage bitmask as the names used in the API and
// the UI.
func KeyUsageStrings(usage x509.KeyUsage) []string {
	all := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	var out []string
	for _, u := range all {
		if usage&u.bit != 0 {
			out = append(out, u.name)
		}
	}
	return out
}

// ParseKeyUsages converts usage names back into a bitmask.
func ParseKeyUsages(names []string) (x509.KeyUsage, error) {
	lookup := map[string]x509.KeyUsage{
		"digitalsignature":  x509.KeyUsageDigitalSignature,
		"contentcommitment": x509.KeyUsageContentCommitment,
		"nonrepudiation":    x509.KeyUsageContentCommitment,
		"keyencipherment":   x509.KeyUsageKeyEncipherment,
		"dataencipherment":  x509.KeyUsageDataEncipherment,
		"keyagreement":      x509.KeyUsageKeyAgreement,
		"certsign":          x509.KeyUsageCertSign,
		"keycertsign":       x509.KeyUsageCertSign,
		"crlsign":           x509.KeyUsageCRLSign,
		"encipheronly":      x509.KeyUsageEncipherOnly,
		"decipheronly":      x509.KeyUsageDecipherOnly,
	}
	var usage x509.KeyUsage
	for _, n := range names {
		bit, ok := lookup[normalizeUsage(n)]
		if !ok {
			return 0, fmt.Errorf("pki: unknown key usage %q", n)
		}
		usage |= bit
	}
	return usage, nil
}

// ExtKeyUsageStrings renders extended key usages as API names.
func ExtKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "Any",
		x509.ExtKeyUsageServerAuth:                 "ServerAuth",
		x509.ExtKeyUsageClientAuth:                 "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                "CodeSigning",
		x509.ExtKeyUsageEmailProtection:            "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:             "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                  "IPSECUser",
		x509.ExtKeyUsageTimeStamping:               "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "NetscapeServerGatedCrypto",
	}
	var out []string
	for _, u := range usages {
		if name, ok := names[u]; ok {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("Unknown(%d)", u))
		}
	}
	return out
}

// ParseExtKeyUsages converts extended key usage names into their x509 values.
func ParseExtKeyUsages(names []string) ([]x509.ExtKeyUsage, error) {
	lookup := map[string]x509.ExtKeyUsage{
		"any":             x509.ExtKeyUsageAny,
		"serverauth":      x509.ExtKeyUsageServerAuth,
		"clientauth":      x509.ExtKeyUsageClientAuth,
		"codesigning":     x509.ExtKeyUsageCodeSigning,
		"emailprotection": x509.ExtKeyUsageEmailProtection,
		"ipsecendsystem":  x509.ExtKeyUsageIPSECEndSystem,
		"ipsectunnel":     x509.ExtKeyUsageIPSECTunnel,
		"ipsecuser":       x509.ExtKeyUsageIPSECUser,
		"timestamping":    x509.ExtKeyUsageTimeStamping,
		"ocspsigning":     x509.ExtKeyUsageOCSPSigning,
	}
	var out []x509.ExtKeyUsage
	for _, n := range names {
		u, ok := lookup[normalizeUsage(n)]
		if !ok {
			return nil, fmt.Errorf("pki: unknown extended key usage %q", n)
		}
		out = append(out, u)
	}
	return out, nil
}

func normalizeUsage(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "", "_", "").Replace(strings.TrimSpace(s)))
}
