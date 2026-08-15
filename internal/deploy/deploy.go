// Package deploy pushes a renewed certificate to where it is actually used.
//
// Auto-renewal without this is half a feature: it produces a new certificate
// on a schedule and leaves somebody to copy it onto a server by hand, which is
// the step that gets forgotten and the reason the certificate expired in the
// first place. A deployment target closes the loop — renewal writes the new
// material to the Kubernetes Secret, the load balancer or the webhook that
// consumes it, and reloads whatever needs reloading.
//
// Targets are best-effort in the same way notifications are: a target that is
// down must never turn a successful renewal into a failed one. Failures are
// recorded on the target row and retried on the next pass.
package deploy

import (
	"context"
	"fmt"
	"time"
)

// Target kinds.
const (
	KindKubernetes = "kubernetes"
	KindSSH        = "ssh"
	KindWebhook    = "webhook"
)

// Kinds lists every target kind, for the settings UI.
func Kinds() []string { return []string{KindKubernetes, KindSSH, KindWebhook} }

// Bundle is the material a target writes out. Not every target uses every
// field: a webhook receives all of it, an SSH target writes only the paths it
// was configured with.
type Bundle struct {
	CommonName   string
	SerialNumber string
	NotAfter     time.Time

	CertificatePEM []byte
	// ChainPEM is the issuers above the leaf; FullchainPEM is the leaf
	// followed by those issuers, which is what most servers want in one file.
	ChainPEM      []byte
	FullchainPEM  []byte
	RootPEM       []byte
	PrivateKeyPEM []byte
}

// HasKey reports whether the bundle carries private key material. A BYO-CSR
// certificate has none, and a target that needs one has to say so rather than
// write an empty file over a working key.
func (b Bundle) HasKey() bool { return len(b.PrivateKeyPEM) > 0 }

// Target delivers a bundle to one destination.
type Target interface {
	Deploy(ctx context.Context, bundle Bundle) error
	Kind() string
	// Describe is the one-line summary shown in the UI and the audit log. It
	// must never include a secret.
	Describe() string
}

// Build constructs a Target from a kind and its decrypted settings.
func Build(kind string, config map[string]string) (Target, error) {
	switch kind {
	case KindKubernetes:
		return buildKubernetes(config)
	case KindSSH:
		return buildSSH(config)
	case KindWebhook:
		return buildWebhook(config)
	}
	return nil, fmt.Errorf("deploy: unknown target kind %q (want %s)", kind, joinKinds())
}

func joinKinds() string {
	kinds := Kinds()
	out := ""
	for i, k := range kinds {
		switch {
		case i == 0:
			out = k
		case i == len(kinds)-1:
			out += " or " + k
		default:
			out += ", " + k
		}
	}
	return out
}

// firstNonEmpty returns the first non-empty value, so a config key can have an
// alias without every call site repeating the fallback.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
