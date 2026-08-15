package deploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jkaninda/okapi/client"
)

// Kubernetes writes the certificate into a `kubernetes.io/tls` Secret.
//
// It talks to the API server directly rather than shelling out to kubectl:
// Certio is a single static binary and adding a kubectl dependency to a
// container image would be a much larger change than one HTTP call. The token
// needs only get/create/update on secrets in the one namespace — a Role that
// narrow is worth writing out rather than reaching for cluster-admin.
type Kubernetes struct {
	// APIURL is the API server, e.g. https://10.0.0.1:6443. Inside a cluster
	// this is https://kubernetes.default.svc.
	APIURL string
	// Token is a ServiceAccount token.
	Token      string
	Namespace  string
	SecretName string
	// CABundlePEM verifies the API server. In a cluster this is the contents
	// of /var/run/secrets/kubernetes.io/serviceaccount/ca.crt.
	CABundlePEM string
	// InsecureSkipVerify disables that verification. It exists because a
	// freshly bootstrapped cluster may be presenting a certificate this very
	// instance has not yet issued.
	InsecureSkipVerify bool
	// Annotations and Labels are written onto the Secret, which is how a
	// reloader controller is told to restart the pods that mount it.
	Annotations map[string]string
	Labels      map[string]string
}

// Kind identifies the target type.
func (k *Kubernetes) Kind() string { return KindKubernetes }

// Describe summarises the target without naming the token.
func (k *Kubernetes) Describe() string {
	return fmt.Sprintf("secret %s/%s on %s", k.Namespace, k.SecretName, k.APIURL)
}

// Deploy creates or replaces the Secret.
func (k *Kubernetes) Deploy(ctx context.Context, bundle Bundle) error {
	if !bundle.HasKey() {
		return fmt.Errorf(
			"deploy: a kubernetes.io/tls Secret needs the private key, and Certio does not hold one " +
				"for this certificate (it was issued from a CSR)")
	}

	httpClient, err := k.httpClient()
	if err != nil {
		return err
	}
	api := client.New(strings.TrimRight(k.APIURL, "/"),
		client.WithHTTPClient(httpClient),
		client.WithBearerToken(k.Token),
		client.WithUserAgent("certio-deploy"),
		client.WithTimeout(30*time.Second),
	)

	// tls.crt carries the full chain, not the leaf alone. An ingress serving
	// only the leaf is the single most common cause of "works in curl -k,
	// fails everywhere else".
	chain := bundle.FullchainPEM
	if len(chain) == 0 {
		chain = bundle.CertificatePEM
	}

	secret := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":        k.SecretName,
			"namespace":   k.Namespace,
			"annotations": k.mergedAnnotations(bundle),
			"labels":      k.mergedLabels(),
		},
		"data": map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(chain),
			"tls.key": base64.StdEncoding.EncodeToString(bundle.PrivateKeyPEM),
			// ca.crt is not part of the kubernetes.io/tls contract, but plenty
			// of workloads mount it to verify peers signed by the same root.
			"ca.crt": base64.StdEncoding.EncodeToString(bundle.RootPEM),
		},
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", k.Namespace, k.SecretName)

	// PUT replaces an existing Secret. A 404 means this is the first
	// deployment, so fall through to creating it.
	resp, err := api.Put(path).WithContext(ctx).JSONBody(secret).Do()
	if err != nil {
		return fmt.Errorf("deploy: update %s: %w", k.Describe(), err)
	}
	if resp.IsSuccess() {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("deploy: update %s: %s", k.Describe(), apiError(resp.Body, resp.Status))
	}

	created, err := api.Post(fmt.Sprintf("/api/v1/namespaces/%s/secrets", k.Namespace)).
		WithContext(ctx).JSONBody(secret).Do()
	if err != nil {
		return fmt.Errorf("deploy: create %s: %w", k.Describe(), err)
	}
	if !created.IsSuccess() {
		return fmt.Errorf("deploy: create %s: %s", k.Describe(), apiError(created.Body, created.Status))
	}
	return nil
}

// mergedAnnotations adds the certificate's identity to whatever the operator
// configured, so `kubectl describe secret` answers "which certificate is this
// and when does it expire" without a round trip to Certio.
func (k *Kubernetes) mergedAnnotations(bundle Bundle) map[string]string {
	out := map[string]string{
		"certio.jkaninda.dev/common-name":   bundle.CommonName,
		"certio.jkaninda.dev/serial-number": bundle.SerialNumber,
		"certio.jkaninda.dev/not-after":     bundle.NotAfter.UTC().Format(time.RFC3339),
	}
	for key, value := range k.Annotations {
		out[key] = value
	}
	return out
}

func (k *Kubernetes) mergedLabels() map[string]string {
	out := map[string]string{"app.kubernetes.io/managed-by": "certio"}
	for key, value := range k.Labels {
		out[key] = value
	}
	return out
}

// httpClient builds the transport, trusting the configured bundle.
func (k *Kubernetes) httpClient() (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: k.InsecureSkipVerify, //nolint:gosec // opt-in, documented
	}
	if k.CABundlePEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(k.CABundlePEM)) {
			return nil, fmt.Errorf("deploy: the kubernetes ca_bundle is not valid PEM")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}, nil
}

// apiError pulls the message out of a Kubernetes Status object, which is far
// more useful than the status line on its own.
func apiError(body []byte, status string) string {
	message := strings.TrimSpace(string(body))
	if len(message) > 512 {
		message = message[:512] + "…"
	}
	if message == "" {
		return status
	}
	return status + ": " + message
}

func buildKubernetes(config map[string]string) (Target, error) {
	insecure, _ := strconv.ParseBool(config["insecure_skip_verify"])

	target := &Kubernetes{
		APIURL:             firstNonEmpty(config["api_url"], config["server"]),
		Token:              config["token"],
		Namespace:          firstNonEmpty(config["namespace"], "default"),
		SecretName:         firstNonEmpty(config["secret_name"], config["secret"]),
		CABundlePEM:        firstNonEmpty(config["ca_bundle"], config["ca_crt"]),
		InsecureSkipVerify: insecure,
		Annotations:        parsePairs(config["annotations"]),
		Labels:             parsePairs(config["labels"]),
	}
	if target.APIURL == "" || target.Token == "" || target.SecretName == "" {
		return nil, fmt.Errorf("deploy: a kubernetes target needs api_url, token and secret_name")
	}
	return target, nil
}

// parsePairs reads "key=value,key=value" into a map. Commas and newlines both
// separate, because a textarea in the UI and a single-line config value are
// both reasonable ways to type this.
func parsePairs(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := map[string]string{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	}) {
		key, value, ok := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
