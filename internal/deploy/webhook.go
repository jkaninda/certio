package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jkaninda/okapi/client"
)

// Webhook posts the renewed material to an endpoint that knows what to do with
// it — the escape hatch for every deployment Certio does not model natively.
//
// The body is signed with HMAC-SHA256 over the exact bytes sent, so a receiver
// about to install a private key can verify it came from Certio and not from
// whoever else can reach the URL. Verifying that signature is the difference
// between a deployment hook and a way to have arbitrary key material installed
// on your servers.
type Webhook struct {
	URL     string
	Secret  string
	Headers map[string]string
	// IncludeKey controls whether the private key is sent at all. A receiver
	// that only needs to know a renewal happened should not be handed one.
	IncludeKey bool
}

// Kind identifies the target type.
func (w *Webhook) Kind() string { return KindWebhook }

// Describe summarises the target without naming the secret.
func (w *Webhook) Describe() string { return w.URL }

// webhookPayload is the JSON a receiver gets.
type webhookPayload struct {
	Event        string    `json:"event"`
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number"`
	NotAfter     time.Time `json:"not_after"`
	Timestamp    time.Time `json:"timestamp"`

	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	FullchainPEM   string `json:"fullchain_pem,omitempty"`
	RootPEM        string `json:"root_pem,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

// Deploy posts the bundle.
func (w *Webhook) Deploy(ctx context.Context, bundle Bundle) error {
	if w.URL == "" {
		return errors.New("deploy: a webhook target needs a url")
	}

	payload := webhookPayload{
		Event:          "certificate.deployed",
		CommonName:     bundle.CommonName,
		SerialNumber:   bundle.SerialNumber,
		NotAfter:       bundle.NotAfter.UTC(),
		Timestamp:      time.Now().UTC(),
		CertificatePEM: string(bundle.CertificatePEM),
		ChainPEM:       string(bundle.ChainPEM),
		FullchainPEM:   string(bundle.FullchainPEM),
		RootPEM:        string(bundle.RootPEM),
	}
	if w.IncludeKey {
		payload.PrivateKeyPEM = string(bundle.PrivateKeyPEM)
	}

	// The body is marshalled once and both signed and sent, so the signature
	// covers exactly the bytes that arrive. Re-marshalling for the signature
	// would let map ordering make it verify against something else.
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("deploy: marshal the webhook payload: %w", err)
	}

	req := client.New("", client.WithTimeout(30*time.Second), client.WithUserAgent("certio-deploy")).
		Post(w.URL).
		WithContext(ctx).
		Header("Content-Type", "application/json").
		Headers(w.Headers).
		RawBody(body)

	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req = req.Header("X-Certio-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := req.Do()
	if err != nil {
		return fmt.Errorf("deploy: post to %s: %w", w.URL, err)
	}
	if !resp.IsSuccess() {
		snippet := strings.TrimSpace(string(resp.Body))
		if len(snippet) > 512 {
			snippet = snippet[:512] + "…"
		}
		return fmt.Errorf("deploy: %s returned %s: %s", w.URL, resp.Status, snippet)
	}
	return nil
}

func buildWebhook(config map[string]string) (Target, error) {
	includeKey, err := strconv.ParseBool(firstNonEmpty(config["include_key"], "true"))
	if err != nil {
		includeKey = true
	}

	target := &Webhook{
		URL:        config["url"],
		Secret:     config["secret"],
		Headers:    parsePairs(config["headers"]),
		IncludeKey: includeKey,
	}
	if target.URL == "" {
		return nil, errors.New("deploy: a webhook target needs a url")
	}
	if target.IncludeKey && target.Secret == "" {
		return nil, errors.New(
			"deploy: a webhook that receives the private key needs a secret, so the receiver " +
				"can verify the X-Certio-Signature before installing it; " +
				"set include_key=false if the key is not wanted")
	}
	return target, nil
}
