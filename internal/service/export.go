package service

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// Export formats accepted by the download endpoint.
const (
	FormatPEM       = "pem"
	FormatKey       = "key"
	FormatFullchain = "fullchain"
	FormatChain     = "chain"
	FormatRoot      = "root"
	FormatCSR       = "csr"
	FormatPKCS12    = "p12"
	FormatZIP       = "zip"
	FormatK8s       = "k8s"
	FormatNginx     = "nginx"
	FormatTraefik   = "traefik"
	FormatHAProxy   = "haproxy"
	FormatCompose   = "compose"
	// FormatGoma is a Goma Gateway global TLS block; FormatGomaRoute is a
	// per-route one, which takes precedence over the global certificates.
	FormatGoma      = "goma"
	FormatGomaRoute = "goma-route"
)

// Content types the exports are served with.
const (
	mimePEM  = "application/x-pem-file"
	mimeYAML = "application/yaml"
)

// ExportFormats lists every format, in the order the download menu shows them.
func ExportFormats() []string {
	return []string{
		FormatPEM, FormatKey, FormatFullchain, FormatChain, FormatRoot, FormatCSR,
		FormatPKCS12, FormatZIP, FormatK8s, FormatNginx, FormatTraefik, FormatHAProxy,
		FormatGoma, FormatGomaRoute, FormatCompose,
	}
}

// FormatNeedsKey reports whether a format includes private key material, and
// therefore has to pass the download policy check.
func FormatNeedsKey(format string) bool {
	switch format {
	case FormatKey, FormatPKCS12, FormatZIP, FormatK8s, FormatCompose:
		return true
	default:
		return false
	}
}

// Export is a rendered download: bytes plus the metadata the HTTP layer needs
// to set Content-Type and Content-Disposition.
type Export struct {
	Filename    string
	ContentType string
	Data        []byte
}

// ExportOptions tunes a rendered download.
type ExportOptions struct {
	Format string
	// Password protects a PKCS#12 file and, when set, the PEM key.
	Password string
	// SecretName overrides the generated Kubernetes Secret name.
	SecretName string
	// Namespace scopes the generated Kubernetes Secret.
	Namespace string
}

// ExportCertificate renders a stored certificate in the requested format.
func (s *Service) ExportCertificate(cert *store.Certificate, bundle pki.Bundle, opts ExportOptions) (*Export, error) {
	base := safeFilename(cert.CommonName)

	switch opts.Format {
	case FormatPEM, "":
		return &Export{base + ".crt", mimePEM, bundle.CertPEM()}, nil

	case FormatFullchain:
		return &Export{base + "-fullchain.pem", mimePEM, bundle.FullChainPEM()}, nil

	case FormatChain:
		return &Export{base + "-chain.pem", mimePEM, bundle.ChainPEM()}, nil

	case FormatRoot:
		return &Export{base + "-root.crt", mimePEM, bundle.RootPEM()}, nil

	case FormatCSR:
		if cert.CSRPEM == "" {
			return nil, validationError("no CSR was stored for %s — it was issued with a managed key", cert.CommonName)
		}
		return &Export{base + ".csr", "application/pkcs10", []byte(cert.CSRPEM)}, nil

	case FormatKey:
		keyPEM, err := bundle.KeyPEM(opts.Password)
		if err != nil {
			return nil, err
		}
		return &Export{base + ".key", mimePEM, keyPEM}, nil

	case FormatPKCS12:
		if opts.Password == "" {
			return nil, validationError("a password is required for PKCS#12 export")
		}
		data, err := bundle.PKCS12(opts.Password)
		if err != nil {
			return nil, err
		}
		return &Export{base + ".p12", "application/x-pkcs12", data}, nil

	case FormatK8s:
		data, err := s.kubernetesSecret(cert, bundle, opts)
		if err != nil {
			return nil, err
		}
		return &Export{base + "-tls-secret.yaml", mimeYAML, data}, nil

	case FormatNginx:
		return &Export{base + "-nginx.conf", "text/plain; charset=utf-8", nginxSnippet(cert, base)}, nil

	case FormatTraefik:
		return &Export{base + "-traefik.yaml", mimeYAML, traefikSnippet(base)}, nil

	case FormatHAProxy:
		return &Export{base + "-haproxy.cfg", "text/plain; charset=utf-8", haproxySnippet(base)}, nil

	case FormatGoma:
		return &Export{base + "-goma.yml", mimeYAML, gomaSnippet(cert, base)}, nil

	case FormatGomaRoute:
		return &Export{base + "-goma-route.yml", mimeYAML, gomaRouteSnippet(cert, base)}, nil

	case FormatCompose:
		return &Export{base + "-compose.yml", mimeYAML, composeSnippet(cert, base)}, nil

	case FormatZIP:
		data, err := s.zipBundle(cert, bundle, base, opts)
		if err != nil {
			return nil, err
		}
		return &Export{base + ".zip", "application/zip", data}, nil
	}

	return nil, validationError("unknown export format %q (want one of %s)",
		opts.Format, strings.Join(ExportFormats(), ", "))
}

// zipBundle packages every artifact for one certificate, plus a README that
// explains which file goes where.
func (s *Service) zipBundle(cert *store.Certificate, bundle pki.Bundle, base string, opts ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	if err := add(base+".crt", bundle.CertPEM()); err != nil {
		return nil, err
	}
	if err := add(base+"-fullchain.pem", bundle.FullChainPEM()); err != nil {
		return nil, err
	}
	if len(bundle.Chain) > 0 {
		if err := add(base+"-chain.pem", bundle.ChainPEM()); err != nil {
			return nil, err
		}
		if err := add("root.crt", bundle.RootPEM()); err != nil {
			return nil, err
		}
	}
	if bundle.PrivateKey != nil {
		keyPEM, err := bundle.KeyPEM(opts.Password)
		if err != nil {
			return nil, err
		}
		if err := add(base+".key", keyPEM); err != nil {
			return nil, err
		}
	}
	if cert.CSRPEM != "" {
		if err := add(base+".csr", []byte(cert.CSRPEM)); err != nil {
			return nil, err
		}
	}
	if err := add("README.txt", zipReadme(cert, base, bundle.PrivateKey != nil)); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip: %w", err)
	}
	return buf.Bytes(), nil
}

func zipReadme(cert *store.Certificate, base string, hasKey bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Certificate bundle for %s\n", cert.CommonName)
	fmt.Fprintf(&b, "Issued by Certio on %s\n\n", cert.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Serial number : %s\n", cert.SerialNumber)
	fmt.Fprintf(&b, "SHA-256       : %s\n", cert.FingerprintSHA256)
	fmt.Fprintf(&b, "Valid from    : %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(&b, "Valid until   : %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "SANs          : %s\n\n", strings.Join(cert.SANs.Data.Strings(), ", "))

	b.WriteString("Files\n-----\n")
	fmt.Fprintf(&b, "  %-28s the certificate on its own\n", base+".crt")
	fmt.Fprintf(&b, "  %-28s certificate + issuers, in that order\n", base+"-fullchain.pem")
	fmt.Fprintf(&b, "  %-28s the issuers only\n", base+"-chain.pem")
	fmt.Fprintf(&b, "  %-28s the trust anchor to install on clients\n", "root.crt")
	if hasKey {
		fmt.Fprintf(&b, "  %-28s the private key — keep it secret\n", base+".key")
	}

	b.WriteString("\nWhich file does my server want?\n")
	b.WriteString("  nginx      ssl_certificate -> fullchain.pem, ssl_certificate_key -> .key\n")
	b.WriteString("  Apache     SSLCertificateFile -> .crt, SSLCertificateChainFile -> chain.pem\n")
	b.WriteString("  HAProxy    one file containing the fullchain followed by the key\n")
	b.WriteString("  Traefik    certFile -> fullchain.pem, keyFile -> .key\n")
	b.WriteString("  Goma       cert -> fullchain.pem, key -> .key; or point certsDir at this folder\n")
	b.WriteString("  Go/Java    fullchain.pem plus the key; add root.crt to the trust store\n")
	return []byte(b.String())
}

// kubernetesSecret renders a kubernetes.io/tls Secret.
func (s *Service) kubernetesSecret(cert *store.Certificate, bundle pki.Bundle, opts ExportOptions) ([]byte, error) {
	if bundle.PrivateKey == nil {
		return nil, ErrKeyUnavailable
	}
	keyPEM, err := bundle.KeyPEM("")
	if err != nil {
		return nil, err
	}

	name := opts.SecretName
	if name == "" {
		name = safeFilename(cert.CommonName) + "-tls"
	}
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "default"
	}

	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", name, namespace)
	b.WriteString("  labels:\n    app.kubernetes.io/managed-by: certio\n")
	b.WriteString("  annotations:\n")
	fmt.Fprintf(&b, "    certio.jkaninda.dev/serial-number: %q\n", cert.SerialNumber)
	fmt.Fprintf(&b, "    certio.jkaninda.dev/not-after: %q\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "    certio.jkaninda.dev/certificate-id: %q\n", cert.ID)
	b.WriteString("data:\n")
	// The fullchain goes in tls.crt: an ingress controller serving only the
	// leaf breaks any client that lacks the intermediate.
	fmt.Fprintf(&b, "  tls.crt: %s\n", base64.StdEncoding.EncodeToString(bundle.FullChainPEM()))
	fmt.Fprintf(&b, "  tls.key: %s\n", base64.StdEncoding.EncodeToString(keyPEM))
	if len(bundle.Chain) > 0 {
		fmt.Fprintf(&b, "  ca.crt: %s\n", base64.StdEncoding.EncodeToString(bundle.RootPEM()))
	}
	return []byte(b.String()), nil
}

func nginxSnippet(cert *store.Certificate, base string) []byte {
	names := dnsNames(cert)

	var b strings.Builder
	b.WriteString("# Generated by Certio\nserver {\n    listen 443 ssl;\n    http2 on;\n")
	fmt.Fprintf(&b, "    server_name %s;\n\n", strings.Join(names, " "))
	fmt.Fprintf(&b, "    ssl_certificate     /etc/nginx/certs/%s-fullchain.pem;\n", base)
	fmt.Fprintf(&b, "    ssl_certificate_key /etc/nginx/certs/%s.key;\n\n", base)
	b.WriteString("    ssl_protocols       TLSv1.2 TLSv1.3;\n")
	b.WriteString("    ssl_session_cache   shared:SSL:10m;\n")
	b.WriteString("    ssl_session_timeout 1d;\n")
	b.WriteString("    ssl_prefer_server_ciphers off;\n\n")
	if cert.Profile == pki.ProfilePeer || cert.Profile == pki.ProfileClient {
		b.WriteString("    # Mutual TLS: require a client certificate from the same CA.\n")
		b.WriteString("    ssl_client_certificate /etc/nginx/certs/root.crt;\n")
		b.WriteString("    ssl_verify_client      on;\n")
		b.WriteString("    ssl_verify_depth       2;\n\n")
	}
	b.WriteString("    location / {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n")
	return []byte(b.String())
}

func traefikSnippet(base string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by Certio — a Traefik dynamic configuration file.\n")
	b.WriteString("tls:\n  certificates:\n")
	fmt.Fprintf(&b, "    - certFile: /certs/%s-fullchain.pem\n", base)
	fmt.Fprintf(&b, "      keyFile:  /certs/%s.key\n", base)
	b.WriteString("  stores:\n    default:\n      defaultCertificate:\n")
	fmt.Fprintf(&b, "        certFile: /certs/%s-fullchain.pem\n", base)
	fmt.Fprintf(&b, "        keyFile:  /certs/%s.key\n", base)
	b.WriteString("  options:\n    default:\n      minVersion: VersionTLS12\n")
	return []byte(b.String())
}

func haproxySnippet(base string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by Certio\n")
	b.WriteString("# HAProxy wants ONE file: the fullchain followed by the private key.\n")
	fmt.Fprintf(&b, "#   cat %s-fullchain.pem %s.key > /etc/haproxy/certs/%s.pem\n\n", base, base, base)
	b.WriteString("frontend https\n    bind *:443 ssl crt /etc/haproxy/certs/\n")
	b.WriteString("    mode http\n    option httplog\n")
	b.WriteString("    http-request set-header X-Forwarded-Proto https\n")
	b.WriteString("    default_backend app\n\n")
	b.WriteString("backend app\n    mode http\n    server app1 127.0.0.1:8080 check\n")
	return []byte(b.String())
}

// dnsNames returns the certificate's DNS SANs, falling back to the common name
// so a snippet never ends up with an empty host list.
func dnsNames(cert *store.Certificate) []string {
	names := make([]string, 0, len(cert.SANs.Data))
	for _, san := range cert.SANs.Data {
		if san.Type == pki.SANDNS {
			names = append(names, san.Value)
		}
	}
	if len(names) == 0 && cert.CommonName != "" {
		names = append(names, cert.CommonName)
	}
	return names
}

// gomaSnippet renders a Goma Gateway global TLS block.
//
// Goma accepts a file path, a base64 blob or raw PEM in `cert` and `key`.
// Paths are used here because they survive a renewal: the file is replaced and
// the gateway reloads, whereas inlined PEM would have to be regenerated.
func gomaSnippet(cert *store.Certificate, base string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by Certio — Goma Gateway global TLS configuration.\n")
	fmt.Fprintf(&b, "# Certificate: %s (expires %s)\n", cert.CommonName, cert.NotAfter.Format("2006-01-02"))
	b.WriteString("#\n")
	b.WriteString("# Goma matches a certificate to a request by SNI, against the certificate's\n")
	b.WriteString("# common name and SANs. This one covers:\n")
	for _, name := range dnsNames(cert) {
		fmt.Fprintf(&b, "#   %s\n", name)
	}
	b.WriteString("\nversion: 2\ngateway:\n  tls:\n    certificates:\n")
	// The fullchain goes in `cert`: serving the leaf alone breaks any client
	// that does not already hold the intermediate.
	fmt.Fprintf(&b, "      - cert: /etc/goma/certs/%s-fullchain.pem\n", base)
	fmt.Fprintf(&b, "        key: /etc/goma/certs/%s.key\n", base)
	b.WriteString("\n")
	b.WriteString("    # Fallback for a request whose SNI matches no certificate above.\n")
	b.WriteString("    # default:\n")
	fmt.Fprintf(&b, "    #   cert: /etc/goma/certs/%s-fullchain.pem\n", base)
	fmt.Fprintf(&b, "    #   key: /etc/goma/certs/%s.key\n", base)
	b.WriteString("\n")
	b.WriteString("    # Or drop the list entirely and let Goma discover every certificate in a\n")
	b.WriteString("    # directory. Files pair up by base name — <name>.crt/.cert/.pem with\n")
	b.WriteString("    # <name>.key — which is what the Certio ZIP export already produces.\n")
	b.WriteString("    # certsDir: /etc/goma/certs\n")
	return []byte(b.String())
}

// gomaRouteSnippet renders a Goma Gateway route with its own certificate.
// A route-level certificate takes precedence over the global list, which is
// what you want when one backend needs a certificate the rest do not.
func gomaRouteSnippet(cert *store.Certificate, base string) []byte {
	names := dnsNames(cert)

	var b strings.Builder
	b.WriteString("# Generated by Certio — Goma Gateway route with a dedicated certificate.\n")
	fmt.Fprintf(&b, "# Certificate: %s (expires %s)\n", cert.CommonName, cert.NotAfter.Format("2006-01-02"))
	b.WriteString("# A route-level certificate overrides the gateway-wide list for these hosts.\n")

	b.WriteString("\nversion: 2\ngateway:\n  routes:\n")
	b.WriteString("    - path: /\n")
	fmt.Fprintf(&b, "      name: %s\n", base)
	fmt.Fprintf(&b, "      hosts: [%s]\n", quoteList(names))
	b.WriteString("      backends:\n")
	b.WriteString("        - endpoint: http://127.0.0.1:8080\n")
	b.WriteString("      tls:\n")

	b.WriteString("        certificate:\n")
	fmt.Fprintf(&b, "          cert: /etc/goma/certs/%s-fullchain.pem\n", base)
	fmt.Fprintf(&b, "          key: /etc/goma/certs/%s.key\n", base)

	b.WriteString("        provider: none\n")

	if cert.Profile == pki.ProfilePeer || cert.Profile == pki.ProfileClient {
		b.WriteString("\n")
		b.WriteString("      # This certificate carries clientAuth, so it can also be presented to\n")
		b.WriteString("      # the backend instead of only being served to callers:\n")
		b.WriteString("      #   security:\n")
		b.WriteString("      #     tls:\n")
		fmt.Fprintf(&b, "      #       clientCert: /etc/goma/certs/%s.crt\n", base)
		fmt.Fprintf(&b, "      #       clientKey:  /etc/goma/certs/%s.key\n", base)
		b.WriteString("      #       rootCAs:    /etc/goma/certs/root.crt\n")
		b.WriteString("      #\n")
		b.WriteString("      # Verifying *incoming* callers is gateway-wide, not per route:\n")
		b.WriteString("      #   gateway:\n")
		b.WriteString("      #     tls:\n")
		b.WriteString("      #       clientAuth:\n")
		b.WriteString("      #         clientCA: /etc/goma/certs/root.crt\n")
		b.WriteString("      #         required: true\n")
	}
	return []byte(b.String())
}

// quoteList renders values as a YAML flow sequence body: "a", "b".
// Quoting matters here because a wildcard host is invalid YAML unquoted.
func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(quoted, ", ")
}

func composeSnippet(cert *store.Certificate, base string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by Certio — mount the bundle read-only into your service.\n")
	fmt.Fprintf(&b, "# Certificate: %s (expires %s)\n", cert.CommonName, cert.NotAfter.Format("2006-01-02"))
	b.WriteString("services:\n  app:\n    image: nginx:alpine\n    ports:\n      - \"443:443\"\n")
	b.WriteString("    volumes:\n")
	fmt.Fprintf(&b, "      - ./certs/%s-fullchain.pem:/etc/nginx/certs/%s-fullchain.pem:ro\n", base, base)
	fmt.Fprintf(&b, "      - ./certs/%s.key:/etc/nginx/certs/%s.key:ro\n", base, base)
	fmt.Fprintf(&b, "      - ./certs/%s-nginx.conf:/etc/nginx/conf.d/default.conf:ro\n", base)
	b.WriteString("    restart: unless-stopped\n")
	return []byte(b.String())
}

// safeFilename turns a common name — which may be a wildcard — into something
// safe on every filesystem.
func safeFilename(name string) string {
	replacer := strings.NewReplacer(
		"*", "wildcard", "/", "-", "\\", "-", ":", "-",
		" ", "-", "..", "-", "<", "-", ">", "-", "|", "-", "?", "-", "\"", "-",
	)
	out := strings.Trim(replacer.Replace(strings.ToLower(strings.TrimSpace(name))), "-.")
	out = strings.TrimPrefix(out, "wildcard.")
	if out == "" {
		return "certificate"
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// TrustInstructions is a per-platform recipe for installing a CA root.
type TrustInstructions struct {
	Platform string `json:"platform"`
	Title    string `json:"title"`
	Commands string `json:"commands"`
	Note     string `json:"note,omitempty"`
}

// TrustGuide returns the copy-paste instructions for trusting a CA root on
// each platform, which is the step that makes a private PKI actually usable.
func (s *Service) TrustGuide(a *store.Authority) []TrustInstructions {
	base := s.Config.Server.BaseURL
	rootURL := fmt.Sprintf("%s/ca/%s/root.crt", base, a.ID)
	file := safeFilename(a.Name) + "-root.crt"

	return []TrustInstructions{
		{
			Platform: "linux-debian",
			Title:    "Linux (Debian, Ubuntu)",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\nsudo cp %s /usr/local/share/ca-certificates/%s\nsudo update-ca-certificates",
				rootURL, file, file, strings.TrimSuffix(file, ".crt")+".crt"),
		},
		{
			Platform: "linux-rhel",
			Title:    "Linux (RHEL, Fedora, Rocky)",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\nsudo cp %s /etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust extract",
				rootURL, file, file),
		},
		{
			Platform: "macos",
			Title:    "macOS",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\nsudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain %s",
				rootURL, file, file),
			Note: "Firefox keeps its own trust store; import the root under Settings → Privacy & Security → Certificates.",
		},
		{
			Platform: "windows",
			Title:    "Windows (PowerShell as Administrator)",
			Commands: fmt.Sprintf(
				"Invoke-WebRequest -Uri %s -OutFile %s\nImport-Certificate -FilePath %s -CertStoreLocation Cert:\\LocalMachine\\Root",
				rootURL, file, file),
		},
		{
			Platform: "java",
			Title:    "Java keystore",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\nkeytool -importcert -trustcacerts -noprompt \\\n  -alias %s -file %s \\\n  -keystore \"$JAVA_HOME/lib/security/cacerts\" -storepass changeit",
				rootURL, file, Slugify(a.Name), file),
		},
		{
			Platform: "node",
			Title:    "Node.js",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\nexport NODE_EXTRA_CA_CERTS=\"$PWD/%s\"",
				rootURL, file, file),
			Note: "NODE_EXTRA_CA_CERTS is read once at startup; restart the process after setting it.",
		},
		{
			Platform: "docker",
			Title:    "Docker image",
			Commands: fmt.Sprintf(
				"# In your Dockerfile:\nCOPY %s /usr/local/share/ca-certificates/\nRUN update-ca-certificates",
				file),
		},
		{
			Platform: "curl",
			Title:    "One-off with curl or git",
			Commands: fmt.Sprintf(
				"curl -fsSL %s -o %s\ncurl --cacert %s https://your-service.example\ngit -c http.sslCAInfo=%s clone https://your-service.example/repo.git",
				rootURL, file, file, file),
		},
	}
}
