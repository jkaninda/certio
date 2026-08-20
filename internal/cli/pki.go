package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ca",
		Short:   "Manage certificate authorities",
		Aliases: []string{"authority", "authorities"},
	}
	cmd.AddCommand(caCreateCmd(), caListCmd(), caShowCmd(), caImportCmd(), caExportCmd(), caCRLCmd())
	return cmd
}

func caCreateCmd() *cobra.Command {
	var (
		name, cn, org, country, province, locality string
		caType, parent, keyAlgo                    string
		days, pathLen                              int
		usePathLen                                 bool

		permitDNS, excludeDNS     []string
		permitIP, excludeIP       []string
		permitEmail, excludeEmail []string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a root or intermediate certificate authority",
		Example: "  certio ca create --name \"jkanTech Root\" --cn \"jkanTech Root CA\" \\\n" +
			"      --org jkanTech --country CD --days 3650\n\n" +
			"  certio ca create --type intermediate --parent jkantech-root \\\n" +
			"      --cn \"jkanTech Issuing CA\" --days 1825",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			in := service.CreateAuthorityInput{
				Name: name, Type: caType, ParentID: parent,
				Subject: pki.Subject{
					CommonName: cn, Organization: org, Country: country,
					Province: province, Locality: locality,
				},
				KeyAlgorithm: keyAlgo, ValidityDays: days,
				// A passphrase on argv would land in the shell history.
				Passphrase:       promptSecret("CERTIO_CA_PASSPHRASE"),
				ParentPassphrase: promptSecret("CERTIO_PARENT_PASSPHRASE"),
			}
			if usePathLen {
				in.MaxPathLen = &pathLen
			}
			in.NameConstraints = pki.NameConstraints{
				PermittedDNS: permitDNS, ExcludedDNS: excludeDNS,
				PermittedIP: permitIP, ExcludedIP: excludeIP,
				PermittedEmail: permitEmail, ExcludedEmail: excludeEmail,
			}

			ca, err := instance.Service.CreateAuthority(cliActor(), in)
			if err != nil {
				return err
			}

			cmd.Printf("created %s certificate authority\n\n", ca.Type)
			printAuthority(cmd, ca)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "display name (defaults to the common name)")
	cmd.Flags().StringVar(&cn, "cn", "", "common name (required)")
	cmd.Flags().StringVar(&org, "org", "", "organization")
	cmd.Flags().StringVar(&country, "country", "", "two-letter country code")
	cmd.Flags().StringVar(&province, "province", "", "state or province")
	cmd.Flags().StringVar(&locality, "locality", "", "locality")
	cmd.Flags().StringVar(&caType, "type", "root", "root or intermediate")
	cmd.Flags().StringVar(&parent, "parent", "", "issuing CA id or slug (required for an intermediate)")
	cmd.Flags().StringVar(&keyAlgo, "key", "", "key algorithm: "+strings.Join(pki.SupportedKeySpecs(), ", "))
	cmd.Flags().IntVar(&days, "days", 0, "validity in days (default 3650 root, 1825 intermediate)")
	cmd.Flags().IntVar(&pathLen, "path-len", 0, "how many CAs may sit below this one")
	cmd.Flags().BoolVar(&usePathLen, "set-path-len", false, "apply --path-len as a basicConstraints pathLenConstraint")
	cmd.Flags().StringSliceVar(&permitDNS, "permit-dns", nil,
		"limit this CA to a domain and its subdomains (repeatable) — recommended for any root you install in a trust store")
	cmd.Flags().StringSliceVar(&excludeDNS, "exclude-dns", nil, "domain this CA may never certify (repeatable)")
	cmd.Flags().StringSliceVar(&permitIP, "permit-ip", nil, "CIDR range this CA may certify, e.g. 10.0.0.0/8 (repeatable)")
	cmd.Flags().StringSliceVar(&excludeIP, "exclude-ip", nil, "CIDR range this CA may never certify (repeatable)")
	cmd.Flags().StringSliceVar(&permitEmail, "permit-email", nil, "address, host or domain this CA may certify (repeatable)")
	cmd.Flags().StringSliceVar(&excludeEmail, "exclude-email", nil, "address, host or domain this CA may never certify (repeatable)")
	_ = cmd.MarkFlagRequired("cn")
	return cmd
}

func caListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List certificate authorities",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			rows, err := instance.Store.Authorities.All()
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				cmd.Println("no certificate authorities yet — create one with `certio ca create`")
				return nil
			}

			cmd.Printf("%s %s %s %s %s\n",
				pad("SLUG", 24), pad("TYPE", 14), pad("COMMON NAME", 32), pad("EXPIRES", 12), "STATUS")
			for i := range rows {
				ca := &rows[i]
				days := int(time.Until(ca.NotAfter).Hours() / 24)
				cmd.Printf("%s %s %s %s %s\n",
					pad(truncate(ca.Slug, 23), 24),
					pad(ca.Type, 14),
					pad(truncate(ca.Subject.Data.CommonName, 31), 32),
					pad(fmt.Sprintf("%dd", days), 12),
					ca.Status)
			}
			return nil
		},
	}
}

func caShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id-or-slug>",
		Short: "Show one certificate authority",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			ca, err := instance.Store.Authorities.Resolve(args[0])
			if err != nil {
				return err
			}
			printAuthority(cmd, ca)

			certs, err := instance.Store.Certificates.ByAuthority(ca.ID)
			if err != nil {
				return err
			}
			cmd.Printf("  Issued           %d certificate(s)\n", len(certs))
			return nil
		},
	}
}

func caImportCmd() *cobra.Command {
	var name, certPath, keyPath string

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Adopt an existing CA from PEM files",
		Long: "Imports a CA that was created elsewhere — for example one generated by\n" +
			"the openssl recipes this project replaces. Nothing is re-issued; the\n" +
			"existing certificate and key are adopted as they are.",
		Example: "  certio ca import --cert certs/example-ca.crt --key certs/example-ca.key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			certPEM, err := os.ReadFile(certPath) //nolint:gosec // operator-provided path
			if err != nil {
				return fmt.Errorf("read certificate: %w", err)
			}
			keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // operator-provided path
			if err != nil {
				return fmt.Errorf("read key: %w", err)
			}

			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			ca, err := instance.Service.ImportAuthority(cliActor(), service.ImportAuthorityInput{
				Name: name, CertPEM: string(certPEM), KeyPEM: string(keyPEM),
				Passphrase: promptSecret("CERTIO_CA_PASSPHRASE"),
			})
			if err != nil {
				return err
			}

			cmd.Printf("imported certificate authority\n\n")
			printAuthority(cmd, ca)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "display name (defaults to the certificate's common name)")
	cmd.Flags().StringVar(&certPath, "cert", "", "path to the CA certificate PEM (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the CA private key PEM (required)")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func caExportCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "export <id-or-slug>",
		Short: "Write a CA's root certificate and chain to disk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			ca, err := instance.Store.Authorities.Resolve(args[0])
			if err != nil {
				return err
			}
			if err := os.MkdirAll(out, 0o750); err != nil {
				return err
			}

			base := service.Slugify(ca.Name)
			rootPath := filepath.Join(out, base+"-root.crt")
			if err := os.WriteFile(rootPath, []byte(ca.CertPEM), 0o644); err != nil { //nolint:gosec // a public certificate
				return err
			}
			cmd.Printf("wrote %s\n", rootPath)

			chain, err := instance.Store.Authorities.Chain(ca)
			if err != nil {
				return err
			}
			if len(chain) > 0 {
				pemBytes := []byte(ca.CertPEM)
				for _, parent := range chain {
					pemBytes = append(pemBytes, parent.CertPEM...)
				}
				chainPath := filepath.Join(out, base+"-chain.pem")
				if err := os.WriteFile(chainPath, pemBytes, 0o644); err != nil { //nolint:gosec // public certificates
					return err
				}
				cmd.Printf("wrote %s\n", chainPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", ".", "output directory")
	return cmd
}

func caCRLCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "crl <id-or-slug>",
		Short: "Regenerate and publish a CA's revocation list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			der, err := instance.Service.GenerateCRL(cliActor(), args[0],
				promptSecret("CERTIO_CA_PASSPHRASE"))
			if err != nil {
				return err
			}

			if out == "" {
				cmd.Print(string(pki.EncodeCRLPEM(der)))
				return nil
			}
			if err := os.WriteFile(out, pki.EncodeCRLPEM(der), 0o644); err != nil { //nolint:gosec // a public CRL
				return err
			}
			cmd.Printf("wrote %s\n", out)
			return nil
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", "", "write the CRL here instead of stdout")
	return cmd
}

func printAuthority(cmd *cobra.Command, ca *store.Authority) {
	cmd.Printf("  ID               %s\n", ca.ID)
	cmd.Printf("  Slug             %s\n", ca.Slug)
	cmd.Printf("  Name             %s\n", ca.Name)
	cmd.Printf("  Type             %s\n", ca.Type)
	cmd.Printf("  Subject          %s\n", ca.Subject.Data.DN())
	cmd.Printf("  Key              %s\n", ca.KeySpec().Display())
	cmd.Printf("  Serial           %s\n", ca.SerialNumber)
	cmd.Printf("  SHA-256          %s\n", ca.FingerprintSHA256)
	cmd.Printf("  Valid            %s → %s (%d days left)\n",
		ca.NotBefore.Format("2006-01-02"), ca.NotAfter.Format("2006-01-02"),
		int(time.Until(ca.NotAfter).Hours()/24))
	cmd.Printf("  Status           %s\n", ca.Status)
	if ca.PassphraseProtected {
		cmd.Printf("  Passphrase       required (set CERTIO_CA_PASSPHRASE to use this CA)\n")
	}
	if ca.CRLURL != "" {
		cmd.Printf("  CRL              %s\n", ca.CRLURL)
	}
	if ca.OCSPURL != "" {
		cmd.Printf("  OCSP             %s\n", ca.OCSPURL)
	}
	printNameConstraints(cmd, ca.NameConstraints.Data)
}

// printNameConstraints reports what a CA may certify. An unconstrained CA says
// so explicitly rather than staying silent: "this CA can certify any name on
// the internet" is worth reading before installing its root in a trust store.
func printNameConstraints(cmd *cobra.Command, n pki.NameConstraints) {
	if n.IsZero() {
		cmd.Printf("  Constraints      none — this CA may certify any name\n")
		return
	}
	for _, row := range []struct {
		label  string
		values []string
	}{
		{"Permitted DNS", n.PermittedDNS},
		{"Excluded DNS", n.ExcludedDNS},
		{"Permitted IP", n.PermittedIP},
		{"Excluded IP", n.ExcludedIP},
		{"Permitted email", n.PermittedEmail},
		{"Excluded email", n.ExcludedEmail},
		{"Permitted URI", n.PermittedURI},
		{"Excluded URI", n.ExcludedURI},
	} {
		if len(row.values) > 0 {
			cmd.Printf("  %-16s %s\n", row.label, strings.Join(row.values, ", "))
		}
	}
}
