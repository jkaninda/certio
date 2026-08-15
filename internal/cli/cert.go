package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/spf13/cobra"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cert",
		Short:   "Issue, renew, revoke and inspect certificates",
		Aliases: []string{"certificate", "certificates"},
	}
	cmd.AddCommand(
		certReleaseHoldCmd(),
		certIssueCmd(), certListCmd(), certShowCmd(), certRenewCmd(),
		certRevokeCmd(), certSignCmd(), certExportCmd(), certInspectCmd(),
	)
	return cmd
}

func certIssueCmd() *cobra.Command {
	var (
		ca, cn, org, country, profile, keyAlgo, out string
		sans                                        []string
		days                                        int
		autoRenew                                   bool
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate with a managed key pair",
		Example: "  certio cert issue --ca jkantech-root --cn \"*.jkaninda.dev\" \\\n" +
			"      --san dns:jkaninda.dev --san 'dns:*.jkaninda.dev' --san ip:127.0.0.1 \\\n" +
			"      --days 397 -o ./out",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			sanSet, err := parseSANFlags(sans)
			if err != nil {
				return err
			}

			result, err := instance.Service.Issue(cliActor(), service.IssueInput{
				AuthorityID: ca, CAPassphrase: promptSecret("CERTIO_CA_PASSPHRASE"),
				Subject:      pki.Subject{CommonName: cn, Organization: org, Country: country},
				SANs:         sanSet,
				Profile:      profile,
				KeyAlgorithm: keyAlgo,
				ValidityDays: days,
				AutoRenew:    autoRenew,
			})
			if err != nil {
				return err
			}

			cmd.Printf("issued certificate %s\n\n", result.Certificate.CommonName)
			printCertificate(cmd, result.Certificate, "")

			if out == "" {
				cmd.Println("\nPass -o <dir> to write the certificate, chain and key to disk.")
				return nil
			}
			return writeBundle(cmd, out, result)
		},
	}

	cmd.Flags().StringVar(&ca, "ca", "", "issuing CA id or slug (required)")
	cmd.Flags().StringVar(&cn, "cn", "", "common name (required)")
	cmd.Flags().StringVar(&org, "org", "", "organization")
	cmd.Flags().StringVar(&country, "country", "", "two-letter country code")
	cmd.Flags().StringArrayVar(&sans, "san", nil,
		"subject alternative name; repeatable. e.g. dns:api.example.com, ip:10.0.0.1, email:a@b.c, uri:spiffe://…")
	cmd.Flags().StringVar(&profile, "profile", "server", "server, client, peer or code-signing")
	cmd.Flags().StringVar(&keyAlgo, "key", "", "key algorithm: "+strings.Join(pki.SupportedKeySpecs(), ", "))
	cmd.Flags().IntVar(&days, "days", 0, "validity in days (default 397)")
	cmd.Flags().BoolVar(&autoRenew, "auto-renew", false, "let the scheduler renew this certificate")
	cmd.Flags().StringVarP(&out, "out", "o", "", "write cert, chain and key into this directory")
	_ = cmd.MarkFlagRequired("ca")
	_ = cmd.MarkFlagRequired("cn")
	return cmd
}

func certSignCmd() *cobra.Command {
	var ca, csrPath, profile, out string
	var days int

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an externally generated CSR",
		Long: "Signs a PKCS#10 request. The private key stays with whoever generated\n" +
			"the CSR — Certio never sees it, and cannot renew the certificate\n" +
			"later without either a new CSR or a rekey.",
		Example: "  certio cert sign --ca jkantech-root --csr server.csr -o ./out",
		RunE: func(cmd *cobra.Command, _ []string) error {
			csrPEM, err := os.ReadFile(csrPath) //nolint:gosec // operator-provided path
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}

			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			result, err := instance.Service.SignCSR(cliActor(), service.SignCSRInput{
				AuthorityID: ca, CAPassphrase: promptSecret("CERTIO_CA_PASSPHRASE"),
				CSRPEM: string(csrPEM), Profile: profile, ValidityDays: days,
			})
			if err != nil {
				return err
			}

			cmd.Printf("signed certificate %s\n\n", result.Certificate.CommonName)
			printCertificate(cmd, result.Certificate, "")
			if out != "" {
				return writeBundle(cmd, out, result)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ca, "ca", "", "issuing CA id or slug (required)")
	cmd.Flags().StringVar(&csrPath, "csr", "", "path to the CSR (required)")
	cmd.Flags().StringVar(&profile, "profile", "server", "server, client, peer or code-signing")
	cmd.Flags().IntVar(&days, "days", 0, "validity in days (default 397)")
	cmd.Flags().StringVarP(&out, "out", "o", "", "write cert and chain into this directory")
	_ = cmd.MarkFlagRequired("ca")
	_ = cmd.MarkFlagRequired("csr")
	return cmd
}

func certListCmd() *cobra.Command {
	var ca, status, expiringIn string
	var labels []string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List certificates",
		Aliases: []string{"ls"},
		Example: "  certio cert list --expiring-in 30d\n" +
			"  certio cert list --label env=prod --label team=payments",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			filter := store.CertificateFilter{
				Status: status, IncludeRevoked: true, SortBy: "not_after",
			}
			if ca != "" {
				row, err := instance.Store.Authorities.Resolve(ca)
				if err != nil {
					return err
				}
				filter.AuthorityID = row.ID
			}
			if expiringIn != "" {
				days, err := strconv.Atoi(strings.TrimSuffix(expiringIn, "d"))
				if err != nil {
					return fmt.Errorf("--expiring-in wants a number of days, e.g. 30 or 30d")
				}
				filter.ExpiringInDays = &days
			}
			for _, raw := range labels {
				key, value, ok := strings.Cut(raw, "=")
				if !ok || strings.TrimSpace(key) == "" {
					return fmt.Errorf("--label wants key=value, got %q", raw)
				}
				if filter.Labels == nil {
					filter.Labels = map[string]string{}
				}
				filter.Labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}

			page, err := instance.Store.Certificates.List(filter, store.Pagination{Page: 1, Limit: 200})
			if err != nil {
				return err
			}
			if len(page.Items) == 0 {
				cmd.Println("no certificates match")
				return nil
			}

			cmd.Printf("%s %s %s %s %s\n",
				pad("COMMON NAME", 34), pad("PROFILE", 14), pad("EXPIRES", 12),
				pad("SERIAL", 18), "STATUS")
			for i := range page.Items {
				cert := &page.Items[i]
				cmd.Printf("%s %s %s %s %s\n",
					pad(truncate(cert.CommonName, 33), 34),
					pad(cert.Profile, 14),
					pad(fmt.Sprintf("%dd", cert.DaysRemaining()), 12),
					pad(truncate(cert.SerialNumber, 17), 18),
					cert.DeriveStatus(instance.Config.Scheduler.ExpiryWarnDays))
			}
			cmd.Printf("\n%d certificate(s)\n", page.Total)
			return nil
		},
	}

	cmd.Flags().StringVar(&ca, "ca", "", "filter by issuing CA")
	cmd.Flags().StringVar(&status, "status", "", "active, expiring, expired, held or revoked")
	cmd.Flags().StringVar(&expiringIn, "expiring-in", "", "only those expiring within N days, e.g. 30d")
	cmd.Flags().StringSliceVar(&labels, "label", nil,
		"filter by label as key=value; repeat to require several (e.g. --label env=prod --label team=payments)")
	return cmd
}

func certShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show one certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			cert, ca, err := instance.Store.Certificates.GetWithAuthority(args[0])
			if err != nil {
				return err
			}
			printCertificate(cmd, cert, ca.Name)
			return nil
		},
	}
}

func certRenewCmd() *cobra.Command {
	var rekey bool
	var days int
	var out string

	cmd := &cobra.Command{
		Use:   "renew <id>",
		Short: "Renew a certificate",
		Long: "Creates a new certificate linked to the old one. Nothing is mutated in\n" +
			"place, so the previous certificate stays downloadable and revocable.\n" +
			"The key is preserved unless --rekey is passed, which keeps any pinning\n" +
			"that depends on it working.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			result, err := instance.Service.Renew(cliActor(), args[0], service.RenewInput{
				Trigger: "cli",
				Rekey:   rekey, ValidityDays: days,
				CAPassphrase: promptSecret("CERTIO_CA_PASSPHRASE"),
			})
			if err != nil {
				return err
			}

			cmd.Printf("renewed %s\n\n", result.Certificate.CommonName)
			printCertificate(cmd, result.Certificate, "")
			if out != "" {
				return writeBundle(cmd, out, result)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rekey, "rekey", false, "generate a fresh key pair")
	cmd.Flags().IntVar(&days, "days", 0, "validity in days (defaults to the original)")
	cmd.Flags().StringVarP(&out, "out", "o", "", "write the renewed bundle into this directory")
	return cmd
}

func certRevokeCmd() *cobra.Command {
	var reason int

	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a certificate and republish the CRL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			rev, err := instance.Service.Revoke(cliActor(), args[0], service.RevokeInput{
				ReasonCode: reason, CAPassphrase: promptSecret("CERTIO_CA_PASSPHRASE"),
			})
			if err != nil {
				return err
			}

			cmd.Printf("revoked serial %s (%s) at %s\n",
				rev.SerialNumber, rev.Reason, rev.RevokedAt.Format(time.RFC3339))
			cmd.Println("the CA's CRL has been republished")
			return nil
		},
	}

	cmd.Flags().IntVar(&reason, "reason", 0,
		"RFC 5280 reason code: 0 unspecified, 1 keyCompromise, 4 superseded, 5 cessationOfOperation")
	return cmd
}

func certExportCmd() *cobra.Command {
	var format, out, password string

	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a certificate in any supported format",
		Long:  "Formats: " + strings.Join(service.ExportFormats(), ", "),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			bundle, cert, err := instance.Service.LoadBundle(args[0], service.FormatNeedsKey(format))
			if err != nil {
				return err
			}

			export, err := instance.Service.ExportCertificate(cert, bundle, service.ExportOptions{
				Format: format, Password: password,
			})
			if err != nil {
				return err
			}

			if out == "" {
				cmd.Print(string(export.Data))
				return nil
			}
			path := out
			if info, err := os.Stat(out); err == nil && info.IsDir() {
				path = filepath.Join(out, export.Filename)
			}
			if err := os.WriteFile(path, export.Data, 0o600); err != nil {
				return err
			}
			cmd.Printf("wrote %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "pem", "export format")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file or directory; stdout when empty")
	cmd.Flags().StringVar(&password, "password", "", "password for the p12 format")
	return cmd
}

func certInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file>",
		Short: "Decode a certificate, chain, CSR, key or CRL",
		Long:  "The local equivalent of `openssl x509 -text`, for any PEM Certio understands.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0]) // operator-provided path
			if err != nil {
				return err
			}

			result, err := pki.Inspect(data)
			if err != nil {
				return err
			}

			switch result.Kind {
			case pki.KindCertificate:
				printDetails(cmd, result.Certificate)
				for i := range result.Chain {
					cmd.Printf("\n--- chain[%d] ---\n", i)
					printDetails(cmd, &result.Chain[i])
				}
			case pki.KindCSR:
				cmd.Printf("Kind             certificate signing request\n")
				cmd.Printf("Subject          %s\n", result.CSR.DN)
				cmd.Printf("Key              %s\n", result.CSR.KeyAlgorithm)
				cmd.Printf("Signature        %s\n", result.CSR.SignatureAlgorithm)
				cmd.Printf("SANs             %s\n", strings.Join(result.CSR.SANs.Strings(), ", "))
			case pki.KindPrivateKey:
				cmd.Printf("Kind             private key\n")
				cmd.Printf("Key              %s\n", result.Key.KeyAlgorithm)
			case pki.KindCRL:
				cmd.Printf("Kind             certificate revocation list\n")
				cmd.Printf("Issuer           %s\n", result.CRL.Issuer)
				cmd.Printf("Number           %s\n", result.CRL.Number)
				cmd.Printf("This update      %s\n", result.CRL.ThisUpdate.Format(time.RFC3339))
				cmd.Printf("Next update      %s\n", result.CRL.NextUpdate.Format(time.RFC3339))
				cmd.Printf("Revoked          %d\n", len(result.CRL.Entries))
				for _, entry := range result.CRL.Entries {
					cmd.Printf("  %s  %s  %s\n",
						pad(entry.SerialNumber, 34), pad(entry.Reason, 22),
						entry.RevokedAt.Format(time.RFC3339))
				}
			}
			return nil
		},
	}
}

func printDetails(cmd *cobra.Command, d *pki.CertificateDetails) {
	cmd.Printf("Kind             certificate\n")
	cmd.Printf("Subject          %s\n", d.SubjectDN)
	cmd.Printf("Issuer           %s\n", d.IssuerDN)
	cmd.Printf("Serial           %s\n", d.SerialNumber)
	cmd.Printf("Valid            %s → %s (%d days left)\n",
		d.NotBefore.Format("2006-01-02"), d.NotAfter.Format("2006-01-02"), d.DaysRemaining)
	cmd.Printf("Key              %s\n", d.KeyAlgorithm)
	cmd.Printf("Signature        %s\n", d.SignatureAlgorithm)
	cmd.Printf("Is CA            %t\n", d.IsCA)
	cmd.Printf("Profile          %s\n", d.Profile)
	cmd.Printf("Key usage        %s\n", strings.Join(d.KeyUsage, ", "))
	cmd.Printf("Ext key usage    %s\n", strings.Join(d.ExtKeyUsage, ", "))
	cmd.Printf("SANs             %s\n", strings.Join(d.SANs.Strings(), ", "))
	cmd.Printf("SHA-256          %s\n", d.FingerprintSHA256)
}

func printCertificate(cmd *cobra.Command, cert *store.Certificate, caName string) {
	cmd.Printf("  ID               %s\n", cert.ID)
	cmd.Printf("  Common name      %s\n", cert.CommonName)
	if caName != "" {
		cmd.Printf("  Issued by        %s\n", caName)
	}
	cmd.Printf("  Profile          %s\n", cert.Profile)
	cmd.Printf("  Key              %s\n",
		pki.KeySpec{Algorithm: cert.KeyAlgorithm, Size: cert.KeySize, Curve: cert.KeyCurve}.Display())
	cmd.Printf("  Serial           %s\n", cert.SerialNumber)
	cmd.Printf("  SHA-256          %s\n", cert.FingerprintSHA256)
	cmd.Printf("  SANs             %s\n", strings.Join(cert.SANs.Data.Strings(), ", "))
	cmd.Printf("  Valid            %s → %s (%d days left)\n",
		cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), cert.DaysRemaining())
	cmd.Printf("  Status           %s\n", cert.Status)
	if cert.AutoRenew {
		cmd.Printf("  Auto-renew       yes, %d days before expiry\n", cert.RenewBeforeDays)
	}
}

// writeBundle writes the certificate, chain and key of a fresh issuance.
func writeBundle(cmd *cobra.Command, dir string, result *service.IssueResult) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	base := service.Slugify(result.Certificate.CommonName)

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{base + ".crt", result.Bundle.CertPEM(), 0o644},
		{base + "-fullchain.pem", result.Bundle.FullChainPEM(), 0o644},
	}
	if len(result.Bundle.Chain) > 0 {
		files = append(files,
			struct {
				name string
				data []byte
				mode os.FileMode
			}{base + "-chain.pem", result.Bundle.ChainPEM(), 0o644},
			struct {
				name string
				data []byte
				mode os.FileMode
			}{"root.crt", result.Bundle.RootPEM(), 0o644},
		)
	}
	if len(result.PrivateKeyPEM) > 0 {
		// 0600: the key is the one file here that must not be world-readable.
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{base + ".key", result.PrivateKeyPEM, 0o600})
	}

	cmd.Println()
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			return err
		}
		cmd.Printf("wrote %s\n", path)
	}
	return nil
}

// parseSANFlags turns repeated --san values into a validated set.
func parseSANFlags(values []string) (pki.SANSet, error) {
	var set pki.SANSet
	for _, raw := range values {
		san, err := pki.ParseSAN(raw)
		if err != nil {
			return nil, err
		}
		set = set.Add(san)
	}
	return set, nil
}

// certReleaseHoldCmd lifts a certificateHold.
func certReleaseHoldCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "release-hold <id>",
		Short: "Lift a certificateHold and republish the CRL",
		Long: "Reverses a revocation made with --reason 6 (certificateHold), the only\n" +
			"reversible reason RFC 5280 defines. A certificate revoked for any other\n" +
			"reason stays revoked — that is not something a command should undo.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			cert, err := instance.Service.ReleaseHold(cliActor(), args[0],
				promptSecret("CERTIO_CA_PASSPHRASE"))
			if err != nil {
				return err
			}
			cmd.Printf("released the hold on %s (%s)\n", cert.CommonName, cert.SerialNumber)
			cmd.Println("the CRL has been republished without it")
			return nil
		},
	}
}
