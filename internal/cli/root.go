// Package cli implements the certio command tree. Every subcommand drives the
// same service layer the HTTP API does, so the terminal and the dashboard can
// never drift apart.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/jkaninda/certio/internal/app"
	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/store"
	"github.com/spf13/cobra"
)

// BuildInfo carries the values stamped in at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// configPath is the shared --config flag.
var configPath string

// build holds the link-time metadata for the running process.
var build BuildInfo

// Execute runs the command tree.
func Execute(info BuildInfo) error {
	build = info
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "certio",
		Short: "Self-signed PKI and TLS certificate manager",
		Long: "Certio manages a private certificate authority: create roots and intermediates,\n" +
			"issue and renew certificates with full SAN support, revoke and publish CRLs,\n" +
			"and export in every format a server actually wants.\n\n" +
			"The same engine backs the web dashboard, the REST API and this CLI.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       build.Version,
	}

	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "",
		"path to certio.yaml (environment variables always win)")

	root.AddCommand(
		newServeCmd(),
		newMigrateCmd(),
		newKeygenCmd(),
		newUserCmd(),
		newCACmd(),
		newCertCmd(),
		newScanCmd(),
		newBackupCmd(),
		newRestoreCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("certio %s (commit %s, built %s)\n", build.Version, build.Commit, build.Date)
			return nil
		},
	}
}

// openApp builds an instance without the HTTP layer, for commands that talk
// straight to the database.
func openApp() (*app.App, error) {
	instance, err := app.New(app.Options{ConfigPath: configPath, Version: build.Version})
	if err != nil {
		return nil, err
	}
	// Every command tolerates a database that has not been migrated yet: it is
	// less annoying than making the user remember to run `certio migrate`.
	if err := instance.Store.Migrate(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}

// cliActor labels changes made from the terminal, so the audit log
// distinguishes them from dashboard and API activity.
func cliActor() audit.Actor {
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	host, _ := os.Hostname()
	return audit.Actor{
		Type: store.ActorSystem,
		Name: fmt.Sprintf("cli:%s@%s", user, host),
	}
}

// promptSecret reads a value from an environment variable, since a CLI that
// takes a passphrase on the command line leaks it into the shell history.
func promptSecret(envKey string) string {
	return os.Getenv(envKey)
}

// truncate shortens a string for tabular output.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// pad right-pads a string to a fixed width for column output.
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
