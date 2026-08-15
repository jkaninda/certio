package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jkaninda/certio/internal/app"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/spf13/cobra"
)

// webFS is set by the main package to the embedded SPA. It stays a package
// variable so the CLI does not import the embed target, which keeps `go test`
// on this package working before the frontend has ever been built.
var (
	webFS   fs.FS
	webRoot string
)

// SetWebFS registers the embedded dashboard.
func SetWebFS(fsys fs.FS, root string) {
	webFS, webRoot = fsys, root
}

func newServeCmd() *cobra.Command {
	var (
		port        int
		host        string
		noScheduler bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the API, dashboard and background scheduler",
		Long: "Starts the HTTP server, the embedded dashboard and the in-process scheduler.\n" +
			"This is the whole deployment: there is no external cron or worker to run.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := app.New(app.Options{
				ConfigPath: configPath, Version: build.Version,
				Commit: build.Commit, Date: build.Date,
				WebFS: webFS, WebRoot: webRoot, WithServer: true,
			})
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			if cmd.Flags().Changed("port") {
				instance.Config.Server.Port = port
			}
			if cmd.Flags().Changed("host") {
				instance.Config.Server.Host = host
			}
			if noScheduler {
				instance.Config.Scheduler.Enabled = false
			}

			if err := instance.Migrate(); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			instance.Scheduler.Start(ctx)

			// The listener runs on its own goroutine so the main one can wait
			// for a signal and shut everything down in order.
			errCh := make(chan error, 1)
			go func() {
				if err := instance.Server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}()

			instance.Log.Info("certio is ready",
				"version", build.Version,
				"addr", instance.Config.Addr(),
				"docs", instance.Config.Server.BaseURL+"/docs",
				"database", instance.Config.Database.Path)

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				instance.Log.Info("shutting down")
			}

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			instance.Scheduler.Stop()
			if err := instance.Server.Stop(shutdownCtx); err != nil {
				return err
			}
			instance.Log.Info("stopped cleanly")
			return nil
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "port to listen on")
	cmd.Flags().StringVar(&host, "host", "0.0.0.0", "address to bind")
	cmd.Flags().BoolVar(&noScheduler, "no-scheduler", false,
		"do not run expiry scanning, auto-renewal or CRL refresh")
	return cmd
}

func newMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Create or update the database schema",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := app.New(app.Options{ConfigPath: configPath, Version: build.Version})
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			if err := instance.Migrate(); err != nil {
				return err
			}
			cmd.Printf("schema is up to date (%s)\n", instance.Config.Database.Path)
			return nil
		},
	}
}

func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a master key for encrypting stored private keys",
		Long: "Prints a fresh 32-byte master key as hex.\n\n" +
			"Set it as CERTIO_MASTER_KEY, or write it to a file and point\n" +
			"CERTIO_MASTER_KEY_FILE at it. Losing this key means every stored\n" +
			"private key becomes permanently unreadable — back it up separately\n" +
			"from the database.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			master, err := certiocrypto.GenerateMasterKey()
			if err != nil {
				return err
			}
			jwtSecret, err := certiocrypto.RandomString(32)
			if err != nil {
				return err
			}

			cmd.Println("# Add these to your environment or secrets store.")
			cmd.Println("# Back the master key up somewhere other than the database it protects.")

			// The values go to stdout, not to cobra's Print (which writes to
			// stderr), because `eval "$(certio keygen)"` reads stdout. A failed
			// write is reported rather than swallowed: a half-printed key that
			// looks like a whole one is worse than an error.
			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "CERTIO_MASTER_KEY=%s\n", certiocrypto.FormatMasterKey(master)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "CERTIO_JWT_SECRET=%s\n", jwtSecret); err != nil {
				return err
			}
			return nil
		},
	}
}

func newScanCmd() *cobra.Command {
	var crl bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the expiry scan and auto-renewal pass once",
		Long: "Runs exactly what the background scheduler runs, then exits.\n" +
			"Useful from an external cron when --no-scheduler is set.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			instance.Scheduler.RunOnce(ctx)
			if crl {
				instance.Scheduler.RefreshCRLs(ctx)
			}
			cmd.Println("scan complete; see `certio` job history for details")
			return nil
		},
	}

	cmd.Flags().BoolVar(&crl, "crl", false, "also refresh every CA's revocation list")
	return cmd
}
