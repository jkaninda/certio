package cli

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/jkaninda/certio/internal/config"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage dashboard accounts",
	}
	cmd.AddCommand(userCreateCmd(), userListCmd(), userPasswordCmd(),
		userTwoFactorResetCmd(), userDeleteCmd())
	return cmd
}

// userTwoFactorResetCmd is the last way back into an instance whose only
// administrator lost both their authenticator and their recovery codes. It
// needs shell access to the host, which is the point: it is not something that
// can be reached over the network.
func userTwoFactorResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reset-2fa <email>",
		Short:   "Remove an account's two-factor authentication",
		Aliases: []string{"reset-mfa"},
		Long: "Clears the second factor so the account can sign in with its password alone.\n" +
			"Use it when a device and its recovery codes are both gone. The reset is audited.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			user, err := instance.Store.Users.GetByEmail(args[0])
			if err != nil {
				return err
			}
			if err := instance.Service.ResetTwoFactor(cliActor(), user.ID); err != nil {
				return err
			}
			cmd.Printf("two-factor authentication removed from %s\n", user.Email)
			cmd.Println("have them enrol a new device from Settings → Security.")
			return nil
		},
	}
}

func userCreateCmd() *cobra.Command {
	var email, name, role, password string

	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create an account",
		Example: "  CERTIO_USER_PASSWORD=… certio user create --email admin@jkaninda.dev --role admin",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if password == "" {
				password = promptSecret("CERTIO_USER_PASSWORD")
			}
			if password == "" {
				return fmt.Errorf("set CERTIO_USER_PASSWORD, or pass --password " +
					"(which will land in your shell history)")
			}

			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			user, err := instance.Service.CreateUser(cliActor(), service.CreateUserInput{
				Email: email, Name: name, Password: password, Role: role,
			})
			if err != nil {
				return err
			}
			cmd.Printf("created %s (%s)\n", user.Email, user.Role)
			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "email address (required)")
	cmd.Flags().StringVar(&name, "name", "", "display name")
	cmd.Flags().StringVar(&role, "role", store.RoleViewer, "admin, operator or viewer")
	cmd.Flags().StringVar(&password, "password", "",
		"password; prefer the CERTIO_USER_PASSWORD environment variable")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func userListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List accounts",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			page, err := instance.Store.Users.List(store.Pagination{Page: 1, Limit: 200})
			if err != nil {
				return err
			}
			if len(page.Items) == 0 {
				cmd.Println("no accounts yet — create one with `certio user create`")
				return nil
			}

			cmd.Printf("%s %s %s %s %s\n",
				pad("EMAIL", 34), pad("ROLE", 12), pad("STATUS", 12), pad("2FA", 6), "LAST LOGIN")
			for i := range page.Items {
				u := &page.Items[i]
				last := "never"
				if u.LastLoginAt != nil {
					last = u.LastLoginAt.Format("2006-01-02 15:04")
				}
				twoFactor := "off"
				if u.HasTwoFactor() {
					twoFactor = "on"
				}
				cmd.Printf("%s %s %s %s %s\n",
					pad(truncate(u.Email, 33), 34), pad(u.Role, 12), pad(u.Status, 12),
					pad(twoFactor, 6), last)
			}
			return nil
		},
	}
}

func userPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "password <email>",
		Short: "Set an account's password",
		Long:  "Reads the new password from CERTIO_USER_PASSWORD.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptSecret("CERTIO_USER_PASSWORD")
			if password == "" {
				return fmt.Errorf("set CERTIO_USER_PASSWORD to the new password")
			}

			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			user, err := instance.Store.Users.GetByEmail(args[0])
			if err != nil {
				return err
			}
			if _, err := instance.Service.UpdateUser(cliActor(), user.ID, service.UpdateUserInput{
				Password: &password,
			}); err != nil {
				return err
			}
			cmd.Printf("password updated for %s\n", user.Email)
			return nil
		},
	}
}

func userDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <email>",
		Short: "Delete an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			user, err := instance.Store.Users.GetByEmail(args[0])
			if err != nil {
				return err
			}
			if err := instance.Service.DeleteUser(cliActor(), user.ID); err != nil {
				return err
			}
			cmd.Printf("deleted %s\n", user.Email)
			return nil
		},
	}
}

func newBackupCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write a compressed backup of the database",
		Long: "Takes a consistent snapshot with SQLite's VACUUM INTO and archives it.\n" +
			"Safe to run against a live instance: a read lock is all it needs, so\n" +
			"there is no window in which a torn write can be captured.\n\n" +
			"Private keys stay AES-256-GCM encrypted inside the archive, so it is\n" +
			"only as sensitive as the master key is secret.\n\n" +
			"The master key is NOT included. Back it up separately — without it the\n" +
			"archive is unusable, and with it in the same place the encryption buys\n" +
			"you nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := openApp()
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			if out == "" {
				out = fmt.Sprintf("certio-backup-%s.tar.gz", time.Now().Format("20060102-150405"))
			}

			// The snapshot lands beside the archive rather than in the system
			// temp directory: it holds every encrypted private key, and a
			// world-readable /tmp is the wrong place for that even briefly.
			snapshot := out + ".snapshot"
			if err := instance.Store.Backup(snapshot); err != nil {
				return err
			}
			defer func() { _ = os.Remove(snapshot) }()

			if err := writeBackup(snapshot, out); err != nil {
				return err
			}

			info, err := os.Stat(out)
			if err != nil {
				return err
			}
			cmd.Printf("wrote %s (%.1f KiB)\n", out, float64(info.Size())/1024)
			cmd.Println("remember: the master key is not in this archive, and the archive is useless without it")
			return nil
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", "", "output path (default certio-backup-<timestamp>.tar.gz)")
	return cmd
}

// backupEntryName is the single file a backup archive contains. Pinning the
// name means restore does not have to guess, and an archive from some other
// tool is rejected instead of half-restored.
const backupEntryName = "certio.db"

func newRestoreCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "restore <archive>",
		Short: "Restore the database from a backup archive",
		Long: "Replaces the configured database with the one in the archive.\n\n" +
			"Stop the server first: restoring under a running instance leaves it\n" +
			"holding a file that no longer exists.\n\n" +
			"The existing database is moved aside to <path>.superseded-<timestamp>\n" +
			"rather than deleted, so a restore of the wrong archive is recoverable.\n\n" +
			"The master key is not in the archive and is not restored. The archive\n" +
			"is unreadable without the same key the backup was taken under.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if cfg.Database.Driver != config.DriverSQLite {
				return fmt.Errorf("restore is only implemented for sqlite, not %q", cfg.Database.Driver)
			}
			target := cfg.Database.Path
			if target == "" {
				return errors.New("database.path is not configured, so there is nothing to restore into")
			}

			// Registered before the extraction, so a truncated archive does not
			// leave a half-written file sitting next to the live database.
			restored := target + ".restoring"
			defer func() { _ = os.Remove(restored) }()

			if err := extractBackup(args[0], restored); err != nil {
				return err
			}

			// Opening the extracted file before touching the live one turns a
			// corrupt or truncated archive into a refusal rather than into a
			// destroyed database.
			if err := verifyDatabase(restored); err != nil {
				return fmt.Errorf("%s does not contain a usable Certio database: %w", args[0], err)
			}

			if _, err := os.Stat(target); err == nil {
				if !force {
					cmd.Printf("%s already exists.\n", target)
					return errors.New("refusing to replace an existing database without --force")
				}
				superseded := fmt.Sprintf("%s.superseded-%s", target, time.Now().Format("20060102-150405"))
				if err := os.Rename(target, superseded); err != nil {
					return fmt.Errorf("move the existing database aside: %w", err)
				}
				cmd.Printf("moved the existing database to %s\n", superseded)
				// The sidecars belong to the database that just moved; leaving
				// them would let SQLite replay a WAL against the restored file.
				for _, sidecar := range []string{target + "-wal", target + "-shm"} {
					_ = os.Remove(sidecar)
				}
			}

			if err := os.Rename(restored, target); err != nil {
				return fmt.Errorf("put the restored database in place: %w", err)
			}
			cmd.Printf("restored %s from %s\n", target, args[0])
			cmd.Println("start the server with the same CERTIO_MASTER_KEY the backup was taken under")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "replace an existing database (the old one is kept alongside)")
	return cmd
}

// verifyDatabase opens a candidate file and checks it holds the schema, so a
// truncated download is caught before it replaces anything.
func verifyDatabase(path string) error {
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=foreign_keys(1)"), &gorm.Config{
		Logger: gormlogger.Discard,
	})
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	}()

	if err := db.Exec("PRAGMA integrity_check").Error; err != nil {
		return err
	}
	if !db.Migrator().HasTable(&store.Authority{}) {
		return errors.New("no authorities table")
	}
	return nil
}

// writeBackup archives one snapshot file under a fixed entry name.
func writeBackup(snapshot, out string) error {
	archive, err := os.Create(out) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }()

	gz := gzip.NewWriter(archive)
	defer func() { _ = gz.Close() }()

	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	info, err := os.Stat(snapshot)
	if err != nil {
		return err
	}
	return addFileToTar(tw, snapshot, info)
}

func addFileToTar(tw *tar.Writer, path string, info os.FileInfo) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = backupEntryName
	// The snapshot inherits the umask; the archive should not widen it.
	header.Mode = 0o600

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	file, err := os.Open(path) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	_, err = io.Copy(tw, file)
	return err
}

// maxRestoreBytes caps what restore will write. A backup of a private PKI is
// megabytes; a gzip bomb is not something a restore command should sit through.
const maxRestoreBytes = 8 << 30

func extractBackup(archivePath, dst string) error {
	file, err := os.Open(archivePath) //nolint:gosec // G304: the operator names the archive to restore
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", archivePath, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", archivePath, err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}

		name := filepath.Base(header.Name)
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			continue
		}

		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // operator-provided path
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(tr, maxRestoreBytes))
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	}
	return fmt.Errorf("%s contains no database file", archivePath)
}
