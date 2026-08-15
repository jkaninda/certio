package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH writes the certificate onto a server over SSH and runs a reload command.
//
// Files are written by piping into `cat` inside a shell that has already set a
// restrictive umask, rather than over SFTP: it needs no subsystem enabled on
// the far end, and it keeps the private key from existing world-readable even
// momentarily. The write goes to a temporary file and is then moved into
// place, so a server reading the file during the copy never sees half of one.
type SSH struct {
	Host string
	Port int
	User string
	// PrivateKeyPEM authenticates to the host. Password is the fallback for
	// an appliance that allows nothing else.
	PrivateKeyPEM string
	Passphrase    string
	Password      string

	// HostKey is the expected public key, in authorized_keys form. Deploying
	// a private key to a host whose identity was never checked would hand it
	// to whoever answers the address.
	HostKey string
	// InsecureIgnoreHostKey disables that check. It is a deliberate opt-in and
	// it is named to be unpleasant to type.
	InsecureIgnoreHostKey bool

	// Paths to write. An empty path is skipped, so a target can deploy the
	// fullchain alone if that is all the server reads.
	CertPath      string
	KeyPath       string
	ChainPath     string
	FullchainPath string
	RootPath      string

	// ReloadCommand runs after a successful write, e.g. "systemctl reload nginx".
	ReloadCommand string
	// FileMode is applied to everything except the key, which is always 0600.
	FileMode string
}

// Kind identifies the target type.
func (s *SSH) Kind() string { return KindSSH }

// Describe summarises the target without naming any credential.
func (s *SSH) Describe() string {
	return fmt.Sprintf("%s@%s", s.User, net.JoinHostPort(s.Host, strconv.Itoa(s.port())))
}

func (s *SSH) port() int {
	if s.Port > 0 {
		return s.Port
	}
	return 22
}

// Deploy copies the bundle and reloads the service.
func (s *SSH) Deploy(ctx context.Context, bundle Bundle) error {
	auth, err := s.authMethods()
	if err != nil {
		return err
	}
	hostKeyCallback, err := s.hostKeyCallback()
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            s.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         20 * time.Second,
	}

	dialer := &net.Dialer{Timeout: 20 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.port())))
	if err != nil {
		return fmt.Errorf("deploy: dial %s: %w", s.Describe(), err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(s.Host, strconv.Itoa(s.port())), config)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("deploy: ssh handshake with %s: %w", s.Describe(), err)
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	writes := []struct {
		path    string
		content []byte
		mode    string
	}{
		{s.CertPath, bundle.CertificatePEM, s.fileMode()},
		{s.FullchainPath, bundle.FullchainPEM, s.fileMode()},
		{s.ChainPath, bundle.ChainPEM, s.fileMode()},
		{s.RootPath, bundle.RootPEM, s.fileMode()},
		// The key is never given the configured mode: 0600 is the only
		// defensible answer and making it configurable invites 0644.
		{s.KeyPath, bundle.PrivateKeyPEM, "0600"},
	}

	wrote := 0
	for _, w := range writes {
		if w.path == "" || len(w.content) == 0 {
			continue
		}
		if err := s.writeFile(ctx, sshClient, w.path, w.content, w.mode); err != nil {
			return err
		}
		wrote++
	}
	if wrote == 0 {
		return errors.New("deploy: this ssh target has no paths configured, so there is nothing to write")
	}

	if s.ReloadCommand != "" {
		if err := s.run(ctx, sshClient, s.ReloadCommand); err != nil {
			return fmt.Errorf("deploy: files were written to %s but the reload failed: %w", s.Describe(), err)
		}
	}
	return nil
}

// writeFile streams content into a temporary file and moves it into place.
func (s *SSH) writeFile(ctx context.Context, sshClient *ssh.Client, path string, content []byte, mode string) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("deploy: open a session on %s: %w", s.Describe(), err)
	}
	defer func() { _ = session.Close() }()

	session.Stdin = bytes.NewReader(content)
	var stderr bytes.Buffer
	session.Stderr = &stderr

	// umask before the redirect, so the temporary file is never briefly
	// readable. The move is atomic within a filesystem, so a server reloading
	// mid-deploy reads either the old file or the new one.
	quoted := shellQuote(path)
	temp := shellQuote(path + ".certio-tmp")
	script := fmt.Sprintf(
		"umask 077 && cat > %s && chmod %s %s && mv -f %s %s",
		temp, shellQuote(mode), temp, temp, quoted)

	if err := runSession(ctx, session, script); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("deploy: write %s on %s: %w (%s)", path, s.Describe(), err, detail)
		}
		return fmt.Errorf("deploy: write %s on %s: %w", path, s.Describe(), err)
	}
	return nil
}

// run executes the reload command.
func (s *SSH) run(ctx context.Context, sshClient *ssh.Client, command string) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr

	if err := runSession(ctx, session, command); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return fmt.Errorf("%w: %s", err, detail)
		}
		return err
	}
	return nil
}

// runSession runs a command and honours the context, which ssh.Session does
// not do on its own: a hung reload would otherwise hold the deployment pass
// open indefinitely.
func runSession(ctx context.Context, session *ssh.Session, command string) error {
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return ctx.Err()
	}
}

func (s *SSH) fileMode() string {
	if s.FileMode != "" {
		return s.FileMode
	}
	return "0644"
}

func (s *SSH) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if s.PrivateKeyPEM != "" {
		var (
			signer ssh.Signer
			err    error
		)
		if s.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.PrivateKeyPEM), []byte(s.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(s.PrivateKeyPEM))
		}
		if err != nil {
			return nil, fmt.Errorf("deploy: parse the ssh private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		methods = append(methods, ssh.Password(s.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("deploy: an ssh target needs private_key or password")
	}
	return methods, nil
}

// hostKeyCallback pins the expected host key.
func (s *SSH) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if s.InsecureIgnoreHostKey {
		//nolint:gosec // explicit opt-in, and the config field says so
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if s.HostKey == "" {
		return nil, errors.New(
			"deploy: an ssh target needs host_key (the line ssh-keyscan prints), " +
				"or insecure_ignore_host_key=true to accept any host — which hands the " +
				"private key to whoever answers the address")
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.HostKey))
	if err != nil {
		return nil, fmt.Errorf("deploy: parse host_key: %w", err)
	}
	return ssh.FixedHostKey(key), nil
}

// shellQuote wraps a value in single quotes for the remote shell, escaping any
// single quote it contains. Paths come from configuration rather than from a
// request, but a path with a quote in it should fail as a bad path and not as
// a command.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func buildSSH(config map[string]string) (Target, error) {
	port, _ := strconv.Atoi(config["port"])
	insecure, _ := strconv.ParseBool(config["insecure_ignore_host_key"])

	target := &SSH{
		Host:                  config["host"],
		Port:                  port,
		User:                  firstNonEmpty(config["user"], config["username"], "root"),
		PrivateKeyPEM:         firstNonEmpty(config["private_key"], config["key"]),
		Passphrase:            config["passphrase"],
		Password:              config["password"],
		HostKey:               config["host_key"],
		InsecureIgnoreHostKey: insecure,
		CertPath:              config["cert_path"],
		KeyPath:               config["key_path"],
		ChainPath:             config["chain_path"],
		FullchainPath:         config["fullchain_path"],
		RootPath:              config["root_path"],
		ReloadCommand:         firstNonEmpty(config["reload_command"], config["reload"]),
		FileMode:              config["file_mode"],
	}
	if target.Host == "" {
		return nil, errors.New("deploy: an ssh target needs a host")
	}
	if target.CertPath == "" && target.KeyPath == "" &&
		target.ChainPath == "" && target.FullchainPath == "" && target.RootPath == "" {
		return nil, errors.New(
			"deploy: an ssh target needs at least one path to write " +
				"(cert_path, key_path, chain_path, fullchain_path or root_path)")
	}
	// Building the auth and the host-key callback now means a missing key or a
	// forgotten host_key is reported while the form is open, not at 3 a.m.
	// during an unattended renewal.
	if _, err := target.authMethods(); err != nil {
		return nil, err
	}
	if _, err := target.hostKeyCallback(); err != nil {
		return nil, err
	}
	return target, nil
}
