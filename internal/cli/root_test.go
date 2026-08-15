package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestCommandOutputGoesToStdout pins down a cobra default that is easy to get
// wrong: Command.Print falls back to *stderr* when no output is set. Left
// unset, `certio cert export … > cert.pem` would write an empty file and print
// the certificate to the terminal instead.
func TestCommandOutputGoesToStdout(t *testing.T) {
	root := newRootCmd()

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}

	if !strings.Contains(stdout.String(), "certio") {
		t.Errorf("command output did not reach stdout; stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
}

// TestRootCommandDefaultsToOsStdout checks the wiring itself, since the test
// above passes either way once SetOut is called explicitly.
func TestRootCommandDefaultsToOsStdout(t *testing.T) {
	root := newRootCmd()

	// OutOrStderr returns the configured output, falling back to stderr. With
	// the wiring in place it must not be stderr.
	if root.OutOrStderr() != root.OutOrStdout() {
		t.Error("the root command's output is not stdout, so piped results would go to stderr")
	}
}

func TestSlugAndPadHelpers(t *testing.T) {
	if got := pad("abc", 6); got != "abc   " {
		t.Errorf("pad = %q", got)
	}
	if got := pad("abcdef", 3); got != "abcdef" {
		t.Errorf("pad should not truncate: %q", got)
	}
	if got := truncate("abcdefgh", 4); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("ab", 4); got != "ab" {
		t.Errorf("truncate should leave short values alone: %q", got)
	}
}
