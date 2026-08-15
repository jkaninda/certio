// Command certio is the single binary that serves the API, the dashboard and
// the CLI for a self-hosted private PKI.
package main

import (
	"fmt"
	"os"

	"github.com/jkaninda/certio/internal/cli"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X main.commit=$(git rev-parse --short HEAD)"
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := cli.Execute(cli.BuildInfo{Version: version, Commit: commit, Date: date}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
