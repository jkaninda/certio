package main

import (
	"embed"
	"io/fs"

	"github.com/jkaninda/certio/internal/cli"
)

// dist holds the built dashboard. `all:` is required so Nuxt's _nuxt directory
// — every asset filename starts with an underscore — is embedded too.
//
// The placeholder keeps `go build` working before the frontend has ever been
// built; `make ui` writes the real output over it.
//
//go:embed all:dist
var dist embed.FS

func init() {
	// A build without the dashboard still serves the API; the SPA fallback is
	// simply not registered.
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return
	}
	cli.SetWebFS(dist, "dist")
}
