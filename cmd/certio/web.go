// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Certio - Self-signed PKI and TLS certificate management
// Copyright (C) 2026 Jonas Kaninda
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
