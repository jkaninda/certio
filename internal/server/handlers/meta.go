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

package handlers

import (
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
)

// pkiProfiles maps the engine's profile table onto its API shape.
func pkiProfiles() []dto.ProfileResponse {
	profiles := pki.Profiles()
	out := make([]dto.ProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, dto.ProfileResponse{
			Name:         p.Name,
			Description:  p.Description,
			KeyUsage:     pki.KeyUsageStrings(p.KeyUsage),
			ExtKeyUsage:  pki.ExtKeyUsageStrings(p.ExtKeyUsage),
			ValidityDays: p.ValidityDays,
			IsCA:         p.IsCA,
		})
	}
	return out
}

func keyAlgorithms() []string { return pki.SupportedKeySpecs() }

func reasonName(code int) string { return pki.RevocationReasonName(code) }

func maxLeafValidity() int { return pki.MaxLeafValidityDays }

// tokenScopes maps the service's scope catalog onto its API shape, so the
// token form never hard-codes a list the backend enforces.
func tokenScopes() []dto.ScopeDTO {
	scopes := service.Scopes()
	out := make([]dto.ScopeDTO, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, dto.ScopeDTO{Name: s.Name, Description: s.Description})
	}
	return out
}
