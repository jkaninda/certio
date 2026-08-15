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
