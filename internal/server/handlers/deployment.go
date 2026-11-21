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
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/okapi"
)

// ListDeployments returns every configured deployment target.
func (h *Handler) ListDeployments(c *okapi.Context) error {
	rows, err := h.Service.Store.Deployments.All()
	if err != nil {
		return h.fail(c, err)
	}
	items := make([]dto.DeploymentResponse, 0, len(rows))
	for i := range rows {
		items = append(items, dto.NewDeploymentResponse(&rows[i]))
	}
	return c.OK(dto.DeploymentListResponse{Items: items, Total: len(items)})
}

// CreateDeployment configures a target.
func (h *Handler) CreateDeployment(c *okapi.Context, req *dto.CreateDeploymentRequest) error {
	in := req.Body
	row, err := h.Service.CreateDeploymentTarget(h.actor(c), service.CreateDeploymentInput{
		Name: in.Name, Kind: in.Kind, Config: in.Config,
		Selector: in.Selector, CommonName: in.CommonName, Enabled: in.Enabled,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.NewDeploymentResponse(row))
}

// UpdateDeployment edits a target.
func (h *Handler) UpdateDeployment(c *okapi.Context, req *dto.UpdateDeploymentRequest) error {
	in := req.Body
	row, err := h.Service.UpdateDeploymentTarget(h.actor(c), req.ID, service.UpdateDeploymentInput{
		Name: in.Name, Config: in.Config, Selector: in.Selector,
		CommonName: in.CommonName, Enabled: in.Enabled,
	})
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewDeploymentResponse(row))
}

// DeleteDeployment removes a target.
func (h *Handler) DeleteDeployment(c *okapi.Context, req *dto.DeploymentRefRequest) error {
	if err := h.Service.DeleteDeploymentTarget(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "deployment target deleted"})
}

// TestDeployment pushes the current matching certificate to one target.
func (h *Handler) TestDeployment(c *okapi.Context, req *dto.DeploymentRefRequest) error {
	result, err := h.Service.TestDeploymentTarget(h.actor(c), req.ID)
	if err != nil {
		return h.fail(c, err)
	}
	// The push itself failing is reported in the body rather than as an HTTP
	// error: the request was handled correctly and the interesting detail is
	// which target said what.
	return c.OK(dto.DeployResultResponse{Results: []service.DeployResult{result}})
}

// DeployCertificate pushes one certificate to every target that selects it.
func (h *Handler) DeployCertificate(c *okapi.Context, req *dto.DeployCertificateRequest) error {
	results, err := h.Service.DeployCertificate(h.actor(c), req.ID, req.Force)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.DeployResultResponse{Results: results})
}
