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
