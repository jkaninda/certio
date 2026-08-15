package handlers

import (
	"errors"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// errEmptyBulk is returned when a bulk request carries no IDs.
var errEmptyBulk = errors.New("at least one certificate id is required")

// timeNow is a seam so chain descriptions can be evaluated at a fixed instant
// in tests.
var timeNow = time.Now

// ListAuditLogs returns a filtered page of audit entries. There is
// deliberately no create, update or delete counterpart.
func (h *Handler) ListAuditLogs(c *okapi.Context, req *dto.ListAuditLogsRequest) error {
	p := page(req.Page, req.Limit)

	filter := store.AuditFilter{
		ActorID:      req.ActorID,
		Action:       req.Action,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Query:        req.Query,
		Since:        parseTime(req.Since),
		Until:        parseTime(req.Until),
	}

	result, err := h.Service.Store.Audit.List(filter, p)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.AuditListResponse{
		Items: result.Items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// ListJobs returns the scheduler's run history.
func (h *Handler) ListJobs(c *okapi.Context, req *dto.ListJobsRequest) error {
	p := page(req.Page, req.Limit)
	result, err := h.Service.Store.Jobs.List(req.Kind, p)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.JobListResponse{
		Items: result.Items, PageMeta: meta(p, result.Total, result.TotalPages),
	})
}

// GetSettings returns the instance defaults.
func (h *Handler) GetSettings(c *okapi.Context) error {
	return c.OK(dto.SettingsResponse{
		DefaultOrganization: h.Config.PKI.DefaultOrganization,
		DefaultCountry:      h.Config.PKI.DefaultCountry,
		DefaultKeyAlgorithm: h.Config.PKI.DefaultKeyAlgorithm,
		DefaultValidityDays: h.Config.PKI.DefaultValidityDays,
		ExpiryWarnDays:      h.Config.Scheduler.ExpiryWarnDays,
		KeyDownloadPolicy:   h.Config.Security.KeyDownloadPolicy,
		BaseURL:             h.Config.Server.BaseURL,
		SchedulerEnabled:    h.Config.Scheduler.Enabled,
	})
}

// UpdateSettings edits the instance defaults. They are persisted to the
// settings table and applied to the running configuration, so a change takes
// effect without a restart.
func (h *Handler) UpdateSettings(c *okapi.Context, req *dto.UpdateSettingsRequest) error {
	in := req.Body

	apply := func(key, value string) error {
		return h.Service.Store.Settings.Set(key, value)
	}

	if in.DefaultOrganization != nil {
		if err := apply("default_organization", *in.DefaultOrganization); err != nil {
			return h.fail(c, err)
		}
		h.Config.PKI.DefaultOrganization = *in.DefaultOrganization
	}
	if in.DefaultCountry != nil {
		if err := apply("default_country", *in.DefaultCountry); err != nil {
			return h.fail(c, err)
		}
		h.Config.PKI.DefaultCountry = *in.DefaultCountry
	}
	if in.DefaultKeyAlgorithm != nil {
		if err := apply("default_key_algorithm", *in.DefaultKeyAlgorithm); err != nil {
			return h.fail(c, err)
		}
		h.Config.PKI.DefaultKeyAlgorithm = *in.DefaultKeyAlgorithm
	}
	if in.DefaultValidityDays != nil {
		if err := apply("default_validity_days", itoa(*in.DefaultValidityDays)); err != nil {
			return h.fail(c, err)
		}
		h.Config.PKI.DefaultValidityDays = *in.DefaultValidityDays
	}
	if in.ExpiryWarnDays != nil {
		if err := apply("expiry_warn_days", itoa(*in.ExpiryWarnDays)); err != nil {
			return h.fail(c, err)
		}
		h.Config.Scheduler.ExpiryWarnDays = *in.ExpiryWarnDays
	}

	h.Service.Audit.Record(h.actor(c), audit.Entry{
		Action: audit.ActionSettingUpdate, ResourceType: audit.ResourceSetting,
	})
	return h.GetSettings(c)
}

// ListNotifications returns the configured delivery channels.
func (h *Handler) ListNotifications(c *okapi.Context) error {
	rows, err := h.Service.Store.Notifications.All()
	if err != nil {
		return h.fail(c, err)
	}
	items := make([]dto.NotificationResponse, 0, len(rows))
	for i := range rows {
		items = append(items, dto.NewNotificationResponse(&rows[i]))
	}
	return c.OK(dto.NotificationListResponse{Items: items, Total: len(items)})
}

// CreateNotification configures a delivery channel, sealing its settings.
func (h *Handler) CreateNotification(c *okapi.Context, req *dto.CreateNotificationRequest) error {
	in := req.Body
	row, err := h.Service.CreateNotification(h.actor(c),
		in.Name, in.Channel, in.Config, in.Events, in.Enabled)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Created(dto.NewNotificationResponse(row))
}

// UpdateNotification edits a delivery channel.
func (h *Handler) UpdateNotification(c *okapi.Context, req *dto.UpdateNotificationRequest) error {
	row, err := h.Service.UpdateNotification(h.actor(c), req.ID,
		req.Body.Name, req.Body.Config, req.Body.Events, req.Body.Enabled)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewNotificationResponse(row))
}

// DeleteNotification removes a delivery channel.
func (h *Handler) DeleteNotification(c *okapi.Context, req *dto.NotificationRefRequest) error {
	if err := h.Service.DeleteNotification(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "notification channel deleted"})
}

// TestNotification sends a probe through a channel so an operator can confirm
// it works before relying on it for an expiry warning.
func (h *Handler) TestNotification(c *okapi.Context, req *dto.NotificationRefRequest) error {
	if err := h.Service.TestNotification(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "test notification sent"})
}

// parseTime reads an RFC 3339 timestamp, returning nil when absent or invalid.
func parseTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	return &t
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
