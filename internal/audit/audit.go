// Package audit records every mutation Certio performs. The log is
// append-only: this package offers no update or delete, and neither does the
// API surface built on it.
package audit

import (
	"log/slog"

	"github.com/jkaninda/certio/internal/store"
)

// Action names. They are stable strings because they end up in exported audit
// trails and in operators' alerting rules.
const (
	ActionLogin        = "auth.login"
	ActionLoginFailed  = "auth.login_failed"
	ActionLogout       = "auth.logout"
	ActionTokenIssued  = "auth.token_issued"  //nolint:gosec // G101: an action name, not a credential
	ActionTokenRevoked = "auth.token_revoked" //nolint:gosec // G101: an action name, not a credential

	ActionOAuthConfigured  = "auth.oauth_configured"
	ActionOAuthRemoved     = "auth.oauth_removed"
	ActionOAuthProvisioned = "auth.oauth_provisioned"
	ActionOAuthLinked      = "auth.oauth_linked"

	ActionTwoFactorEnabled     = "auth.2fa_enabled"
	ActionTwoFactorDisabled    = "auth.2fa_disabled"
	ActionTwoFactorFailed      = "auth.2fa_failed"
	ActionTwoFactorReset       = "auth.2fa_reset"
	ActionRecoveryCodeUsed     = "auth.recovery_code_used"
	ActionRecoveryCodesRenewed = "auth.recovery_codes_renewed"

	ActionCACreate  = "ca.create"
	ActionCAImport  = "ca.import"
	ActionCAUpdate  = "ca.update"
	ActionCADelete  = "ca.delete"
	ActionCARenew   = "ca.renew"
	ActionCRLIssued = "ca.crl_issued"

	ActionCertIssue         = "cert.issue"
	ActionCertSignCSR       = "cert.sign_csr"
	ActionCertRenew         = "cert.renew"
	ActionCertReleaseHold   = "certificate.release_hold"
	ActionCertRevoke        = "cert.revoke"
	ActionCertDelete        = "cert.delete"
	ActionCertUpdate        = "cert.update"
	ActionCertDownload      = "cert.download"
	ActionKeyDownload       = "cert.key_download"
	ActionKeyDownloadDenied = "cert.key_download_denied"

	ActionUserCreate = "user.create"
	ActionUserUpdate = "user.update"
	ActionUserDelete = "user.delete"

	ActionSettingUpdate      = "setting.update"
	ActionACMEAccountCreate  = "acme.account_create"
	ActionACMEExternalCreate = "acme.external_account_create"
	ActionACMEExternalDelete = "acme.external_account_delete"

	ActionDeploymentCreate = "deployment.create"
	ActionDeploymentUpdate = "deployment.update"
	ActionDeploymentDelete = "deployment.delete"
	ActionDeploymentRun    = "deployment.run"

	ActionNotificationCreate = "notification.create"
	ActionNotificationUpdate = "notification.update"
	ActionNotificationDelete = "notification.delete"

	ActionJobRun = "job.run"
)

// Resource type names used in the resource_type column.
const (
	ResourceAuthority    = "authority"
	ResourceCertificate  = "certificate"
	ResourceUser         = "user"
	ResourceToken        = "api_token"
	ResourceDeployment   = "deployment"
	ResourceNotification = "notification"
	ResourceACMEAccount  = "acme_account"
	ResourceACMEExternal = "acme_external_account"
	ResourceSetting      = "setting"
	ResourceOAuth        = "oauth_provider"
	ResourceJob          = "job"
)

// Actor identifies who performed an action.
type Actor struct {
	Type      string // user | token | system
	ID        string
	Name      string
	IP        string
	UserAgent string
}

// SystemActor is the actor for anything the scheduler does on its own.
func SystemActor() Actor {
	return Actor{Type: store.ActorSystem, Name: "certio-scheduler"}
}

// Entry describes one auditable event.
type Entry struct {
	Action       string
	ResourceType string
	ResourceID   string
	ResourceName string
	Metadata     map[string]any
	Success      bool
	Error        string
}

// Logger appends entries to the store. A failure to write an audit record is
// logged but never propagated: losing the audit trail must not roll back the
// operation the user asked for, and the application log preserves the event.
type Logger struct {
	repo *store.AuditRepo
	log  *slog.Logger
}

// New builds a Logger.
func New(repo *store.AuditRepo, log *slog.Logger) *Logger {
	if log == nil {
		log = slog.Default()
	}
	return &Logger{repo: repo, log: log}
}

// Record appends a successful entry.
func (l *Logger) Record(actor Actor, entry Entry) {
	entry.Success = true
	l.write(actor, entry)
}

// RecordFailure appends a failed entry with the error attached.
func (l *Logger) RecordFailure(actor Actor, entry Entry, err error) {
	entry.Success = false
	if err != nil {
		entry.Error = err.Error()
	}
	l.write(actor, entry)
}

func (l *Logger) write(actor Actor, entry Entry) {
	if l == nil || l.repo == nil {
		return
	}
	if actor.Type == "" {
		actor.Type = store.ActorSystem
	}

	record := &store.AuditLog{
		ActorType:    actor.Type,
		ActorID:      actor.ID,
		ActorName:    actor.Name,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		ResourceName: entry.ResourceName,
		Metadata:     store.JSON(entry.Metadata),
		IP:           actor.IP,
		UserAgent:    actor.UserAgent,
		Success:      entry.Success,
		Error:        entry.Error,
	}

	if err := l.repo.Append(record); err != nil {
		l.log.Error("could not write audit entry",
			"error", err, "action", entry.Action, "resource_id", entry.ResourceID)
	}
}
