package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/notify"
	"github.com/jkaninda/certio/internal/store"
)

// CreateNotification configures a delivery channel, sealing its settings.
func (s *Service) CreateNotification(
	actor audit.Actor, name, channel string, config map[string]string, events []string, enabled bool,
) (*store.Notification, error) {
	if name == "" {
		return nil, validationError("a channel name is required")
	}
	// Building the notifier now surfaces a missing URL or recipient at
	// configuration time rather than at 3 a.m. when a certificate expires.
	if _, err := notify.Build(channel, config); err != nil {
		return nil, validationError("%s", err)
	}
	if len(events) == 0 {
		events = []string{"*"}
	}

	sealed, nonce, salt, err := s.sealConfig(config)
	if err != nil {
		return nil, err
	}

	row := &store.Notification{
		Name: name, Channel: channel,
		ConfigEncrypted: sealed, ConfigNonce: nonce, ConfigSalt: salt,
		Events: store.JSON(events), Enabled: enabled,
	}
	if err := s.Store.Notifications.Create(row); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionNotificationCreate, ResourceType: audit.ResourceNotification,
		ResourceID: row.ID, ResourceName: row.Name,
		Metadata: map[string]any{"channel": channel, "events": events},
	})
	return row, nil
}

// UpdateNotification edits a delivery channel. Every optional field is a
// pointer so that "not supplied" stays distinguishable from "set to empty" —
// which is why config is a *map and not the bare map gocritic would prefer.
//
//nolint:gocritic // ptrToRefParam: nil is a meaningful value here
func (s *Service) UpdateNotification(
	actor audit.Actor, id string, name *string, config *map[string]string, events *[]string, enabled *bool,
) (*store.Notification, error) {
	row, err := s.Store.Notifications.Get(id)
	if err != nil {
		return nil, err
	}

	if name != nil {
		row.Name = *name
	}
	if events != nil {
		row.Events = store.JSON(*events)
	}
	if enabled != nil {
		row.Enabled = *enabled
	}
	if config != nil {
		if _, err := notify.Build(row.Channel, *config); err != nil {
			return nil, validationError("%s", err)
		}
		sealed, nonce, salt, err := s.sealConfig(*config)
		if err != nil {
			return nil, err
		}
		row.ConfigEncrypted, row.ConfigNonce, row.ConfigSalt = sealed, nonce, salt
	}

	if err := s.Store.Notifications.Update(row); err != nil {
		return nil, err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionNotificationUpdate, ResourceType: audit.ResourceNotification,
		ResourceID: row.ID, ResourceName: row.Name,
	})
	return row, nil
}

// DeleteNotification removes a delivery channel.
func (s *Service) DeleteNotification(actor audit.Actor, id string) error {
	row, err := s.Store.Notifications.Get(id)
	if err != nil {
		return err
	}
	if err := s.Store.Notifications.Delete(id); err != nil {
		return err
	}
	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionNotificationDelete, ResourceType: audit.ResourceNotification,
		ResourceID: row.ID, ResourceName: row.Name,
	})
	return nil
}

// TestNotification sends a probe through one channel and records the outcome
// on the row, so a misconfiguration is visible in the UI.
func (s *Service) TestNotification(actor audit.Actor, id string) error {
	row, err := s.Store.Notifications.Get(id)
	if err != nil {
		return err
	}

	notifier, err := s.notifierFor(row)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	event := notify.Event{
		Type:      notify.EventTest,
		Title:     "Certio test notification",
		Message:   fmt.Sprintf("This is a test from the %q channel. If you can read this, delivery works.", row.Name),
		Severity:  "info",
		Timestamp: time.Now().UTC(),
		Data:      map[string]any{"channel": row.Channel, "instance": s.Config.Server.BaseURL},
	}

	sendErr := notifier.Send(ctx, event)
	s.recordDelivery(row, sendErr)
	return sendErr
}

// maxDeliveryAttempts is how many times a failing channel is retried before
// the delivery is abandoned. Six attempts with the backoff below spans about
// half an hour, which covers a restart or a brief outage at the receiving end
// without holding a doomed delivery forever.
const maxDeliveryAttempts = 6

// retryBackoff is the wait before attempt N. A failed webhook is usually a
// receiver that is briefly down, so the first retry is quick and the tail is
// long enough not to hammer it.
var retryBackoff = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	30 * time.Minute,
}

// Dispatch delivers an event to every enabled channel subscribed to it.
//
// A failure is never propagated — a broken webhook must not turn a successful
// renewal into a failed one — but it is no longer simply dropped either: the
// attempt is queued and the scheduler retries it with backoff. An expiry
// warning lost to a thirty-second outage is exactly the notification that
// mattered most.
func (s *Service) Dispatch(event notify.Event) {
	rows, err := s.Store.Notifications.Enabled(event.Type)
	if err != nil {
		s.Log.Error("could not load notification channels", "error", err, "event", event.Type)
		return
	}
	if len(rows) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := range rows {
		row := &rows[i]
		if err := s.deliver(ctx, row, event); err != nil {
			s.queueRetry(row, event, err)
		}
	}
}

// deliver makes one attempt and records its outcome on the channel row.
func (s *Service) deliver(ctx context.Context, row *store.Notification, event notify.Event) error {
	notifier, err := s.notifierFor(row)
	if err != nil {
		s.Log.Error("could not build the notifier", "error", err, "channel", row.Name)
		s.recordDelivery(row, err)
		return err
	}
	if err := notifier.Send(ctx, event); err != nil {
		s.Log.Warn("notification delivery failed", "error", err, "channel", row.Name, "event", event.Type)
		s.recordDelivery(row, err)
		return err
	}
	s.recordDelivery(row, nil)
	return nil
}

// queueRetry parks a failed delivery for the scheduler to pick up.
func (s *Service) queueRetry(row *store.Notification, event notify.Event, cause error) {
	payload, err := eventPayload(event)
	if err != nil {
		s.Log.Error("could not queue a notification for retry", "error", err, "channel", row.Name)
		return
	}

	delivery := &store.Delivery{
		NotificationID: row.ID,
		Event:          event.Type,
		Payload:        store.JSON(payload),
		Status:         store.DeliveryPending,
		Attempts:       1,
		LastError:      cause.Error(),
		NextAttemptAt:  time.Now().UTC().Add(retryBackoff[0]),
	}
	if err := s.Store.Deliveries.Create(delivery); err != nil {
		s.Log.Error("could not queue a notification for retry", "error", err, "channel", row.Name)
	}
}

// RetryDeliveries makes one pass over the queue. The scheduler calls it; it
// returns how many were delivered, retried and abandoned so the job history
// says something useful.
func (s *Service) RetryDeliveries(ctx context.Context) (delivered, retried, abandoned int, err error) {
	due, err := s.Store.Deliveries.Due(time.Now(), 100)
	if err != nil {
		return 0, 0, 0, err
	}

	for i := range due {
		row := &due[i]
		channel := row.Notification
		if channel.ID == "" || !channel.Enabled {
			// The channel was deleted or turned off while the delivery waited.
			// Retrying into it would be sending somewhere nobody asked for any
			// more.
			row.Status = store.DeliveryFailed
			row.LastError = "the channel was removed or disabled before this could be delivered"
			if updateErr := s.Store.Deliveries.Update(row); updateErr != nil {
				s.Log.Error("could not close an orphaned delivery", "error", updateErr, "delivery", row.ID)
			}
			abandoned++
			continue
		}

		event := eventFromPayload(row.Payload.Data)
		row.Attempts++

		sendErr := s.deliver(ctx, &channel, event)
		switch {
		case sendErr == nil:
			now := time.Now().UTC()
			row.Status, row.DeliveredAt, row.LastError = store.DeliveryDelivered, &now, ""
			delivered++

		case row.Attempts >= maxDeliveryAttempts:
			row.Status = store.DeliveryFailed
			row.LastError = sendErr.Error()
			s.Log.Error("giving up on a notification after repeated failures",
				"channel", channel.Name, "event", row.Event, "attempts", row.Attempts, "error", sendErr)
			abandoned++

		default:
			row.LastError = sendErr.Error()
			row.NextAttemptAt = time.Now().UTC().Add(backoffFor(row.Attempts))
			retried++
		}

		if updateErr := s.Store.Deliveries.Update(row); updateErr != nil {
			s.Log.Error("could not record a delivery attempt", "error", updateErr, "delivery", row.ID)
		}
	}
	return delivered, retried, abandoned, nil
}

// backoffFor returns the wait before the given attempt number, holding at the
// longest interval once the table runs out.
func backoffFor(attempt int) time.Duration {
	index := attempt - 1
	if index < 0 {
		index = 0
	}
	if index >= len(retryBackoff) {
		index = len(retryBackoff) - 1
	}
	return retryBackoff[index]
}

// eventPayload renders an event as the map a Delivery row stores. Round-
// tripping through JSON keeps the stored shape identical to the wire one, so a
// retry sends what the first attempt would have sent.
func eventPayload(event notify.Event) (map[string]any, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal notification event: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse notification event: %w", err)
	}
	return payload, nil
}

// eventFromPayload rebuilds an event from a stored row.
func eventFromPayload(payload map[string]any) notify.Event {
	raw, err := json.Marshal(payload)
	if err != nil {
		return notify.Event{}
	}
	var event notify.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return notify.Event{}
	}
	return event
}

// notifierFor decrypts a channel's settings and builds its notifier.
func (s *Service) notifierFor(row *store.Notification) (notify.Notifier, error) {
	config, err := s.openConfig(row)
	if err != nil {
		return nil, err
	}
	return notify.Build(row.Channel, config)
}

// recordDelivery stamps the last attempt on a channel row.
func (s *Service) recordDelivery(row *store.Notification, sendErr error) {
	s.Metrics.Notifications.WithLabelValues(row.Channel, metrics.Result(sendErr)).Inc()

	now := time.Now().UTC()
	row.LastSentAt = &now
	row.LastError = ""
	if sendErr != nil {
		row.LastError = sendErr.Error()
	}
	if err := s.Store.Notifications.Update(row); err != nil {
		s.Log.Error("could not record the notification result", "error", err, "channel", row.ID)
	}
}

// sealConfig encrypts a channel's settings map.
func (s *Service) sealConfig(config map[string]string) (ciphertext, nonce, salt []byte, err error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal notification config: %w", err)
	}
	env, err := s.Keyring.Seal(raw, "")
	if err != nil {
		return nil, nil, nil, err
	}
	return env.Ciphertext, env.Nonce, env.Salt, nil
}

// openConfig decrypts a channel's settings map.
func (s *Service) openConfig(row *store.Notification) (map[string]string, error) {
	return s.openSealedConfig(row.ConfigEncrypted, row.ConfigNonce, row.ConfigSalt)
}

// openSealedConfig decrypts any sealed settings map. Notification channels and
// deployment targets both store one, and both would otherwise repeat this.
func (s *Service) openSealedConfig(ciphertext, nonce, salt []byte) (map[string]string, error) {
	if len(ciphertext) == 0 {
		return map[string]string{}, nil
	}
	raw, err := s.Keyring.Open(certiocrypto.Envelope{
		Ciphertext: ciphertext, Nonce: nonce, Salt: salt,
	}, "")
	if err != nil {
		return nil, err
	}
	var config map[string]string
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse the sealed configuration: %w", err)
	}
	return config, nil
}
