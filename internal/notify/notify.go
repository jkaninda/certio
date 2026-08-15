// Package notify delivers expiry, renewal and revocation events to webhooks,
// SMTP, Slack and Telegram. Delivery is best-effort: a channel that is down
// must never block or fail the PKI operation that triggered it.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/jkaninda/okapi/client"
)

// Event names channels can subscribe to. "*" matches every event.
const (
	EventCertificateExpiring = "certificate.expiring"
	EventCertificateExpired  = "certificate.expired"
	EventCertificateRenewed  = "certificate.renewed"
	EventCertificateRevoked  = "certificate.revoked"
	EventCertificateIssued   = "certificate.issued"
	EventAuthorityExpiring   = "authority.expiring"
	EventRenewalFailed       = "renewal.failed"
	EventTest                = "test"
)

// EventNames lists every event, for the settings UI.
func EventNames() []string {
	return []string{
		EventCertificateIssued, EventCertificateExpiring, EventCertificateExpired,
		EventCertificateRenewed, EventCertificateRevoked, EventAuthorityExpiring,
		EventRenewalFailed,
	}
}

// Event is one notification payload.
type Event struct {
	Type      string         `json:"event"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	Severity  string         `json:"severity"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data,omitempty"`
}

// Notifier sends an event through one configured channel.
type Notifier interface {
	Send(ctx context.Context, event Event) error
	Channel() string
}

// httpClient is shared so connections are reused across deliveries, with a
// timeout tight enough that a hung endpoint cannot stall the scheduler.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// Webhook posts the event as JSON.
type Webhook struct {
	URL     string
	Secret  string
	Headers map[string]string
}

// Channel identifies the transport.
func (w *Webhook) Channel() string { return "webhook" }

// Send posts the event to the configured URL.
func (w *Webhook) Send(ctx context.Context, event Event) error {
	if w.URL == "" {
		return fmt.Errorf("notify: webhook url is not configured")
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("notify: marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certio-notifier")
	if w.Secret != "" {
		req.Header.Set("X-Certio-Token", w.Secret)
	}
	for key, value := range w.Headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: deliver webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		// Read a little of the body so the recorded error says something
		// useful, but never enough to fill the log with an HTML error page.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify: webhook returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// Slack posts to an incoming-webhook URL.
type Slack struct {
	WebhookURL string
	Channel_   string
	Username   string
}

// Channel identifies the transport.
func (s *Slack) Channel() string { return "slack" }

// Send posts a Block Kit message.
func (s *Slack) Send(ctx context.Context, event Event) error {
	if s.WebhookURL == "" {
		return fmt.Errorf("notify: slack webhook url is not configured")
	}

	payload := map[string]any{
		"text": event.Title,
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": severityEmoji(event.Severity) + " " + event.Title},
			},
			{
				"type": "section",
				"text": map[string]string{"type": "mrkdwn", "text": event.Message},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{"type": "mrkdwn", "text": "*certio* · " + event.Type + " · " + event.Timestamp.Format(time.RFC3339)},
				},
			},
		},
	}
	if s.Username != "" {
		payload["username"] = s.Username
	}
	if s.Channel_ != "" {
		payload["channel"] = s.Channel_
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: deliver slack message: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify: slack returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// telegramAPI is the public Bot API root, used when a channel does not
// override it.
const telegramAPI = "https://api.telegram.org"

// telegramMaxText is the Bot API limit for a sendMessage body. A longer text
// is rejected outright, so an oversized event is trimmed rather than dropped.
const telegramMaxText = 4096

// telegramClient carries no base URL: the notifier builds an absolute URL so a
// channel can point at a self-hosted Bot API server.
var telegramClient = client.New("",
	client.WithTimeout(15*time.Second),
	client.WithUserAgent("certio-notifier"),
)

// Telegram sends the event to a chat through a bot.
type Telegram struct {
	BotToken string
	ChatID   string
	// ThreadID targets one topic inside a forum-style supergroup. Empty sends
	// to the general thread.
	ThreadID string
	// Silent delivers without a notification sound.
	Silent bool
	// APIBaseURL overrides the public Bot API root, for a self-hosted server.
	APIBaseURL string
}

// Channel identifies the transport.
func (t *Telegram) Channel() string { return "telegram" }

// Send posts the event as an HTML-formatted message.
func (t *Telegram) Send(ctx context.Context, event Event) error {
	if t.BotToken == "" || t.ChatID == "" {
		return fmt.Errorf("notify: telegram bot token and chat id are required")
	}

	payload := map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     telegramText(event),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if t.ThreadID != "" {
		payload["message_thread_id"] = t.ThreadID
	}
	if t.Silent {
		payload["disable_notification"] = true
	}

	base := strings.TrimRight(firstNonEmpty(t.APIBaseURL, telegramAPI), "/")
	resp, err := telegramClient.
		Post(base + "/bot" + t.BotToken + "/sendMessage").
		WithContext(ctx).
		JSONBody(payload).
		Do()
	if err != nil {
		return fmt.Errorf("notify: deliver telegram message: %w", err)
	}

	// The Bot API reports a bad chat id or a blocked bot as ok:false, so the
	// body decides the outcome as much as the status code does.
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = resp.JSON(&result)
	if !resp.IsSuccess() || !result.OK {
		detail := strings.TrimSpace(result.Description)
		if detail == "" {
			detail = strings.TrimSpace(string(resp.Body[:min(len(resp.Body), 512)]))
		}
		return fmt.Errorf("notify: telegram returned %s: %s", resp.Status, detail)
	}
	return nil
}

// telegramText renders the event with the small subset of HTML the Bot API
// accepts. Every interpolated value is escaped: a certificate subject is
// attacker-influenced and an unescaped "<" would make Telegram reject the
// whole message.
func telegramText(event Event) string {
	var b strings.Builder
	b.WriteString(severityEmoji(event.Severity))
	b.WriteString(" <b>")
	b.WriteString(html.EscapeString(event.Title))
	b.WriteString("</b>\n\n")
	b.WriteString(html.EscapeString(event.Message))

	if len(event.Data) > 0 {
		b.WriteString("\n")
		for _, key := range sortedKeys(event.Data) {
			fmt.Fprintf(&b, "\n• <b>%s</b>: <code>%s</code>",
				html.EscapeString(key), html.EscapeString(fmt.Sprint(event.Data[key])))
		}
	}

	fmt.Fprintf(&b, "\n\n<i>certio · %s · %s</i>",
		html.EscapeString(event.Type), event.Timestamp.Format(time.RFC3339))

	text := b.String()
	if len(text) > telegramMaxText {
		const ellipsis = "…"
		// Cut on a rune boundary and drop any trailing tag fragment, which
		// would otherwise leave the HTML unbalanced and be rejected whole.
		text = strings.ToValidUTF8(text[:telegramMaxText-len(ellipsis)], "")
		if cut := strings.LastIndexByte(text, '<'); cut > strings.LastIndexByte(text, '>') {
			text = text[:cut]
		}
		text += ellipsis
	}
	return text
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical", "expired":
		return "🔴"
	case "warning", "expiring":
		return "🟠"
	case "success":
		return "🟢"
	default:
		return "🔵"
	}
}

// SMTP sends the event as an email.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	// TLS selects the transport: "starttls" (default), "tls" for implicit TLS,
	// or "none" for a plaintext relay on a trusted network.
	TLS string
	// InsecureSkipVerify disables certificate verification. It exists because
	// a private PKI is often bootstrapped against a mail server whose
	// certificate this very instance has not yet issued.
	InsecureSkipVerify bool
}

// Channel identifies the transport.
func (s *SMTP) Channel() string { return "smtp" }

// Send delivers the event by email.
func (s *SMTP) Send(ctx context.Context, event Event) error {
	if s.Host == "" || len(s.To) == 0 {
		return fmt.Errorf("notify: smtp host and at least one recipient are required")
	}
	port := s.Port
	if port == 0 {
		port = 587
	}
	from := s.From
	if from == "" {
		from = "certio@localhost"
	}

	message := buildMessage(from, s.To, event)
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))

	tlsConfig := &tls.Config{
		ServerName:         s.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.InsecureSkipVerify, //nolint:gosec // opt-in, documented
	}

	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}

	// Implicit TLS needs the connection wrapped before the SMTP handshake;
	// net/smtp only knows how to STARTTLS an existing plaintext connection.
	if strings.EqualFold(s.TLS, "tls") {
		return s.sendImplicitTLS(ctx, addr, tlsConfig, auth, from, message)
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: dial smtp %s: %w", addr, err)
	}

	smtpClient, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notify: smtp handshake: %w", err)
	}
	defer func() { _ = smtpClient.Quit() }()

	if !strings.EqualFold(s.TLS, "none") {
		if ok, _ := smtpClient.Extension("STARTTLS"); ok {
			if err := smtpClient.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("notify: smtp starttls: %w", err)
			}
		}
	}
	if auth != nil {
		if err := smtpClient.Auth(auth); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	return deliver(smtpClient, from, s.To, message)
}

func (s *SMTP) sendImplicitTLS(ctx context.Context, addr string, tlsConfig *tls.Config,
	auth smtp.Auth, from string, message []byte,
) error {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: dial smtp over tls %s: %w", addr, err)
	}

	smtpClient, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notify: smtp handshake: %w", err)
	}
	defer func() { _ = smtpClient.Quit() }()

	if auth != nil {
		if err := smtpClient.Auth(auth); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	return deliver(smtpClient, from, s.To, message)
}

func deliver(smtpClient *smtp.Client, from string, to []string, message []byte) error {
	if err := smtpClient.Mail(from); err != nil {
		return fmt.Errorf("notify: smtp MAIL FROM: %w", err)
	}
	for _, recipient := range to {
		if err := smtpClient.Rcpt(recipient); err != nil {
			return fmt.Errorf("notify: smtp RCPT TO %s: %w", recipient, err)
		}
	}
	w, err := smtpClient.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp DATA: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("notify: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: close message: %w", err)
	}
	return nil
}

// buildMessage renders a multipart-free plain-text email.
func buildMessage(from string, to []string, event Event) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: [certio] %s\r\n", event.Title)
	fmt.Fprintf(&b, "Date: %s\r\n", event.Timestamp.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("X-Certio-Event: " + event.Type + "\r\n")
	b.WriteString("\r\n")

	b.WriteString(event.Message)
	b.WriteString("\r\n")

	if len(event.Data) > 0 {
		b.WriteString("\r\nDetails\r\n-------\r\n")
		for _, key := range sortedKeys(event.Data) {
			fmt.Fprintf(&b, "  %-20s %v\r\n", key+":", event.Data[key])
		}
	}
	b.WriteString("\r\n-- \r\nSent by Certio\r\n")
	return []byte(b.String())
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// A tiny insertion sort keeps the output deterministic without importing
	// sort for a map that is never more than a handful of entries.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// Build constructs a Notifier from a channel name and its decrypted settings.
func Build(channel string, config map[string]string) (Notifier, error) {
	switch channel {
	case "webhook":
		return &Webhook{
			URL:    config["url"],
			Secret: config["secret"],
		}, nil

	case "slack":
		return &Slack{
			WebhookURL: firstNonEmpty(config["webhook_url"], config["url"]),
			Channel_:   config["channel"],
			Username:   firstNonEmpty(config["username"], "certio"),
		}, nil

	case "telegram":
		silent, _ := strconv.ParseBool(config["silent"])
		token := firstNonEmpty(config["bot_token"], config["token"])
		chat := firstNonEmpty(config["chat_id"], config["chat"])
		if token == "" || chat == "" {
			return nil, fmt.Errorf("notify: telegram bot token and chat id are required")
		}
		return &Telegram{
			BotToken:   token,
			ChatID:     chat,
			ThreadID:   firstNonEmpty(config["message_thread_id"], config["thread_id"]),
			Silent:     silent,
			APIBaseURL: config["api_base_url"],
		}, nil

	case "smtp":
		port, _ := strconv.Atoi(config["port"])
		insecure, _ := strconv.ParseBool(config["insecure_skip_verify"])
		return &SMTP{
			Host: config["host"], Port: port,
			Username: config["username"], Password: config["password"],
			From:               config["from"],
			To:                 splitList(config["to"]),
			TLS:                firstNonEmpty(config["tls"], "starttls"),
			InsecureSkipVerify: insecure,
		}, nil
	}
	return nil, fmt.Errorf("notify: unknown channel %q (want webhook, smtp, slack or telegram)", channel)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
