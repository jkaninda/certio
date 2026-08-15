package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testEvent is a representative event, with a title that would break the Bot
// API if it were interpolated into HTML unescaped.
var testEvent = Event{
	Type:      EventCertificateExpiring,
	Title:     "api.example.com <expiring>",
	Message:   "Expires in 7 days",
	Severity:  "warning",
	Timestamp: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
	Data:      map[string]any{"serial": "0A:1B", "issuer": "Certio Root & CA"},
}

// TestTelegramSend checks the request Certio puts on the wire: the bot token
// belongs in the path, never in the body, and the text is escaped HTML.
func TestTelegramSend(t *testing.T) {
	var gotPath string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer server.Close()

	tg := &Telegram{BotToken: "123:ABC", ChatID: "-1001", ThreadID: "42", APIBaseURL: server.URL}
	if err := tg.Send(context.Background(), testEvent); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if want := "/bot123:ABC/sendMessage"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotBody["chat_id"] != "-1001" {
		t.Errorf("chat_id = %v, want -1001", gotBody["chat_id"])
	}
	if gotBody["message_thread_id"] != "42" {
		t.Errorf("message_thread_id = %v, want 42", gotBody["message_thread_id"])
	}
	if gotBody["parse_mode"] != "HTML" {
		t.Errorf("parse_mode = %v, want HTML", gotBody["parse_mode"])
	}
	if _, ok := gotBody["disable_notification"]; ok {
		t.Error("disable_notification was sent for a non-silent channel")
	}

	text, _ := gotBody["text"].(string)
	if strings.Contains(text, "<expiring>") || strings.Contains(text, "Root & CA") {
		t.Errorf("text was not HTML-escaped: %q", text)
	}
	for _, want := range []string{"&lt;expiring&gt;", "Root &amp; CA", "<b>", "🟠"} {
		if !strings.Contains(text, want) {
			t.Errorf("text = %q, want it to contain %q", text, want)
		}
	}
}

// TestTelegramSendAPIError checks that ok:false is treated as a failure even
// though the Bot API answers it with 200.
func TestTelegramSendAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"chat not found"}`))
	}))
	defer server.Close()

	tg := &Telegram{BotToken: "123:ABC", ChatID: "-1001", APIBaseURL: server.URL}
	err := tg.Send(context.Background(), testEvent)
	if err == nil {
		t.Fatal("Send returned nil for an ok:false response")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("error = %v, want it to quote the API description", err)
	}
}

// TestTelegramSendMissingConfig checks the guard that keeps an unconfigured
// channel from reaching the network.
func TestTelegramSendMissingConfig(t *testing.T) {
	tg := &Telegram{ChatID: "-1001"}
	if err := tg.Send(context.Background(), testEvent); err == nil {
		t.Fatal("Send returned nil without a bot token")
	}
}

// TestTelegramTextTruncation checks that an oversized event is trimmed to the
// Bot API limit without leaving a half-written tag behind.
func TestTelegramTextTruncation(t *testing.T) {
	event := testEvent
	event.Message = strings.Repeat("long detail. ", 500)

	text := telegramText(event)
	if len(text) > telegramMaxText {
		t.Errorf("len(text) = %d, want <= %d", len(text), telegramMaxText)
	}
	if strings.LastIndexByte(text, '<') > strings.LastIndexByte(text, '>') {
		t.Errorf("text ends with an unterminated tag: %q", text[len(text)-40:])
	}
}

// TestBuildTelegram checks the settings map the API and UI send.
func TestBuildTelegram(t *testing.T) {
	notifier, err := Build("telegram", map[string]string{
		"bot_token": "123:ABC", "chat_id": "-1001", "silent": "true",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if notifier.Channel() != "telegram" {
		t.Errorf("Channel() = %q, want telegram", notifier.Channel())
	}
	tg, ok := notifier.(*Telegram)
	if !ok {
		t.Fatalf("Build returned %T, want *Telegram", notifier)
	}
	if tg.BotToken != "123:ABC" || tg.ChatID != "-1001" || !tg.Silent {
		t.Errorf("Build = %+v, want the configured token, chat and silent flag", tg)
	}

	// A channel saved without a chat id would fail only at delivery time, so
	// Build rejects it while the operator is still looking at the form.
	if _, err := Build("telegram", map[string]string{"bot_token": "123:ABC"}); err == nil {
		t.Error("Build accepted a telegram channel with no chat id")
	}
}
