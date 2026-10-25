package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavis/clavis/internal/notify"
)

// TestClassifyOpenFailure verifies the mapping of open-time key errors to
// GUI notification kinds.
func TestClassifyOpenFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want notify.Kind
	}{
		{"nil", nil, notify.KindInfo},
		{"connection refused", errors.New("keyclient: request failed: dial tcp 10.0.0.1:8443: connect: connection refused"), notify.KindOffline},
		{"all servers failed", errors.New("keyclient: all 2 servers failed to issue reader key: last error"), notify.KindOffline},
		{"dns", errors.New("keyclient: request failed: Get \"https://keys.example.com\": dial tcp: lookup keys.example.com: no such host"), notify.KindOffline},
		{"timeout", errors.New("keyclient: request failed: context deadline exceeded"), notify.KindOffline},
		{"tls", errors.New("keyclient: request failed: x509: certificate signed by unknown authority"), notify.KindOffline},
		{"e2e no relay", errors.New("e2e mode requires server.relay_addr"), notify.KindOffline},
		{"unknown owner", errors.New("owner not found"), notify.KindKeyMissing},
		{"server 404", errors.New("keyclient: server error: 404 Not Found"), notify.KindKeyMissing},
		{"unwrap", errors.New("fuse: unwrap document key: invalid key wrap"), notify.KindKeyMissing},
		{"unexpected", errors.New("boom"), notify.KindInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyOpenFailure(tc.err); got != tc.want {
				t.Errorf("classifyOpenFailure(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestKeyFailureNotifierPushes verifies that the notifier classifies the
// failure, includes the file base name and pushes onto the bus.
func TestKeyFailureNotifierPushes(t *testing.T) {
	bus := notify.NewBus(10)
	n := keyFailureNotifier{bus: bus}

	n.OpenFailed("/secure/docs/report.docx", errors.New("owner not found"))
	n.OpenFailed("/secure/docs/notes.txt", errors.New("dial tcp 10.0.0.1:8443: connect: connection refused"))

	recent := bus.Recent()
	if len(recent) != 2 {
		t.Fatalf("Recent() len = %d, want 2", len(recent))
	}
	if recent[0].Kind != notify.KindKeyMissing {
		t.Errorf("notice[0].Kind = %v, want KindKeyMissing", recent[0].Kind)
	}
	if !strings.Contains(recent[0].Text, "report.docx") {
		t.Errorf("notice[0].Text = %q, want it to mention the file name", recent[0].Text)
	}
	if recent[1].Kind != notify.KindOffline {
		t.Errorf("notice[1].Kind = %v, want KindOffline", recent[1].Kind)
	}
}

// TestNotificationsEndpoint verifies that GET /api/notifications returns
// the collect notice list as JSON.
func TestNotificationsEndpoint(t *testing.T) {
	bus := notify.NewBus(10)
	bus.Push(notify.KindOffline, "нет доступа к серверам")

	s := &UIServer{bus: bus}
	rec := httptest.NewRecorder()
	s.handleNotifications(rec, httptest.NewRequest(http.MethodGet, "/api/notifications", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"notifications"`) || !strings.Contains(body, `"offline"`) {
		t.Errorf("body = %q, want the notifications list with kind offline", body)
	}
}
