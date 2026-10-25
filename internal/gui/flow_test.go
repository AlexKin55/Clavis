package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavis/clavis/internal/agentapi"
)

// fakeUI records the flow's UI calls instead of showing real widgets.
type fakeUI struct {
	confirmCalls int
	confirmPeer  string
	decide       func(grant bool)
	infos        []string
	errs         []error
}

func (f *fakeUI) ConfirmApproval(peerAgent string, onDecision func(bool)) {
	f.confirmCalls++
	f.confirmPeer = peerAgent
	f.decide = onDecision
}

func (f *fakeUI) ShowInfo(message string) { f.infos = append(f.infos, message) }

func (f *fakeUI) ShowError(err error) { f.errs = append(f.errs, err) }

// pendingAgentServer emulates the agent's localhost UI API: it serves
// pending e2e sessions and records approved session ids.
func pendingAgentServer(t *testing.T, sessions []agentapi.PendingE2ESession) (*httptest.Server, *[]string) {
	t.Helper()
	var approved []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/e2e/pending", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"pending": sessions})
	})
	mux.HandleFunc("POST /api/e2e/approve", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionID string `json:"session_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		approved = append(approved, req.SessionID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"granted": true})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &approved
}

// =========================================================================
// Case 1: an end-to-end key request — "give the key or not". The pending
// request is emulated by the agent API; the decision dialog is shown and
// the user either grants the key (approve endpoint called) or refuses.
// =========================================================================

// TestCheckPendingRequestsShowsDialog verifies that a pending e2e request
// shows the approval dialog with the peer identity, and that granting it
// calls the approve endpoint (the key is handed over).
func TestCheckPendingRequestsShowsDialog(t *testing.T) {
	srv, approved := pendingAgentServer(t, []agentapi.PendingE2ESession{
		{SessionID: "e2e-abc", PeerAgent: "agent-peer1"},
	})
	ui := &fakeUI{}
	api := agentapi.NewClient(srv.URL)

	n, err := CheckPendingRequests(api, ui)
	if err != nil {
		t.Fatalf("CheckPendingRequests() error: %v", err)
	}
	if n != 1 {
		t.Errorf("pending count = %d, want 1", n)
	}
	// The approval dialog must have been presented with the peer's id.
	if ui.confirmCalls != 1 {
		t.Fatalf("ConfirmApproval calls = %d, want 1 (dialog shown)", ui.confirmCalls)
	}
	if ui.confirmPeer != "agent-peer1" {
		t.Errorf("dialog peer = %q, want agent-peer1", ui.confirmPeer)
	}

	// The user grants the key.
	ui.decide(true)
	if len(*approved) != 1 || (*approved)[0] != "e2e-abc" {
		t.Errorf("approved sessions = %v, want [e2e-abc]", *approved)
	}
	if len(ui.infos) == 0 || ui.infos[len(ui.infos)-1] != "Ключ доступа передан." {
		t.Errorf("infos = %v, want a success message", ui.infos)
	}
}

// TestCheckPendingRequestsRefuse verifies the "no" branch of the key
// request case: refusing the dialog does not call the approve endpoint.
func TestCheckPendingRequestsRefuse(t *testing.T) {
	srv, approved := pendingAgentServer(t, []agentapi.PendingE2ESession{
		{SessionID: "e2e-xyz", PeerAgent: "agent-peer2"},
	})
	ui := &fakeUI{}

	if _, err := CheckPendingRequests(agentapi.NewClient(srv.URL), ui); err != nil {
		t.Fatal(err)
	}
	if ui.confirmCalls != 1 {
		t.Fatalf("dialog calls = %d, want 1", ui.confirmCalls)
	}

	ui.decide(false)
	if len(*approved) != 0 {
		t.Errorf("approved sessions = %v, want none", *approved)
	}
	last := ui.infos[len(ui.infos)-1]
	if !strings.Contains(last, "отклонён") {
		t.Errorf("info = %q, want a declined message", last)
	}
}

// TestCheckPendingRequestsNone verifies the no-pending case: no dialog,
// only an informational message.
func TestCheckPendingRequestsNone(t *testing.T) {
	srv, _ := pendingAgentServer(t, nil)
	ui := &fakeUI{}

	n, err := CheckPendingRequests(agentapi.NewClient(srv.URL), ui)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("pending count = %d, want 0", n)
	}
	if ui.confirmCalls != 0 {
		t.Errorf("dialog calls = %d, want 0", ui.confirmCalls)
	}
	if len(ui.infos) != 1 || !strings.Contains(ui.infos[0], "Нет ожидающих") {
		t.Errorf("infos = %v, want a no-pending message", ui.infos)
	}
}

// TestCheckPendingRequestsUnreachable verifies that an unreachable agent
// surfaces an error through the UI and no dialog is shown.
func TestCheckPendingRequestsUnreachable(t *testing.T) {
	ui := &fakeUI{}
	api := agentapi.NewClient("http://127.0.0.1:1") // closed port

	n, err := CheckPendingRequests(api, ui)
	if err == nil {
		t.Fatal("CheckPendingRequests() error = nil, want an error")
	}
	if n != 0 {
		t.Errorf("pending count = %d, want 0", n)
	}
	if len(ui.errs) != 1 {
		t.Errorf("errors reported = %d, want 1", len(ui.errs))
	}
	if ui.confirmCalls != 0 {
		t.Errorf("dialog calls = %d, want 0", ui.confirmCalls)
	}
}

// --- Case 2: unlock failure notification ---
//
// A notification that no key could be found to decrypt a document
// ("возможно агент оффлайн") or that the key servers are unreachable is
// presented to the user. The agent's /api/notifications is emulated with
// an httptest server; the presenter records what would be shown.

// fakeNotifier records displayed notifications instead of rendering them.
type fakeNotifier struct {
	titles   []string
	contents []string
}

func (f *fakeNotifier) ShowNotification(title, content string) {
	f.titles = append(f.titles, title)
	f.contents = append(f.contents, content)
}

// notificationAgentServer emulates the agent's /api/notifications.
func notificationAgentServer(t *testing.T, notes []agentapi.Notification) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/notifications", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"notifications": notes})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchNewNotificationsNoKeyOffline verifies that "no key found" and
// "offline" notifications from the agent are presented with the right
// titles, reported once (id deduplication) and skipped when already seen.
func TestFetchNewNotificationsNoKeyOffline(t *testing.T) {
	srv := notificationAgentServer(t, []agentapi.Notification{
		{ID: 1, Kind: "offline", Text: `Не удалось открыть "letter.txt": keyclient: all 1 servers failed to issue reader key: connection refused`},
		{ID: 2, Kind: "key_missing", Text: `Не удалось открыть "report.docx": fuse: reader key for owner not found`},
	})
	presenter := &fakeNotifier{}

	// First poll: both notifications are new.
	lastID, shown, err := FetchNewNotifications(agentapi.NewClient(srv.URL), presenter, 0)
	if err != nil {
		t.Fatalf("FetchNewNotifications() error: %v", err)
	}
	if shown != 2 {
		t.Errorf("shown = %d, want 2", shown)
	}
	if lastID != 2 {
		t.Errorf("lastID = %d, want 2", lastID)
	}
	if len(presenter.titles) != 2 {
		t.Fatalf("titles = %v, want 2 notifications", presenter.titles)
	}
	// offline title
	if presenter.titles[0] != "Clavis: нет доступа к серверам ключей" {
		t.Errorf("titles[0] = %q, want the offline title", presenter.titles[0])
	}
	// key_missing title
	if presenter.titles[1] != "Clavis: не найден ключ для документа" {
		t.Errorf("titles[1] = %q, want the no-key title", presenter.titles[1])
	}
	if !strings.Contains(presenter.contents[1], "report.docx") {
		t.Errorf("content = %q, want the document name", presenter.contents[1])
	}

	// Second poll with the same lastID: nothing is shown again.
	lastID, shown, err = FetchNewNotifications(agentapi.NewClient(srv.URL), presenter, lastID)
	if err != nil {
		t.Fatal(err)
	}
	if shown != 0 || len(presenter.titles) != 2 {
		t.Errorf("duplicate notification shown: shown = %d, total titles = %d", shown, len(presenter.titles))
	}
	if lastID != 2 {
		t.Errorf("lastID after second poll = %d, want 2", lastID)
	}
}

// TestFetchNewNotificationsGenericTitle verifies the fallback title for
// unknown kinds and the empty-no-notifications case.
func TestFetchNewNotificationsGenericTitle(t *testing.T) {
	srv := notificationAgentServer(t, []agentapi.Notification{
		{ID: 7, Kind: "info", Text: "просто информация"},
	})
	presenter := &fakeNotifier{}

	lastID, shown, err := FetchNewNotifications(agentapi.NewClient(srv.URL), presenter, 0)
	if err != nil {
		t.Fatal(err)
	}
	if shown != 1 || lastID != 7 {
		t.Errorf("shown = %d, lastID = %d, want 1 / 7", shown, lastID)
	}
	if presenter.titles[0] != "Clavis" {
		t.Errorf("title = %q, want the generic title", presenter.titles[0])
	}
}
