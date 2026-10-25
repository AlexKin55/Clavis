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

// TestCheckPendingRequestsShowsDialog simulates an end-to-end key request:
// the agent reports a pending session, the dialog must be shown with the
// peer identity, and granting the request must call the approve endpoint.
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

// TestCheckPendingRequestsRefuse verifies that refusing the dialog does
// not call the approve endpoint.
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
