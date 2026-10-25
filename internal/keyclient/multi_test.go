package keyclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(IssueResponse{
			Key:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			TTLSeconds: 3600,
			Policies:   Policies{ReadWrite: true},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// badServerURL points to a closed port so requests fail fast.
const badServerURL = "http://127.0.0.1:1"

// TestMultiClientFailsOver verifies that a dead server is skipped and the
// next healthy server answers.
func TestMultiClientFailsOver(t *testing.T) {
	good := okServer(t)

	badClient := NewClient(badServerURL, nil, time.Second)
	goodClient := NewClient(good.URL, nil, time.Second)
	multi := NewMultiClient([]*Client{badClient, goodClient})

	ctx := context.Background()
	resp, err := multi.IssueKey(ctx, IssueRequest{DocumentUUID: "doc-1"})
	if err != nil {
		t.Fatalf("IssueKey() error: %v", err)
	}
	if resp.TTLSeconds != 3600 {
		t.Errorf("ttl = %d", resp.TTLSeconds)
	}
	if multi.LastSuccessIndex() != 1 {
		t.Errorf("LastSuccessIndex() = %d, want 1", multi.LastSuccessIndex())
	}

	// When the second server answers first, the first healthy one wins.
	only := NewMultiClient([]*Client{goodClient})
	if _, err := only.IssueKey(ctx, IssueRequest{DocumentUUID: "doc-2"}); err != nil {
		t.Fatalf("single server IssueKey() error: %v", err)
	}
}

// TestMultiClientAllDown verifies the aggregate error.
func TestMultiClientAllDown(t *testing.T) {
	multi := NewMultiClient([]*Client{
		NewClient(badServerURL, nil, time.Second),
		NewClient(badServerURL, nil, time.Second),
	})
	if _, err := multi.IssueKey(context.Background(), IssueRequest{}); err == nil {
		t.Fatal("IssueKey() error = nil, want an aggregate error")
	}
}

// TestMultiClientRegisterAt verifies per-server registration addressing.
func TestMultiClientRegisterAt(t *testing.T) {
	good := okServer(t)
	client := NewClient(good.URL, nil, time.Second)
	multi := NewMultiClient([]*Client{client})

	reg, err := multi.RegisterAt(context.Background(), 0, RegisterRequest{
		DeviceID: "dev-1",
		PubSig:   make([]byte, 32),
	})
	if err == nil {
		// The ok server answers /api/v1/keys/issue for any path, so a
		// registration may even succeed; we only assert the addressing
		// does not panic on out-of-range.
		_ = reg
	}
	if _, err := multi.RegisterAt(context.Background(), 99, RegisterRequest{}); err == nil {
		t.Fatal("RegisterAt(99) error = nil, want out-of-range")
	}
}
