package keyserver

import (
	"testing"

	"github.com/clavis/clavis/internal/keyclient"
)

// TestMemoryStoreServerAttribution verifies that records written through
// a store constructed with a server id carry that id, mirroring the
// PostgreSQL behaviour.
func TestMemoryStoreServerAttribution(t *testing.T) {
	store := NewMemoryStore("server-t0ken")

	// Registration records the producing instance.
	rec := AgentRecord{AgentID: "a1", OwnerKeyID: "owner-1"}
	if err := store.RegisterAgent(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := store.AgentByID("a1")
	if !ok {
		t.Fatal("agent not found")
	}
	if got.ServerID != "server-t0ken" {
		t.Errorf("agent server_id = %q, want server-t0ken", got.ServerID)
	}

	// Every audit entry is attributed to the instance.
	store.AddAudit(AuditEntry{AgentID: "a1", Reason: "issued"})
	entries := store.ListAudit(10)
	if len(entries) != 1 || entries[0].ServerID != "server-t0ken" {
		t.Errorf("audit = %+v, want one entry with server_id server-t0ken", entries)
	}

	// e2e rendezvous and peer observations too.
	session, err := store.CreateE2ESession("owner-1", "a2")
	if err != nil {
		t.Fatal(err)
	}
	if session.ServerID != "server-t0ken" {
		t.Errorf("e2e session server_id = %q, want server-t0ken", session.ServerID)
	}
	store.RecordPeerStatus("https://ks2:8443", true)
	if states := store.PeerStates(); len(states) != 1 || states[0].ServerID != "server-t0ken" {
		t.Errorf("peer states = %+v, want one state with server_id server-t0ken", states)
	}

	// Documents too.
	doc, err := store.EnsureDocument("uuid-1", keyclient.Policies{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if doc.ServerID != "server-t0ken" {
		t.Errorf("document server_id = %q, want server-t0ken", doc.ServerID)
	}
}

// TestMemoryStoreNoServerID verifies the default constructor keeps working
// without a server id (empty attribution).
func TestMemoryStoreNoServerID(t *testing.T) {
	store := NewMemoryStore()
	if err := store.RegisterAgent(AgentRecord{AgentID: "a", OwnerKeyID: "o"}); err != nil {
		t.Fatal(err)
	}
	rec, ok := store.AgentByID("a")
	if !ok || rec.ServerID != "" {
		t.Errorf("agent without server id = %+v, want empty server_id", rec)
	}
}
