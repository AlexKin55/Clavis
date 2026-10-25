// Package keyserver_test contains black-box integration tests for the
// Key Server HTTP API (using the public Handler).
package keyserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/keyclient"
	"github.com/clavis/clavis/internal/keyserver"
)

const testAgent = "agent-001"

func serverPubKey() ed25519.PublicKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func newTestServer() *httptest.Server {
	srv := keyserver.NewServer(keyserver.Config{
		DefaultPolicies: keyclient.Policies{ReadWrite: true},
		DefaultTTL:      time.Hour,
		ServerKey:       serverPubKey(),
	}, keyserver.NewMemoryStore())
	ts := httptest.NewServer(srv.Handler())
	return ts
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, agentID string, body any) (*http.Response, []byte) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if agentID != "" {
		req.Header.Set("X-Agent-ID", agentID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// TestIssueDeterministicKey verifies the v1 contract: same document UUID
// always yields the same key with policies/TTL.
func TestIssueDeterministicKey(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	uuid := "11111111-2222-3333-4444-555555555555"
	var first string
	for i := 0; i < 2; i++ {
		resp, body := doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", testAgent, keyclient.IssueRequest{
			DocumentUUID: uuid,
			Subject:      keyclient.Subject{PID: 42, Comm: "gedit"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		var out keyclient.IssueResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Key) != 64 {
			t.Errorf("key length = %d", len(out.Key))
		}
		if !out.Policies.CanWrite() {
			t.Error("default policies must allow writes")
		}
		if i == 0 {
			first = out.Key
		} else if out.Key != first {
			t.Error("key changed between issuances")
		}
	}
}

// TestIssueSameKeyAcrossAgents verifies the key is per-document.
func TestIssueSameKeyAcrossAgents(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	uuid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	keys := map[string]string{}
	for _, agent := range []string{"agent-a", "agent-b"} {
		resp, body := doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", agent, keyclient.IssueRequest{DocumentUUID: uuid})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var out keyclient.IssueResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		keys[agent] = out.Key
	}
	if keys["agent-a"] != keys["agent-b"] {
		t.Error("keys differ between agents for the same document")
	}
}

// TestRevocations verifies document and agent revocation (403 after).
func TestRevocations(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// Document revoke.
	docUUID := "deadbeef-dead-beef-dead-beefdeadbeef"
	if resp, body := doJSON(t, srv, http.MethodPost, "/api/v1/keys/revoke", "", map[string]string{"document_uuid": docUUID}); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", resp.StatusCode, body)
	}
	resp, _ := doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", testAgent, keyclient.IssueRequest{DocumentUUID: docUUID})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("issue after document revoke status = %d, want 403", resp.StatusCode)
	}

	// Agent revoke.
	agentUUID := "00000000-0000-0000-0000-000000000099"
	doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", "alice", keyclient.IssueRequest{DocumentUUID: agentUUID})
	doJSON(t, srv, http.MethodPost, "/api/v1/agents/revoke", "", map[string]string{"agent_id": "alice"})
	resp, _ = doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", "alice", keyclient.IssueRequest{DocumentUUID: agentUUID})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("issue after agent revoke status = %d, want 403", resp.StatusCode)
	}
}

// TestSetPolicy verifies policy updates propagate.
func TestSetPolicy(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	uuid := "99999999-8888-7777-6666-555555555555"
	doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", testAgent, keyclient.IssueRequest{DocumentUUID: uuid})

	body := map[string]any{
		"policies":    map[string]bool{"read_only": true},
		"ttl_seconds": 60,
	}
	if resp, b := doJSON(t, srv, http.MethodPut, "/api/v1/documents/"+uuid+"/policy", "", body); resp.StatusCode != http.StatusOK {
		t.Fatalf("set policy status = %d, body = %s", resp.StatusCode, b)
	}

	resp, b := doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", testAgent, keyclient.IssueRequest{DocumentUUID: uuid})
	var out keyclient.IssueResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue status = %d", resp.StatusCode)
	}
	if out.Policies.CanWrite() {
		t.Error("read_only policy must forbid writes")
	}
	if out.TTLSeconds != 60 {
		t.Errorf("ttl = %d, want 60", out.TTLSeconds)
	}
}

// TestV2AgentRegistrationAndReaderKey covers the whole v2 registration
// flow: register -> derive AS -> store AS -> retrieve AS by owner key id.
func TestV2AgentRegistrationAndReaderKey(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := keyclient.NewClient(srv.URL, nil, time.Second)
	ctx := context.Background()

	identity, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}

	reg, err := client.Register(ctx, keyclient.RegisterRequest{
		DeviceID: "dev-a",
		PubSig:   identity.PublicSignatureKey(),
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	pubServer, err := hex.DecodeString(reg.PublicKeyServer)
	if err != nil {
		t.Fatal(err)
	}
	nonceServer, err := hex.DecodeString(reg.NonceServer)
	if err != nil {
		t.Fatal(err)
	}
	asA, err := identity.ReaderKey(pubServer, nonceServer)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.SetReaderKey(ctx, keyclient.SetReaderKeyRequest{AgentID: reg.AgentID, ReaderKey: asA}); err != nil {
		t.Fatalf("SetReaderKey() error: %v", err)
	}

	owner := identity.OwnerKeyID()
	ownerKeyHex := hex.EncodeToString(owner[:])
	got, err := client.ReaderKey(ctx, ownerKeyHex)
	if err != nil {
		t.Fatalf("ReaderKey() error: %v", err)
	}
	if !bytes.Equal(got.ReaderKey, asA) {
		t.Error("reader key round trip mismatch")
	}
	if !bytes.Equal(got.PubSig, identity.PublicSignatureKey()) {
		t.Error("pub_sig round trip mismatch")
	}

	// Revoking the agent blocks further reader-key issuance.
	doJSON(t, srv, http.MethodPost, "/api/v1/agents/revoke", "", map[string]string{"agent_id": reg.AgentID})
	if _, err := client.ReaderKey(ctx, ownerKeyHex); err == nil {
		t.Error("ReaderKey() after revoke error = nil, want an error")
	}
}

// TestE2EWithClient exercises the full v1 loop with keyclient.Getter.
func TestE2EWithClient(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	client := keyclient.NewClient(srv.URL, nil, time.Second)
	getter := keyclient.NewGetter(client, keyclient.NewCache())

	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	first, err := getter.LoadKey(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	second, err := getter.LoadKey(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("cached key differs")
	}
	if len(first) != 32 {
		t.Errorf("key length = %d, want 32", len(first))
	}
}

// TestAudit verifies the audit trail records decisions.
type auditEntry struct {
	Time     string `json:"time"`
	AgentID  string `json:"agent_id"`
	Document string `json:"document"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

func TestAudit(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	uuid := "12345678-1234-5678-1234-567812345678"
	doJSON(t, srv, http.MethodPost, "/api/v1/keys/issue", testAgent, keyclient.IssueRequest{DocumentUUID: uuid})

	resp, body := doJSON(t, srv, http.MethodGet, "/api/v1/audit?limit=10", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit status = %d", resp.StatusCode)
	}
	var out struct {
		Audit []auditEntry `json:"audit"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Audit) == 0 {
		t.Fatal("audit is empty")
	}
	found := false
	for _, e := range out.Audit {
		if e.Document == uuid && e.Allowed {
			found = true
		}
	}
	if !found {
		t.Error("audit does not contain the granted decision")
	}
}

// TestV2StoreCore verifies the store-level registration primitives
// through the public API.
func TestV2StoreCore(t *testing.T) {
	store := keyserver.NewMemoryStore()

	rec := keyserver.AgentRecord{
		AgentID:     "ag-1",
		DeviceID:    "dev-1",
		PubSig:      []byte{1, 2, 3},
		OwnerKeyID:  "owner-1",
		NonceServer: []byte{4, 5, 6},
	}
	if err := store.RegisterAgent(rec); err != nil {
		t.Fatal(err)
	}
	if err := store.SetReaderKey("owner-1", []byte{0xAA, 0xBB}); err != nil {
		t.Fatal(err)
	}
	got, ok := store.AgentByOwnerKeyID("owner-1")
	if !ok {
		t.Fatal("agent by owner not found")
	}
	if string(got.ReaderKey) != string([]byte{0xAA, 0xBB}) {
		t.Errorf("reader key mismatch: %x", got.ReaderKey)
	}
	if err := store.SetReaderKey("nobody", []byte{1}); err == nil {
		t.Error("SetReaderKey(unknown owner) error = nil, want an error")
	}
	store.RevokeAgent("ag-1")
	if !store.AgentRevoked("ag-1") {
		t.Error("revoked flag not set")
	}
}

// TestHealth verifies the liveness endpoint.
func TestHealth(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, body := doJSON(t, srv, http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", resp.StatusCode, body)
	}
}
