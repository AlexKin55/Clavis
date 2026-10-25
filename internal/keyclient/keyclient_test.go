package keyclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clavis/clavis/internal/subject"
)

func fixedUUID() [16]byte {
	var u [16]byte
	for i := range u {
		u[i] = byte(i)
	}
	return u
}

func testKeyHex() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	return hex.EncodeToString(key)
}

// TestPoliciesCanWrite verifies the policy write gate.
func TestPoliciesCanWrite(t *testing.T) {
	if !(Policies{ReadWrite: true}).CanWrite() {
		t.Error("ReadWrite must allow writes")
	}
	if (Policies{ReadOnly: true}).CanWrite() {
		t.Error("ReadOnly must forbid writes")
	}
	if (Policies{ReadOnly: true, ReadWrite: true}).CanWrite() {
		t.Error("ReadOnly + ReadWrite must forbid writes")
	}
}

// TestPoliciesValidate verifies policy invariants.
func TestPoliciesValidate(t *testing.T) {
	if err := (Policies{}).Validate(); err != nil {
		t.Errorf("empty policies: %v", err)
	}
	if err := (Policies{ReadOnly: true, ReadWrite: true}).Validate(); err == nil {
		t.Error("conflicting policies must fail validation")
	}
}

// TestCachePutGet verifies the happy path.
func TestCachePutGet(t *testing.T) {
	c := NewCache()
	uuid := formatUUID(fixedUUID())
	key := []byte{1, 2, 3}

	if _, _, ok := c.Get(uuid); ok {
		t.Fatal("cache must be empty initially")
	}

	c.Put(uuid, key, Policies{ReadWrite: true}, time.Minute)
	got, pol, ok := c.Get(uuid)
	if !ok {
		t.Fatal("entry not found after Put")
	}
	if string(got) != string(key) {
		t.Errorf("key mismatch")
	}
	if !pol.CanWrite() {
		t.Error("policies mismatch")
	}
}

// TestCacheExpired verifies TTL enforcement.
func TestCacheExpired(t *testing.T) {
	c := NewCache()
	uuid := formatUUID(fixedUUID())

	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	c.Put(uuid, []byte{9}, Policies{}, time.Hour)

	c.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, _, ok := c.Get(uuid); ok {
		t.Fatal("expired entry must not be returned")
	}
}

// TestCacheRevoke verifies revocation removal.
func TestCacheRevoke(t *testing.T) {
	c := NewCache()
	uuid := formatUUID(fixedUUID())
	c.Put(uuid, []byte{1}, Policies{}, time.Hour)
	c.Revoke(uuid)
	if _, _, ok := c.Get(uuid); ok {
		t.Fatal("revoked entry must not be returned")
	}
}

// testServer starts a mock Key Server returning the given handler.
func testServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// TestClientIssueKey verifies request/response of the protocol.
func TestClientIssueKey(t *testing.T) {
	var gotReq IssueRequest
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != issuePath {
			t.Errorf("path = %q, want %q", r.URL.Path, issuePath)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(IssueResponse{
			Key:        testKeyHex(),
			TTLSeconds: 3600,
			Policies:   Policies{ReadWrite: true},
		})
	})

	client := NewClient(srv.URL, nil, time.Second)
	resp, err := client.IssueKey(context.Background(), IssueRequest{
		DocumentUUID: formatUUID(fixedUUID()),
		Subject:      Subject{PID: 42, UID: 1000, Comm: "gedit"},
	})
	if err != nil {
		t.Fatalf("IssueKey() error: %v", err)
	}
	if resp.TTLSeconds != 3600 || !resp.Policies.CanWrite() {
		t.Errorf("unexpected response: %+v", resp)
	}
	if gotReq.DocumentUUID != formatUUID(fixedUUID()) {
		t.Errorf("document_uuid = %q", gotReq.DocumentUUID)
	}
	if gotReq.Subject.PID != 42 || gotReq.Subject.Comm != "gedit" {
		t.Errorf("subject not transmitted: %+v", gotReq.Subject)
	}
}

// TestClientServerError verifies non-200 handling.
func TestClientServerError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "access denied", http.StatusForbidden)
	})

	client := NewClient(srv.URL, nil, time.Second)
	_, err := client.IssueKey(context.Background(), IssueRequest{})
	if err == nil {
		t.Fatal("IssueKey() error = nil, want a server error")
	}
	if _, ok := err.(*serverError); !ok {
		t.Errorf("error type = %T, want *serverError", err)
	}
}

// TestGetterCaches verifies that a cache hit avoids a new server round trip.
func TestGetterCaches(t *testing.T) {
	var calls atomic.Int32
	srv := testServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(IssueResponse{
			Key:        testKeyHex(),
			TTLSeconds: 3600,
			Policies:   Policies{ReadWrite: true},
		})
	})

	client := NewClient(srv.URL, nil, time.Second)
	g := NewGetter(client, NewCache())

	ctx := subject.WithContext(context.Background(), subject.Info{PID: 1, Comm: "app"})
	first, err := g.LoadKey(ctx, fixedUUID())
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.LoadKey(ctx, fixedUUID())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("keys from cache differ")
	}
	if calls.Load() != 1 {
		t.Errorf("server calls = %d, want 1 (second served from cache)", calls.Load())
	}
}

// TestGetterTLZZero does not cache when the response TTL is non-positive.
func TestGetterTLZZero(t *testing.T) {
	var calls atomic.Int32
	srv := testServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(IssueResponse{Key: testKeyHex(), TTLSeconds: 0})
	})

	g := NewGetter(NewClient(srv.URL, nil, time.Second), nil)
	ctx := context.Background()

	if _, err := g.LoadKey(ctx, fixedUUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.LoadKey(ctx, fixedUUID()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("server calls = %d, want 2 (no caching with TTL<=0)", calls.Load())
	}
}

// TestSubjectTransport verifies the subject round trip.
func TestSubjectTransport(t *testing.T) {
	orig := subject.Info{PID: 7, UID: 1000, GID: 999, Comm: "vim", FileName: "/x", InFirejail: true}
	got := FromInfo(orig).ToInfo()
	if got.PID != orig.PID || got.UID != orig.UID || got.Comm != orig.Comm || !got.InFirejail {
		t.Errorf("round trip mismatch: %+v != %+v", got, orig)
	}
}

// TestNewTLSConfig verifies that a config can be built without files.
func TestNewTLSConfig(t *testing.T) {
	cfg, err := NewTLSConfig(TLSConfig{})
	if err != nil {
		t.Fatalf("NewTLSConfig() error: %v", err)
	}
	if cfg == nil {
		t.Fatal("NewTLSConfig() = nil")
	}
}

// TestFormatUUID sanity-check.
func TestFormatUUID(t *testing.T) {
	u := fixedUUID()
	if got := formatUUID(u); len(got) != 36 || got[8] != '-' {
		t.Errorf("formatUUID() = %q", got)
	}
}

// TestIssueResponseJSON mimics a full protocol exchange.
func TestIssueResponseJSON(t *testing.T) {
	raw := `{"key":"` + testKeyHex() + `","ttl_seconds":60,"policies":{"read_write":true}}`
	var resp IssueResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Policies.CanWrite() {
		t.Error("policies not parsed")
	}
}
