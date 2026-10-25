package agentid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavis/clavis/internal/keyclient"
	"github.com/clavis/clavis/internal/keyserver"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := keyserver.NewServer(keyserver.Config{
		DefaultPolicies: keyclient.Policies{ReadWrite: true},
		DefaultTTL:      time.Hour,
		ServerKey: func() ed25519.PublicKey {
			seed := make([]byte, 32)
			for i := range seed {
				seed[i] = byte(i)
			}
			return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		}(),
	}, keyserver.NewMemoryStore())
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestLoadOrCreatePersistent verifies that the identity state survives
// reload and reconstructs the same keys.
func TestLoadOrCreatePersistent(t *testing.T) {
	path := t.TempDir() + "/identity.json"

	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate() error: %v", err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.MasterKeyHex != second.MasterKeyHex {
		t.Error("master key changed between reloads")
	}

	id1, err := first.Identity()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := second.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id1.MasterKey, id2.MasterKey) {
		t.Error("restored master key mismatch")
	}
	if !bytes.Equal(id1.PublicSignatureKey(), id2.PublicSignatureKey()) {
		t.Error("restored public key mismatch")
	}
}

// TestEnsureRegistered verifies the registration flow against a real
// Key Server handler and that repeated calls remain idempotent.
func TestEnsureRegistered(t *testing.T) {
	srv := testServer(t)
	client := keyclient.NewClient(srv.URL, nil, time.Second)
	ctx := context.Background()

	path := t.TempDir() + "/identity.json"
	state, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := EnsureRegistered(ctx, keyclient.NewMultiClient([]*keyclient.Client{client}), []string{srv.URL}, state, path); err != nil {
		t.Fatalf("EnsureRegistered() error: %v", err)
	}
	if len(state.Servers) == 0 || state.Servers[0].AgentID == "" {
		t.Fatal("agent id was not assigned")
	}

	agentID := state.Servers[0].AgentID
	if err := EnsureRegistered(ctx, keyclient.NewMultiClient([]*keyclient.Client{client}), []string{srv.URL}, state, path); err != nil {
		t.Fatalf("EnsureRegistered() second call error: %v", err)
	}
	if state.Servers[0].AgentID != agentID {
		t.Error("agent id changed on repeated registration")
	}
}

// TestDerivedReaderKeyMatchesServer verifies that the AS derived locally
// equals the one fetchable from the server by owner key id.
func TestDerivedReaderKeyMatchesServer(t *testing.T) {
	srv := testServer(t)
	client := keyclient.NewClient(srv.URL, nil, time.Second)
	ctx := context.Background()

	path := t.TempDir() + "/identity.json"
	state, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureRegistered(ctx, keyclient.NewMultiClient([]*keyclient.Client{client}), []string{srv.URL}, state, path); err != nil {
		t.Fatal(err)
	}

	identity, err := state.Identity()
	if err != nil {
		t.Fatal(err)
	}
	owner := identity.OwnerKeyID()
	mat, err := client.ReaderKey(ctx, hexEncode(owner[:]))
	if err != nil {
		t.Fatalf("ReaderKey() error: %v", err)
	}

	as, err := identity.UnifiedReaderKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mat.ReaderKey, as) {
		t.Error("reader key on the server differs from local derivation")
	}
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
