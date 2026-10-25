package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/clavis/clavis/internal/cache"
	"github.com/clavis/clavis/internal/crypto"
)

// keyMaterial is one owner's read-only key material (AS + public sig key).
type keyMaterial struct {
	as  []byte
	pub []byte
}

// switchableProvider is a fuse.ReaderKeyProvider whose "network" can be
// toggled to simulate the agent going offline.
type switchableProvider struct {
	online bool
	keys   map[[16]byte]keyMaterial
}

// ReaderKey implements fuse.ReaderKeyProvider.
func (p *switchableProvider) ReaderKey(_ context.Context, owner [16]byte, _ crypto.Mode) ([]byte, []byte, error) {
	if !p.online {
		return nil, nil, errors.New("offline: key server unreachable")
	}
	k, ok := p.keys[owner]
	if !ok {
		return nil, nil, errors.New("owner not found")
	}
	return k.as, k.pub, nil
}

// TestCachedReaderKeysOfflineMixed verifies the offline behaviour with a
// partially filled SQLite cache: documents whose reader key is cached
// open, documents without one fail without disturbing the cached ones,
// and the cache survives a restart (fresh Store over the same database).
func TestCachedReaderKeysOfflineMixed(t *testing.T) {
	ownerA, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	asA, err := ownerA.UnifiedReaderKey()
	if err != nil {
		t.Fatal(err)
	}
	asB, err := ownerB.UnifiedReaderKey()
	if err != nil {
		t.Fatal(err)
	}

	master := make([]byte, crypto.MasterKeySize) // fixed test master key A
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	store, err := cache.Open(dbPath, master)
	if err != nil {
		t.Fatal(err)
	}

	inner := &switchableProvider{
		online: true,
		keys: map[[16]byte]keyMaterial{
			ownerA.OwnerKeyID(): {as: asA, pub: ownerA.PublicSignatureKey()},
			ownerB.OwnerKeyID(): {as: asB, pub: ownerB.PublicSignatureKey()},
		},
	}
	// Only A's key is cached (e.g. A was opened online earlier).
	if err := store.Put(ownerA.OwnerKeyID(), asA, ownerA.PublicSignatureKey()); err != nil {
		t.Fatal(err)
	}
	keys := &cachedReaderKeys{inner: inner, store: store}
	ctx := context.Background()

	get := func(owner *crypto.AgentIdentity, wantAS []byte) error {
		as, _, err := keys.ReaderKey(ctx, owner.OwnerKeyID(), crypto.ModeProxy)
		if err != nil {
			return err
		}
		if !bytes.Equal(as, wantAS) {
			return errors.New("reader key mismatch")
		}
		return nil
	}

	// Offline: A (cached) opens, B (uncached) fails.
	inner.online = false
	if err := get(ownerA, asA); err != nil {
		t.Fatalf("offline open of cached document: %v", err)
	}
	if err := get(ownerB, asB); err == nil {
		t.Fatal("offline open of uncached document: error = nil, want an error")
	}
	// The agent keeps serving the cached document after the miss.
	if err := get(ownerA, asA); err != nil {
		t.Fatalf("cached document failed after an uncached miss: %v", err)
	}

	// Online: B opens and its key is now cached.
	inner.online = true
	if err := get(ownerB, asB); err != nil {
		t.Fatalf("online open of document: %v", err)
	}

	// Offline again: both open from the cache.
	inner.online = false
	if err := get(ownerA, asA); err != nil {
		t.Fatal(err)
	}
	if err := get(ownerB, asB); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: a fresh Store over the same database still serves both.
	restarted, err := cache.Open(dbPath, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	rebooted := &cachedReaderKeys{inner: inner, store: restarted}
	if as, _, err := rebooted.ReaderKey(ctx, ownerA.OwnerKeyID(), crypto.ModeProxy); err != nil || !bytes.Equal(as, asA) {
		t.Fatalf("cached key lost after restart: as=%x err=%v", as, err)
	}
	if as, _, err := rebooted.ReaderKey(ctx, ownerB.OwnerKeyID(), crypto.ModeProxy); err != nil || !bytes.Equal(as, asB) {
		t.Fatalf("cached key lost after restart: as=%x err=%v", as, err)
	}
}
