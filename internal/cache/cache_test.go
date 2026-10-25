package cache

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

func testOwner() [16]byte {
	var o [16]byte
	for i := range o {
		o[i] = byte(i + 1)
	}
	return o
}

// TestPutGetRoundTrip verifies the basic store/load cycle.
func TestPutGetRoundTrip(t *testing.T) {
	master := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "cache.db")

	s, err := Open(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	owner := testOwner()
	as := bytes.Repeat([]byte{0xAB}, 32)
	pub := bytes.Repeat([]byte{0xCD}, 32)

	if _, _, ok := s.Get(owner); ok {
		t.Fatal("cache must be empty initially")
	}
	if err := s.Put(owner, as, pub); err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	gotAS, gotPub, ok := s.Get(owner)
	if !ok {
		t.Fatal("Get() miss after Put")
	}
	if !bytes.Equal(gotAS, as) || !bytes.Equal(gotPub, pub) {
		t.Error("round trip mismatch")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: data must survive (offline use case).
	s2, err := Open(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	gotAS, gotPub, ok = s2.Get(owner)
	if !ok {
		t.Fatal("Get() miss after reopen")
	}
	if !bytes.Equal(gotAS, as) || !bytes.Equal(gotPub, pub) {
		t.Error("persisted round trip mismatch")
	}
}

// TestGetWrongMaster verifies the wrapped payload cannot be read without
// the correct master key A.
func TestGetWrongMaster(t *testing.T) {
	master := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "cache.db")

	s, err := Open(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	owner := testOwner()
	if err := s.Put(owner, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	wrong := make([]byte, 32)
	wrong[0] = 0xFF
	s2, err := Open(path, wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if _, _, ok := s2.Get(owner); ok {
		t.Fatal("cache must be unreadable with a wrong master key")
	}
}

// TestUnknownOwner verifies Get on an absent owner.
func TestUnknownOwner(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "c.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	var other [16]byte
	other[0] = 77
	if _, _, ok := s.Get(other); ok {
		t.Fatal("unknown owner found")
	}
}

var _ = crypto.MasterKeySize
