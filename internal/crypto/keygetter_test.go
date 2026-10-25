package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

var testUUID = [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

// TestFileKeyGetterHex loads a key stored as 64 hex characters.
func TestFileKeyGetterHex(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "key.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewFileKeyGetter(path)
	got, err := g.LoadKey(context.Background(), testUUID)
	if err != nil {
		t.Fatalf("LoadKey() error: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("LoadKey() key mismatch")
	}
}

// TestFileKeyGetterRaw loads a key stored as raw bytes.
func TestFileKeyGetterRaw(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xff - i)
	}
	path := filepath.Join(t.TempDir(), "key.raw")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewFileKeyGetter(path)
	got, err := g.LoadKey(context.Background(), testUUID)
	if err != nil {
		t.Fatalf("LoadKey() error: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("LoadKey() key mismatch")
	}
}

// TestFileKeyGetterCached verifies that repeated calls return equal keys.
func TestFileKeyGetterCached(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.hex")
	key := make([]byte, 32)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewFileKeyGetter(path)
	first, err := g.LoadKey(context.Background(), testUUID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.LoadKey(context.Background(), testUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("cached keys differ")
	}
}

// TestFileKeyGetterBadLength verifies rejection of a key of invalid length.
func TestFileKeyGetterBadLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.hex")
	// 20 hex chars = 10 bytes — invalid AES key length.
	if err := os.WriteFile(path, []byte("00112233445566778899\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewFileKeyGetter(path)
	if _, err := g.LoadKey(context.Background(), testUUID); err == nil {
		t.Fatal("LoadKey() error = nil, want an error")
	}
}

// TestFileKeyGetterMissing verifies the error for a non-existent key file.
func TestFileKeyGetterMissing(t *testing.T) {
	g := NewFileKeyGetter(filepath.Join(t.TempDir(), "nope.key"))
	if _, err := g.LoadKey(context.Background(), testUUID); err == nil {
		t.Fatal("LoadKey() error = nil, want an error")
	}
}

// TestGenerateKeyFile verifies that GenerateKeyFile writes a loadable key.
func TestGenerateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generated.key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile() error: %v", err)
	}

	g := NewFileKeyGetter(path)
	got, err := g.LoadKey(context.Background(), testUUID)
	if err != nil {
		t.Fatalf("LoadKey() error: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("generated key length = %d, want 32", len(got))
	}
}
