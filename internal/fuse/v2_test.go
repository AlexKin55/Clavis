package fuse

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

// staticReaderProvider serves precomputed owner reader material.
type staticReaderProvider map[[16]byte]struct {
	as  []byte
	pub []byte
}

func (p staticReaderProvider) ReaderKey(_ context.Context, owner [16]byte) ([]byte, []byte, error) {
	e, ok := p[owner]
	if !ok {
		return nil, nil, errors.New("owner not found")
	}
	return e.as, e.pub, nil
}

func v2Fixture(t *testing.T) (owner *crypto.AgentIdentity, serverPub, serverNonce []byte) {
	t.Helper()
	id, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPub = make([]byte, 32)
	serverNonce = make([]byte, 16)
	if _, err := rand.Read(serverNonce); err != nil {
		t.Fatal(err)
	}
	return id, serverPub, serverNonce
}

// TestV2CreateSignedDocument verifies the full v2 cycle: A creates a
// signed document, B reads it via the reader-key provider and the owner
// signature is verified on a full read.
func TestV2CreateSignedDocument(t *testing.T) {
	owner, serverPub, serverNonce := v2Fixture(t)
	sourceDir := t.TempDir()

	ownerRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    owner,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
		DefaultMode: crypto.ModeProxy,
	})

	path := filepath.Join(sourceDir, "v2doc.txt")
	f, err := ownerRoot.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatalf("createProtectedFile() error: %v", err)
	}
	payload := []byte("v2 signed secret payload")
	if _, e := f.Write(context.Background(), payload, 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.Release(context.Background()); e != 0 {
		t.Fatalf("Release() errno: %v", e)
	}

	// Layout check: v2 header + signature block.
	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if physical[4] != crypto.HeaderVersion+1 {
		t.Errorf("version byte = %d, want 2", physical[4])
	}
	wantLen := crypto.HeaderV2Size + crypto.SignatureBlockLen + len(payload)
	if len(physical) != wantLen {
		t.Errorf("physical length = %d, want %d", len(physical), wantLen)
	}
	if bytes.Contains(physical, payload) {
		t.Error("plaintext found on disk")
	}

	// B reads the document through the reader-key provider.
	as, err := owner.ReaderKey(serverPub, serverNonce)
	if err != nil {
		t.Fatal(err)
	}
	provider := staticReaderProvider{owner.OwnerKeyID(): {as: as, pub: owner.PublicSignatureKey()}}

	readerRoot := NewSecureRoot(&Config{
		SourceDir:  sourceDir,
		KeyGetter:  crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		ReaderKeys: provider,
	})
	rf, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR)
	if err != nil {
		t.Fatalf("openProtectedFile() error: %v", err)
	}
	dest := make([]byte, len(payload))
	res, e := rf.Read(context.Background(), dest, 0)
	if e != 0 {
		t.Fatalf("Read() errno: %v (owner signature must verify)", e)
	}
	got, status := res.Bytes(dest)
	if status != 0 {
		t.Fatalf("Read() status: %v", status)
	}
	if !bytes.Equal(got, payload) {
		t.Error("read content mismatch")
	}
	_ = rf.Release(context.Background())
}

// TestV2TamperFailsSignature verifies that modified ciphertext breaks the
// owner signature on a full read.
func TestV2TamperFailsSignature(t *testing.T) {
	owner, serverPub, serverNonce := v2Fixture(t)
	sourceDir := t.TempDir()
	ownerRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    owner,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
	})

	path := filepath.Join(sourceDir, "tamper.txt")
	f, err := ownerRoot.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if _, e := f.Write(context.Background(), payload, 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.Release(context.Background()); e != 0 {
		t.Fatal(e)
	}

	// Corrupt one ciphertext byte.
	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	full := crypto.HeaderV2Size + crypto.SignatureBlockLen
	physical[full] ^= 0xff
	if err := os.WriteFile(path, physical, 0o600); err != nil {
		t.Fatal(err)
	}

	as, _ := owner.ReaderKey(serverPub, serverNonce)
	provider := staticReaderProvider{owner.OwnerKeyID(): {as: as, pub: owner.PublicSignatureKey()}}
	readerRoot := NewSecureRoot(&Config{
		SourceDir:  sourceDir,
		KeyGetter:  crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		ReaderKeys: provider,
	})

	rf, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	dest := make([]byte, len(payload))
	_, e := rf.Read(context.Background(), dest, 0)
	if e != syscall.EACCES {
		t.Fatalf("Read() errno = %v, want EACCES (signature failure)", e)
	}
	_ = rf.Release(context.Background())
}

// TestV2UnknownOwner verifies that a document whose owner is unknown to the
// provider cannot be opened.
func TestV2UnknownOwner(t *testing.T) {
	owner, serverPub, serverNonce := v2Fixture(t)
	sourceDir := t.TempDir()
	ownerRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    owner,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
	})
	path := filepath.Join(sourceDir, "unknown.txt")
	f, err := ownerRoot.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Release(context.Background())

	readerRoot := NewSecureRoot(&Config{
		SourceDir:  sourceDir,
		KeyGetter:  crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		ReaderKeys: staticReaderProvider{},
	})
	if _, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR); err == nil {
		t.Fatal("openProtectedFile(unknown owner) error = nil, want an error")
	}
}
