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

func (p staticReaderProvider) ReaderKey(_ context.Context, owner [16]byte, _ crypto.Mode) ([]byte, []byte, error) {
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
	as, err := owner.UnifiedReaderKey()
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

	as, _ := owner.UnifiedReaderKey()
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

// TestV2OwnershipChange verifies that editing a foreign document
// re-encrypts it to the editor: the header owner becomes B and the new
// signature verifies under B's key.
func TestV2OwnershipChange(t *testing.T) {
	ownerA, serverPub, serverNonce := v2Fixture(t)
	ownerB, _, _ := v2Fixture(t)

	sourceDir := t.TempDir()
	createRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    ownerA,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
	})

	path := filepath.Join(sourceDir, "doc.txt")
	f, err := createRoot.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("original content from A")
	if _, e := f.Write(context.Background(), original, 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.Release(context.Background()); e != 0 {
		t.Fatal(e)
	}

	// B opens the document (read-only) and then edits it.
	asA, _ := ownerA.UnifiedReaderKey()
	asB, _ := ownerB.UnifiedReaderKey()
	providerAB := staticReaderProvider{
		ownerA.OwnerKeyID(): {as: asA, pub: ownerA.PublicSignatureKey()},
		ownerB.OwnerKeyID(): {as: asB, pub: ownerB.PublicSignatureKey()},
	}
	readerRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    ownerB,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
		ReaderKeys:  providerAB,
	})

	rf, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	// Read everything first (verifies A's signature).
	dest := make([]byte, len(original))
	if _, e := rf.Read(context.Background(), dest, 0); e != 0 {
		t.Fatalf("Read() errno: %v", e)
	}
	// Edit: append a line.
	addition := []byte("\nedited by B")
	if _, e := rf.Write(context.Background(), addition, int64(len(original))); e != 0 {
		t.Fatal(e)
	}
	if e := rf.Release(context.Background()); e != 0 {
		t.Fatalf("Release() errno: %v (re-encrypt to B)", e)
	}

	// The header owner must now be B.
	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeaderV2(physical[:crypto.HeaderV2Size])
	if err != nil {
		t.Fatal(err)
	}
	if header.OwnerKeyID != ownerB.OwnerKeyID() {
		t.Error("document owner was not changed to B")
	}

	// An agent reading as B gets the full edited content with B's signature.
	rfB, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, original...), addition...)
	out := make([]byte, len(want))
	res, e := rfB.Read(context.Background(), out, 0)
	if e != 0 {
		t.Fatalf("Read() after ownership change errno: %v", e)
	}
	got, _ := res.Bytes(out)
	if !bytes.Equal(got, want) {
		t.Errorf("content mismatch after ownership change: %q", got)
	}
	_ = rfB.Release(context.Background())
}

// TestV2ReadOnlyDoesNotChangeOwner verifies that reading a foreign
// document without edits keeps the original owner.
func TestV2ReadOnlyDoesNotChangeOwner(t *testing.T) {
	ownerA, serverPub, serverNonce := v2Fixture(t)
	ownerB, _, _ := v2Fixture(t)

	sourceDir := t.TempDir()
	createRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    ownerA,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
	})
	path := filepath.Join(sourceDir, "doc.txt")
	f, err := createRoot.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("read only")
	if _, e := f.Write(context.Background(), payload, 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.Release(context.Background()); e != 0 {
		t.Fatal(e)
	}

	asA, _ := ownerA.UnifiedReaderKey()
	readerRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:    ownerB,
		ServerPub:   serverPub,
		ServerNonce: serverNonce,
		ReaderKeys: staticReaderProvider{
			ownerA.OwnerKeyID(): {as: asA, pub: ownerA.PublicSignatureKey()},
		},
	})
	rf, err := readerRoot.openProtectedFile(context.Background(), path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, e := rf.Read(context.Background(), buf, 0); e != 0 {
		t.Fatal(e)
	}
	if e := rf.Release(context.Background()); e != 0 {
		t.Fatal(e)
	}

	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeaderV2(physical[:crypto.HeaderV2Size])
	if err != nil {
		t.Fatal(err)
	}
	if header.OwnerKeyID != ownerA.OwnerKeyID() {
		t.Error("read-only access must not change the owner")
	}
}

// TestV2ModeProvider verifies that the GUI-selected mode is applied to
// newly created documents.
func TestV2ModeProvider(t *testing.T) {
	owner, serverPub, serverNonce := v2Fixture(t)
	sourceDir := t.TempDir()

	root := NewSecureRoot(&Config{
		SourceDir:    sourceDir,
		KeyGetter:    crypto.NewFileKeyGetter(filepath.Join(t.TempDir(), "unused.key")),
		Identity:     owner,
		ServerPub:    serverPub,
		ServerNonce:  serverNonce,
		ModeProvider: func() crypto.Mode { return crypto.ModeE2E },
	})

	path := filepath.Join(sourceDir, "mode.txt")
	f, err := root.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Release(context.Background())

	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeaderV2(physical[:crypto.HeaderV2Size])
	if err != nil {
		t.Fatal(err)
	}
	if header.Mode != crypto.ModeE2E {
		t.Errorf("Mode = %d, want ModeE2E (from ModeProvider)", header.Mode)
	}
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
