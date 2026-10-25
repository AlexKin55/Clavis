package token

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

// fakeUnwrapper simulates a token whose master key XORs the payload.
type fakeUnwrapper struct {
	master []byte
}

func newFakeUnwrapper() *fakeUnwrapper {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0xa5)
	}
	return &fakeUnwrapper{master: master}
}

func (f *fakeUnwrapper) Wrap(raw []byte) ([]byte, error) {
	return f.transform(raw), nil
}

func (f *fakeUnwrapper) Unwrap(blob []byte) ([]byte, error) {
	return f.transform(blob), nil
}

func (f *fakeUnwrapper) Close() error { return nil }

func (f *fakeUnwrapper) transform(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ f.master[i%len(f.master)]
	}
	return out
}

func testDocUUID() [16]byte {
	var u [16]byte
	for i := range u {
		u[i] = byte(i + 1)
	}
	return u
}

// TestGetterFirstUse verifies that the first call generates a key, wraps
// it into a blob and that later calls recover the same key from the blob.
func TestGetterFirstUse(t *testing.T) {
	blobsDir := t.TempDir()
	fake := newFakeUnwrapper()
	g := NewGetter(fake, blobsDir)

	uuid := testDocUUID()
	first, err := g.LoadKey(context.Background(), uuid)
	if err != nil {
		t.Fatalf("LoadKey() error: %v", err)
	}
	if len(first) != 32 {
		t.Errorf("key length = %d, want 32", len(first))
	}

	blobPath := BlobPath(blobsDir, uuid)
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob not stored: %v", err)
	}

	second, err := g.LoadKey(context.Background(), uuid)
	if err != nil {
		t.Fatalf("LoadKey() second error: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("keys differ between first and cached/token calls")
	}
}

// TestGetterDifferentDocuments verifies that each document gets its own key.
func TestGetterDifferentDocuments(t *testing.T) {
	blobsDir := t.TempDir()
	g := NewGetter(newFakeUnwrapper(), blobsDir)

	a := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	b := [16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	keyA, err := g.LoadKey(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := g.LoadKey(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Error("different documents must have different keys")
	}
}

// TestGetterTokenFailure verifies that a broken blob blocks access.
func TestGetterTokenFailure(t *testing.T) {
	blobsDir := t.TempDir()
	uuid := testDocUUID()

	// Store a corrupted blob for the document.
	path := BlobPath(blobsDir, uuid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("garbage-not-a-blob"), 0o600); err != nil {
		t.Fatal(err)
	}

	failing := &failingUnwrapper{}
	g := NewGetter(failing, blobsDir)
	if _, err := g.LoadKey(context.Background(), uuid); err == nil {
		t.Fatal("LoadKey() error = nil, want a token error")
	}
}

// failingUnwrapper always fails — simulates "token unavailable".
type failingUnwrapper struct{}

func (failingUnwrapper) Wrap([]byte) ([]byte, error) { return nil, errors.New("no token") }
func (failingUnwrapper) Unwrap([]byte) ([]byte, error) {
	return nil, errors.New("no token")
}
func (failingUnwrapper) Close() error { return nil }

// TestBlobFormat verifies the blob path layout.
func TestBlobFormat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "blobs")
	path := BlobPath(dir, testDocUUID())
	want := filepath.Join(dir, crypto.UUIDString(testDocUUID())+blobSuffix)
	if path != want {
		t.Errorf("BlobPath() = %q, want %q", path, want)
	}
}
