package fuse

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/interceptor"
	"github.com/clavis/clavis/internal/subject"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// newTestRoot creates a SecureRoot backed by a temp source directory and a
// freshly generated key file.
func newTestRoot(t *testing.T) (*SecureRoot, string) {
	t.Helper()
	sourceDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "agent.key")
	if err := crypto.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	kg := crypto.NewFileKeyGetter(keyPath)
	return NewSecureRoot(&Config{SourceDir: sourceDir, KeyGetter: kg}), sourceDir
}

// TestCreateWriteReadRoundTrip exercises the full create/write/read cycle
// through the on-the-fly encryption layer.
func TestCreateWriteReadRoundTrip(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "doc.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatalf("createProtectedFile() error: %v", err)
	}
	defer func() {
		_ = f.Release(context.Background())
	}()

	payload := []byte("top secret document payload")
	n, errno := f.Write(context.Background(), payload, 0)
	if errno != 0 {
		t.Fatalf("Write() errno: %v", errno)
	}
	if n != uint32(len(payload)) {
		t.Errorf("Write() written = %d, want %d", n, len(payload))
	}

	// Read the full visible content.
	dest := make([]byte, len(payload))
	res, rerrno := f.Read(context.Background(), dest, 0)
	if rerrno != 0 {
		t.Fatalf("Read() errno: %v", rerrno)
	}
	got, status := res.Bytes(dest)
	if status != fuse.OK {
		t.Fatalf("Read() result status: %v", status)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("Read() = %q, want %q", got, payload)
	}

	// The physical file must contain the header and no plaintext payload.
	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(physical) != HeaderSize+len(payload) {
		t.Errorf("physical size = %d, want %d", len(physical), HeaderSize+len(payload))
	}
	if string(physical[:4]) != "CLVS" {
		t.Errorf("magic = %q, want %q", physical[:4], "CLVS")
	}
	if bytes.Contains(physical, payload) {
		t.Error("plaintext found in the physical file")
	}
}

// TestReadAfterReopen verifies that a file survives closing and reopening.
func TestReadAfterReopen(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "persist.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("persistent secret")
	if _, e := f.Write(context.Background(), payload, 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.Release(context.Background()); e != 0 {
		t.Fatal(e)
	}

	reopened, err := root.openProtectedFile(path, os.O_RDWR)
	if err != nil {
		t.Fatalf("openProtectedFile() error: %v", err)
	}
	defer func() {
		_ = reopened.Release(context.Background())
	}()

	dest := make([]byte, len(payload))
	res, e := reopened.Read(context.Background(), dest, 0)
	if e != 0 {
		t.Fatal(e)
	}
	got, status := res.Bytes(dest)
	if status != fuse.OK {
		t.Fatalf("Read() result status: %v", status)
	}
	if !bytes.Equal(got, payload) {
		t.Error("reopened file content mismatch")
	}
}

// TestOpenNonProtectedFails verifies that a plain (unprotected) file
// cannot be opened as a Clavis document.
func TestOpenNonProtectedFails(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "plain.txt")
	if err := os.WriteFile(path, []byte("not protected"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := root.openProtectedFile(path, os.O_RDWR); err == nil {
		t.Fatal("openProtectedFile() error = nil, want an error")
	}
}

// TestTruncateKeepsHeader verifies that truncating a file keeps the header.
func TestTruncateKeepsHeader(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "trunc.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Release(context.Background())
	}()

	if _, e := f.Write(context.Background(), []byte("some data that will be truncated"), 0); e != 0 {
		t.Fatal(e)
	}
	if e := f.truncateToVisible(0); e != 0 {
		t.Fatalf("truncateToVisible() errno: %v", e)
	}

	physical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(physical) != HeaderSize {
		t.Errorf("physical size after truncate = %d, want %d", len(physical), HeaderSize)
	}
	if string(physical[:4]) != "CLVS" {
		t.Error("header destroyed by truncate")
	}

	dest := make([]byte, 16)
	res, e := f.Read(context.Background(), dest, 0)
	if e != 0 {
		t.Fatal(e)
	}
	got, status := res.Bytes(dest)
	if status != fuse.OK {
		t.Fatalf("Read() result status: %v", status)
	}
	if len(got) != 0 {
		t.Errorf("read after truncate = %q, want empty", got)
	}
}

// TestRandomAccessWriteRead writes at a nonzero offset and reads it back
// without touching the prefix.
func TestRandomAccessWriteRead(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "random.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Release(context.Background())
	}()

	message := []byte("mid-secret")
	offset := int64(100)
	if _, e := f.Write(context.Background(), message, offset); e != 0 {
		t.Fatal(e)
	}

	dest := make([]byte, len(message))
	res, e := f.Read(context.Background(), dest, offset)
	if e != 0 {
		t.Fatal(e)
	}
	got, status := res.Bytes(dest)
	if status != fuse.OK {
		t.Fatalf("Read() result status: %v", status)
	}
	if !bytes.Equal(got, message) {
		t.Error("random access content mismatch")
	}

	// The prefix must remain empty.
	// The prefix must be the materialized zeros (sparse gap).
	prefix := make([]byte, offset)
	res, e = f.Read(context.Background(), prefix, 0)
	if e != 0 {
		t.Fatal(e)
	}
	got, status = res.Bytes(prefix)
	if status != fuse.OK {
		t.Fatalf("Read() result status: %v", status)
	}
	want := make([]byte, offset)
	if !bytes.Equal(got, want) {
		t.Errorf("prefix is not zero-filled: len=%d", len(got))
	}
}

// TestVisibleSize verifies that visibleSize subtracts the header.
func TestVisibleSize(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "size.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Release(context.Background())
	}()

	payload := make([]byte, 1234)
	if _, e := f.Write(context.Background(), payload, 0); e != 0 {
		t.Fatal(e)
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if got := visibleSize(&st); got != uint64(len(payload)) {
		t.Errorf("visibleSize() = %d, want %d", got, len(payload))
	}
}

// TestOpenAccessDenied verifies that a non-sanctioned process cannot open
// a protected document.
func TestOpenAccessDenied(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "guarded.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Release(context.Background())

	policyRoot := NewSecureRoot(&Config{
		SourceDir:   sourceDir,
		KeyGetter:   root.cfg.KeyGetter,
		Interceptor: interceptor.NewPolicy(interceptor.Config{}, nil),
	})
	node := &secureNode{root: policyRoot, sourcePath: path}

	// An unknown (and probably non-existent) process.
	ctx := &fuse.Context{Caller: fuse.Caller{Pid: 99999999}}
	fh, _, errno := node.Open(ctx, 0)
	if errno != syscall.EACCES {
		t.Fatalf("Open() errno = %v, want EACCES", errno)
	}
	if fh != nil {
		t.Fatal("Open() returned a handle despite denial")
	}
}

// TestOpenAccessGranted verifies that a whitelisted process may open the
// document. The real test process is used so the /proc lookup succeeds.
func TestOpenAccessGranted(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "guarded.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Release(context.Background())

	own, err := subject.FromPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	policyRoot := NewSecureRoot(&Config{
		SourceDir: sourceDir,
		KeyGetter: root.cfg.KeyGetter,
		Interceptor: interceptor.NewPolicy(interceptor.Config{
			Whitelist: []string{own.Comm},
		}, nil),
	})
	node := &secureNode{root: policyRoot, sourcePath: path}

	ctx := &fuse.Context{Caller: fuse.Caller{Pid: uint32(os.Getpid())}}
	fh, _, errno := node.Open(ctx, 0)
	if errno != 0 {
		t.Fatalf("Open() errno = %v, want success", errno)
	}
	if fh == nil {
		t.Fatal("Open() returned no handle")
	}
	if sf, ok := fh.(*secureFile); ok {
		_ = sf.Release(context.Background())
	}
}

// TestUUIDInHeader verifies that new documents receive a UUID.
func TestUUIDInHeader(t *testing.T) {
	root, sourceDir := newTestRoot(t)
	path := filepath.Join(sourceDir, "uuid.txt")

	f, err := root.createProtectedFile(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Release(context.Background())
	}()

	zero := [16]byte{}
	if bytes.Equal(f.header.UUID[:], zero[:]) {
		t.Error("document UUID is all zeros")
	}
	if f.header.Algorithm != crypto.AlgorithmAes256Ctr {
		t.Errorf("Algorithm = %d, want %d", f.header.Algorithm, crypto.AlgorithmAes256Ctr)
	}
}
