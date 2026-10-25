package fuse

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

// benchPayload is the size of the benchmark payload (16 MiB).
const benchPayload = 16 << 20

// benchRoot creates the secure root for benchmarks.
func benchRoot(b *testing.B) (*SecureRoot, string) {
	b.Helper()
	sourceDir := b.TempDir()
	keyPath := filepath.Join(b.TempDir(), "agent.key")
	if err := crypto.GenerateKeyFile(keyPath); err != nil {
		b.Fatal(err)
	}
	return NewSecureRoot(&Config{
		SourceDir: sourceDir,
		KeyGetter: crypto.NewFileKeyGetter(keyPath),
	}), sourceDir
}

// BenchmarkSecureFileWrite measures the on-the-fly encryption throughput
// of the fuse file handle (plaintext in, ciphertext to disk).
func BenchmarkSecureFileWrite(b *testing.B) {
	root, sourceDir := benchRoot(b)
	path := filepath.Join(sourceDir, "bench.dat")

	f, err := root.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = f.Release(context.Background()) }()

	payload := make([]byte, benchPayload)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, errno := f.Write(context.Background(), payload, 0); errno != 0 {
			b.Fatalf("write errno: %v", errno)
		}
	}
}

// BenchmarkSecureFileRead measures the on-the-fly decryption throughput.
func BenchmarkSecureFileRead(b *testing.B) {
	root, sourceDir := benchRoot(b)
	path := filepath.Join(sourceDir, "bench.dat")

	f, err := root.createProtectedFile(context.Background(), path, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = f.Release(context.Background()) }()

	payload := make([]byte, benchPayload)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	if _, errno := f.Write(context.Background(), payload, 0); errno != 0 {
		b.Fatalf("write errno: %v", errno)
	}

	dest := make([]byte, benchPayload)
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, errno := f.Read(context.Background(), dest, 0)
		if errno != 0 {
			b.Fatalf("read errno: %v", errno)
		}
		if _, status := res.Bytes(dest); status != 0 {
			b.Fatalf("read status: %v", status)
		}
	}
}
