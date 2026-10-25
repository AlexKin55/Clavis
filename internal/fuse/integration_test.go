package fuse

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

// fuseAvailable reports whether a real FUSE mount is possible.
func fuseAvailable() bool {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		return false
	}
	if _, err := exec.LookPath("fusermount3"); err != nil {
		return false
	}
	return true
}

// TestIntegrationMount is an end-to-end test: it mounts the secure
// filesystem, writes through the mount point, reads the data back and
// verifies that the physical file is encrypted (header present, no
// plaintext on disk). The test is skipped when FUSE is unavailable.
func TestIntegrationMount(t *testing.T) {
	if !fuseAvailable() {
		t.Skip("FUSE is not available on this host")
	}

	source := t.TempDir()
	mount := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "agent.key")
	if err := crypto.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}

	server, err := Mount(MountConfig{
		SourceDir:  source,
		MountPoint: mount,
		KeyGetter:  crypto.NewFileKeyGetter(keyPath),
	})
	if err != nil {
		t.Skipf("cannot mount FUSE (skipped): %v", err)
	}
	defer func() {
		if err := Unmount(server); err != nil {
			t.Errorf("Unmount() error: %v", err)
		}
	}()

	// Write a document through the mount point.
	payload := []byte("integration secret payload 12345")
	docPath := filepath.Join(mount, "doc.txt")
	if err := os.WriteFile(docPath, payload, 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	// Read the document back through the mount point.
	got, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("ReadFile() = %q, want %q", got, payload)
	}

	// The physical file must carry the header and no plaintext.
	physPath := filepath.Join(source, "doc.txt")
	phys, err := os.ReadFile(physPath)
	if err != nil {
		t.Fatalf("read physical file error: %v", err)
	}
	if !bytes.HasPrefix(phys, []byte("CLVS")) {
		t.Error("physical file has no magic header")
	}
	if bytes.Contains(phys, payload) {
		t.Error("plaintext found on disk")
	}
	if len(phys) != HeaderSize+len(payload) {
		t.Errorf("physical size = %d, want %d", len(phys), HeaderSize+len(payload))
	}

	// The visible size must exclude the header.
	fi, err := os.Stat(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(payload)) {
		t.Errorf("visible size = %d, want %d", fi.Size(), len(payload))
	}

	// Unlink and verify the directory becomes empty.
	if err := os.Remove(docPath); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(mount)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("mount dir not empty after unlink: %d entries", len(entries))
	}
}
