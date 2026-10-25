package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrCreateServerID verifies that the server identity is generated
// on first start, persisted, and stable across restarts.
func TestLoadOrCreateServerID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-id")

	first, err := loadOrCreateServerID(path)
	if err != nil {
		t.Fatalf("loadOrCreateServerID() error: %v", err)
	}
	if !strings.HasPrefix(first, "server-") {
		t.Errorf("server id = %q, want a server- prefixed id", first)
	}

	second, err := loadOrCreateServerID(path)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("server id changed between runs: %q != %q", first, second)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("id file not persisted: %v", err)
	}
	if strings.TrimSpace(string(data)) != first {
		t.Errorf("id file content = %q, want %q", data, first)
	}
}

// TestLoadOrCreateServerIDEphemeral verifies that without a path the id
// is generated (not persisted) and each call yields a fresh one.
func TestLoadOrCreateServerIDEphemeral(t *testing.T) {
	a, err := loadOrCreateServerID("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateServerID("")
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || b == "" {
		t.Fatal("ephemeral server id must not be empty")
	}
	if a == b {
		t.Error("ephemeral ids must differ between processes/runs")
	}
}
