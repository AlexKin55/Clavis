package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigDefaults verifies the default server configuration.
func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("listen: \"127.0.0.1:9999\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.PeerCheckIntervalSeconds <= 0 {
		t.Errorf("PeerCheckIntervalSeconds = %d, want default > 0", cfg.PeerCheckIntervalSeconds)
	}
}

// TestLoadConfigPeers verifies the peers list parsing.
func TestLoadConfigPeers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	content := `
listen: "127.0.0.1:8443"
peers: "https://ks2.example.com:8443, https://ks3.example.com:8443"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers == "" {
		t.Fatal("peers must not be empty")
	}
	got := splitPeers(cfg.Peers)
	if len(got) != 2 {
		t.Fatalf("splitPeers() = %v, want two peers", got)
	}
	if got[1] != "https://ks3.example.com:8443" {
		t.Errorf("second peer = %q", got[1])
	}
}
