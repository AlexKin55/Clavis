package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefault verifies the default configuration values.
func TestDefault(t *testing.T) {
	cfg := Default()
	// agent.id is optional: a random id is generated and persisted at
	// install time by the agent.
	if cfg.Agent.ID != "" {
		t.Errorf("Default().Agent.ID = %q, want empty (generated at install)", cfg.Agent.ID)
	}
	if cfg.Fuse.Directory == "" || cfg.Fuse.MountPoint == "" {
		t.Error("Default Fuse directory/mount_point must not be empty")
	}
	if cfg.Log.Size != "5MB" || cfg.Log.Count != 3 {
		t.Errorf("unexpected default log config: %+v", cfg.Log)
	}
}

// TestLoadValid verifies that a correct YAML file loads completely.
func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	mount := filepath.Join(dir, "mount")
	secure := filepath.Join(dir, "secure")
	if err := os.MkdirAll(secure, 0o755); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "settings.yaml")
	content := `
agent:
  id: "test-agent"
fuse:
  directory: "` + secure + `"
  mount_point: "` + mount + `"
  options:
    - "-f"
log:
  level: "info"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Agent.ID != "test-agent" {
		t.Errorf("Agent.ID = %q, want %q", cfg.Agent.ID, "test-agent")
	}
	if cfg.Fuse.Directory != secure {
		t.Errorf("Fuse.Directory = %q, want %q", cfg.Fuse.Directory, secure)
	}
	if len(cfg.Fuse.Options) != 1 || cfg.Fuse.Options[0] != "-f" {
		t.Errorf("Fuse.Options = %v, want [\"-f\"]", cfg.Fuse.Options)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
}

// TestLoadMissingFile verifies the error for a non-existent settings file.
func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "read settings file") {
		t.Errorf("Load() error = %q, want mention of the file path", err.Error())
	}
}

// TestLoadInvalidYAML verifies the error for a malformed YAML file.
func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("agent: [unclosed"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want a parse error")
	}
}

// TestValidateError verifies validation failures.
func TestValidateError(t *testing.T) {
	existing := t.TempDir()
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"empty agent id", func(c *Config) { c.Agent.ID = "" }, false},
		{"empty directory", func(c *Config) { c.Fuse.Directory = "" }, true},
		{"empty mount point", func(c *Config) { c.Fuse.MountPoint = "" }, true},
		{"dir missing", func(c *Config) { c.Fuse.Directory = filepath.Join(existing, "missing") }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Fuse.Directory = existing
			cfg.Fuse.MountPoint = filepath.Join(t.TempDir(), "mount")
			tc.mutate(cfg)

			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
