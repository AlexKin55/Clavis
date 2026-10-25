// Package mode stores the user-chosen sharing mode applied to newly
// created documents. The GUI writes it; the FUSE agent reads it, so the
// choice is visible to both sides without a network round trip.
package mode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/clavis/clavis/internal/crypto"
)

const defaultStateFile = "clavis-state.json"

// state is the persisted payload.
type state struct {
	// Mode is the sharing mode for new documents: "proxy" or "e2e".
	Mode string `json:"mode"`
}

// Manager reads and writes the mode state.
type Manager struct {
	mu   sync.Mutex
	path string
}

// Open creates a Manager for the given path. An empty path uses the user
// config dir.
func Open(path string) (*Manager, error) {
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			dir = "."
		}
		path = filepath.Join(dir, "clavis", defaultStateFile)
	}
	return &Manager{path: path}, nil
}

// Path returns the underlying state file path.
func (m *Manager) Path() string { return m.path }

// Get returns the current default mode (proxy when unset/invalid).
func (m *Manager) Get() crypto.Mode {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		return crypto.ModeProxy
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return crypto.ModeProxy
	}
	if m, ok := Parse(s.Mode); ok {
		return m
	}
	return crypto.ModeProxy
}

// Names used in the state file and shown in the GUI.
const (
	ModeProxyName = "proxy" // hybrid/proxy sharing through the Key Server
	ModeE2EName   = "e2e"   // end-to-end direct sharing
)

// Parse converts a state-file mode name to a crypto.Mode.
func Parse(s string) (crypto.Mode, bool) {
	switch s {
	case ModeProxyName:
		return crypto.ModeProxy, true
	case ModeE2EName:
		return crypto.ModeE2E, true
	default:
		return 0, false
	}
}

// String converts a crypto.Mode back to its state-file name.
func String(m crypto.Mode) (string, bool) {
	switch m {
	case crypto.ModeProxy:
		return ModeProxyName, true
	case crypto.ModeE2E:
		return ModeE2EName, true
	default:
		return "", false
	}
}

// Set persists the default mode for new documents.
func (m *Manager) Set(mode crypto.Mode) error {
	if mode != crypto.ModeProxy && mode != crypto.ModeE2E {
		return fmt.Errorf("mode: unknown mode %q", mode)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return fmt.Errorf("mode: create dir: %w", err)
	}
	data, err := json.MarshalIndent(state{Mode: string(mode)}, "", "  ")
	if err != nil {
		return fmt.Errorf("mode: marshal: %w", err)
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("mode: write: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("mode: commit: %w", err)
	}
	return nil
}
