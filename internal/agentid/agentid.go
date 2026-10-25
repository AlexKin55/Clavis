// Package agentid persists the agent v2 state: the local identity
// (master key A + Ed25519 signing key) and, per Key Server, the
// registration materials (agent id, server public key S, nonce) plus the
// derived reader key registration. The master key never leaves the
// workstation.
package agentid

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/keyclient"
)

// ServerState holds the registration data for one Key Server.
type ServerState struct {
	// URL of the server (the raw configured address).
	URL         string `json:"url"`
	AgentID     string `json:"agent_id"`
	ServerPub   string `json:"server_public_key"`
	ServerNonce string `json:"server_nonce"`
}

// State is the persisted agent v2 state.
type State struct {
	// LocalID is the agent's random unique identifier generated once at
	// installation time. It is used as the display/audit agent identity.
	LocalID string `json:"local_id,omitempty"`

	// MasterKeyHex and SigPrivHex are the local identity (never exposed).
	MasterKeyHex string `json:"master_key"`
	SigPrivHex   string `json:"sig_private_key"`

	// Servers holds per-server registrations. When empty, the legacy
	// single-server fields below are used.
	Servers []ServerState `json:"servers,omitempty"`

	// Legacy single-server fields (kept for backward compatibility).
	AgentID      string `json:"agent_id,omitempty"`
	ServerPubHex string `json:"server_public_key,omitempty"`
	ServerNonce  string `json:"server_nonce,omitempty"`
}

// Identity reconstructs the crypto.AgentIdentity from the state.
func (s *State) Identity() (*crypto.AgentIdentity, error) {
	master, err := hex.DecodeString(s.MasterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("agentid: master key: %w", err)
	}
	priv, err := hex.DecodeString(s.SigPrivHex)
	if err != nil {
		return nil, fmt.Errorf("agentid: signing key: %w", err)
	}
	if len(master) != crypto.MasterKeySize {
		return nil, fmt.Errorf("agentid: master key length %d", len(master))
	}
	return &crypto.AgentIdentity{
		MasterKey: master,
		SigPriv:   ed25519.PrivateKey(priv),
		SigPub:    priv[ed25519.SeedSize:],
	}, nil
}

// ServerPub returns the server public key S of the first registration.
func (s *State) ServerPub() ([]byte, error) {
	return hex.DecodeString(s.primary().ServerPub)
}

// ServerNonceBytes returns the registration nonce of the first server.
func (s *State) ServerNonceBytes() ([]byte, error) {
	return hex.DecodeString(s.primary().ServerNonce)
}

func (s *State) primary() ServerState {
	if len(s.Servers) > 0 {
		return s.Servers[0]
	}
	return ServerState{
		AgentID:     s.AgentID,
		ServerPub:   s.ServerPubHex,
		ServerNonce: s.ServerNonce,
	}
}

// LoadOrCreate loads the persisted state or generates a fresh identity on
// first use (file mode 0600).
func LoadOrCreate(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var s State
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("agentid: parse state %q: %w", path, err)
		}
		// Migrate the legacy single-server layout into Servers.
		if len(s.Servers) == 0 && s.AgentID != "" {
			s.Servers = []ServerState{{
				AgentID:     s.AgentID,
				ServerPub:   s.ServerPubHex,
				ServerNonce: s.ServerNonce,
			}}
		}
		// Missing local id (pre-random-id installs): generate and persist.
		if s.LocalID == "" {
			s.LocalID = newLocalID()
			if err := s.Save(path); err != nil {
				return nil, err
			}
		}
		return &s, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("agentid: read state %q: %w", path, err)
	}

	identity, err := crypto.NewAgentIdentity()
	if err != nil {
		return nil, err
	}
	s := &State{
		LocalID:      newLocalID(),
		MasterKeyHex: hex.EncodeToString(identity.MasterKey),
		SigPrivHex:   hex.EncodeToString(identity.SigPriv),
	}
	if err := s.Save(path); err != nil {
		return nil, err
	}
	return s, nil
}

// newLocalID returns a random agent identifier.
func newLocalID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("agent-%d", time.Now().UnixNano())
	}
	return "agent-" + hex.EncodeToString(buf)
}

// Save persists the state atomically.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("agentid: marshal state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("agentid: create dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("agentid: write state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("agentid: commit state: %w", err)
	}
	return nil
}

// EnsureRegistered registers the agent with every configured Key Server
// (deriving a per-server reader key AS) and uploads those reader keys.
// Unreachable servers are skipped so the agent keeps working with the
// remaining ones; the missing registration is retried on the next start.
func EnsureRegistered(ctx context.Context, multi *keyclient.MultiClient, urls []string, state *State, statePath string) error {
	identity, err := state.Identity()
	if err != nil {
		return err
	}

	serverCount := len(urls)
	if serverCount == 0 {
		serverCount = multi.Length()
	}
	// The reader key is a single unified derivation (variant 1): it does
	// not depend on any server key S or nonce, so the same AS is
	// registered on every server in the list.
	as, err := identity.UnifiedReaderKey()
	if err != nil {
		return err
	}

	changed := false
	for i := 0; i < serverCount; i++ {
		url := ""
		if i < len(urls) {
			url = urls[i]
		}
		ss := findServer(state, url, i)

		if ss == nil {
			reg, err := multi.RegisterAt(ctx, i, keyclient.RegisterRequest{
				DeviceID: "clavis-device",
				PubSig:   identity.PublicSignatureKey(),
			})
			if err != nil {
				// Server unreachable: skip this one, keep going.
				continue
			}
			ss = &ServerState{
				URL:         url,
				AgentID:     reg.AgentID,
				ServerPub:   reg.PublicKeyServer,
				ServerNonce: reg.NonceServer,
			}
			if i < len(state.Servers) {
				state.Servers[i] = *ss
			} else {
				state.Servers = append(state.Servers, *ss)
			}
			changed = true
		}

		if ss.AgentID == "" {
			continue
		}
		if err := multi.SetReaderKeyAt(ctx, i, keyclient.SetReaderKeyRequest{
			AgentID:   ss.AgentID,
			ReaderKey: as,
		}); err != nil {
			continue
		}
	}

	if changed && statePath != "" {
		return state.Save(statePath)
	}
	return nil
}

func findServer(state *State, url string, index int) *ServerState {
	if index >= 0 && index < len(state.Servers) {
		return &state.Servers[index]
	}
	for i := range state.Servers {
		if state.Servers[i].URL == url {
			return &state.Servers[i]
		}
	}
	return nil
}
