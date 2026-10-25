// Package agentid persists the agent v2 state: the local identity
// (master key A + Ed25519 signing key), the registration materials
// returned by the Key Server (agent id, server public key S, nonce) and
// the derived reader key registration. The master key never leaves the
// workstation.
package agentid

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/keyclient"
)

// State is the persisted agent v2 state.
type State struct {
	AgentID      string `json:"agent_id"`
	MasterKeyHex string `json:"master_key"`
	SigPrivHex   string `json:"sig_private_key"`
	ServerPubHex string `json:"server_public_key"`
	ServerNonce  string `json:"server_nonce"`
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
	pub := priv[ed25519.SeedSize:]

	// Enforce a canonic 32-byte master key.
	key := make([]byte, crypto.MasterKeySize)
	if len(master) != crypto.MasterKeySize {
		return nil, fmt.Errorf("agentid: master key length %d", len(master))
	}
	copy(key, master)
	return &crypto.AgentIdentity{MasterKey: key, SigPriv: ed25519.PrivateKey(priv), SigPub: pub}, nil
}

// ServerPub returns the server public key S (raw bytes).
func (s *State) ServerPub() ([]byte, error) { return hex.DecodeString(s.ServerPubHex) }

// ServerNonceBytes returns the registration nonce.
func (s *State) ServerNonceBytes() ([]byte, error) { return hex.DecodeString(s.ServerNonce) }

// LoadOrCreate loads the persisted state or generates a fresh identity on
// first use (file mode 0600).
func LoadOrCreate(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var s State
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("agentid: parse state %q: %w", path, err)
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
		MasterKeyHex: hex.EncodeToString(identity.MasterKey),
		SigPrivHex:   hex.EncodeToString(identity.SigPriv),
	}
	if err := s.Save(path); err != nil {
		return nil, err
	}
	return s, nil
}

// Save persists the state atomically-ish (write + fsync).
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

// EnsureRegistered registers the agent with the Key Server if it does not
// have an agent id yet, then registers the derived reader key (AS).
// The state is persisted to statePath after any registration change.
func EnsureRegistered(ctx context.Context, client *keyclient.Client, state *State, statePath string) error {
	identity, err := state.Identity()
	if err != nil {
		return err
	}

	if state.AgentID == "" || state.ServerPubHex == "" {
		reg, err := client.Register(ctx, keyclient.RegisterRequest{
			DeviceID: "clavis-device",
			PubSig:   identity.PublicSignatureKey(),
		})
		if err != nil {
			return fmt.Errorf("agentid: register: %w", err)
		}
		state.AgentID = reg.AgentID
		state.ServerPubHex = reg.PublicKeyServer
		state.ServerNonce = reg.NonceServer
		if statePath != "" {
			if err := state.Save(statePath); err != nil {
				return err
			}
		}
	}

	pubServer, err := hex.DecodeString(state.ServerPubHex)
	if err != nil {
		return fmt.Errorf("agentid: server pub: %w", err)
	}
	nonce, err := hex.DecodeString(state.ServerNonce)
	if err != nil {
		return fmt.Errorf("agentid: server nonce: %w", err)
	}
	as, err := identity.ReaderKey(pubServer, nonce)
	if err != nil {
		return err
	}
	if err := client.SetReaderKey(ctx, keyclient.SetReaderKeyRequest{
		AgentID:   state.AgentID,
		ReaderKey: as,
	}); err != nil {
		return fmt.Errorf("agentid: set reader key: %w", err)
	}
	return nil
}
