package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// MasterKeySize is the size of the agent master key A (never leaves the
// workstation).
const MasterKeySize = 32

// readerKeyInfo labels the HKDF context where the reader key (AS) is
// derived from the master key.
const readerKeyInfo = "clavis-reader-key"

// AgentIdentity is the local identity of an agent: the master key A and
// an Ed25519 key pair used to sign documents. Both secrets stay on the
// workstation; only the derived reader key (AS) and the public signature
// key are ever revealed.
type AgentIdentity struct {
	MasterKey []byte
	SigPriv   ed25519.PrivateKey
	SigPub    ed25519.PublicKey
}

// NewAgentIdentity generates a fresh identity.
func NewAgentIdentity() (*AgentIdentity, error) {
	master := make([]byte, MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		return nil, fmt.Errorf("crypto: generate master key: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate signature key: %w", err)
	}
	return &AgentIdentity{MasterKey: master, SigPriv: priv, SigPub: pub}, nil
}

// OwnerKeyID returns the 16-byte public owner identifier: the first 16
// bytes of SHA-256 over the public signature key.
func (id *AgentIdentity) OwnerKeyID() [16]byte {
	sum := sha256.Sum256(id.SigPub)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// ReaderKey derives the read-only wrapper key AS:
//
//	AS = HKDF-SHA256(ikm = A || SigPub, salt = nonceServer || pubServer,
//	                 info = "clavis-reader-key", 32 bytes)
//
// AS is registered with the server and allows unwrapping document keys
// (read access); it cannot create valid modifications (signature needed).
func (id *AgentIdentity) ReaderKey(pubServer, nonceServer []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(id.MasterKey)+len(id.SigPub))
	ikm = append(ikm, id.MasterKey...)
	ikm = append(ikm, id.SigPub...)

	salt := make([]byte, 0, len(nonceServer)+len(pubServer))
	salt = append(salt, nonceServer...)
	salt = append(salt, pubServer...)

	return deriveHKDF(ikm, salt, readerKeyInfo, MasterKeySize)
}

// Sign signs the payload with the identity's Ed25519 key.
func (id *AgentIdentity) Sign(payload []byte) []byte {
	return ed25519.Sign(id.SigPriv, payload)
}

// PublicSignatureKey exposes the public key for signature verification.
func (id *AgentIdentity) PublicSignatureKey() ed25519.PublicKey {
	return id.SigPub
}

// VerifySignature checks the Ed25519 signature.
func VerifySignature(pub ed25519.PublicKey, payload, sig []byte) bool {
	return ed25519.Verify(pub, payload, sig)
}

// deriveHKDF stretches ikm into outLen bytes using HKDF-SHA256.
func deriveHKDF(ikm, salt []byte, info string, outLen int) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, ikm, salt, info, outLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive key: %w", err)
	}
	return key, nil
}
