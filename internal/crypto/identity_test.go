package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestNewAgentIdentity verifies identity generation.
func TestNewAgentIdentity(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(id.MasterKey) != 32 {
		t.Errorf("master key length = %d, want 32", len(id.MasterKey))
	}
	if len(id.SigPriv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d", len(id.SigPriv))
	}
	if len(id.PublicSignatureKey()) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d", len(id.PublicSignatureKey()))
	}
}

// TestOwnerKeyID verifies the deterministic owner identifier.
func TestOwnerKeyID(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	first := id.OwnerKeyID()
	second := id.OwnerKeyID()
	if first != second {
		t.Error("OwnerKeyID must be deterministic")
	}
	// The first 16 bytes of SHA-256(pub) are non-zero.
	zero := [16]byte{}
	if first == zero {
		t.Error("OwnerKeyID is zero")
	}
}

// TestReaderKeyDeterministic verifies that AS is reproducible and differs
// across identities/server materials.
func TestReaderKeyDeterministic(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pubServer := make([]byte, 32)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	a1, err := id.ReaderKey(pubServer, nonce)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := id.ReaderKey(pubServer, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1, a2) {
		t.Error("ReaderKey must be deterministic")
	}

	nonce2 := make([]byte, 16)
	nonce2[0] = 1
	b, err := id.ReaderKey(pubServer, nonce2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a1, b) {
		t.Error("ReaderKey must change when the server nonce changes")
	}
}

// TestUnifiedReaderKey verifies the cluster-wide single AS: it is
// deterministic and independent of any server key/nonce.
func TestUnifiedReaderKey(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	first, err := id.UnifiedReaderKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := id.UnifiedReaderKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("UnifiedReaderKey must be deterministic")
	}
	if bytes.Equal(first, id.MasterKey) {
		t.Error("UnifiedReaderKey must differ from the master key")
	}

	// The same AS is produced regardless of any (future) server materials.
	otherServer := bytes.Repeat([]byte{0x42}, 32)
	otherNonce := bytes.Repeat([]byte{0x24}, 16)
	salted, err := id.ReaderKey(otherServer, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	// The old salted derivation depends on server materials, the unified
	// one does not: they intentionally differ.
	if bytes.Equal(salted, first) {
		t.Error("salted and unified reader keys must differ")
	}
}

// TestReaderKeyNeverEqualsMaster verifies that AS does not reveal A.
func TestReaderKeyNeverEqualsMaster(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	as, err := id.ReaderKey(make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(as, id.MasterKey) {
		t.Error("reader key must differ from the master key")
	}
}

// TestSignVerify tests the Ed25519 wrapper.
func TestSignVerify(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("document payload")
	sig := id.Sign(payload)

	if !VerifySignature(id.PublicSignatureKey(), payload, sig) {
		t.Error("signature must verify")
	}
	if VerifySignature(id.PublicSignatureKey(), []byte("tampered"), sig) {
		t.Error("signature of tampered payload must fail")
	}
}
