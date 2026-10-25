package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestV2ProxyScenario exercises the full proxy flow from the v2 model:
// agent A creates a signed document wrapped under its reader key AS_A;
// agent B reads it with AS_A received from the server and cannot create
// valid modifications (no owner signature).
func TestV2ProxyScenario(t *testing.T) {
	idA, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}

	serverPub := make([]byte, 32)
	serverNonce := make([]byte, 16)
	if _, err := rand.Read(serverNonce); err != nil {
		t.Fatal(err)
	}
	asA, err := idA.ReaderKey(serverPub, serverNonce)
	if err != nil {
		t.Fatal(err)
	}
	asB, err := idB.ReaderKey(serverPub, serverNonce)
	if err != nil {
		t.Fatal(err)
	}

	// --- A creates a document ---
	plain := []byte("strictly confidential report")
	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatal(err)
	}
	var docNonce [8]byte
	if _, err := rand.Read(docNonce[:]); err != nil {
		t.Fatal(err)
	}
	cryptor, err := NewAesCtr(dk, docNonce)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := cryptor.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := wrapKey(asA, dk)
	if err != nil {
		t.Fatal(err)
	}
	var wrappedDK [WrappedKeySize]byte
	copy(wrappedDK[:], wrapped)

	uuid := [16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	header, err := NewHeaderV2(idA.OwnerKeyID(), uuid, ModeProxy, docNonce, wrappedDK)
	if err != nil {
		t.Fatal(err)
	}
	file := SignAndSerialize(idA, header, cipher)

	// --- B opens the file ---
	parsed, err := ParseHeaderV2(file[:HeaderV2Size])
	if err != nil {
		t.Fatalf("ParseHeaderV2() error: %v", err)
	}
	if parsed.Mode != ModeProxy {
		t.Errorf("Mode = %d, want proxy", parsed.Mode)
	}
	if parsed.OwnerKeyID != idA.OwnerKeyID() {
		t.Error("owner key id mismatch")
	}

	// B gets AS_A from the server and unwraps the document key.
	dkFromServer, err := unwrapKey(asA, parsed.WrappedDK[:])
	if err != nil {
		t.Fatalf("unwrap with AS_A error: %v", err)
	}
	if !bytes.Equal(dkFromServer, dk) {
		t.Fatal("unwrapped document key differs")
	}

	reader, err := NewAesCtr(dkFromServer, parsed.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Decrypt(cipher, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("B read mismatch")
	}

	// Signature belongs to the owner A.
	sigBlock := file[HeaderV2Size:]
	if err := parsed.Verify(idA.PublicSignatureKey(), cipher, sigBlock); err != nil {
		t.Fatalf("owner signature must verify: %v", err)
	}
	// B's signature is NOT valid for this document (strict read-only).
	if err := parsed.Verify(idB.PublicSignatureKey(), cipher, sigBlock); err == nil {
		t.Error("foreign signature must not verify")
	}
	// Tampering with the ciphertext breaks verification.
	tampered := append([]byte(nil), cipher...)
	tampered[0] ^= 0xff
	if err := parsed.Verify(idA.PublicSignatureKey(), tampered, sigBlock); err == nil {
		t.Error("signature must fail on tampered data")
	}
	// The wrong reader key (AS_B) cannot unwrap.
	if _, err := unwrapKey(asB, parsed.WrappedDK[:]); err == nil {
		t.Error("unwrap with foreign AS must fail")
	}
}

// TestV2SignatureBlockLayout verifies the serialized file layout.
func TestV2SignatureBlockLayout(t *testing.T) {
	id, err := NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewHeaderV2(id.OwnerKeyID(), [16]byte{}, ModeE2E, [8]byte{}, [WrappedKeySize]byte{})
	if err != nil {
		t.Fatal(err)
	}

	file := SignAndSerialize(id, header, []byte("data"))
	want := HeaderV2Size + SignatureBlockLen
	if len(file) != want {
		t.Errorf("serialized length = %d, want %d", len(file), want)
	}

	parsed, err := ParseHeaderV2(file[:HeaderV2Size])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ParseSignatureBlock(file[HeaderV2Size:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
	payload := signaturePayload(parsed, []byte("data"))
	if !VerifySignature(id.PublicSignatureKey(), payload, sig) {
		t.Error("signature mismatch after reparse")
	}
}
