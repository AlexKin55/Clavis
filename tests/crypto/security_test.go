// Package crypto_test contains black-box security scenarios: the
// "stolen document without a key is useless" property.
package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/clavis/clavis/internal/crypto"
)

// TestStolenV1FileUselessWithoutKey verifies that data encrypted with key
// A cannot be recovered with a different key (or any guess): decryption
// with the wrong key yields garbage, never the original.
func TestStolenV1FileUselessWithoutKey(t *testing.T) {
	docKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(docKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	owner, err := crypto.NewAesCtr(docKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := crypto.NewAesCtr(wrongKey, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("confidential stolen document content 1234567890")
	cipher, err := owner.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, plain) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := attacker.Decrypt(cipher, 0)
	if err != nil {
		// A failed decrypt is also acceptable: nothing leaked.
		t.Logf("wrong-key decrypt failed: %v", err)
		return
	}
	if bytes.Equal(got, plain) {
		t.Fatal("attacker recovered the plaintext with the wrong key")
	}
}

// TestStolenV2FileUselessWithoutReaderKey verifies the v2 property: the
// wrapped document key cannot be unwrapped with a foreign reader key.
func TestStolenV2FileUselessWithoutReaderKey(t *testing.T) {
	owner, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := crypto.NewAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}

	serverPub := make([]byte, 32)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	asOwner, err := owner.ReaderKey(serverPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	asAttacker, err := attacker.ReaderKey(serverPub, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// A finishes a document: DK wrapped under its reader key.
	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(asOwner, dk)
	if err != nil {
		t.Fatal(err)
	}

	// The attacker without the owner's AS cannot unwrap the DK.
	if _, err := crypto.UnwrapKey(asAttacker, wrapped); err == nil {
		t.Fatal("foreign reader key unwrapped the document key")
	}

	// With the rightful AS the DK is recovered.
	got, err := crypto.UnwrapKey(asOwner, wrapped)
	if err != nil {
		t.Fatalf("owner unwrap failed: %v", err)
	}
	if !bytes.Equal(got, dk) {
		t.Fatal("unwrap mismatch with the correct reader key")
	}
}

// TestStolenFileNoHeaderCannotOpen verifies that stripping the header
// (e.g. partial copy) makes the file unusable.
func TestStolenFileNoHeaderCannotOpen(t *testing.T) {
	header, err := crypto.NewHeader([16]byte{1, 2, 3}, crypto.AlgorithmAes256Ctr)
	if err != nil {
		t.Fatal(err)
	}
	blob := header.Encode()

	// Any truncation shortens the header and fails parsing.
	for cut := 0; cut < len(blob); cut++ {
		if _, err := crypto.ParseHeader(blob[:cut]); err == nil {
			t.Fatalf("header parsed with %d bytes", cut)
		}
	}
}
