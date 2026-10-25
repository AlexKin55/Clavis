package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNewCryptorAesCtr builds a cryptor via the header and checks a round trip.
func TestNewCryptorAesCtr(t *testing.T) {
	uuid, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHeader(uuid, AlgorithmAes256Ctr)
	if err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	c, err := NewCryptor(h, key)
	if err != nil {
		t.Fatalf("NewCryptor() error: %v", err)
	}
	if c.Algorithm() != AlgorithmAes256Ctr {
		t.Errorf("Algorithm() = %d, want %d", c.Algorithm(), AlgorithmAes256Ctr)
	}

	plain := []byte("secure document payload")
	enc, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.Decrypt(enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Error("NewCryptor round trip mismatch")
	}
}

// TestNewCryptorUnknownAlgorithm verifies rejection of unknown algorithms.
func TestNewCryptorUnknownAlgorithm(t *testing.T) {
	h := &DocumentHeader{Version: HeaderVersion, Algorithm: AlgorithmID(0x7f)}
	if _, err := NewCryptor(h, make([]byte, 32)); err == nil {
		t.Fatal("NewCryptor() error = nil, want an error")
	}
}

// TestIsKnownAlgorithm verifies the algorithm registry.
func TestIsKnownAlgorithm(t *testing.T) {
	if !IsKnownAlgorithm(AlgorithmAes256Ctr) {
		t.Error("AlgorithmAes256Ctr must be known")
	}
	if IsKnownAlgorithm(AlgorithmID(0)) {
		t.Error("algorithm 0 must not be known")
	}
}
