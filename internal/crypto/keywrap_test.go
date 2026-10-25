package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestKeyWrapRFC3394Vector verifies the AES-256 Key Wrap against the
// official RFC 3394 test vector.
func TestKeyWrapRFC3394Vector(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plain, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want, _ := hex.DecodeString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

	got, err := wrapKey(kek, plain)
	if err != nil {
		t.Fatalf("wrapKey() error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("wrapKey() = %x, want %x", got, want)
	}

	back, err := unwrapKey(kek, want)
	if err != nil {
		t.Fatalf("unwrapKey() error: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Errorf("unwrapKey() = %x, want %x", back, plain)
	}
}

// TestKeyWrapRoundTrip verifies wrap/unwrap for our 32-byte document keys.
func TestKeyWrapRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	dk := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
		dk[i] = byte(0xff - i)
	}

	wrapped, err := wrapKey(kek, dk)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != 40 {
		t.Errorf("wrapped length = %d, want 40", len(wrapped))
	}

	got, err := unwrapKey(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dk) {
		t.Error("unwrap mismatch")
	}
}

// TestKeyWrapWrongKey verifies that a wrong KEK fails unwrapping.
func TestKeyWrapWrongKey(t *testing.T) {
	kek := make([]byte, 32)
	dk := make([]byte, 32)
	wrapped, err := wrapKey(kek, dk)
	if err != nil {
		t.Fatal(err)
	}

	kek[0] ^= 0x01
	if _, err := unwrapKey(kek, wrapped); err == nil {
		t.Fatal("unwrapKey(wrong KEK) error = nil, want ErrCorruptData")
	}
}

// TestKeyWrapBadLength verifies input validation.
func TestKeyWrapBadLength(t *testing.T) {
	kek := make([]byte, 32)
	if _, err := wrapKey(kek, make([]byte, 10)); err == nil {
		t.Error("wrapKey(10 bytes) error = nil, want an error")
	}
	if _, err := wrapKey(kek, make([]byte, 0)); err == nil {
		t.Error("wrapKey(empty) error = nil, want an error")
	}
}
