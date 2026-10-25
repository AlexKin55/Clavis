package crypto

import (
	"bytes"
	"testing"
)

// TestHeaderRoundTrip verifies that Encode followed by ParseHeader
// reproduces the original header.
func TestHeaderRoundTrip(t *testing.T) {
	uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	h, err := NewHeader(uuid, AlgorithmAes256Ctr)
	if err != nil {
		t.Fatalf("NewHeader() error: %v", err)
	}

	parsed, err := ParseHeader(h.Encode())
	if err != nil {
		t.Fatalf("ParseHeader() error: %v", err)
	}
	if parsed.Version != HeaderVersion {
		t.Errorf("Version = %d, want %d", parsed.Version, HeaderVersion)
	}
	if parsed.Algorithm != AlgorithmAes256Ctr {
		t.Errorf("Algorithm = %d, want %d", parsed.Algorithm, AlgorithmAes256Ctr)
	}
	if !bytes.Equal(parsed.UUID[:], uuid[:]) {
		t.Errorf("UUID = %x, want %x", parsed.UUID, uuid)
	}
	if !bytes.Equal(parsed.Nonce[:], h.Nonce[:]) {
		t.Errorf("Nonce = %x, want %x", parsed.Nonce, h.Nonce)
	}
}

// TestNewHeaderUnknownAlgorithm verifies the error for an unknown algorithm.
func TestNewHeaderUnknownAlgorithm(t *testing.T) {
	_, err := NewHeader([16]byte{}, AlgorithmID(0x7f))
	if err == nil {
		t.Fatal("NewHeader() error = nil, want an error")
	}
}

// TestHeaderReservedBytesZero verifies that reserved bytes are zero.
func TestHeaderReservedBytesZero(t *testing.T) {
	h, err := NewHeader([16]byte{}, AlgorithmAes256Ctr)
	if err != nil {
		t.Fatal(err)
	}
	raw := h.Encode()
	if raw[offsetReserved] != 0 || raw[offsetReserved+1] != 0 {
		t.Errorf("reserved bytes = %x, want zeros", raw[offsetReserved:HeaderSize])
	}
}

// TestParseHeaderErrors verifies rejection of malformed headers.
func TestParseHeaderErrors(t *testing.T) {
	valid := func() []byte {
		h, err := NewHeader([16]byte{}, AlgorithmAes256Ctr)
		if err != nil {
			t.Fatal(err)
		}
		return h.Encode()
	}()

	cases := []struct {
		name string
		data []byte
	}{
		{"too short", valid[:HeaderSize-1]},
		{"empty", nil},
		{"bad magic", func() []byte { b := valid; b[offsetMagic] = 'X'; return b }()},
		{"bad version", func() []byte { b := valid; b[offsetVersion] = 0x02; return b }()},
		{"unknown algo", func() []byte { b := valid; b[offsetAlgorithm] = 0x7f; return b }()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHeader(tc.data); err == nil {
				t.Fatal("ParseHeader() error = nil, want an error")
			}
		})
	}
}
