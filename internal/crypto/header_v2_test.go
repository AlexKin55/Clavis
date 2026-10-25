package crypto

import (
	"bytes"
	"testing"
)

// TestHeaderV2RoundTrip verifies encode/parse.
func TestHeaderV2RoundTrip(t *testing.T) {
	var owner, uuid [16]byte
	var nonce [8]byte
	var wrapped [WrappedKeySize]byte
	for i := range uuid {
		uuid[i] = byte(i)
	}
	nonce[0] = 0x42
	wrapped[0] = 0x99

	h, err := NewHeaderV2(owner, uuid, ModeProxy, nonce, wrapped)
	if err != nil {
		t.Fatalf("NewHeaderV2() error: %v", err)
	}

	parsed, err := ParseHeaderV2(h.Encode())
	if err != nil {
		t.Fatalf("ParseHeaderV2() error: %v", err)
	}
	if parsed.Version != HeaderVersion+1 {
		t.Errorf("Version = %d, want %d", parsed.Version, HeaderVersion+1)
	}
	if parsed.Mode != ModeProxy {
		t.Errorf("Mode = %d, want ModeProxy", parsed.Mode)
	}
	if parsed.UUID != uuid {
		t.Errorf("UUID mismatch")
	}
	if parsed.Nonce != nonce {
		t.Errorf("Nonce mismatch")
	}
	if !bytes.Equal(parsed.WrappedDK[:], wrapped[:]) {
		t.Errorf("WrappedDK mismatch")
	}
}

// TestHeaderV2NewE2E verifies the e2e mode header.
func TestHeaderV2NewE2E(t *testing.T) {
	h, err := NewHeaderV2([16]byte{}, [16]byte{}, ModeE2E, [8]byte{}, [WrappedKeySize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if h.Mode != ModeE2E {
		t.Errorf("Mode = %d, want ModeE2E", h.Mode)
	}
}

// TestHeaderV2Errors verifies rejection of malformed headers.
func TestHeaderV2Errors(t *testing.T) {
	h, err := NewHeaderV2([16]byte{}, [16]byte{}, ModeProxy, [8]byte{}, [WrappedKeySize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	valid := h.Encode()

	cases := []struct {
		name string
		data []byte
	}{
		{"too short", valid[:HeaderV2Size-1]},
		{"bad magic", func() []byte { b := valid; b[v2OffMagic] = 'X'; return b }()},
		{"bad version", func() []byte { b := valid; b[v2OffVersion] = 0x03; return b }()},
		{"bad algo", func() []byte { b := valid; b[v2OffAlgorithm] = 0x7f; return b }()},
		{"bad mode", func() []byte { b := valid; b[v2OffMode] = 0x00; return b }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHeaderV2(tc.data); err == nil {
				t.Fatal("ParseHeaderV2() error = nil, want an error")
			}
		})
	}
}

// TestNewHeaderV2BadMode verifies the mode validation in the constructor.
func TestNewHeaderV2BadMode(t *testing.T) {
	if _, err := NewHeaderV2([16]byte{}, [16]byte{}, Mode(0x00), [8]byte{}, [WrappedKeySize]byte{}); err == nil {
		t.Fatal("NewHeaderV2(bad mode) error = nil, want an error")
	}
}

// TestHeaderV2Size sanity check.
func TestHeaderV2Size(t *testing.T) {
	if HeaderV2Size != 88 {
		t.Errorf("HeaderV2Size = %d, want 88", HeaderV2Size)
	}
}
