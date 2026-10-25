package crypto

import (
	"strings"
	"testing"
)

// TestNewUUID verifies RFC 4122 version and variant bits.
func TestNewUUID(t *testing.T) {
	u, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID() error: %v", err)
	}
	if got := u[6] >> 4; got != 0x4 {
		t.Errorf("UUID version = %x, want 4", got)
	}
	if got := u[8] >> 6; got != 0x2 {
		t.Errorf("UUID variant = %x, want 2", got)
	}
}

// TestNewUUIDUnique verifies that two generated UUIDs differ.
func TestNewUUIDUnique(t *testing.T) {
	a, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated UUIDs are equal")
	}
}

// TestUUIDString verifies the canonical 8-4-4-4-12 formatting.
func TestUUIDString(t *testing.T) {
	u := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	got := UUIDString(u)
	want := "00010203-0405-0607-0809-0a0b0c0d0e0f"
	if got != want {
		t.Errorf("UUIDString() = %q, want %q", got, want)
	}
	if len(got) != 36 || strings.Count(got, "-") != 4 {
		t.Errorf("UUIDString() = %q, want 36 chars with 4 dashes", got)
	}
}
