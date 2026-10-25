package crypto

import (
	"crypto/rand"
	"fmt"
)

// NewUUID generates a random RFC 4122 version 4 UUID.
func NewUUID() ([16]byte, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return u, fmt.Errorf("crypto: generate uuid: %w", err)
	}
	// Set the version (4) and the variant bits (RFC 4122).
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u, nil
}

// UUIDString formats a UUID in the canonical 8-4-4-4-12 form, e.g.
// "f81d4fae-7dec-11d0-a765-00a0c91e6bf6".
func UUIDString(u [16]byte) string {
	const hexDigits = "0123456789abcdef"
	var out [36]byte
	idx := 0
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[idx] = '-'
			idx++
		}
		out[idx] = hexDigits[b>>4]
		idx++
		out[idx] = hexDigits[b&0x0f]
		idx++
	}
	return string(out[:])
}
