// Package crypto implements the cryptographic core of the Clavis agent:
// the protected file header (magic, version, algorithm, document UUID,
// nonce), the AES-256-CTR cryptor with random access, and key getters.
//
// The on-disk layout of a protected file:
//
//	[magic 4B][version 1B][algo 1B][uuid 16B][nonce 8B][reserved 2B][payload...]
package crypto

import (
	"fmt"
)

// MagicBytes identifies a Clavis protected file.
const MagicBytes = "CLVS"

// HeaderVersion is the current file header version.
const HeaderVersion byte = 0x01

// HeaderSize is the fixed size of the file header in bytes.
const HeaderSize = 32

// Field offsets within the header.
const (
	offsetMagic     = 0
	offsetVersion   = 4
	offsetAlgorithm = 5
	offsetUUID      = 6
	offsetNonce     = 22
	offsetReserved  = 30
)

// DocumentHeader describes the metadata of a protected document.
type DocumentHeader struct {
	Version   byte
	Algorithm AlgorithmID
	// UUID uniquely identifies the document (requested from the Key Server).
	UUID [16]byte
	// Nonce is a per-file random value used as the first half of the CTR counter.
	Nonce [8]byte
}

// NewHeader creates a header for the given document UUID and algorithm.
// A fresh random nonce is generated for every new document.
func NewHeader(uuid [16]byte, alg AlgorithmID) (*DocumentHeader, error) {
	if !IsKnownAlgorithm(alg) {
		return nil, fmt.Errorf("crypto: unknown algorithm %d", alg)
	}
	nonce, err := randomBytes(8)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	h := &DocumentHeader{
		Version:   HeaderVersion,
		Algorithm: alg,
		UUID:      uuid,
	}
	copy(h.Nonce[:], nonce)
	return h, nil
}

// Encode serializes the header into HeaderSize bytes.
// The reserved bytes are always zero.
func (h *DocumentHeader) Encode() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[offsetMagic:offsetVersion], MagicBytes)
	buf[offsetVersion] = h.Version
	buf[offsetAlgorithm] = byte(h.Algorithm)
	copy(buf[offsetUUID:offsetNonce], h.UUID[:])
	copy(buf[offsetNonce:offsetReserved], h.Nonce[:])
	return buf
}

// ParseHeader decodes a header from raw bytes and validates it.
func ParseHeader(data []byte) (*DocumentHeader, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("crypto: header too short: got %d bytes, want %d", len(data), HeaderSize)
	}
	if string(data[offsetMagic:offsetVersion]) != MagicBytes {
		return nil, fmt.Errorf("crypto: invalid magic %q", data[offsetMagic:offsetVersion])
	}
	version := data[offsetVersion]
	if version != HeaderVersion {
		return nil, fmt.Errorf("crypto: unsupported header version %d", version)
	}
	alg := AlgorithmID(data[offsetAlgorithm])
	if !IsKnownAlgorithm(alg) {
		return nil, fmt.Errorf("crypto: unknown algorithm %d", alg)
	}
	h := &DocumentHeader{
		Version:   version,
		Algorithm: alg,
	}
	copy(h.UUID[:], data[offsetUUID:offsetNonce])
	copy(h.Nonce[:], data[offsetNonce:offsetReserved])
	return h, nil
}
