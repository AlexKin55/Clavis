package crypto

import (
	"crypto/rand"
	"fmt"
)

// AlgorithmID identifies a cipher algorithm stored in the file header.
// A per-document algorithm binding is part of the product design
// (each document may use a different algorithm, including GOST later).
type AlgorithmID byte

// Supported algorithms.
const (
	// AlgorithmAes256Ctr is AES-256 in CTR mode (stream cipher).
	AlgorithmAes256Ctr AlgorithmID = 0x01
)

// Cryptor transforms data at an arbitrary file offset. In CTR mode
// encryption and decryption are the same operation.
//
// Implementations must be safe for concurrent use.
type Cryptor interface {
	// Algorithm returns the algorithm identifier of this cryptor.
	Algorithm() AlgorithmID
	// Encrypt encrypts the plaintext data located at offset in the file.
	Encrypt(data []byte, offset int64) ([]byte, error)
	// Decrypt decrypts the ciphertext data located at offset in the file.
	Decrypt(data []byte, offset int64) ([]byte, error)
}

var knownAlgorithms = map[AlgorithmID]bool{
	AlgorithmAes256Ctr: true,
}

// IsKnownAlgorithm reports whether the given algorithm identifier is supported.
func IsKnownAlgorithm(id AlgorithmID) bool {
	return knownAlgorithms[id]
}

// NewCryptor builds a cryptor for the header's algorithm using the given key.
// The key material must match the algorithm requirements (32 bytes for
// AES-256-CTR).
func NewCryptor(h *DocumentHeader, key []byte) (Cryptor, error) {
	switch h.Algorithm {
	case AlgorithmAes256Ctr:
		return NewAesCtr(key, h.Nonce)
	default:
		return nil, fmt.Errorf("crypto: unsupported algorithm %d", h.Algorithm)
	}
}

// randomBytes returns n cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
