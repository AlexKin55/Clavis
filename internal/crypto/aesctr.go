package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

const (
	// aesBlockSize is the AES block size in bytes.
	aesBlockSize = 16
)

// AesCtrCryptor is an AES-CTR stream cryptor with random access.
//
// The 128-bit CTR counter is composed of two halves:
//
//	counter[0:8]   = file nonce (from the document header)
//	counter[8:16]  = block index (big-endian)
//
// The block index is derived from the file offset, so any byte range can be
// encrypted/decrypted without processing the preceding bytes. This enables
// random access and block-parallel processing. This matches the C++ prototype
// (EVP_aes_256_ctr with the block index placed in IV bytes [8:16]).
type AesCtrCryptor struct {
	key   []byte
	nonce [8]byte
}

// NewAesCtr creates an AES-CTR cryptor. The key must be 16, 24 or 32 bytes
// long (AES-128/192/256). The nonce is the first half of the CTR counter.
func NewAesCtr(key []byte, nonce [8]byte) (*AesCtrCryptor, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("crypto: aes key must be 16, 24 or 32 bytes, got %d", len(key))
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &AesCtrCryptor{key: k, nonce: nonce}, nil
}

// Algorithm implements Cryptor.
func (c *AesCtrCryptor) Algorithm() AlgorithmID {
	return AlgorithmAes256Ctr
}

// Encrypt implements Cryptor. In CTR mode encryption is a simple XOR with
// the keystream, so it never changes the data length.
func (c *AesCtrCryptor) Encrypt(data []byte, offset int64) ([]byte, error) {
	return c.transform(data, offset)
}

// Decrypt implements Cryptor. In CTR mode decryption is identical to encryption.
func (c *AesCtrCryptor) Decrypt(data []byte, offset int64) ([]byte, error) {
	return c.transform(data, offset)
}

// transform XORs data with the AES-CTR keystream generated for the given
// file offset. The offset does not need to be block-aligned.
func (c *AesCtrCryptor) transform(data []byte, offset int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("crypto: negative offset %d", offset)
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("crypto: create aes cipher: %w", err)
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); {
		pos := offset + int64(i)
		blockIndex := pos / aesBlockSize
		within := int(pos % aesBlockSize)

		// CTR keystream block: keystream = E(counter).
		var ks [aesBlockSize]byte
		block.Encrypt(ks[:], counterFor(c.nonce, blockIndex))

		// XOR only the useful tail of the keystream block.
		n := aesBlockSize - within
		if remaining := len(data) - i; n > remaining {
			n = remaining
		}
		for j := 0; j < n; j++ {
			out[i+j] = data[i+j] ^ ks[within+j]
		}
		i += n
	}
	return out, nil
}

// counterFor builds the 16-byte CTR counter for the given block index.
func counterFor(nonce [8]byte, blockIndex int64) []byte {
	ctr := make([]byte, aesBlockSize)
	copy(ctr[0:8], nonce[:])
	binary.BigEndian.PutUint64(ctr[8:16], uint64(blockIndex))
	return ctr
}
