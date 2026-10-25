package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
)

// AES Key Wrap (RFC 3394) for wrapping document keys with the agent
// reader key (AS). Works for any key length that is a multiple of 8 bytes
// (we wrap 32-byte document keys -> 40-byte output).

// keyWrapDefaultIV is the RFC 3394 initial value.
var keyWrapDefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// ErrCorruptData reports malformed/incorrectly unwrapped key material.
var ErrCorruptData = errors.New("crypto: corrupt key material")

// ErrKeyTooShort reports keys shorter than two 64-bit blocks.
var ErrKeyTooShort = errors.New("crypto: key too short for AES key wrap")

// wrapKey encrypts (wraps) the plaintext key with the KEK using RFC 3394.
func wrapKey(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("%w: not a multiple of 8 bytes", ErrCorruptData)
	}
	if len(plaintext) < 16 {
		return nil, ErrKeyTooShort
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	r := make([]uint64, n+1) // r[1..n]
	for i := 1; i <= n; i++ {
		r[i] = binary.BigEndian.Uint64(plaintext[(i-1)*8 : i*8])
	}
	a := binary.BigEndian.Uint64(keyWrapDefaultIV[:])

	cipherBlock := make([]byte, aes.BlockSize)
	blockPlain := make([]byte, aes.BlockSize)

	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			binary.BigEndian.PutUint64(blockPlain[0:8], a)
			binary.BigEndian.PutUint64(blockPlain[8:16], r[i])
			block.Encrypt(cipherBlock, blockPlain)
			t := uint64(n*j + i)
			a = binary.BigEndian.Uint64(cipherBlock[0:8]) ^ t
			r[i] = binary.BigEndian.Uint64(cipherBlock[8:16])
		}
	}

	out := make([]byte, 0, (n+1)*8)
	t8 := make([]byte, 8)
	binary.BigEndian.PutUint64(t8, a)
	out = append(out, t8...)
	for i := 1; i <= n; i++ {
		binary.BigEndian.PutUint64(t8, r[i])
		out = append(out, t8...)
	}
	return out, nil
}

// unwrapKey decrypts (unwraps) the wrapped key with the KEK using RFC 3394.
func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("%w: not a multiple of 8 bytes", ErrCorruptData)
	}
	if len(wrapped) < 24 {
		return nil, fmt.Errorf("%w: wrapped key too short", ErrCorruptData)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(wrapped)/8 - 1
	r := make([]uint64, n+1) // r[1..n]
	for i := 1; i <= n; i++ {
		r[i] = binary.BigEndian.Uint64(wrapped[i*8 : i*8+8])
	}
	a := binary.BigEndian.Uint64(wrapped[0:8])

	cipherBlock := make([]byte, aes.BlockSize)

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(cipherBlock[0:8], a^t)
			binary.BigEndian.PutUint64(cipherBlock[8:16], r[i])
			block.Decrypt(cipherBlock, cipherBlock)
			a = binary.BigEndian.Uint64(cipherBlock[0:8])
			r[i] = binary.BigEndian.Uint64(cipherBlock[8:16])
		}
	}

	if a != binary.BigEndian.Uint64(keyWrapDefaultIV[:]) {
		return nil, ErrCorruptData
	}

	out := make([]byte, 0, n*8)
	t8 := make([]byte, 8)
	for i := 1; i <= n; i++ {
		binary.BigEndian.PutUint64(t8, r[i])
		out = append(out, t8...)
	}
	return out, nil
}
