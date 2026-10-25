package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Signature metadata block layout (immediately after the v2 header):
//
//	[len 2B big-endian][signature 64B]
const (
	MetaSigLenBytes   = 2
	SignatureBlockLen = MetaSigLenBytes + ed25519.SignatureSize
)

// SignatureBlock signs (header || SHA-256(ciphertext)) with the owner
// identity and serializes the metadata block.
func SignatureBlock(h *HeaderV2, identity *AgentIdentity, ciphertext []byte) []byte {
	payload := signaturePayload(h, ciphertext)
	sig := identity.Sign(payload)

	block := make([]byte, SignatureBlockLen)
	binary.BigEndian.PutUint16(block[:MetaSigLenBytes], uint16(len(sig)))
	copy(block[MetaSigLenBytes:], sig)
	return block
}

// ParseSignatureBlock extracts the Ed25519 signature from the metadata
// block.
func ParseSignatureBlock(block []byte) ([]byte, error) {
	if len(block) < SignatureBlockLen {
		return nil, fmt.Errorf("crypto: signature block too short: got %d, want %d", len(block), SignatureBlockLen)
	}
	size := int(binary.BigEndian.Uint16(block[:MetaSigLenBytes]))
	if size != ed25519.SignatureSize {
		return nil, fmt.Errorf("crypto: invalid signature length %d", size)
	}
	sig := make([]byte, size)
	copy(sig, block[MetaSigLenBytes:MetaSigLenBytes+size])
	return sig, nil
}
